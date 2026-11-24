using System.Text;
using Hush.Core.Audit;
using Hush.Core.Crypto;

namespace Hush.Core.Vault;

/// <summary>Listing information for a secret. Never contains the value.</summary>
public sealed record SecretInfo(string Scope, string Name, SecretPolicy Policy, DateTimeOffset Created, DateTimeOffset Updated, DateTimeOffset? LastUsed)
{
    /// <summary>Display form: <c>scope/NAME</c> or <c>NAME</c>.</summary>
    public string QualifiedName => SecretRef.Format(Scope, Name);

    /// <summary>Creates listing information from an entry.</summary>
    public static SecretInfo From(VaultEntry entry)
    {
        ArgumentNullException.ThrowIfNull(entry);
        return new SecretInfo(entry.Scope, entry.Name, entry.Policy, entry.Created, entry.Updated, entry.LastUsed);
    }
}

/// <summary>A decrypted secret, ready to be injected into a process environment.</summary>
/// <param name="Requested">What the caller asked for.</param>
/// <param name="Resolved">The entry that answered (may be a global fallback).</param>
/// <param name="Value">The plaintext value.</param>
[Sensitive]
public sealed record RevealedSecret(SecretRef Requested, SecretRef Resolved, [property: Sensitive] string Value);

/// <summary>
/// An open vault holding the DEK in a pinned buffer. Every mutation takes the cross-process lock, re-reads
/// the file, verifies its MAC, applies the change, appends the audit entry and writes atomically.
/// </summary>
public sealed class UnlockedVault : IDisposable
{
    private static readonly TimeSpan LockTimeout = TimeSpan.FromSeconds(10);

    /// <summary>Largest secret value accepted, in bytes.</summary>
    public const int MaxValueBytes = 64 * 1024;

    private readonly VaultManager _manager;
    private readonly SecureBuffer _dek;
    private (DateTime LastWriteUtc, long Length) _stamp;

    internal UnlockedVault(VaultManager manager, VaultDocument document, SecureBuffer dek, (DateTime, long) stamp)
    {
        _manager = manager;
        Document = document;
        _dek = dek;
        _stamp = stamp;
    }

    /// <summary>The last document read or written.</summary>
    public VaultDocument Document { get; private set; }

    /// <summary>The vault id.</summary>
    public Guid VaultId => Document.VaultId;

    /// <summary>Copies the DEK so it can be handed to the session broker. The caller disposes the copy.</summary>
    public SecureBuffer CopyDek() => _dek.Clone();

    /// <summary>
    /// Re-reads the file if another process replaced it. Throws <see cref="HushErrorCode.Locked"/> if the
    /// held DEK no longer opens it (for example after a rotation elsewhere).
    /// </summary>
    public void Refresh()
    {
        var stamp = _manager.Store.Stamp();
        if (stamp == _stamp)
        {
            return;
        }

        var bytes = _manager.Store.ReadAll();
        Document = Verify(bytes);
        _stamp = stamp;
    }

    /// <summary>Lists every secret, sorted by qualified name.</summary>
    public IReadOnlyList<SecretInfo> List()
    {
        Refresh();
        return Document.Entries.Select(SecretInfo.From).OrderBy(s => s.QualifiedName, StringComparer.OrdinalIgnoreCase).ToList();
    }

    /// <summary>
    /// Decrypts secrets, records their use, and appends one audit entry. Throws
    /// <see cref="HushErrorCode.PresenceRequired"/> if any is always-prompt and
    /// <paramref name="presenceVerified"/> is false.
    /// </summary>
    public IReadOnlyList<RevealedSecret> Reveal(IReadOnlyList<SecretLookup> lookups, bool presenceVerified, AuditEvent audit)
    {
        ArgumentNullException.ThrowIfNull(lookups);
        ArgumentNullException.ThrowIfNull(audit);
        return Mutate(
            document =>
            {
                var now = _manager.Time.GetUtcNow();
                var found = new List<(SecretRef Requested, VaultEntry Entry)>();
                var missing = new List<string>();
                foreach (var lookup in lookups)
                {
                    var entry = FindEntry(document, lookup.Ref, lookup.FallbackToGlobal);
                    if (entry is null)
                    {
                        missing.Add(lookup.Ref.ToString());
                    }
                    else
                    {
                        found.Add((lookup.Ref, entry));
                    }
                }

                if (missing.Count > 0)
                {
                    throw new HushException(HushErrorCode.SecretNotFound, $"Not in the vault: {string.Join(", ", missing)}.");
                }

                var needPresence = found.Where(f => f.Entry.Policy == SecretPolicy.AlwaysPrompt).Select(f => f.Entry.QualifiedName).Distinct().ToList();
                if (needPresence.Count > 0 && !presenceVerified)
                {
                    throw new HushException(HushErrorCode.PresenceRequired, $"Windows Hello confirmation required for: {string.Join(", ", needPresence)}.");
                }

                var revealed = new List<RevealedSecret>(found.Count);
                var touched = new HashSet<Guid>();
                foreach (var (requested, entry) in found)
                {
                    using var plain = Aead.Open(_dek.Span, entry.Ciphertext, VaultCodec.EntryAad(document.VaultId, entry.Id, entry.Version), $"secret '{entry.QualifiedName}'");
                    revealed.Add(new RevealedSecret(requested, new SecretRef(entry.Scope, entry.Name), Encoding.UTF8.GetString(plain.Span)));
                    touched.Add(entry.Id);
                }

                var entries = document.Entries.Select(e => touched.Contains(e.Id) ? e with { LastUsed = now } : e).ToList();
                var auditWithNames = audit with { Secrets = found.Select(f => f.Entry.QualifiedName).Distinct().ToList() };
                return (document with { Entries = entries }, revealed, auditWithNames);
            });
    }

    /// <summary>Adds or replaces a secret. A new value gets a new version (and so a new AAD and nonce).</summary>
    public void Set(SecretRef reference, ReadOnlySpan<byte> utf8Value, SecretPolicy? policy, AuditEvent audit)
    {
        reference.Validate();
        ArgumentNullException.ThrowIfNull(audit);
        if (utf8Value.Length == 0)
        {
            throw new HushException(HushErrorCode.InvalidInput, "The secret value is empty.");
        }

        if (utf8Value.Length > MaxValueBytes)
        {
            throw new HushException(HushErrorCode.InvalidInput, $"Secret values are limited to {MaxValueBytes / 1024} KiB.");
        }

        var value = utf8Value.ToArray();
        try
        {
            Mutate(document =>
            {
                var now = _manager.Time.GetUtcNow();
                var entries = document.Entries.ToList();
                var index = entries.FindIndex(e => Matches(e, reference));
                if (index >= 0)
                {
                    var existing = entries[index];
                    var version = existing.Version + 1;
                    entries[index] = existing with
                    {
                        Version = version,
                        Policy = policy ?? existing.Policy,
                        Updated = now,
                        Ciphertext = Aead.Seal(_dek.Span, value, VaultCodec.EntryAad(document.VaultId, existing.Id, version)),
                    };
                }
                else
                {
                    var id = Guid.NewGuid();
                    entries.Add(new VaultEntry(
                        id,
                        1,
                        reference.Scope,
                        reference.Name,
                        policy ?? SecretPolicy.Session,
                        now,
                        now,
                        null,
                        Aead.Seal(_dek.Span, value, VaultCodec.EntryAad(document.VaultId, id, 1))));
                }

                return (document with { Entries = entries }, true, audit with { Secrets = [reference.ToString()], Detail = audit.Detail ?? (index >= 0 ? "updated" : "created") });
            });
        }
        finally
        {
            System.Security.Cryptography.CryptographicOperations.ZeroMemory(value);
        }
    }

    /// <summary>Changes only the policy of an existing secret.</summary>
    public void SetPolicy(SecretRef reference, SecretPolicy policy, AuditEvent audit)
    {
        ArgumentNullException.ThrowIfNull(audit);
        Mutate(document =>
        {
            var entries = document.Entries.ToList();
            var index = entries.FindIndex(e => Matches(e, reference));
            if (index < 0)
            {
                throw new HushException(HushErrorCode.SecretNotFound, $"'{reference}' is not in the vault.");
            }

            entries[index] = entries[index] with { Policy = policy, Updated = _manager.Time.GetUtcNow() };
            return (document with { Entries = entries }, true, audit with { Secrets = [reference.ToString()] });
        });
    }

    /// <summary>Deletes a secret. Returns false if it did not exist.</summary>
    public bool Remove(SecretRef reference, AuditEvent audit)
    {
        ArgumentNullException.ThrowIfNull(audit);
        return Mutate(document =>
        {
            var entries = document.Entries.Where(e => !Matches(e, reference)).ToList();
            var removed = entries.Count != document.Entries.Count;
            return (document with { Entries = entries }, removed, audit with { Secrets = [reference.ToString()], Result = removed ? audit.Result : "not-found" });
        });
    }

    /// <summary>Appends an audit entry and updates the head stored in the vault.</summary>
    public void Record(AuditEvent audit) => Mutate(document => (document, true, audit));

    /// <summary>Moves events recorded while locked into the chain, marked as deferred.</summary>
    public int FoldPendingAudit()
    {
        using (_manager.Store.AcquireLock(LockTimeout))
        {
            var pending = PendingAudit.Drain(_manager.Paths.PendingAudit);
            if (pending.Count == 0)
            {
                return 0;
            }

            var bytes = _manager.Store.ReadAll();
            var document = Verify(bytes);
            using var auditKey = OpenAuditKey(document);
            var (sequence, head) = AnchorInterruptedEntry(document, auditKey.Span);
            foreach (var (timestamp, auditEvent) in pending)
            {
                (sequence, head) = _manager.AuditLog.Append(auditEvent, auditKey.Span, sequence, head, timestamp, deferred: true);
            }

            var updated = document with { AuditSequence = sequence, AuditHead = head, Updated = _manager.Time.GetUtcNow() };
            _manager.Store.WriteAtomic(VaultCodec.Write(updated, _dek.Span));
            Document = updated;
            _stamp = _manager.Store.Stamp();
            return pending.Count;
        }
    }

    /// <summary>Verifies the audit chain against the head stored in the vault.</summary>
    public AuditVerification VerifyAudit()
    {
        Refresh();
        using var auditKey = OpenAuditKey(Document);
        return _manager.AuditLog.Verify(auditKey.Span, Document.AuditSequence, Document.AuditHead);
    }

    /// <summary>
    /// Builds a portable export: the same format with the hardware factors removed and only the recovery
    /// wrapping kept, so the file opens on any machine with the recovery key and nowhere without it.
    /// </summary>
    public byte[] BuildPortableExport(AuditEvent audit)
    {
        ArgumentNullException.ThrowIfNull(audit);
        Refresh();
        var portable = Document with
        {
            Flags = (Document.Flags & VaultAttributes.TestProvider) | VaultAttributes.Portable,
            Factors = null,
            WrappedKeys = [Document.GetWrappedKey(WrapKind.Recovery)],
            AuditSequence = 0,
            AuditHead = AuditLog.GenesisMac,
            Updated = _manager.Time.GetUtcNow(),
        };
        var bytes = VaultCodec.Write(portable, _dek.Span);
        Record(audit with { Secrets = Document.Entries.Select(e => e.QualifiedName).ToList() });
        return bytes;
    }

    /// <summary>Adds secrets in bulk (import), re-encrypting them under this vault's DEK. One audit entry.</summary>
    public (int Imported, int Skipped) Import(IReadOnlyList<ImportItem> items, bool overwrite, AuditEvent audit)
    {
        ArgumentNullException.ThrowIfNull(items);
        ArgumentNullException.ThrowIfNull(audit);
        return Mutate(document =>
        {
            var now = _manager.Time.GetUtcNow();
            var entries = document.Entries.ToList();
            var imported = new List<string>();
            var skipped = 0;
            foreach (var item in items)
            {
                item.Ref.Validate();
                var index = entries.FindIndex(e => Matches(e, item.Ref));
                if (index >= 0 && !overwrite)
                {
                    skipped++;
                    continue;
                }

                var id = index >= 0 ? entries[index].Id : Guid.NewGuid();
                var version = index >= 0 ? entries[index].Version + 1 : 1;
                var entry = new VaultEntry(
                    id,
                    version,
                    item.Ref.Scope,
                    item.Ref.Name,
                    item.Policy,
                    index >= 0 ? entries[index].Created : now,
                    now,
                    null,
                    Aead.Seal(_dek.Span, item.Value, VaultCodec.EntryAad(document.VaultId, id, version)));
                if (index >= 0)
                {
                    entries[index] = entry;
                }
                else
                {
                    entries.Add(entry);
                }

                imported.Add(item.Ref.ToString());
            }

            return (document with { Entries = entries }, (imported.Count, skipped), audit with { Secrets = imported, Detail = audit.Detail ?? $"{imported.Count} imported, {skipped} skipped" });
        });
    }

    /// <inheritdoc />
    public void Dispose() => _dek.Dispose();

    internal static VaultEntry? FindEntry(VaultDocument document, SecretRef reference, bool fallbackToGlobal)
    {
        var exact = document.Entries.FirstOrDefault(e => Matches(e, reference));
        if (exact is not null || !fallbackToGlobal || reference.Scope.Length == 0)
        {
            return exact;
        }

        return document.Entries.FirstOrDefault(e => e.Scope.Length == 0 && string.Equals(e.Name, reference.Name, StringComparison.OrdinalIgnoreCase));
    }

    private static bool Matches(VaultEntry entry, SecretRef reference) =>
        string.Equals(entry.Scope, reference.Scope, StringComparison.OrdinalIgnoreCase)
        && string.Equals(entry.Name, reference.Name, StringComparison.OrdinalIgnoreCase);

    private VaultDocument Verify(byte[] bytes)
    {
        var document = VaultCodec.Read(bytes);
        if (document.VaultId != Document.VaultId)
        {
            throw new HushException(HushErrorCode.Locked, "The vault file was replaced by a different vault. Unlock again.");
        }

        try
        {
            VaultCodec.VerifyMac(bytes, _dek.Span, document.Salt);
        }
        catch (HushException ex) when (ex.Code == HushErrorCode.TamperDetected)
        {
            throw new HushException(HushErrorCode.Locked, "The vault changed on disk (rotated, recovered or modified). Unlock again.", ex);
        }

        return document;
    }

    /// <summary>
    /// If the previous operation crashed after logging but before updating the vault, chain from its entry and add
    /// an entry saying so, rather than forking the chain. Returns the head to append after.
    /// </summary>
    private (ulong Sequence, byte[] Head) AnchorInterruptedEntry(VaultDocument document, ReadOnlySpan<byte> auditKey)
    {
        if (_manager.AuditLog.FindUnanchoredTail(auditKey, document.AuditSequence, document.AuditHead) is not { } orphan)
        {
            return (document.AuditSequence, document.AuditHead);
        }

        var note = new AuditEvent(
            "audit.interrupted",
            [],
            "warning",
            $"entry {orphan.Sequence} was logged but its vault update did not complete; the operation it records may not have happened",
            Interop.ProcessInspector.Current());
        return _manager.AuditLog.Append(note, auditKey, orphan.Sequence, orphan.Mac, _manager.Time.GetUtcNow());
    }

    private SecureBuffer OpenAuditKey(VaultDocument document) =>
        Aead.Open(_dek.Span, document.WrappedAuditKey, VaultCodec.AuditKeyAad(document.VaultId), "audit key");

    private T Mutate<T>(Func<VaultDocument, (VaultDocument Document, T Result, AuditEvent? Audit)> change)
    {
        using (_manager.Store.AcquireLock(LockTimeout))
        {
            // Writers hold this lock while their temp file exists, so any temp file seen now is from a crash.
            _manager.Store.CleanupStaleTempFiles();
            var bytes = _manager.Store.ReadAll();
            var current = Verify(bytes);
            var (updated, result, audit) = change(current);
            if (audit is not null)
            {
                using var auditKey = OpenAuditKey(updated);
                var (previousSequence, previousHead) = AnchorInterruptedEntry(updated, auditKey.Span);
                var (sequence, head) = _manager.AuditLog.Append(audit, auditKey.Span, previousSequence, previousHead, _manager.Time.GetUtcNow());
                updated = updated with { AuditSequence = sequence, AuditHead = head };
            }

            updated = updated with { Updated = _manager.Time.GetUtcNow() };
            _manager.Store.WriteAtomic(VaultCodec.Write(updated, _dek.Span));
            Document = updated;
            _stamp = _manager.Store.Stamp();
            return result;
        }
    }
}

/// <summary>An opened portable export.</summary>
public sealed class PortableVault : IDisposable
{
    private readonly SecureBuffer _dek;

    internal PortableVault(VaultDocument document, SecureBuffer dek)
    {
        Document = document;
        _dek = dek;
    }

    /// <summary>The export's document.</summary>
    public VaultDocument Document { get; }

    /// <summary>Decrypts every entry. Callers dispose each buffer.</summary>
    public IEnumerable<(VaultEntry Entry, SecureBuffer Plaintext)> DecryptAll()
    {
        foreach (var entry in Document.Entries)
        {
            yield return (entry, Aead.Open(_dek.Span, entry.Ciphertext, VaultCodec.EntryAad(Document.VaultId, entry.Id, entry.Version), $"secret '{entry.QualifiedName}'"));
        }
    }

    /// <inheritdoc />
    public void Dispose() => _dek.Dispose();
}

/// <summary>A secret to look up, optionally falling back from a project scope to the global secret.</summary>
public readonly record struct SecretLookup(SecretRef Ref, bool FallbackToGlobal);

/// <summary>A secret to add during an import.</summary>
/// <param name="Ref">Where to store it.</param>
/// <param name="Policy">Its policy.</param>
/// <param name="Value">The UTF-8 value.</param>
[Sensitive]
public sealed record ImportItem(SecretRef Ref, SecretPolicy Policy, [property: Sensitive] byte[] Value);
