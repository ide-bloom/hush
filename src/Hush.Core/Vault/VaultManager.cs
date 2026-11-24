using System.Security.Cryptography;
using Hush.Core.Audit;
using Hush.Core.Crypto;
using Hush.Core.Keys;

namespace Hush.Core.Vault;

/// <summary>The result of <see cref="VaultManager.CreateAsync"/>.</summary>
/// <param name="Vault">The new, unlocked vault.</param>
/// <param name="RecoveryKey">The recovery key. Show it once, then dispose it.</param>
public sealed record VaultCreation(UnlockedVault Vault, RecoveryKey RecoveryKey);

/// <summary>
/// Creates, unlocks, recovers and rotates the vault. Implements the key hierarchy in docs/crypto.md:
/// K_hello from a deterministic Windows Hello signature, S_tpm from the TPM (or DPAPI), the KEK from both,
/// and the DEK wrapped under the KEK and under the recovery key.
/// </summary>
public sealed class VaultManager
{
    private static readonly TimeSpan LockTimeout = TimeSpan.FromSeconds(10);
    private readonly IHardwareKeyProvider _provider;
    private readonly TimeProvider _time;

    /// <summary>Creates a manager for the vault at <paramref name="paths"/>.</summary>
    public VaultManager(HushPaths paths, IHardwareKeyProvider provider, VaultStore? store = null, TimeProvider? time = null)
    {
        ArgumentNullException.ThrowIfNull(paths);
        ArgumentNullException.ThrowIfNull(provider);
        TestProviderGate.EnsureAllowed(provider);
        Paths = paths;
        _provider = provider;
        _time = time ?? TimeProvider.System;
        Store = store ?? VaultStore.For(paths);
        AuditLog = new AuditLog(paths.AuditLog);
    }

    /// <summary>File locations.</summary>
    public HushPaths Paths { get; }

    /// <summary>The vault file store.</summary>
    public VaultStore Store { get; }

    /// <summary>The audit log.</summary>
    public AuditLog AuditLog { get; }

    /// <summary>True if a vault exists.</summary>
    public bool Exists => Store.Exists;

    internal TimeProvider Time => _time;

    /// <summary>Reads the vault without unlocking it. Metadata (names, policies) is readable but unauthenticated.</summary>
    public VaultDocument ReadDocument() => VaultCodec.Read(Store.ReadAll());

    /// <summary>
    /// Creates a new vault: enrolls a Windows Hello key and verifies that its signatures are deterministic,
    /// seals S_tpm with the TPM (or DPAPI when no TPM is usable), generates the DEK and the recovery key.
    /// </summary>
    public async Task<VaultCreation> CreateAsync(PromptContext prompt, IProgress<string>? progress, CancellationToken cancellationToken)
    {
        if (Exists)
        {
            throw new HushException(HushErrorCode.VaultAlreadyExists, $"A vault already exists at {Store.Path}.");
        }

        Paths.EnsureHome();
        Store.CleanupStaleTempFiles();

        var vaultId = Guid.NewGuid();
        var salt = RandomNumberGenerator.GetBytes(32);
        var challenge = RandomNumberGenerator.GetBytes(32);
        const uint generation = 1;

        var enrollment = await EnrollFactorsAsync(vaultId, generation, salt, challenge, prompt, progress, cancellationToken).ConfigureAwait(false);
        using var kek = enrollment.Kek;
        var dek = SecureBuffer.Random(32);
        var recovery = RecoveryKey.Generate();
        try
        {
            using var recoveryWrappingKey = recovery.DeriveWrappingKey(salt);
            using var auditKey = Kdf.Derive(dek.Span, salt, Kdf.AuditInfo);
            var now = _time.GetUtcNow();
            var flags = VaultAttributes.None;
            if (enrollment.Factors.SecondFactor == SecondFactorKind.Dpapi)
            {
                flags |= VaultAttributes.Degraded;
            }

            if (_provider.Kind == KeyProviderKind.Test)
            {
                flags |= VaultAttributes.TestProvider;
            }

            var document = new VaultDocument
            {
                FormatVersion = VaultCodec.CurrentVersion,
                Flags = flags,
                VaultId = vaultId,
                Salt = salt,
                Challenge = challenge,
                Created = now,
                Updated = now,
                Generation = generation,
                AuditSequence = 0,
                AuditHead = AuditLog.GenesisMac,
                Factors = enrollment.Factors,
                WrappedAuditKey = Aead.Seal(dek.Span, auditKey.Span, VaultCodec.AuditKeyAad(vaultId)),
                WrappedKeys =
                [
                    new WrappedKey(WrapKind.Factors, Aead.Seal(kek.Span, dek.Span, VaultCodec.WrapAad(vaultId, WrapKind.Factors))),
                    new WrappedKey(WrapKind.Recovery, Aead.Seal(recoveryWrappingKey.Span, dek.Span, VaultCodec.WrapAad(vaultId, WrapKind.Recovery))),
                ],
                Entries = [],
            };

            // A fresh vault starts a fresh audit chain.
            if (File.Exists(AuditLog.Path))
            {
                File.Move(AuditLog.Path, AuditLog.Path + $".{now:yyyyMMddHHmmss}.old", overwrite: true);
            }

            using (Store.AcquireLock(LockTimeout))
            {
                Store.WriteAtomic(VaultCodec.Write(document, dek.Span));
            }

            var vault = new UnlockedVault(this, document, dek, Store.Stamp());
            vault.Record(new AuditEvent("vault.create", [], "ok", Describe(enrollment.Factors), Interop.ProcessInspector.Current()));
            return new VaultCreation(vault, recovery);
        }
        catch
        {
            dek.Dispose();
            recovery.Dispose();
            throw;
        }
    }

    /// <summary>Unlocks with Windows Hello and the TPM (or DPAPI) factor.</summary>
    public async Task<UnlockedVault> UnlockAsync(PromptContext prompt, CancellationToken cancellationToken)
    {
        var bytes = Store.ReadAll();
        var document = VaultCodec.Read(bytes);
        var factors = EnsureOpenable(document);

        using var kek = await DeriveKekAsync(document, factors, prompt, cancellationToken).ConfigureAwait(false);
        var dek = Aead.Open(kek.Span, document.GetWrappedKey(WrapKind.Factors).Blob, VaultCodec.WrapAad(document.VaultId, WrapKind.Factors), "wrapped vault key");
        try
        {
            VaultCodec.VerifyMac(bytes, dek.Span, document.Salt);
            return new UnlockedVault(this, document, dek, Store.Stamp());
        }
        catch
        {
            dek.Dispose();
            throw;
        }
    }

    /// <summary>
    /// Opens the vault with a DEK handed over by an unlocking client (the session broker uses this). The
    /// DEK is copied; the caller keeps ownership of <paramref name="dek"/>.
    /// </summary>
    public UnlockedVault OpenWithDek(ReadOnlySpan<byte> dek)
    {
        var bytes = Store.ReadAll();
        var document = VaultCodec.Read(bytes);
        EnsureOpenable(document);
        if (dek.Length != 32)
        {
            throw new HushException(HushErrorCode.InvalidInput, "The vault key has the wrong length.");
        }

        VaultCodec.VerifyMac(bytes, dek, document.Salt);
        return new UnlockedVault(this, document, SecureBuffer.CopyOf(dek), Store.Stamp());
    }

    /// <summary>Opens the vault with only the recovery key, without touching the hardware factors.</summary>
    public UnlockedVault UnlockWithRecoveryKey(RecoveryKey recoveryKey)
    {
        ArgumentNullException.ThrowIfNull(recoveryKey);
        var bytes = Store.ReadAll();
        var document = VaultCodec.Read(bytes);
        var dek = OpenWithRecovery(bytes, document, recoveryKey);
        return new UnlockedVault(this, document, dek, Store.Stamp());
    }

    /// <summary>
    /// Restores access after Windows Hello was reset, the TPM was cleared, or the vault moved to a new
    /// machine: opens the DEK with the recovery key and enrolls new Hello and TPM factors.
    /// </summary>
    public async Task<UnlockedVault> RecoverAsync(RecoveryKey recoveryKey, PromptContext prompt, IProgress<string>? progress, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(recoveryKey);
        var bytes = Store.ReadAll();
        var document = VaultCodec.Read(bytes);
        using var dek = OpenWithRecovery(bytes, document, recoveryKey);

        var generation = document.Generation + 1;
        var enrollment = await EnrollFactorsAsync(document.VaultId, generation, document.Salt, document.Challenge, prompt, progress, cancellationToken).ConfigureAwait(false);
        using var kek = enrollment.Kek;

        VaultDocument updated;
        using (Store.AcquireLock(LockTimeout))
        {
            var currentBytes = Store.ReadAll();
            var current = VaultCodec.Read(currentBytes);
            VaultCodec.VerifyMac(currentBytes, dek.Span, current.Salt);
            var flags = current.Flags & ~VaultAttributes.Degraded;
            if (enrollment.Factors.SecondFactor == SecondFactorKind.Dpapi)
            {
                flags |= VaultAttributes.Degraded;
            }

            updated = current with
            {
                Flags = flags,
                Generation = generation,
                Factors = enrollment.Factors,
                Updated = _time.GetUtcNow(),
                WrappedKeys =
                [
                    new WrappedKey(WrapKind.Factors, Aead.Seal(kek.Span, dek.Span, VaultCodec.WrapAad(current.VaultId, WrapKind.Factors))),
                    current.GetWrappedKey(WrapKind.Recovery),
                ],
            };
            Store.WriteAtomic(VaultCodec.Write(updated, dek.Span));
        }

        var vault = new UnlockedVault(this, updated, dek.Clone(), Store.Stamp());
        vault.Record(new AuditEvent("vault.recover", [], "ok", Describe(enrollment.Factors), Interop.ProcessInspector.Current()));

        if (document.Factors is { } old)
        {
            await RemoveOldFactorsAsync(old, progress, cancellationToken).ConfigureAwait(false);
        }

        return vault;
    }

    /// <summary>
    /// Rotates the DEK: re-encrypts every entry under a new DEK, re-wraps it under the hardware factors and
    /// a new recovery key. The old recovery key stops working. Requires a Windows Hello confirmation.
    /// </summary>
    public async Task<VaultCreation> RotateAsync(PromptContext prompt, CancellationToken cancellationToken)
    {
        var bytes = Store.ReadAll();
        var document = VaultCodec.Read(bytes);
        var factors = EnsureOpenable(document);
        using var kek = await DeriveKekAsync(document, factors, prompt, cancellationToken).ConfigureAwait(false);
        using var oldDek = Aead.Open(kek.Span, document.GetWrappedKey(WrapKind.Factors).Blob, VaultCodec.WrapAad(document.VaultId, WrapKind.Factors), "wrapped vault key");

        var newDek = SecureBuffer.Random(32);
        var recovery = RecoveryKey.Generate();
        try
        {
            VaultDocument rotated;
            using (Store.AcquireLock(LockTimeout))
            {
                var currentBytes = Store.ReadAll();
                var current = VaultCodec.Read(currentBytes);
                VaultCodec.VerifyMac(currentBytes, oldDek.Span, current.Salt);

                using var auditKey = Aead.Open(oldDek.Span, current.WrappedAuditKey, VaultCodec.AuditKeyAad(current.VaultId), "audit key");
                using var recoveryWrappingKey = recovery.DeriveWrappingKey(current.Salt);
                var entries = new List<VaultEntry>(current.Entries.Count);
                foreach (var entry in current.Entries)
                {
                    using var plain = Aead.Open(oldDek.Span, entry.Ciphertext, VaultCodec.EntryAad(current.VaultId, entry.Id, entry.Version), $"secret '{entry.QualifiedName}'");
                    var version = entry.Version + 1;
                    entries.Add(entry with
                    {
                        Version = version,
                        Ciphertext = Aead.Seal(newDek.Span, plain.Span, VaultCodec.EntryAad(current.VaultId, entry.Id, version)),
                    });
                }

                rotated = current with
                {
                    Updated = _time.GetUtcNow(),
                    Entries = entries,
                    WrappedAuditKey = Aead.Seal(newDek.Span, auditKey.Span, VaultCodec.AuditKeyAad(current.VaultId)),
                    WrappedKeys =
                    [
                        new WrappedKey(WrapKind.Factors, Aead.Seal(kek.Span, newDek.Span, VaultCodec.WrapAad(current.VaultId, WrapKind.Factors))),
                        new WrappedKey(WrapKind.Recovery, Aead.Seal(recoveryWrappingKey.Span, newDek.Span, VaultCodec.WrapAad(current.VaultId, WrapKind.Recovery))),
                    ],
                };
                Store.WriteAtomic(VaultCodec.Write(rotated, newDek.Span));
            }

            var vault = new UnlockedVault(this, rotated, newDek, Store.Stamp());
            vault.Record(new AuditEvent("vault.rotate", [], "ok", $"{rotated.Entries.Count} entries re-encrypted; new recovery key issued", Interop.ProcessInspector.Current()));
            return new VaultCreation(vault, recovery);
        }
        catch
        {
            newDek.Dispose();
            recovery.Dispose();
            throw;
        }
    }

    /// <summary>
    /// Signs a broker-issued nonce with the vault's Windows Hello key. The broker verifies the signature
    /// against the public key in the vault header, which proves a fresh, in-person confirmation.
    /// </summary>
    public async Task<byte[]> SignPresenceAsync(ReadOnlyMemory<byte> nonce, PromptContext prompt, CancellationToken cancellationToken)
    {
        var document = ReadDocument();
        var factors = EnsureOpenable(document);
        return await _provider.SignWithHelloAsync(factors.HelloKeyName, nonce, prompt, cancellationToken).ConfigureAwait(false);
    }

    /// <summary>Verifies a presence signature against the Hello public key (PKCS#1 v1.5 or PSS, SHA-256).</summary>
    public static bool VerifyPresence(FactorInfo factors, ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> signature)
    {
        ArgumentNullException.ThrowIfNull(factors);
        using var rsa = RSA.Create();
        rsa.ImportSubjectPublicKeyInfo(factors.HelloPublicKey, out _);
        return rsa.VerifyData(nonce, signature, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1)
            || rsa.VerifyData(nonce, signature, HashAlgorithmName.SHA256, RSASignaturePadding.Pss);
    }

    /// <summary>Opens a portable export file with its recovery key.</summary>
    public static PortableVault OpenPortable(ReadOnlySpan<byte> fileBytes, RecoveryKey recoveryKey)
    {
        ArgumentNullException.ThrowIfNull(recoveryKey);
        var document = VaultCodec.Read(fileBytes);
        if (!document.Flags.HasFlag(VaultAttributes.Portable))
        {
            throw new HushException(HushErrorCode.InvalidInput, "That file is a vault, not a Hush export. Use 'hush recover' for a vault file.");
        }

        var dek = OpenWithRecovery(fileBytes, document, recoveryKey);
        return new PortableVault(document, dek);
    }

    internal static SecureBuffer OpenWithRecovery(ReadOnlySpan<byte> bytes, VaultDocument document, RecoveryKey recoveryKey)
    {
        using var wrappingKey = recoveryKey.DeriveWrappingKey(document.Salt);
        SecureBuffer dek;
        try
        {
            dek = Aead.Open(wrappingKey.Span, document.GetWrappedKey(WrapKind.Recovery).Blob, VaultCodec.WrapAad(document.VaultId, WrapKind.Recovery), "recovery wrapping");
        }
        catch (HushException ex) when (ex.Code == HushErrorCode.TamperDetected)
        {
            throw new HushException(HushErrorCode.InvalidRecoveryKey, "That recovery key does not open this vault.", ex);
        }

        try
        {
            VaultCodec.VerifyMac(bytes, dek.Span, document.Salt);
            return dek;
        }
        catch
        {
            dek.Dispose();
            throw;
        }
    }

    private static FactorInfo EnsureOpenable(VaultDocument document)
    {
        if (document.Flags.HasFlag(VaultAttributes.TestProvider) && !TestProviderGate.IsTestHost)
        {
            throw new HushException(HushErrorCode.TestProviderRefused, "This vault was created by the Hush test suite and cannot be opened by a production build.");
        }

        if (document.Flags.HasFlag(VaultAttributes.Portable) || document.Factors is null)
        {
            throw new HushException(HushErrorCode.InvalidInput, "This file is a portable export; import it with 'hush import'.");
        }

        return document.Factors;
    }

    private async Task<SecureBuffer> DeriveKekAsync(VaultDocument document, FactorInfo factors, PromptContext prompt, CancellationToken cancellationToken)
    {
        var signature = await _provider.SignWithHelloAsync(factors.HelloKeyName, document.Challenge, prompt, cancellationToken).ConfigureAwait(false);
        try
        {
            using var helloKey = Kdf.Derive(signature, document.Salt, Kdf.HelloInfo);
            using var secondFactor = _provider.OpenSecondFactor(factors.SecondFactor, factors.SecondFactorKeyName, factors.SealedSecondFactor);
            return Kdf.DeriveKek(helloKey.Span, secondFactor.Span, document.Salt);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(signature);
        }
    }

    private async Task<(FactorInfo Factors, SecureBuffer Kek)> EnrollFactorsAsync(
        Guid vaultId,
        uint generation,
        byte[] salt,
        byte[] challenge,
        PromptContext prompt,
        IProgress<string>? progress,
        CancellationToken cancellationToken)
    {
        var helloProblem = await _provider.CheckHelloAsync(cancellationToken).ConfigureAwait(false);
        if (helloProblem is not null)
        {
            throw new HushException(HushErrorCode.HelloUnavailable, helloProblem);
        }

        var keyName = $"hush-{vaultId:N}-g{generation}";
        progress?.Report("Creating a Windows Hello key for this vault (verification 1 of 3)...");
        var hello = await _provider.CreateHelloKeyAsync(keyName, prompt, cancellationToken).ConfigureAwait(false);
        try
        {
            progress?.Report("Deriving the Hello factor (verification 2 of 3)...");
            var first = await _provider.SignWithHelloAsync(keyName, challenge, prompt, cancellationToken).ConfigureAwait(false);
            progress?.Report("Confirming the Hello signature is deterministic (verification 3 of 3)...");
            var second = await _provider.SignWithHelloAsync(keyName, challenge, prompt, cancellationToken).ConfigureAwait(false);
            try
            {
                if (!CryptographicOperations.FixedTimeEquals(first, second))
                {
                    throw new HushException(
                        HushErrorCode.HelloNotDeterministic,
                        "Windows Hello produced two different signatures for the same challenge, so it cannot be used to derive a stable key. The vault was not created.");
                }

                using var helloKey = Kdf.Derive(first, salt, Kdf.HelloInfo);
                var choice = _provider.ChooseSecondFactor();
                using var secret = SecureBuffer.Random(32);
                byte[] sealedSecret;
                var degradedReason = choice.DegradedReason;
                var kind = choice.Kind;
                if (kind == SecondFactorKind.Tpm)
                {
                    try
                    {
                        sealedSecret = _provider.SealSecondFactor(kind, keyName, secret.Span);
                    }
                    catch (HushException ex) when (ex.Code == HushErrorCode.TpmFailure)
                    {
                        kind = SecondFactorKind.Dpapi;
                        degradedReason = ex.Message;
                        sealedSecret = _provider.SealSecondFactor(kind, keyName, secret.Span);
                    }
                }
                else
                {
                    sealedSecret = _provider.SealSecondFactor(kind, keyName, secret.Span);
                }

                var factors = new FactorInfo(kind, keyName, hello.PublicKey, keyName, sealedSecret, kind == SecondFactorKind.Dpapi ? degradedReason : null);
                return (factors, Kdf.DeriveKek(helloKey.Span, secret.Span, salt));
            }
            finally
            {
                CryptographicOperations.ZeroMemory(first);
                CryptographicOperations.ZeroMemory(second);
            }
        }
        catch
        {
            await _provider.DeleteHelloKeyAsync(keyName, CancellationToken.None).ConfigureAwait(false);
            throw;
        }
    }

    private async Task RemoveOldFactorsAsync(FactorInfo old, IProgress<string>? progress, CancellationToken cancellationToken)
    {
        try
        {
            await _provider.DeleteHelloKeyAsync(old.HelloKeyName, cancellationToken).ConfigureAwait(false);
            _provider.DeleteSecondFactor(old.SecondFactor, old.SecondFactorKeyName);
        }
        catch (Exception ex) when (ex is HushException or CryptographicException or System.Runtime.InteropServices.COMException)
        {
            // The vault already works with the new factors; leftover keys are harmless but worth reporting.
            progress?.Report($"Note: could not delete the previous factor keys ({ex.Message}).");
        }
    }

    private static string Describe(FactorInfo factors) => factors.SecondFactor switch
    {
        SecondFactorKind.Tpm => "factors: windows-hello + tpm",
        SecondFactorKind.Dpapi => "factors: windows-hello + dpapi (degraded)",
        _ => $"factors: windows-hello + {factors.SecondFactor.ToString().ToLowerInvariant()}",
    };
}
