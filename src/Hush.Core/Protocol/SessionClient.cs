using Hush.Core.Interop;
using Hush.Core.Keys;
using Hush.Core.Manifest;
using Hush.Core.Vault;

namespace Hush.Core.Protocol;

/// <summary>
/// Client-side session logic shared by the CLI and the tray app. Windows Hello prompts happen here, in the
/// process the user is looking at (with its window as the owner); the broker only ever receives the DEK or a
/// presence signature and verifies the latter against the Hello public key in the vault header.
/// </summary>
public sealed class SessionClient
{
    private readonly VaultManager _manager;
    private readonly IBrokerTransport _transport;
    private readonly Func<string, PromptContext> _prompt;

    /// <summary>Creates a session client.</summary>
    /// <param name="manager">Vault access for client-side unlocks.</param>
    /// <param name="transport">Connection to the broker.</param>
    /// <param name="prompt">Builds the prompt context (owner window) for a given reason.</param>
    public SessionClient(VaultManager manager, IBrokerTransport transport, Func<string, PromptContext> prompt)
    {
        _manager = manager;
        _transport = transport;
        _prompt = prompt;
    }

    /// <summary>Raised just before a Windows Hello prompt, with the reason.</summary>
    public event EventHandler<string>? PromptingForPresence;

    /// <summary>The vault manager.</summary>
    public VaultManager Manager => _manager;

    /// <summary>Asks the broker for its status.</summary>
    public async Task<BrokerStatus> StatusAsync(CancellationToken cancellationToken)
    {
        var response = await SendAsync(new BrokerRequest { Op = BrokerOps.Status }, cancellationToken).ConfigureAwait(false);
        return response.Status ?? new BrokerStatus();
    }

    /// <summary>Unlocks with Windows Hello unless the broker is already unlocked (or <paramref name="force"/>).</summary>
    public async Task<bool> UnlockAsync(bool force, CancellationToken cancellationToken)
    {
        if (!force)
        {
            var status = await StatusAsync(cancellationToken).ConfigureAwait(false);
            if (status.Unlocked)
            {
                return false;
            }
        }

        const string reason = "Unlock your Hush vault";
        PromptingForPresence?.Invoke(this, reason);
        UnlockedVault vault;
        try
        {
            vault = await _manager.UnlockAsync(_prompt(reason), cancellationToken).ConfigureAwait(false);
        }
        catch (HushException ex) when (ex.Code is not HushErrorCode.VaultNotFound)
        {
            // No audit key is available while locked: record the failure as pending, then let it propagate.
            RecordWhileLocked("session.unlock", ex.Code == HushErrorCode.HelloCancelled ? "cancelled" : "failed", ex.Message);
            throw;
        }

        using (vault)
        {
            await HandOverAsync(vault, cancellationToken).ConfigureAwait(false);
        }

        return true;
    }

    /// <summary>Gives an already unlocked vault's DEK to the broker (after init, recover or rotate).</summary>
    public async Task HandOverAsync(UnlockedVault vault, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(vault);
        using var dek = vault.CopyDek();
        var encoded = Convert.ToBase64String(dek.Span);
        await SendAsync(new BrokerRequest { Op = BrokerOps.Unlock, Dek = encoded }, cancellationToken).ConfigureAwait(false);
    }

    /// <summary>Locks the session.</summary>
    public Task LockAsync(CancellationToken cancellationToken) =>
        SendAsync(new BrokerRequest { Op = BrokerOps.Lock }, cancellationToken);

    /// <summary>
    /// Decrypts secrets for <paramref name="bindings"/>, unlocking first if needed and performing a fresh
    /// Windows Hello confirmation when an always-prompt secret is involved (or <paramref name="requirePresence"/>).
    /// </summary>
    public async Task<IReadOnlyList<WireRevealed>> RevealAsync(IReadOnlyList<EnvBinding> bindings, string? detail, bool requirePresence, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(bindings);
        var refs = bindings.Select(b => new WireSecretRef(b.Secret.Scope, b.Secret.Name, b.FallbackToGlobal)).ToList();
        await UnlockAsync(force: false, cancellationToken).ConfigureAwait(false);

        PresenceProof? proof = requirePresence ? await ProvePresenceAsync("Confirm access to a protected secret", cancellationToken).ConfigureAwait(false) : null;
        var request = new BrokerRequest { Op = BrokerOps.Reveal, Secrets = refs, Detail = detail, Presence = proof };
        var response = await _transport.SendAsync(request, cancellationToken).ConfigureAwait(false);
        if (!response.Ok && response.ErrorCode == nameof(HushErrorCode.Locked))
        {
            await UnlockAsync(force: true, cancellationToken).ConfigureAwait(false);
            response = await _transport.SendAsync(request, cancellationToken).ConfigureAwait(false);
        }

        if (!response.Ok && response.ErrorCode == nameof(HushErrorCode.PresenceRequired) && proof is null)
        {
            proof = await ProvePresenceAsync(response.Error ?? "Confirm access to a protected secret", cancellationToken).ConfigureAwait(false);
            response = await _transport.SendAsync(request with { Presence = proof }, cancellationToken).ConfigureAwait(false);
        }

        return response.EnsureSuccess().Values ?? [];
    }

    /// <summary>Adds or replaces a secret.</summary>
    public Task SetAsync(SecretRef reference, string value, SecretPolicy? policy, CancellationToken cancellationToken) =>
        SendUnlockedAsync(
            new BrokerRequest { Op = BrokerOps.Set, Secret = new WireSecretRef(reference.Scope, reference.Name), Value = value, Policy = policy is null ? null : PolicyNames.Format(policy.Value) },
            cancellationToken);

    /// <summary>Changes a secret's policy.</summary>
    public Task SetPolicyAsync(SecretRef reference, SecretPolicy policy, CancellationToken cancellationToken) =>
        SendUnlockedAsync(new BrokerRequest { Op = BrokerOps.SetPolicy, Secret = new WireSecretRef(reference.Scope, reference.Name), Policy = PolicyNames.Format(policy) }, cancellationToken);

    /// <summary>Deletes a secret; returns false if it did not exist.</summary>
    public async Task<bool> RemoveAsync(SecretRef reference, CancellationToken cancellationToken)
    {
        var response = await SendUnlockedAsync(new BrokerRequest { Op = BrokerOps.Remove, Secret = new WireSecretRef(reference.Scope, reference.Name) }, cancellationToken).ConfigureAwait(false);
        return response.Count > 0;
    }

    /// <summary>Verifies the audit chain (needs the audit key, so the session must be unlocked).</summary>
    public async Task<WireAuditVerification> VerifyAuditAsync(CancellationToken cancellationToken)
    {
        var response = await SendUnlockedAsync(new BrokerRequest { Op = BrokerOps.AuditVerify }, cancellationToken).ConfigureAwait(false);
        return response.Audit ?? throw new HushException(HushErrorCode.Unknown, "The agent returned no audit result.");
    }

    /// <summary>Records a client-side action in the audit log.</summary>
    public Task RecordAsync(string action, string result, string? detail, IReadOnlyList<SecretRef> secrets, CancellationToken cancellationToken) =>
        SendUnlockedAsync(
            new BrokerRequest { Op = BrokerOps.Record, Action = action, Result = result, Detail = detail, Secrets = secrets.Select(s => new WireSecretRef(s.Scope, s.Name)).ToList() },
            cancellationToken);

    /// <summary>Writes a portable export protected by the recovery key.</summary>
    public Task ExportAsync(string path, CancellationToken cancellationToken) =>
        SendUnlockedAsync(new BrokerRequest { Op = BrokerOps.Export, Path = Path.GetFullPath(path) }, cancellationToken);

    /// <summary>Imports secrets from an opened portable export.</summary>
    public async Task<(int Imported, int Skipped)> ImportAsync(PortableVault source, bool overwrite, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(source);
        var items = new List<WireImportItem>();
        foreach (var (entry, plain) in source.DecryptAll())
        {
            using (plain)
            {
                items.Add(new WireImportItem(entry.Scope, entry.Name, PolicyNames.Format(entry.Policy), System.Text.Encoding.UTF8.GetString(plain.Span)));
            }
        }

        var response = await SendUnlockedAsync(new BrokerRequest { Op = BrokerOps.Import, Items = items, Overwrite = overwrite }, cancellationToken).ConfigureAwait(false);
        return (response.Count, response.Count2);
    }

    /// <summary>Asks the broker to clear the clipboard after a delay if it still holds our copy.</summary>
    public Task ScheduleClipboardClearAsync(uint sequence, int delaySeconds, CancellationToken cancellationToken) =>
        SendAsync(new BrokerRequest { Op = BrokerOps.ClipboardClear, ClipboardSequence = sequence, DelaySeconds = delaySeconds }, cancellationToken);

    /// <summary>Tells the broker to re-read settings.json.</summary>
    public Task ReloadSettingsAsync(CancellationToken cancellationToken) =>
        SendAsync(new BrokerRequest { Op = BrokerOps.ReloadSettings }, cancellationToken);

    /// <summary>Gets a broker nonce and signs it with Windows Hello.</summary>
    public async Task<PresenceProof> ProvePresenceAsync(string reason, CancellationToken cancellationToken)
    {
        var challenge = await SendAsync(new BrokerRequest { Op = BrokerOps.Challenge }, cancellationToken).ConfigureAwait(false);
        var nonce = Convert.FromBase64String(challenge.Nonce ?? throw new HushException(HushErrorCode.Unknown, "The agent returned no challenge."));
        PromptingForPresence?.Invoke(this, reason);
        byte[] signature;
        try
        {
            signature = await _manager.SignPresenceAsync(nonce, _prompt(reason), cancellationToken).ConfigureAwait(false);
        }
        catch (HushException ex) when (ex.Code == HushErrorCode.HelloCancelled)
        {
            await SendAsync(new BrokerRequest { Op = BrokerOps.Record, Action = "secret.presence", Result = "cancelled", Detail = reason }, cancellationToken).ConfigureAwait(false);
            throw;
        }

        return new PresenceProof(Convert.ToBase64String(nonce), Convert.ToBase64String(signature));
    }

    private async Task<BrokerResponse> SendUnlockedAsync(BrokerRequest request, CancellationToken cancellationToken)
    {
        await UnlockAsync(force: false, cancellationToken).ConfigureAwait(false);
        var response = await _transport.SendAsync(request, cancellationToken).ConfigureAwait(false);
        if (!response.Ok && response.ErrorCode == nameof(HushErrorCode.Locked))
        {
            await UnlockAsync(force: true, cancellationToken).ConfigureAwait(false);
            response = await _transport.SendAsync(request, cancellationToken).ConfigureAwait(false);
        }

        return response.EnsureSuccess();
    }

    private async Task<BrokerResponse> SendAsync(BrokerRequest request, CancellationToken cancellationToken) =>
        (await _transport.SendAsync(request, cancellationToken).ConfigureAwait(false)).EnsureSuccess();

    /// <summary>Creates a client that talks to this user's broker, launching it if needed.</summary>
    public static SessionClient ForCurrentUser(VaultManager manager, Func<string, PromptContext> prompt) =>
        new(manager, NamedPipeBrokerTransport.ForCurrentUser(), prompt);

    /// <summary>Records an event that happened while locked; it joins the chain at the next unlock.</summary>
    public void RecordWhileLocked(string action, string result, string? detail) =>
        Audit.PendingAudit.Append(_manager.Paths.PendingAudit, new Audit.AuditEvent(action, [], result, detail, ProcessInspector.Current()), DateTimeOffset.UtcNow);
}

/// <summary>Converts <see cref="SecretPolicy"/> to and from its CLI spelling.</summary>
public static class PolicyNames
{
    /// <summary>CLI spelling of a policy.</summary>
    public static string Format(SecretPolicy policy) => policy == SecretPolicy.AlwaysPrompt ? "always-prompt" : "session";

    /// <summary>Parses <c>session</c> or <c>always-prompt</c>.</summary>
    public static SecretPolicy Parse(string text) => text.ToLowerInvariant() switch
    {
        "session" => SecretPolicy.Session,
        "always-prompt" or "alwaysprompt" or "always" => SecretPolicy.AlwaysPrompt,
        _ => throw new HushException(HushErrorCode.InvalidInput, $"Unknown policy '{text}'. Use 'session' or 'always-prompt'."),
    };
}
