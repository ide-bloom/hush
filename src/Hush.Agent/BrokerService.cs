using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using Hush.Core;
using Hush.Core.Audit;
using Hush.Core.Interop;
using Hush.Core.Keys;
using Hush.Core.Protocol;
using Hush.Core.Settings;
using Hush.Core.Vault;
using Microsoft.Extensions.Logging;

namespace Hush.Agent;

/// <summary>
/// The broker's request handling, independent of the pipe so it can be tested in-process. It holds at most
/// one <see cref="UnlockedVault"/>; locking disposes it, which zeroes the DEK.
/// </summary>
public sealed partial class BrokerService : IDisposable
{
    private static readonly TimeSpan NonceLifetime = TimeSpan.FromMinutes(2);
    private readonly VaultManager _manager;
    private readonly Func<HushSettings> _loadSettings;
    private readonly TimeProvider _time;
    private readonly ILogger _logger;
    private readonly SemaphoreSlim _gate = new(1, 1);
    private readonly Dictionary<string, DateTimeOffset> _nonces = new(StringComparer.Ordinal);
    private UnlockedVault? _vault;
    private HushSettings _settings;
    private DateTimeOffset _lastActivity;
    private string? _lastLockReason;

    /// <summary>Creates the service.</summary>
    public BrokerService(VaultManager manager, Func<HushSettings> loadSettings, ILogger logger, TimeProvider? time = null)
    {
        _manager = manager;
        _loadSettings = loadSettings;
        _logger = logger;
        _time = time ?? TimeProvider.System;
        _settings = loadSettings();
        _lastActivity = _time.GetUtcNow();
    }

    /// <summary>Raised after the vault is locked or unlocked.</summary>
    public event EventHandler<bool>? LockStateChanged;

    /// <summary>Raised when a client asks the broker to exit.</summary>
    public event EventHandler? ShutdownRequested;

    /// <summary>True while the DEK is held.</summary>
    public bool IsUnlocked => _vault is not null;

    /// <summary>Current settings.</summary>
    public HushSettings Settings => _settings;

    /// <summary>Handles one request from a verified client.</summary>
    public async Task<BrokerResponse> HandleAsync(BrokerRequest request, ProcessIdentity client, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(request);
        ArgumentNullException.ThrowIfNull(client);
        await _gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            return Dispatch(request, client);
        }
        catch (HushException ex)
        {
            if (ex.Code == HushErrorCode.Locked && _vault is not null)
            {
                LockCore("vault changed on disk");
            }

            Log.RequestFailed(_logger, request.Op, ex.Code.ToString());
            return BrokerResponse.Failure(ex.Code, ex.Message);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or CryptographicException or FormatException)
        {
            Log.RequestError(_logger, request.Op, ex);
            return BrokerResponse.Failure(HushErrorCode.Unknown, $"The Hush agent could not complete '{request.Op}': {ex.Message}");
        }
        finally
        {
            _gate.Release();
        }
    }

    /// <summary>Locks the vault (idempotent). Called for timeouts, workstation lock, sleep and session switches.</summary>
    public void Lock(string reason)
    {
        _gate.Wait();
        try
        {
            LockCore(reason);
        }
        finally
        {
            _gate.Release();
        }
    }

    /// <summary>Locks if the idle timeout has elapsed. Called periodically by the host.</summary>
    public void CheckIdle()
    {
        if (_vault is not null && _time.GetUtcNow() - _lastActivity >= _settings.IdleTimeout)
        {
            Lock($"idle for {_settings.IdleTimeoutMinutes} min");
        }
    }

    /// <inheritdoc />
    public void Dispose()
    {
        LockCore("agent stopped");
        _gate.Dispose();
    }

    private BrokerResponse Dispatch(BrokerRequest request, ProcessIdentity client)
    {
        switch (request.Op)
        {
            case BrokerOps.Status:
                return new BrokerResponse { Ok = true, Status = BuildStatus() };
            case BrokerOps.Challenge:
                return IssueChallenge();
            case BrokerOps.ClipboardClear:
                ScheduleClipboardClear(request.ClipboardSequence, request.DelaySeconds);
                return BrokerResponse.Success();
            case BrokerOps.ReloadSettings:
                _settings = _loadSettings();
                return BrokerResponse.Success();
            case BrokerOps.Shutdown:
                LockCore("agent shutdown requested");
                ShutdownRequested?.Invoke(this, EventArgs.Empty);
                return BrokerResponse.Success();
            case BrokerOps.Unlock:
                return Unlock(request, client);
            case BrokerOps.Lock:
                LockCore("locked by user", client);
                return BrokerResponse.Success();
        }

        var vault = _vault ?? throw new HushException(HushErrorCode.Locked, "The vault is locked.");
        _lastActivity = _time.GetUtcNow();
        switch (request.Op)
        {
            case BrokerOps.Reveal:
                return Reveal(vault, request, client);
            case BrokerOps.Set:
            {
                var reference = ToRef(request.Secret);
                var value = request.Value ?? throw new HushException(HushErrorCode.InvalidInput, "No value was sent.");
                var policy = request.Policy is null ? (SecretPolicy?)null : PolicyNames.Parse(request.Policy);
                vault.Set(reference, Encoding.UTF8.GetBytes(value), policy, Event("secret.set", "ok", request.Detail, client));
                return BrokerResponse.Success();
            }

            case BrokerOps.SetPolicy:
                vault.SetPolicy(ToRef(request.Secret), PolicyNames.Parse(request.Policy ?? "session"), Event("secret.policy", "ok", request.Policy, client));
                return BrokerResponse.Success();
            case BrokerOps.Remove:
            {
                var removed = vault.Remove(ToRef(request.Secret), Event("secret.remove", "ok", null, client));
                return new BrokerResponse { Ok = true, Count = removed ? 1 : 0 };
            }

            case BrokerOps.AuditVerify:
            {
                var result = vault.VerifyAudit();
                return new BrokerResponse { Ok = true, Audit = new WireAuditVerification(result.IsValid, result.EntryCount, result.Problems, result.Warnings) };
            }

            case BrokerOps.Record:
            {
                var action = request.Action ?? throw new HushException(HushErrorCode.InvalidInput, "No action was sent.");
                if (!ActionName().IsMatch(action))
                {
                    throw new HushException(HushErrorCode.InvalidInput, "Invalid audit action name.");
                }

                var names = (request.Secrets ?? []).Select(s => SecretRef.Format(s.Scope, s.Name)).ToList();
                vault.Record(new AuditEvent(action, names, request.Result ?? "ok", request.Detail, client));
                return BrokerResponse.Success();
            }

            case BrokerOps.Export:
            {
                var path = request.Path ?? throw new HushException(HushErrorCode.InvalidInput, "No export path was sent.");
                var bytes = vault.BuildPortableExport(Event("vault.export", "ok", path, client));
                VaultStore.WriteAtomic(path, bytes);
                return BrokerResponse.Success(path);
            }

            case BrokerOps.Import:
            {
                var items = (request.Items ?? []).Select(i => new ImportItem(new SecretRef(i.Scope, i.Name), PolicyNames.Parse(i.Policy), Encoding.UTF8.GetBytes(i.Value))).ToList();
                var (imported, skipped) = vault.Import(items, request.Overwrite, Event("vault.import", "ok", null, client));
                return new BrokerResponse { Ok = true, Count = imported, Count2 = skipped };
            }

            default:
                throw new HushException(HushErrorCode.InvalidInput, $"Unknown operation '{request.Op}'.");
        }
    }

    private BrokerResponse Unlock(BrokerRequest request, ProcessIdentity client)
    {
        var encoded = request.Dek ?? throw new HushException(HushErrorCode.InvalidInput, "No key was sent.");
        var dek = Convert.FromBase64String(encoded);
        try
        {
            var vault = _manager.OpenWithDek(dek);
            _vault?.Dispose();
            _vault = vault;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(dek);
        }

        _lastActivity = _time.GetUtcNow();
        _lastLockReason = null;
        var folded = _vault.FoldPendingAudit();
        _vault.Record(Event("session.unlock", "ok", folded > 0 ? $"{folded} deferred event(s) added to the chain" : null, client));
        Log.Unlocked(_logger, client.Pid);
        LockStateChanged?.Invoke(this, true);
        return BrokerResponse.Success();
    }

    private BrokerResponse Reveal(UnlockedVault vault, BrokerRequest request, ProcessIdentity client)
    {
        var lookups = (request.Secrets ?? []).Select(s => new SecretLookup(ToRef(s), s.FallbackToGlobal)).ToList();
        if (lookups.Count == 0)
        {
            throw new HushException(HushErrorCode.InvalidInput, "No secrets were requested.");
        }

        var presenceVerified = request.Presence is { } proof && VerifyPresence(vault, proof);
        if (request.Presence is not null && !presenceVerified)
        {
            vault.Record(Event("secret.read", "denied", "invalid or expired Windows Hello proof", client) with { Secrets = lookups.Select(l => l.Ref.ToString()).ToList() });
            throw new HushException(HushErrorCode.PresenceRequired, "The Windows Hello confirmation was invalid or expired. Try again.");
        }

        try
        {
            var revealed = vault.Reveal(lookups, presenceVerified, Event("secret.read", "ok", request.Detail, client) with { Detail = Detail(request.Detail, presenceVerified) });
            return new BrokerResponse { Ok = true, Values = revealed.Select(r => new WireRevealed(r.Requested.ToString(), r.Resolved.ToString(), r.Value)).ToList() };
        }
        catch (HushException ex) when (ex.Code is HushErrorCode.SecretNotFound or HushErrorCode.PresenceRequired)
        {
            var result = ex.Code == HushErrorCode.SecretNotFound ? "not-found" : "presence-required";
            vault.Record(Event("secret.read", result, request.Detail, client) with { Secrets = lookups.Select(l => l.Ref.ToString()).ToList() });
            throw;
        }
    }

    private bool VerifyPresence(UnlockedVault vault, PresenceProof proof)
    {
        var now = _time.GetUtcNow();
        if (!_nonces.Remove(proof.Nonce, out var expiry) || expiry < now)
        {
            return false;
        }

        var factors = vault.Document.Factors;
        return factors is not null && VaultManager.VerifyPresence(factors, Convert.FromBase64String(proof.Nonce), Convert.FromBase64String(proof.Signature));
    }

    private BrokerResponse IssueChallenge()
    {
        var now = _time.GetUtcNow();
        foreach (var expired in _nonces.Where(n => n.Value < now).Select(n => n.Key).ToList())
        {
            _nonces.Remove(expired);
        }

        var nonce = Convert.ToBase64String(RandomNumberGenerator.GetBytes(32));
        _nonces[nonce] = now + NonceLifetime;
        return new BrokerResponse { Ok = true, Nonce = nonce };
    }

    private void ScheduleClipboardClear(uint sequence, int delaySeconds)
    {
        var delay = TimeSpan.FromSeconds(Math.Clamp(delaySeconds, 1, 600));
        _ = Task.Run(async () =>
        {
            await Task.Delay(delay, _time).ConfigureAwait(false);
            try
            {
                if (SecureClipboard.ClearIfUnchanged(sequence))
                {
                    Log.ClipboardCleared(_logger);
                }
            }
            catch (HushException ex)
            {
                Log.ClipboardClearFailed(_logger, ex.Message);
            }
        });
    }

    private BrokerStatus BuildStatus()
    {
        var exists = _manager.Exists;
        VaultDocument? document = null;
        if (exists)
        {
            document = _manager.ReadDocument();
        }

        var remaining = _vault is null ? (int?)null : (int)Math.Max(0, (_settings.IdleTimeout - (_time.GetUtcNow() - _lastActivity)).TotalSeconds);
        return new BrokerStatus
        {
            VaultExists = exists,
            Unlocked = _vault is not null,
            Degraded = document?.IsDegraded ?? false,
            DegradedReason = document?.Factors?.DegradedReason,
            SecondFactor = document?.Factors?.SecondFactor switch
            {
                SecondFactorKind.Tpm => "tpm",
                SecondFactorKind.Dpapi => "dpapi",
                SecondFactorKind.Test => "test",
                _ => null,
            },
            SecretCount = document?.Entries.Count ?? 0,
            IdleTimeoutMinutes = (int)_settings.IdleTimeout.TotalMinutes,
            LockOnSleep = _settings.LockOnSleep,
            IdleRemainingSeconds = remaining,
            VaultPath = _manager.Store.Path,
            BrokerPid = Environment.ProcessId,
            LastLockReason = _lastLockReason,
        };
    }

    private void LockCore(string reason, ProcessIdentity? client = null)
    {
        var vault = _vault;
        if (vault is null)
        {
            return;
        }

        try
        {
            vault.Record(Event("session.lock", "ok", reason, client));
        }
        catch (Exception ex) when (ex is HushException or IOException or UnauthorizedAccessException)
        {
            Log.LockAuditFailed(_logger, ex.Message);
        }
        finally
        {
            vault.Dispose();
            _vault = null;
            _nonces.Clear();
            _lastLockReason = reason;
            Log.Locked(_logger, reason);
            LockStateChanged?.Invoke(this, false);
        }
    }

    private static SecretRef ToRef(WireSecretRef? wire)
    {
        if (wire is null)
        {
            throw new HushException(HushErrorCode.InvalidInput, "No secret was named.");
        }

        var reference = new SecretRef(wire.Scope, wire.Name);
        reference.Validate();
        return reference;
    }

    private static AuditEvent Event(string action, string result, string? detail, ProcessIdentity? client) =>
        new(action, [], result, detail, client ?? ProcessInspector.Current());

    private static string? Detail(string? detail, bool presenceVerified) =>
        presenceVerified ? (detail is null ? "windows-hello confirmed" : $"{detail}; windows-hello confirmed") : detail;

    [GeneratedRegex("^[a-z][a-z0-9.-]{1,63}$")]
    private static partial Regex ActionName();

    private static partial class Log
    {
        [LoggerMessage(1, LogLevel.Information, "Vault unlocked by process {Pid}")]
        public static partial void Unlocked(ILogger logger, int pid);

        [LoggerMessage(2, LogLevel.Information, "Vault locked: {Reason}")]
        public static partial void Locked(ILogger logger, string reason);

        [LoggerMessage(3, LogLevel.Warning, "Request {Op} failed: {Code}")]
        public static partial void RequestFailed(ILogger logger, string op, string code);

        [LoggerMessage(4, LogLevel.Error, "Request {Op} raised an error")]
        public static partial void RequestError(ILogger logger, string op, Exception exception);

        [LoggerMessage(5, LogLevel.Warning, "Could not record the lock in the audit log: {Error}")]
        public static partial void LockAuditFailed(ILogger logger, string error);

        [LoggerMessage(6, LogLevel.Information, "Clipboard cleared")]
        public static partial void ClipboardCleared(ILogger logger);

        [LoggerMessage(7, LogLevel.Warning, "Could not clear the clipboard: {Error}")]
        public static partial void ClipboardClearFailed(ILogger logger, string error);
    }
}
