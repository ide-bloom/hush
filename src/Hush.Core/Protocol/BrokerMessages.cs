using System.Text.Json.Serialization;

namespace Hush.Core.Protocol;

/// <summary>Operation names understood by the session broker.</summary>
public static class BrokerOps
{
    /// <summary>Report lock state and vault health.</summary>
    public const string Status = "status";

    /// <summary>Hand over a DEK obtained by the client's Windows Hello unlock.</summary>
    public const string Unlock = "unlock";

    /// <summary>Forget the DEK.</summary>
    public const string Lock = "lock";

    /// <summary>Decrypt secrets (may require a presence proof).</summary>
    public const string Reveal = "reveal";

    /// <summary>Add or replace a secret.</summary>
    public const string Set = "set";

    /// <summary>Change a secret's policy.</summary>
    public const string SetPolicy = "set-policy";

    /// <summary>Delete a secret.</summary>
    public const string Remove = "remove";

    /// <summary>Issue a one-time nonce for a Windows Hello presence proof.</summary>
    public const string Challenge = "challenge";

    /// <summary>Verify the audit chain.</summary>
    public const string AuditVerify = "audit-verify";

    /// <summary>Append an audit entry for a client-side action.</summary>
    public const string Record = "record";

    /// <summary>Write a portable export.</summary>
    public const string Export = "export";

    /// <summary>Import secrets decrypted from a portable export.</summary>
    public const string Import = "import";

    /// <summary>Clear the clipboard later if it still holds what the client copied.</summary>
    public const string ClipboardClear = "clipboard-clear";

    /// <summary>Re-read settings.json.</summary>
    public const string ReloadSettings = "reload-settings";

    /// <summary>Stop the broker process.</summary>
    public const string Shutdown = "shutdown";
}

/// <summary>A secret reference on the wire.</summary>
public sealed record WireSecretRef(string Scope, string Name, bool FallbackToGlobal = false);

/// <summary>A Windows Hello signature over a broker nonce.</summary>
public sealed record PresenceProof(string Nonce, string Signature);

/// <summary>A secret to import.</summary>
[Sensitive]
public sealed record WireImportItem(string Scope, string Name, string Policy, [property: Sensitive] string Value);

/// <summary>A request to the broker. Fields are used depending on <see cref="Op"/>.</summary>
public sealed record BrokerRequest
{
    /// <summary>The operation (see <see cref="BrokerOps"/>).</summary>
    public required string Op { get; init; }

    /// <summary>Base64 DEK for <see cref="BrokerOps.Unlock"/>.</summary>
    [Sensitive]
    public string? Dek { get; init; }

    /// <summary>Secrets for <see cref="BrokerOps.Reveal"/>.</summary>
    public IReadOnlyList<WireSecretRef>? Secrets { get; init; }

    /// <summary>The target secret for set, set-policy and remove.</summary>
    public WireSecretRef? Secret { get; init; }

    /// <summary>The value for <see cref="BrokerOps.Set"/>.</summary>
    [Sensitive]
    public string? Value { get; init; }

    /// <summary><c>session</c> or <c>always-prompt</c>.</summary>
    public string? Policy { get; init; }

    /// <summary>Presence proof for always-prompt secrets.</summary>
    public PresenceProof? Presence { get; init; }

    /// <summary>Audit context, such as the program launched by <c>hush run</c>.</summary>
    public string? Detail { get; init; }

    /// <summary>Audit action for <see cref="BrokerOps.Record"/>.</summary>
    public string? Action { get; init; }

    /// <summary>Audit result for <see cref="BrokerOps.Record"/>.</summary>
    public string? Result { get; init; }

    /// <summary>Destination for <see cref="BrokerOps.Export"/>.</summary>
    public string? Path { get; init; }

    /// <summary>Items for <see cref="BrokerOps.Import"/>.</summary>
    public IReadOnlyList<WireImportItem>? Items { get; init; }

    /// <summary>Overwrite existing secrets on import.</summary>
    public bool Overwrite { get; init; }

    /// <summary>Clipboard sequence number for <see cref="BrokerOps.ClipboardClear"/>.</summary>
    public uint ClipboardSequence { get; init; }

    /// <summary>Seconds until the clipboard is cleared.</summary>
    public int DelaySeconds { get; init; }
}

/// <summary>Lock state and vault health.</summary>
public sealed record BrokerStatus
{
    /// <summary>True if a vault file exists.</summary>
    public bool VaultExists { get; init; }

    /// <summary>True if the broker holds the DEK.</summary>
    public bool Unlocked { get; init; }

    /// <summary>True if the vault uses the DPAPI fallback.</summary>
    public bool Degraded { get; init; }

    /// <summary>Why the TPM is not used.</summary>
    public string? DegradedReason { get; init; }

    /// <summary><c>tpm</c>, <c>dpapi</c> or <c>test</c>.</summary>
    public string? SecondFactor { get; init; }

    /// <summary>Number of secrets.</summary>
    public int SecretCount { get; init; }

    /// <summary>Configured idle timeout.</summary>
    public int IdleTimeoutMinutes { get; init; }

    /// <summary>Whether sleep locks the vault.</summary>
    public bool LockOnSleep { get; init; }

    /// <summary>Seconds until the idle timeout locks the vault, when unlocked.</summary>
    public int? IdleRemainingSeconds { get; init; }

    /// <summary>The vault file.</summary>
    public string? VaultPath { get; init; }

    /// <summary>The broker's process id.</summary>
    public int BrokerPid { get; init; }

    /// <summary>Why the vault was last locked (idle, workstation lock, sleep, manual...).</summary>
    public string? LastLockReason { get; init; }
}

/// <summary>A decrypted secret on the wire.</summary>
[Sensitive]
public sealed record WireRevealed(string Requested, string Resolved, [property: Sensitive] string Value);

/// <summary>Audit verification on the wire.</summary>
public sealed record WireAuditVerification(bool IsValid, int EntryCount, IReadOnlyList<string> Problems, IReadOnlyList<string> Warnings);

/// <summary>A response from the broker.</summary>
public sealed record BrokerResponse
{
    /// <summary>True on success.</summary>
    public bool Ok { get; init; }

    /// <summary>Error code name (see <see cref="HushErrorCode"/>) on failure.</summary>
    public string? ErrorCode { get; init; }

    /// <summary>User-facing error message on failure.</summary>
    public string? Error { get; init; }

    /// <summary>Status, for <see cref="BrokerOps.Status"/>.</summary>
    public BrokerStatus? Status { get; init; }

    /// <summary>Values, for <see cref="BrokerOps.Reveal"/>.</summary>
    public IReadOnlyList<WireRevealed>? Values { get; init; }

    /// <summary>Base64 nonce, for <see cref="BrokerOps.Challenge"/>.</summary>
    public string? Nonce { get; init; }

    /// <summary>Audit verification result.</summary>
    public WireAuditVerification? Audit { get; init; }

    /// <summary>A short informational message.</summary>
    public string? Message { get; init; }

    /// <summary>A count (imported, skipped...).</summary>
    public int Count { get; init; }

    /// <summary>A second count.</summary>
    public int Count2 { get; init; }

    /// <summary>Creates a success response.</summary>
    public static BrokerResponse Success(string? message = null) => new() { Ok = true, Message = message };

    /// <summary>Creates a failure response from an error code and message.</summary>
    public static BrokerResponse Failure(HushErrorCode code, string message) => new() { Ok = false, ErrorCode = code.ToString(), Error = message };

    /// <summary>Throws the equivalent <see cref="HushException"/> if this is a failure.</summary>
    public BrokerResponse EnsureSuccess()
    {
        if (Ok)
        {
            return this;
        }

        var code = Enum.TryParse<HushErrorCode>(ErrorCode, out var parsed) ? parsed : HushErrorCode.Unknown;
        throw new HushException(code, Error ?? "The Hush agent reported an error.");
    }
}

/// <summary>Source-generated JSON metadata for the broker protocol.</summary>
[JsonSourceGenerationOptions(PropertyNamingPolicy = JsonKnownNamingPolicy.CamelCase, DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull)]
[JsonSerializable(typeof(BrokerRequest))]
[JsonSerializable(typeof(BrokerResponse))]
public sealed partial class BrokerJsonContext : JsonSerializerContext;
