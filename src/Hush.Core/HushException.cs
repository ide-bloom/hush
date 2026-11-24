namespace Hush.Core;

/// <summary>Machine-readable reason for a <see cref="HushException"/>.</summary>
public enum HushErrorCode
{
    /// <summary>An unexpected failure.</summary>
    Unknown = 0,

    /// <summary>No vault exists yet; run <c>hush init</c>.</summary>
    VaultNotFound,

    /// <summary>A vault already exists at the target location.</summary>
    VaultAlreadyExists,

    /// <summary>The vault file is malformed or uses an unsupported format version.</summary>
    VaultCorrupt,

    /// <summary>An integrity check failed: the vault or a blob was modified.</summary>
    TamperDetected,

    /// <summary>The session is locked and the operation needs the vault key.</summary>
    Locked,

    /// <summary>Windows Hello is not available or not set up.</summary>
    HelloUnavailable,

    /// <summary>The user cancelled or failed the Windows Hello prompt.</summary>
    HelloCancelled,

    /// <summary>Windows Hello produced different signatures for the same challenge.</summary>
    HelloNotDeterministic,

    /// <summary>The TPM key is missing or the TPM refused the operation.</summary>
    TpmFailure,

    /// <summary>The recovery key is malformed, has a typo, or does not open this vault.</summary>
    InvalidRecoveryKey,

    /// <summary>A secret with the requested name does not exist.</summary>
    SecretNotFound,

    /// <summary>The input is invalid (bad name, bad option, and so on).</summary>
    InvalidInput,

    /// <summary>The session broker could not be reached or rejected the request.</summary>
    BrokerUnavailable,

    /// <summary>The peer on the other end of the broker pipe failed verification.</summary>
    PeerVerificationFailed,

    /// <summary>A fresh Windows Hello confirmation is required for an always-prompt secret.</summary>
    PresenceRequired,

    /// <summary>The project manifest is malformed.</summary>
    ManifestInvalid,

    /// <summary>A migration could not be applied or undone safely.</summary>
    MigrationFailed,

    /// <summary>A test-only key provider was used outside a test host.</summary>
    TestProviderRefused,
}

/// <summary>
/// The single exception type Hush throws for expected failures. Messages are written for the user and
/// never contain secret values.
/// </summary>
public sealed class HushException : Exception
{
    /// <summary>Creates an exception with a code and a user-facing message.</summary>
    public HushException(HushErrorCode code, string message)
        : base(message)
    {
        Code = code;
    }

    /// <summary>Creates an exception that wraps a lower-level cause.</summary>
    public HushException(HushErrorCode code, string message, Exception innerException)
        : base(message, innerException)
    {
        Code = code;
    }

    /// <summary>Creates an exception with <see cref="HushErrorCode.Unknown"/>.</summary>
    public HushException()
        : this(HushErrorCode.Unknown, "Unknown error.")
    {
    }

    /// <summary>Creates an exception with <see cref="HushErrorCode.Unknown"/>.</summary>
    public HushException(string message)
        : this(HushErrorCode.Unknown, message)
    {
    }

    /// <summary>Creates an exception with <see cref="HushErrorCode.Unknown"/>.</summary>
    public HushException(string message, Exception innerException)
        : this(HushErrorCode.Unknown, message, innerException)
    {
    }

    /// <summary>The machine-readable reason.</summary>
    public HushErrorCode Code { get; }
}
