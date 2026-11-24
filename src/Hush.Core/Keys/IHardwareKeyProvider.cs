using Hush.Core.Crypto;

namespace Hush.Core.Keys;

/// <summary>Which mechanism protects the second-factor secret <c>S_tpm</c>.</summary>
public enum SecondFactorKind : byte
{
    /// <summary>No factor (portable export files).</summary>
    None = 0,

    /// <summary>A non-exportable RSA-2048 key in the Microsoft Platform Crypto Provider (TPM).</summary>
    Tpm = 1,

    /// <summary>Degraded mode: DPAPI (current user) because no usable TPM exists.</summary>
    Dpapi = 2,

    /// <summary>The deterministic software provider used by the test suite.</summary>
    Test = 3,
}

/// <summary>Whether a provider talks to real hardware or is the test double.</summary>
public enum KeyProviderKind
{
    /// <summary>Windows Hello, the TPM and DPAPI.</summary>
    Platform,

    /// <summary>Deterministic software keys for tests. Refused outside a test host.</summary>
    Test,
}

/// <summary>How to present a Windows Hello prompt.</summary>
/// <param name="OwnerWindow">Window that owns the prompt so it appears in the foreground; 0 if unknown.</param>
/// <param name="Reason">Short description of why presence is needed, shown by the caller before the prompt.</param>
public sealed record PromptContext(nint OwnerWindow, string Reason)
{
    /// <summary>A context with no owner window.</summary>
    public static PromptContext Headless(string reason) => new(0, reason);
}

/// <summary>A Windows Hello key credential.</summary>
/// <param name="Name">Credential name inside the user's Hello container.</param>
/// <param name="PublicKey">The public key as DER-encoded SubjectPublicKeyInfo.</param>
public sealed record HelloKey(string Name, byte[] PublicKey);

/// <summary>The second factor chosen for a new vault.</summary>
/// <param name="Kind">TPM, DPAPI (degraded) or test.</param>
/// <param name="DegradedReason">Why the TPM could not be used, when <paramref name="Kind"/> is DPAPI.</param>
public sealed record SecondFactorChoice(SecondFactorKind Kind, string? DegradedReason);

/// <summary>
/// All hardware access goes through this interface so the vault logic can be tested on machines
/// without Windows Hello or a TPM.
/// </summary>
public interface IHardwareKeyProvider
{
    /// <summary>Platform or test provider.</summary>
    KeyProviderKind Kind { get; }

    /// <summary>Returns null if Windows Hello is ready, or a user-facing explanation of why it is not.</summary>
    Task<string?> CheckHelloAsync(CancellationToken cancellationToken);

    /// <summary>Picks TPM when a usable TPM exists, otherwise the degraded DPAPI fallback.</summary>
    SecondFactorChoice ChooseSecondFactor();

    /// <summary>Creates (or replaces) a Windows Hello key. Shows a Hello prompt.</summary>
    Task<HelloKey> CreateHelloKeyAsync(string name, PromptContext prompt, CancellationToken cancellationToken);

    /// <summary>Signs <paramref name="data"/> with the Hello key. Shows a Hello prompt.</summary>
    Task<byte[]> SignWithHelloAsync(string name, ReadOnlyMemory<byte> data, PromptContext prompt, CancellationToken cancellationToken);

    /// <summary>Deletes a Hello key; succeeds if it does not exist.</summary>
    Task DeleteHelloKeyAsync(string name, CancellationToken cancellationToken);

    /// <summary>Creates the second-factor key and encrypts <paramref name="secret"/> with it.</summary>
    byte[] SealSecondFactor(SecondFactorKind kind, string keyName, ReadOnlySpan<byte> secret);

    /// <summary>Decrypts a secret sealed by <see cref="SealSecondFactor"/>.</summary>
    SecureBuffer OpenSecondFactor(SecondFactorKind kind, string keyName, ReadOnlySpan<byte> sealedSecret);

    /// <summary>Deletes the second-factor key; succeeds if it does not exist.</summary>
    void DeleteSecondFactor(SecondFactorKind kind, string keyName);
}
