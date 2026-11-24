using Hush.Core.Keys;

namespace Hush.Core.Vault;

/// <summary>How a secret may be served.</summary>
public enum SecretPolicy : byte
{
    /// <summary>Served from the unlocked session without a new prompt.</summary>
    Session = 0,

    /// <summary>Every use requires a fresh Windows Hello confirmation.</summary>
    AlwaysPrompt = 1,
}

/// <summary>Vault-level flags stored in the header.</summary>
[Flags]
public enum VaultAttributes : ushort
{
    /// <summary>No flags.</summary>
    None = 0,

    /// <summary>No usable TPM: the second factor is protected by DPAPI only.</summary>
    Degraded = 1 << 0,

    /// <summary>A portable export: no hardware factors, only the recovery wrapping.</summary>
    Portable = 1 << 1,

    /// <summary>Created by the software test provider. Production builds refuse to open it.</summary>
    TestProvider = 1 << 2,
}

/// <summary>Which key a wrapped DEK blob is sealed under.</summary>
public enum WrapKind : byte
{
    /// <summary>The KEK derived from Windows Hello and the TPM (or DPAPI) factor.</summary>
    Factors = 1,

    /// <summary>The key derived from the recovery key.</summary>
    Recovery = 2,
}

/// <summary>Metadata for the two hardware factors.</summary>
/// <param name="SecondFactor">TPM, DPAPI or test.</param>
/// <param name="HelloKeyName">Name of the Windows Hello key credential.</param>
/// <param name="HelloPublicKey">SubjectPublicKeyInfo of the Hello key, used to verify presence proofs.</param>
/// <param name="SecondFactorKeyName">Name of the TPM key (also mixed into the DPAPI entropy).</param>
/// <param name="SealedSecondFactor">S_tpm encrypted with RSA-OAEP-SHA256 under the TPM key (or DPAPI-protected).</param>
/// <param name="DegradedReason">Why the TPM was not used, if degraded.</param>
public sealed record FactorInfo(
    SecondFactorKind SecondFactor,
    string HelloKeyName,
    byte[] HelloPublicKey,
    string SecondFactorKeyName,
    byte[] SealedSecondFactor,
    string? DegradedReason);

/// <summary>The DEK sealed under one wrapping key.</summary>
/// <param name="Kind">Which key seals it.</param>
/// <param name="Blob">AES-256-GCM blob (nonce, ciphertext, tag).</param>
public sealed record WrappedKey(WrapKind Kind, byte[] Blob);

/// <summary>One encrypted secret.</summary>
/// <param name="Id">Random entry id; part of the AAD.</param>
/// <param name="Version">Incremented on every update; part of the AAD.</param>
/// <param name="Scope">Project scope, or empty for global secrets.</param>
/// <param name="Name">Secret name.</param>
/// <param name="Policy">Session or always-prompt.</param>
/// <param name="Created">Creation time.</param>
/// <param name="Updated">Last value change.</param>
/// <param name="LastUsed">Last time the value was served, if ever.</param>
/// <param name="Ciphertext">AES-256-GCM blob of the UTF-8 value under the DEK.</param>
public sealed record VaultEntry(
    Guid Id,
    uint Version,
    string Scope,
    string Name,
    SecretPolicy Policy,
    DateTimeOffset Created,
    DateTimeOffset Updated,
    DateTimeOffset? LastUsed,
    byte[] Ciphertext)
{
    /// <summary>Display form: <c>scope/NAME</c>, or <c>NAME</c> for global secrets.</summary>
    public string QualifiedName => SecretRef.Format(Scope, Name);
}

/// <summary>The decoded contents of a vault file.</summary>
public sealed record VaultDocument
{
    /// <summary>Format version written to the file.</summary>
    public required ushort FormatVersion { get; init; }

    /// <summary>Vault flags.</summary>
    public required VaultAttributes Flags { get; init; }

    /// <summary>Random vault id.</summary>
    public required Guid VaultId { get; init; }

    /// <summary>32-byte HKDF salt.</summary>
    public required byte[] Salt { get; init; }

    /// <summary>32-byte challenge that Windows Hello signs to derive K_hello.</summary>
    public required byte[] Challenge { get; init; }

    /// <summary>When the vault was created.</summary>
    public required DateTimeOffset Created { get; init; }

    /// <summary>When the file was last written.</summary>
    public required DateTimeOffset Updated { get; init; }

    /// <summary>Factor enrollment generation; incremented by recovery.</summary>
    public required uint Generation { get; init; }

    /// <summary>Sequence number of the last audit entry.</summary>
    public required ulong AuditSequence { get; init; }

    /// <summary>MAC of the last audit entry (32 bytes); detects truncation of the log.</summary>
    public required byte[] AuditHead { get; init; }

    /// <summary>Hardware factor metadata; null for portable exports.</summary>
    public required FactorInfo? Factors { get; init; }

    /// <summary>The audit HMAC key sealed under the DEK.</summary>
    public required byte[] WrappedAuditKey { get; init; }

    /// <summary>The DEK sealed under each wrapping key.</summary>
    public required IReadOnlyList<WrappedKey> WrappedKeys { get; init; }

    /// <summary>The encrypted secrets.</summary>
    public required IReadOnlyList<VaultEntry> Entries { get; init; }

    /// <summary>True when the second factor is DPAPI rather than the TPM.</summary>
    public bool IsDegraded => Flags.HasFlag(VaultAttributes.Degraded);

    /// <summary>Returns the wrapped DEK for <paramref name="kind"/>.</summary>
    public WrappedKey GetWrappedKey(WrapKind kind) =>
        WrappedKeys.FirstOrDefault(w => w.Kind == kind)
        ?? throw new HushException(HushErrorCode.VaultCorrupt, $"The vault has no {kind} key wrapping.");
}
