using System.Security.Cryptography;
using System.Text;

namespace Hush.Core.Crypto;

/// <summary>HKDF-SHA256 derivations with the fixed, versioned info labels used by the vault format.</summary>
public static class Kdf
{
    /// <summary>Label for the key derived from the Windows Hello signature.</summary>
    public const string HelloInfo = "hush/hello/v1";

    /// <summary>Label for the key-encryption key derived from both hardware factors.</summary>
    public const string KekInfo = "hush/kek/v1";

    /// <summary>Label for the key derived from the recovery key.</summary>
    public const string RecoveryInfo = "hush/recovery/v1";

    /// <summary>Label for the vault MAC key (derived from the DEK).</summary>
    public const string HeaderMacInfo = "hush/header-mac/v1";

    /// <summary>Label for the initial audit key (derived from the DEK at vault creation).</summary>
    public const string AuditInfo = "hush/audit/v1";

    /// <summary>Derives 32 bytes with HKDF-SHA256 into a new pinned buffer.</summary>
    public static SecureBuffer Derive(ReadOnlySpan<byte> inputKeyMaterial, ReadOnlySpan<byte> salt, string info)
    {
        var output = new SecureBuffer(32);
        Span<byte> infoBytes = stackalloc byte[Encoding.UTF8.GetMaxByteCount(info.Length)];
        var written = Encoding.UTF8.GetBytes(info, infoBytes);
        HKDF.DeriveKey(HashAlgorithmName.SHA256, inputKeyMaterial, output.Span, salt, infoBytes[..written]);
        return output;
    }

    /// <summary>
    /// KEK = HKDF-SHA256(K_hello || S_tpm, salt, "hush/kek/v1"). The concatenation lives in a pinned
    /// buffer that is zeroed before returning.
    /// </summary>
    public static SecureBuffer DeriveKek(ReadOnlySpan<byte> helloKey, ReadOnlySpan<byte> secondFactorSecret, ReadOnlySpan<byte> salt)
    {
        using var ikm = new SecureBuffer(helloKey.Length + secondFactorSecret.Length);
        helloKey.CopyTo(ikm.Span);
        secondFactorSecret.CopyTo(ikm.Span[helloKey.Length..]);
        return Derive(ikm.Span, salt, KekInfo);
    }
}
