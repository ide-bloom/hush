using System.Security.Cryptography;

namespace Hush.Core.Crypto;

/// <summary>
/// AES-256-GCM sealing in the vault's blob layout: <c>nonce (12) || ciphertext || tag (16)</c>.
/// Every call draws a fresh random 96-bit nonce.
/// </summary>
public static class Aead
{
    /// <summary>Nonce size in bytes.</summary>
    public const int NonceSize = 12;

    /// <summary>Authentication tag size in bytes.</summary>
    public const int TagSize = 16;

    /// <summary>Bytes added to a plaintext by <see cref="Seal"/>.</summary>
    public const int Overhead = NonceSize + TagSize;

    /// <summary>Encrypts and authenticates <paramref name="plaintext"/> with <paramref name="associatedData"/>.</summary>
    public static byte[] Seal(ReadOnlySpan<byte> key, ReadOnlySpan<byte> plaintext, ReadOnlySpan<byte> associatedData)
    {
        var blob = new byte[Overhead + plaintext.Length];
        var nonce = blob.AsSpan(0, NonceSize);
        var ciphertext = blob.AsSpan(NonceSize, plaintext.Length);
        var tag = blob.AsSpan(NonceSize + plaintext.Length, TagSize);
        RandomNumberGenerator.Fill(nonce);
        using var gcm = new AesGcm(key, TagSize);
        gcm.Encrypt(nonce, plaintext, ciphertext, tag, associatedData);
        return blob;
    }

    /// <summary>
    /// Verifies and decrypts a blob into a new pinned buffer. Throws <see cref="HushException"/> with
    /// <see cref="HushErrorCode.TamperDetected"/> if the tag does not verify.
    /// </summary>
    public static SecureBuffer Open(ReadOnlySpan<byte> key, ReadOnlySpan<byte> blob, ReadOnlySpan<byte> associatedData, string what)
    {
        if (blob.Length < Overhead)
        {
            throw new HushException(HushErrorCode.VaultCorrupt, $"The {what} is truncated.");
        }

        var plaintextLength = blob.Length - Overhead;
        var output = new SecureBuffer(plaintextLength);
        try
        {
            using var gcm = new AesGcm(key, TagSize);
            gcm.Decrypt(
                blob[..NonceSize],
                blob.Slice(NonceSize, plaintextLength),
                blob.Slice(NonceSize + plaintextLength, TagSize),
                output.Span,
                associatedData);
            return output;
        }
        catch (AuthenticationTagMismatchException ex)
        {
            output.Dispose();
            throw new HushException(HushErrorCode.TamperDetected, $"The {what} failed authentication: it was modified or the key is wrong.", ex);
        }
    }

    /// <summary>Returns the nonce portion of a sealed blob.</summary>
    public static ReadOnlySpan<byte> NonceOf(ReadOnlySpan<byte> blob) => blob[..NonceSize];
}
