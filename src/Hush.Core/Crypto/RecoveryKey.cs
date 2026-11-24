using System.Security.Cryptography;
using System.Text;

namespace Hush.Core.Crypto;

/// <summary>
/// The 160-bit recovery key. It is shown once at <c>hush init</c> as nine groups of four Crockford
/// Base32 characters: eight groups of key material followed by one checksum group, for example
/// <c>7K3M-…-Q9TZ-CHK0</c>. The checksum catches typos before any cryptography runs.
/// </summary>
[Sensitive]
public sealed class RecoveryKey : IDisposable
{
    /// <summary>Key size in bytes (160 bits).</summary>
    public const int Size = 20;

    private const int GroupLength = 4;
    private const int DataChars = 32;
    private static readonly byte[] ChecksumLabel = Encoding.ASCII.GetBytes("hush/recovery-checksum/v1");

    private readonly SecureBuffer _bytes;

    private RecoveryKey(SecureBuffer bytes) => _bytes = bytes;

    /// <summary>The raw key bytes.</summary>
    public ReadOnlySpan<byte> Bytes => _bytes.Span;

    /// <summary>Generates a new random recovery key.</summary>
    public static RecoveryKey Generate() => new(SecureBuffer.Random(Size));

    /// <summary>Wraps existing key bytes (used by tests and by import).</summary>
    public static RecoveryKey FromBytes(ReadOnlySpan<byte> bytes)
    {
        if (bytes.Length != Size)
        {
            throw new HushException(HushErrorCode.InvalidRecoveryKey, "A recovery key is exactly 160 bits.");
        }

        return new RecoveryKey(SecureBuffer.CopyOf(bytes));
    }

    /// <summary>
    /// Parses the displayed form. Hyphens, spaces and case are ignored; I/L read as 1 and O as 0.
    /// Throws <see cref="HushException"/> with <see cref="HushErrorCode.InvalidRecoveryKey"/> on any error.
    /// </summary>
    public static RecoveryKey Parse(string text)
    {
        ArgumentNullException.ThrowIfNull(text);
        Span<char> compact = stackalloc char[64];
        var length = 0;
        foreach (var c in text)
        {
            if (c is '-' or ' ' or '\t' or '\r' or '\n')
            {
                continue;
            }

            if (length == compact.Length)
            {
                throw new HushException(HushErrorCode.InvalidRecoveryKey, "That recovery key is too long.");
            }

            compact[length++] = c;
        }

        if (length != DataChars + GroupLength)
        {
            throw new HushException(
                HushErrorCode.InvalidRecoveryKey,
                $"A recovery key has {DataChars + GroupLength} characters (nine groups of four); got {length}.");
        }

        var bytes = new SecureBuffer(Size);
        try
        {
            if (!CrockfordBase32.TryDecode(compact[..DataChars], bytes.Span))
            {
                throw new HushException(HushErrorCode.InvalidRecoveryKey, "The recovery key contains characters that are not valid.");
            }

            var expected = Checksum(bytes.Span);
            Span<char> actual = stackalloc char[GroupLength];
            for (var i = 0; i < GroupLength; i++)
            {
                var value = CrockfordBase32.ValueOf(compact[DataChars + i]);
                if (value < 0)
                {
                    throw new HushException(HushErrorCode.InvalidRecoveryKey, "The checksum group contains characters that are not valid.");
                }

                actual[i] = CrockfordBase32.CharOf(value);
            }

            if (!actual.SequenceEqual(expected))
            {
                throw new HushException(HushErrorCode.InvalidRecoveryKey, "The recovery key checksum does not match. Check for a typo.");
            }

            return new RecoveryKey(bytes);
        }
        catch
        {
            bytes.Dispose();
            throw;
        }
        finally
        {
            compact.Clear();
        }
    }

    /// <summary>Formats the key for display, with the checksum group last.</summary>
    public string ToDisplayString()
    {
        var data = CrockfordBase32.Encode(_bytes.Span) + Checksum(_bytes.Span);
        var builder = new StringBuilder(data.Length + data.Length / GroupLength);
        for (var i = 0; i < data.Length; i += GroupLength)
        {
            if (i > 0)
            {
                builder.Append('-');
            }

            builder.Append(data, i, GroupLength);
        }

        return builder.ToString();
    }

    /// <summary>Derives the recovery wrapping key: HKDF-SHA256(recovery key, vault salt, "hush/recovery/v1").</summary>
    public SecureBuffer DeriveWrappingKey(ReadOnlySpan<byte> vaultSalt) => Kdf.Derive(_bytes.Span, vaultSalt, Kdf.RecoveryInfo);

    /// <inheritdoc />
    public void Dispose() => _bytes.Dispose();

    /// <summary>First 20 bits of SHA-256(label || key), as four Crockford characters.</summary>
    private static string Checksum(ReadOnlySpan<byte> key)
    {
        Span<byte> input = stackalloc byte[ChecksumLabel.Length + Size];
        ChecksumLabel.CopyTo(input);
        key.CopyTo(input[ChecksumLabel.Length..]);
        Span<byte> hash = stackalloc byte[32];
        SHA256.HashData(input, hash);
        CryptographicOperations.ZeroMemory(input);

        // 20 bits = the first 2.5 bytes; Encode(3 bytes) gives 5 characters, of which the first 4 cover 20 bits.
        return CrockfordBase32.Encode(hash[..3])[..GroupLength];
    }
}
