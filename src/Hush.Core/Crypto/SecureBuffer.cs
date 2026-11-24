using System.Security.Cryptography;

namespace Hush.Core.Crypto;

/// <summary>
/// A fixed-size byte buffer for key material. The array is allocated on the pinned object heap so the
/// GC never copies it, and it is zeroed with <see cref="CryptographicOperations.ZeroMemory"/> on dispose.
/// </summary>
[Sensitive]
public sealed class SecureBuffer : IDisposable
{
    private readonly byte[] _bytes;
    private bool _disposed;

    /// <summary>Allocates a zero-filled pinned buffer.</summary>
    public SecureBuffer(int length)
    {
        ArgumentOutOfRangeException.ThrowIfNegative(length);
        _bytes = GC.AllocateArray<byte>(length, pinned: true);
    }

    /// <summary>Number of bytes in the buffer.</summary>
    public int Length => _bytes.Length;

    /// <summary>The buffer contents. Throws once disposed.</summary>
    public Span<byte> Span
    {
        get
        {
            ObjectDisposedException.ThrowIf(_disposed, this);
            return _bytes;
        }
    }

    /// <summary>The buffer contents as read-only memory. Throws once disposed.</summary>
    public ReadOnlyMemory<byte> Memory
    {
        get
        {
            ObjectDisposedException.ThrowIf(_disposed, this);
            return _bytes;
        }
    }

    /// <summary>Copies <paramref name="source"/> into a new pinned buffer.</summary>
    public static SecureBuffer CopyOf(ReadOnlySpan<byte> source)
    {
        var buffer = new SecureBuffer(source.Length);
        source.CopyTo(buffer._bytes);
        return buffer;
    }

    /// <summary>Creates a buffer filled with cryptographically secure random bytes.</summary>
    public static SecureBuffer Random(int length)
    {
        var buffer = new SecureBuffer(length);
        RandomNumberGenerator.Fill(buffer._bytes);
        return buffer;
    }

    /// <summary>Creates an independent copy.</summary>
    public SecureBuffer Clone() => CopyOf(Span);

    /// <inheritdoc />
    public void Dispose()
    {
        if (_disposed)
        {
            return;
        }

        CryptographicOperations.ZeroMemory(_bytes);
        _disposed = true;
    }
}
