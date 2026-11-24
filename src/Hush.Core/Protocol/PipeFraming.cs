using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization.Metadata;

namespace Hush.Core.Protocol;

/// <summary>Length-prefixed JSON frames over a stream, and the per-user pipe name.</summary>
public static class PipeFraming
{
    /// <summary>Largest accepted frame.</summary>
    public const int MaxFrameBytes = 4 * 1024 * 1024;

    /// <summary>
    /// The broker pipe name: <c>hush-broker-</c> plus the first 16 hex digits of SHA-256 of the user's SID,
    /// so each user gets a distinct pipe without exposing the SID itself.
    /// </summary>
    public static string PipeNameForCurrentUser()
    {
        using var identity = WindowsIdentity.GetCurrent();
        var sid = identity.User?.Value ?? throw new InvalidOperationException("The current user has no SID.");
        return PipeNameFor(sid);
    }

    /// <summary>The pipe name for a given SID string.</summary>
    public static string PipeNameFor(string sid)
    {
        var hash = SHA256.HashData(Encoding.UTF8.GetBytes(sid));
        return "hush-broker-" + Convert.ToHexStringLower(hash)[..16];
    }

    /// <summary>Writes one frame.</summary>
    public static async Task WriteAsync<T>(Stream stream, T message, JsonTypeInfo<T> typeInfo, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(stream);
        var payload = JsonSerializer.SerializeToUtf8Bytes(message, typeInfo);
        try
        {
            var header = new byte[4];
            BinaryPrimitives.WriteInt32LittleEndian(header, payload.Length);
            await stream.WriteAsync(header, cancellationToken).ConfigureAwait(false);
            await stream.WriteAsync(payload, cancellationToken).ConfigureAwait(false);
            await stream.FlushAsync(cancellationToken).ConfigureAwait(false);
        }
        finally
        {
            // Frames may carry secret values; do not leave them in the managed heap longer than needed.
            CryptographicOperations.ZeroMemory(payload);
        }
    }

    /// <summary>Reads one frame, or returns default at end of stream.</summary>
    public static async Task<T?> ReadAsync<T>(Stream stream, JsonTypeInfo<T> typeInfo, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(stream);
        var header = new byte[4];
        if (!await ReadExactlyOrEndAsync(stream, header, cancellationToken).ConfigureAwait(false))
        {
            return default;
        }

        var length = BinaryPrimitives.ReadInt32LittleEndian(header);
        if (length is <= 0 or > MaxFrameBytes)
        {
            throw new InvalidDataException("Invalid frame length.");
        }

        var payload = new byte[length];
        try
        {
            if (!await ReadExactlyOrEndAsync(stream, payload, cancellationToken).ConfigureAwait(false))
            {
                throw new EndOfStreamException("The connection closed mid-frame.");
            }

            return JsonSerializer.Deserialize(payload, typeInfo);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(payload);
        }
    }

    private static async Task<bool> ReadExactlyOrEndAsync(Stream stream, byte[] buffer, CancellationToken cancellationToken)
    {
        var read = 0;
        while (read < buffer.Length)
        {
            var n = await stream.ReadAsync(buffer.AsMemory(read), cancellationToken).ConfigureAwait(false);
            if (n == 0)
            {
                return read == 0 ? false : throw new EndOfStreamException("The connection closed mid-frame.");
            }

            read += n;
        }

        return true;
    }
}
