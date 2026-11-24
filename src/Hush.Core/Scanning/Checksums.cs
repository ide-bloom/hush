using System.Text;
using System.Text.Json;

namespace Hush.Core.Scanning;

/// <summary>Format validators that turn a format match into a high-confidence match.</summary>
public static class Checksums
{
    private const string Base62 = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";

    /// <summary>Runs the named validator. Unknown names validate nothing (returns null).</summary>
    public static bool? Validate(string? kind, string secret) => kind switch
    {
        null => null,
        "github-crc32" => ValidateCrc32Token(secret),
        "jwt" => ValidateJwt(secret),
        _ => null,
    };

    /// <summary>
    /// GitHub-style tokens (also npm): <c>prefix_</c> + 30 random base62 characters + 6 base62 characters of
    /// the CRC32 of the random part, left-padded with zeros.
    /// </summary>
    public static bool ValidateCrc32Token(string token)
    {
        ArgumentNullException.ThrowIfNull(token);
        var underscore = token.LastIndexOf('_');
        if (underscore < 0 || token.Length - underscore - 1 != 36)
        {
            return false;
        }

        var body = token.AsSpan(underscore + 1);
        return body[30..].SequenceEqual(Crc32Base62(body[..30]));
    }

    /// <summary>The 6-character base62 CRC32 checksum used by GitHub-style tokens.</summary>
    public static string Crc32Base62(ReadOnlySpan<char> randomPart)
    {
        var bytes = Encoding.ASCII.GetBytes(randomPart.ToArray());
        var crc = Crc32(bytes);
        Span<char> digits = stackalloc char[6];
        for (var i = 5; i >= 0; i--)
        {
            digits[i] = Base62[(int)(crc % 62)];
            crc /= 62;
        }

        return new string(digits);
    }

    /// <summary>CRC-32 (IEEE 802.3, reflected, polynomial 0xEDB88320), as used by zlib.</summary>
    public static uint Crc32(ReadOnlySpan<byte> data)
    {
        var crc = 0xFFFFFFFFu;
        foreach (var b in data)
        {
            crc ^= b;
            for (var bit = 0; bit < 8; bit++)
            {
                crc = (crc & 1) != 0 ? (crc >> 1) ^ 0xEDB88320u : crc >> 1;
            }
        }

        return ~crc;
    }

    /// <summary>A JWT whose header decodes to a JSON object with an <c>alg</c> member.</summary>
    public static bool ValidateJwt(string token)
    {
        ArgumentNullException.ThrowIfNull(token);
        var dot = token.IndexOf('.', StringComparison.Ordinal);
        if (dot <= 0)
        {
            return false;
        }

        try
        {
            var header = Base64UrlDecode(token[..dot]);
            using var document = JsonDocument.Parse(header);
            return document.RootElement.ValueKind == JsonValueKind.Object && document.RootElement.TryGetProperty("alg", out _);
        }
        catch (Exception ex) when (ex is FormatException or JsonException)
        {
            // Not base64url JSON: the match is not a JWT.
            return false;
        }
    }

    /// <summary>Shannon entropy in bits per character.</summary>
    public static double Entropy(string value)
    {
        ArgumentNullException.ThrowIfNull(value);
        if (value.Length == 0)
        {
            return 0;
        }

        var counts = new Dictionary<char, int>();
        foreach (var c in value)
        {
            counts[c] = counts.GetValueOrDefault(c) + 1;
        }

        double entropy = 0;
        foreach (var count in counts.Values)
        {
            var p = (double)count / value.Length;
            entropy -= p * Math.Log2(p);
        }

        return entropy;
    }

    private static byte[] Base64UrlDecode(string text)
    {
        var padded = text.Replace('-', '+').Replace('_', '/');
        padded += (padded.Length % 4) switch
        {
            2 => "==",
            3 => "=",
            _ => string.Empty,
        };
        return Convert.FromBase64String(padded);
    }
}
