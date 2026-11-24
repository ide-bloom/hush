namespace Hush.Core.Crypto;

/// <summary>
/// Crockford Base32: digits and uppercase letters without I, L, O and U, so a key read aloud or typed by
/// hand survives common confusions. Decoding is case-insensitive and maps I/L to 1 and O to 0.
/// </summary>
public static class CrockfordBase32
{
    private const string Alphabet = "0123456789ABCDEFGHJKMNPQRSTVWXYZ";

    /// <summary>Encodes bytes; the output has <c>ceil(bits / 5)</c> characters.</summary>
    public static string Encode(ReadOnlySpan<byte> data)
    {
        var chars = new char[(data.Length * 8 + 4) / 5];
        var buffer = 0;
        var bits = 0;
        var index = 0;
        foreach (var b in data)
        {
            buffer = (buffer << 8) | b;
            bits += 8;
            while (bits >= 5)
            {
                chars[index++] = Alphabet[(buffer >> (bits - 5)) & 31];
                bits -= 5;
            }
        }

        if (bits > 0)
        {
            chars[index++] = Alphabet[(buffer << (5 - bits)) & 31];
        }

        return new string(chars, 0, index);
    }

    /// <summary>Decodes into exactly <c>destination.Length</c> bytes. Returns false on invalid characters or a length mismatch.</summary>
    public static bool TryDecode(ReadOnlySpan<char> text, Span<byte> destination)
    {
        var buffer = 0;
        var bits = 0;
        var index = 0;
        foreach (var c in text)
        {
            var value = ValueOf(c);
            if (value < 0)
            {
                return false;
            }

            buffer = (buffer << 5) | value;
            bits += 5;
            if (bits >= 8)
            {
                if (index >= destination.Length)
                {
                    return false;
                }

                destination[index++] = (byte)(buffer >> (bits - 8));
                bits -= 8;
            }
        }

        return index == destination.Length;
    }

    /// <summary>Returns the canonical character for a 5-bit value.</summary>
    public static char CharOf(int value) => Alphabet[value & 31];

    /// <summary>Maps a character to its 5-bit value, or -1 if it is not part of the alphabet.</summary>
    public static int ValueOf(char c)
    {
        c = char.ToUpperInvariant(c);
        return c switch
        {
            'I' or 'L' => 1,
            'O' => 0,
            _ => Alphabet.IndexOf(c, StringComparison.Ordinal),
        };
    }
}
