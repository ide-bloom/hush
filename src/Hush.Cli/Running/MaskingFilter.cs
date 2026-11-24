using System.Text;

namespace Hush.Cli.Running;

/// <summary>
/// Replaces every occurrence of a secret value in a byte stream with <c>••••</c>. Bytes that could be the
/// start of a secret split across two writes are held back until the next write (or <see cref="Flush"/>),
/// so a secret printed in two chunks is still masked.
/// </summary>
internal sealed class MaskingFilter
{
    /// <summary>Values shorter than this are not masked: they would mangle ordinary output.</summary>
    public const int MinimumLength = 4;

    private static readonly byte[] Replacement = Encoding.UTF8.GetBytes("••••");
    private readonly byte[][] _secrets;
    private readonly List<byte> _pending = [];

    public MaskingFilter(IEnumerable<string> secrets)
    {
        _secrets = secrets
            .Where(s => s.Length >= MinimumLength)
            .Distinct(StringComparer.Ordinal)
            .Select(Encoding.UTF8.GetBytes)
            .OrderByDescending(b => b.Length)
            .ToArray();
    }

    /// <summary>True when bytes are being held back.</summary>
    public bool HasPending => _pending.Count > 0;

    /// <summary>Filters <paramref name="data"/> and writes everything that is safe to emit.</summary>
    public void Write(ReadOnlySpan<byte> data, Stream output)
    {
        ArgumentNullException.ThrowIfNull(output);
        if (_secrets.Length == 0)
        {
            output.Write(data);
            return;
        }

        _pending.AddRange(data);
        var buffer = _pending.ToArray();
        var emit = new List<byte>(buffer.Length);
        var i = 0;
        while (i < buffer.Length)
        {
            var matched = false;
            var partial = false;
            foreach (var secret in _secrets)
            {
                var available = buffer.Length - i;
                if (available >= secret.Length)
                {
                    if (buffer.AsSpan(i, secret.Length).SequenceEqual(secret))
                    {
                        emit.AddRange(Replacement);
                        i += secret.Length;
                        matched = true;
                        break;
                    }
                }
                else if (buffer.AsSpan(i).SequenceEqual(secret.AsSpan(0, available)))
                {
                    partial = true;
                }
            }

            if (matched)
            {
                continue;
            }

            if (partial)
            {
                break;
            }

            emit.Add(buffer[i]);
            i++;
        }

        _pending.Clear();
        _pending.AddRange(buffer.AsSpan(i).ToArray());
        if (emit.Count > 0)
        {
            output.Write(emit.ToArray());
            output.Flush();
        }
    }

    /// <summary>Writes held-back bytes (they did not turn out to be a secret).</summary>
    public void Flush(Stream output)
    {
        ArgumentNullException.ThrowIfNull(output);
        if (_pending.Count > 0)
        {
            output.Write(_pending.ToArray());
            _pending.Clear();
        }

        output.Flush();
    }
}
