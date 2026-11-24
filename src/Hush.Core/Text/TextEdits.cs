namespace Hush.Core.Text;

/// <summary>Replace <c>[Start, End)</c> with <see cref="Replacement"/>. An insertion has Start == End.</summary>
public sealed record TextEdit(int Start, int End, string Replacement);

/// <summary>Applies non-overlapping edits to a string.</summary>
public static class TextEdits
{
    /// <summary>
    /// Applies <paramref name="edits"/> from the end of the text backwards so earlier offsets stay valid.
    /// When an insertion and a removal start at the same offset, the removal is applied first.
    /// </summary>
    public static string Apply(string text, IEnumerable<TextEdit> edits)
    {
        ArgumentNullException.ThrowIfNull(text);
        ArgumentNullException.ThrowIfNull(edits);
        var ordered = edits.OrderByDescending(e => e.Start).ThenByDescending(e => e.End).ToList();
        for (var i = 1; i < ordered.Count; i++)
        {
            var later = ordered[i - 1];
            var earlier = ordered[i];
            if (earlier.End > later.Start && !(earlier.Start == earlier.End && earlier.Start == later.Start))
            {
                throw new InvalidOperationException("Overlapping text edits.");
            }
        }

        var result = text;
        foreach (var edit in ordered)
        {
            result = string.Concat(result.AsSpan(0, edit.Start), edit.Replacement, result.AsSpan(edit.End));
        }

        return result;
    }

    /// <summary>The leading whitespace of the line containing <paramref name="offset"/>.</summary>
    public static string IndentAt(string text, int offset)
    {
        ArgumentNullException.ThrowIfNull(text);
        var lineStart = text.LastIndexOf('\n', Math.Max(0, Math.Min(offset, text.Length) - 1)) + 1;
        var end = lineStart;
        while (end < text.Length && text[end] is ' ' or '\t')
        {
            end++;
        }

        return text[lineStart..end];
    }

    /// <summary>The newline sequence the text uses (CRLF if it contains any, otherwise LF).</summary>
    public static string NewlineOf(string text) => text != null && text.Contains("\r\n", StringComparison.Ordinal) ? "\r\n" : "\n";
}
