using System.Globalization;
using System.Text;

namespace Hush.Core.Text;

/// <summary>Unified diffs (Myers' O(ND) algorithm) for <c>hush migrate --dry-run</c>.</summary>
public static class UnifiedDiff
{
    private enum Op
    {
        Equal,
        Delete,
        Insert,
    }

    /// <summary>
    /// Produces a unified diff with three lines of context. <paramref name="oldText"/> null means the file is
    /// new. Returns an empty string when the texts are equal.
    /// </summary>
    public static string Create(string path, string? oldText, string newText, int context = 3)
    {
        ArgumentNullException.ThrowIfNull(newText);
        var a = SplitLines(oldText ?? string.Empty);
        var b = SplitLines(newText);
        var script = Diff(a, b);
        if (script.All(s => s.Op == Op.Equal))
        {
            return string.Empty;
        }

        var output = new StringBuilder();
        output.Append("--- ").Append(oldText is null ? "/dev/null" : "a/" + path).Append('\n');
        output.Append("+++ b/").Append(path).Append('\n');

        // Group the edit script into hunks separated by more than 2*context unchanged lines.
        var index = 0;
        while (index < script.Count)
        {
            while (index < script.Count && script[index].Op == Op.Equal)
            {
                index++;
            }

            if (index >= script.Count)
            {
                break;
            }

            var hunkStart = Math.Max(0, index - context);
            var hunkEnd = index;
            var lastChange = index;
            while (hunkEnd < script.Count)
            {
                if (script[hunkEnd].Op != Op.Equal)
                {
                    lastChange = hunkEnd;
                }
                else if (hunkEnd - lastChange > context * 2)
                {
                    break;
                }

                hunkEnd++;
            }

            hunkEnd = Math.Min(script.Count, lastChange + context + 1);
            var oldStart = script[hunkStart].OldIndex;
            var newStart = script[hunkStart].NewIndex;
            var oldCount = script.Skip(hunkStart).Take(hunkEnd - hunkStart).Count(s => s.Op != Op.Insert);
            var newCount = script.Skip(hunkStart).Take(hunkEnd - hunkStart).Count(s => s.Op != Op.Delete);
            output.Append(CultureInfo.InvariantCulture, $"@@ -{(oldCount == 0 ? oldStart : oldStart + 1)},{oldCount} +{(newCount == 0 ? newStart : newStart + 1)},{newCount} @@\n");
            for (var i = hunkStart; i < hunkEnd; i++)
            {
                var step = script[i];
                output.Append(step.Op switch { Op.Equal => ' ', Op.Delete => '-', _ => '+' });
                output.Append(step.Op == Op.Insert ? b[step.NewIndex] : a[step.OldIndex]).Append('\n');
            }

            index = hunkEnd;
        }

        return output.ToString();
    }

    private static string[] SplitLines(string text)
    {
        if (text.Length == 0)
        {
            return [];
        }

        var lines = text.Replace("\r\n", "\n", StringComparison.Ordinal).Split('\n');
        return text.EndsWith('\n') ? lines[..^1] : lines;
    }

    private static List<(Op Op, int OldIndex, int NewIndex)> Diff(string[] a, string[] b)
    {
        var n = a.Length;
        var m = b.Length;
        var max = n + m;
        var offset = max + 1;
        var v = new int[2 * max + 3];
        var trace = new List<int[]>();
        var found = false;
        for (var d = 0; d <= max && !found; d++)
        {
            trace.Add((int[])v.Clone());
            for (var k = -d; k <= d; k += 2)
            {
                var x = k == -d || (k != d && v[offset + k - 1] < v[offset + k + 1]) ? v[offset + k + 1] : v[offset + k - 1] + 1;
                var y = x - k;
                while (x < n && y < m && a[x] == b[y])
                {
                    x++;
                    y++;
                }

                v[offset + k] = x;
                if (x >= n && y >= m)
                {
                    found = true;
                    break;
                }
            }
        }

        trace.Add((int[])v.Clone());

        // Walk the trace backwards to recover the edit script.
        var script = new List<(Op, int, int)>();
        int cx = n, cy = m;
        for (var d = trace.Count - 2; d >= 0 && (cx > 0 || cy > 0); d--)
        {
            var vd = trace[d];
            var k = cx - cy;
            var prevK = k == -d || (k != d && vd[offset + k - 1] < vd[offset + k + 1]) ? k + 1 : k - 1;
            var prevX = d == 0 ? 0 : vd[offset + prevK];
            var prevY = prevX - prevK;
            while (cx > prevX && cy > prevY)
            {
                cx--;
                cy--;
                script.Add((Op.Equal, cx, cy));
            }

            if (d > 0)
            {
                if (cx == prevX)
                {
                    cy--;
                    script.Add((Op.Insert, cx, cy));
                }
                else
                {
                    cx--;
                    script.Add((Op.Delete, cx, cy));
                }
            }
        }

        while (cx > 0 && cy > 0)
        {
            cx--;
            cy--;
            script.Add((Op.Equal, cx, cy));
        }

        script.Reverse();
        return script;
    }
}
