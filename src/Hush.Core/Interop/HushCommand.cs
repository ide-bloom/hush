namespace Hush.Core.Interop;

/// <summary>Decides how rewritten MCP configs should invoke Hush.</summary>
public static class HushCommand
{
    /// <summary>
    /// <c>hush</c> when the first hush.exe on PATH is <paramref name="hushExecutable"/> (so configs keep working
    /// across upgrades), otherwise the full path, because MCP clients launch servers without a shell.
    /// </summary>
    public static string For(string hushExecutable)
    {
        ArgumentNullException.ThrowIfNull(hushExecutable);
        var target = Path.GetFullPath(hushExecutable);
        foreach (var directory in (Environment.GetEnvironmentVariable("PATH") ?? string.Empty).Split(';', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
        {
            string candidate;
            try
            {
                candidate = Path.Combine(directory.Trim('"'), "hush.exe");
            }
            catch (ArgumentException)
            {
                // A malformed PATH entry cannot hold hush.exe; skip it like a shell would.
                continue;
            }

            if (File.Exists(candidate))
            {
                return string.Equals(Path.GetFullPath(candidate), target, StringComparison.OrdinalIgnoreCase) ? "hush" : target;
            }
        }

        return target;
    }
}
