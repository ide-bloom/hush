using System.Runtime.InteropServices;
using System.Text;

namespace Hush.Cli.Terminal;

/// <summary>Console I/O, abstracted so commands can be tested.</summary>
internal interface ITerminal
{
    TextWriter Out { get; }

    TextWriter Error { get; }

    /// <summary>True when stdin is a pipe or file rather than a console.</summary>
    bool IsInputRedirected { get; }

    /// <summary>True when a person can answer prompts (a console exists).</summary>
    bool CanPrompt { get; }

    /// <summary>True when ANSI colors should be written to <see cref="Out"/>.</summary>
    bool UseColor { get; }

    /// <summary>Reads all of stdin.</summary>
    string ReadAllInput();

    /// <summary>Reads a line without echoing it. Returns null if cancelled or no console exists.</summary>
    string? ReadSecret(string prompt);

    /// <summary>Reads a visible line from the console, even when stdin is redirected.</summary>
    string? ReadLine(string prompt);

    /// <summary>Asks a yes/no question; anything but y/yes is no.</summary>
    bool Confirm(string prompt);
}

/// <summary>The real console.</summary>
internal sealed partial class SystemTerminal : ITerminal
{
    private const int StdOutputHandle = -11;
    private const uint EnableVirtualTerminalProcessing = 0x0004;

    public SystemTerminal()
    {
        Console.OutputEncoding = Encoding.UTF8;
        UseColor = !Console.IsOutputRedirected
            && Environment.GetEnvironmentVariable("NO_COLOR") is null
            && EnableVirtualTerminal();
    }

    public TextWriter Out => Console.Out;

    public TextWriter Error => Console.Error;

    public bool IsInputRedirected => Console.IsInputRedirected;

    public bool CanPrompt => !Console.IsInputRedirected || HasConsole();

    public bool UseColor { get; }

    public string ReadAllInput() => Console.In.ReadToEnd();

    public string? ReadSecret(string prompt)
    {
        Console.Error.Write(prompt);
        if (Console.IsInputRedirected)
        {
            return ReadConsoleLine();
        }

        var builder = new StringBuilder();
        while (true)
        {
            var key = Console.ReadKey(intercept: true);
            if (key.Key == ConsoleKey.Enter)
            {
                Console.Error.WriteLine();
                var result = builder.ToString();
                builder.Clear();
                return result;
            }

            if (key.Key == ConsoleKey.Escape)
            {
                Console.Error.WriteLine();
                return null;
            }

            if (key.Key == ConsoleKey.Backspace)
            {
                if (builder.Length > 0)
                {
                    builder.Length--;
                }
            }
            else if (!char.IsControl(key.KeyChar))
            {
                builder.Append(key.KeyChar);
            }
        }
    }

    public string? ReadLine(string prompt)
    {
        Console.Error.Write(prompt);
        return Console.IsInputRedirected ? ReadConsoleLine() : Console.ReadLine();
    }

    public bool Confirm(string prompt)
    {
        var answer = ReadLine(prompt + " [y/N] ");
        return answer is not null && (answer.Trim().Equals("y", StringComparison.OrdinalIgnoreCase) || answer.Trim().Equals("yes", StringComparison.OrdinalIgnoreCase));
    }

    /// <summary>Reads from CONIN$ so prompts work when stdin carries data (for example `echo x | hush set`).</summary>
    private static string? ReadConsoleLine()
    {
        try
        {
            using var stream = new FileStream("CONIN$", FileMode.Open, FileAccess.Read);
            using var reader = new StreamReader(stream, Console.InputEncoding);
            return reader.ReadLine();
        }
        catch (IOException)
        {
            // No console is attached (for example when an MCP client runs Hush); callers treat null as "cannot prompt".
            return null;
        }
        catch (UnauthorizedAccessException)
        {
            // Same: the console input exists but is not ours to read, so there is nobody to prompt.
            return null;
        }
    }

    private static bool HasConsole() => GetConsoleWindow() != 0;

    private static bool EnableVirtualTerminal()
    {
        var handle = GetStdHandle(StdOutputHandle);
        return GetConsoleMode(handle, out var mode) && ((mode & EnableVirtualTerminalProcessing) != 0 || SetConsoleMode(handle, mode | EnableVirtualTerminalProcessing));
    }

    [LibraryImport("kernel32.dll")]
    private static partial nint GetStdHandle(int handle);

    [LibraryImport("kernel32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool GetConsoleMode(nint handle, out uint mode);

    [LibraryImport("kernel32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool SetConsoleMode(nint handle, uint mode);

    [LibraryImport("kernel32.dll")]
    private static partial nint GetConsoleWindow();
}

/// <summary>ANSI styling helpers that become no-ops when color is off.</summary>
internal static class Style
{
    public static string Red(this ITerminal t, string s) => t.UseColor ? $"\u001b[91m{s}\u001b[0m" : s;

    public static string Yellow(this ITerminal t, string s) => t.UseColor ? $"\u001b[93m{s}\u001b[0m" : s;

    public static string Green(this ITerminal t, string s) => t.UseColor ? $"\u001b[92m{s}\u001b[0m" : s;

    public static string Cyan(this ITerminal t, string s) => t.UseColor ? $"\u001b[96m{s}\u001b[0m" : s;

    public static string Dim(this ITerminal t, string s) => t.UseColor ? $"\u001b[2m{s}\u001b[0m" : s;

    public static string Bold(this ITerminal t, string s) => t.UseColor ? $"\u001b[1m{s}\u001b[0m" : s;
}
