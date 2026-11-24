using Hush.Core.Interop;

namespace Hush.Core.Keys;

/// <summary>
/// Finds the window that should own a Windows Hello prompt raised from a console process, so the prompt
/// opens in front of the terminal instead of behind it.
/// </summary>
public static class PromptOwner
{
    /// <summary>
    /// Resolution order:
    /// 1. The console window, when it is a visible classic conhost window.
    /// 2. The root owner of the console window. Windows Terminal and VS Code host consoles through ConPTY,
    ///    whose pseudo console window is invisible but owned by the real terminal window.
    /// 3. The foreground window, which is the terminal or IDE the user just typed the command into, or the
    ///    app (an MCP client, for example) that launched Hush without a console.
    /// </summary>
    public static nint ForConsole()
    {
        var console = NativeMethods.GetConsoleWindow();
        if (console != 0)
        {
            if (NativeMethods.IsWindowVisible(console))
            {
                return console;
            }

            var root = NativeMethods.GetAncestor(console, NativeMethods.GA_ROOTOWNER);
            if (root != 0 && root != console && NativeMethods.IsWindowVisible(root))
            {
                return root;
            }
        }

        return NativeMethods.GetForegroundWindow();
    }
}
