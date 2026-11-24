using System.Windows;
using System.Windows.Interop;
using Hush.Core;
using Hush.Core.Keys;
using Hush.Core.Protocol;
using Hush.Core.Vault;

namespace Hush.App.Infrastructure;

/// <summary>
/// The tray app's access to Hush. It uses exactly the same Core library and broker as the CLI: no vault or
/// crypto logic lives in the app.
/// </summary>
internal sealed class AppServices
{
    private readonly Func<Window> _owner;

    public AppServices(Func<Window> owner)
    {
        _owner = owner;
        Paths = HushPaths.Default();
        Manager = new VaultManager(Paths, new PlatformKeyProvider());
        Session = new SessionClient(Manager, NamedPipeBrokerTransport.ForCurrentUser(launchIfNeeded: true), Prompt);
    }

    public HushPaths Paths { get; }

    public VaultManager Manager { get; }

    public SessionClient Session { get; }

    /// <summary>
    /// Windows Hello needs a visible owner window to appear in the foreground. The session client may call this
    /// from a background thread, so marshal to the UI thread and bring the main window up first.
    /// </summary>
    private PromptContext Prompt(string reason) =>
        Application.Current.Dispatcher.Invoke(() =>
        {
            var window = _owner();
            if (!window.IsVisible)
            {
                window.Show();
            }

            if (window.WindowState == WindowState.Minimized)
            {
                window.WindowState = WindowState.Normal;
            }

            window.Activate();
            return new PromptContext(new WindowInteropHelper(window).Handle, reason);
        });
}
