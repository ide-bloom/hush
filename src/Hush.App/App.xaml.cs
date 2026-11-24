using System.Windows;
using Hush.App.Infrastructure;

namespace Hush.App;

/// <summary>Single-instance tray application.</summary>
public partial class App : Application, IDisposable
{
    private const string MutexName = @"Local\Hush.Tray";
    private const string ShowEventName = @"Local\Hush.Tray.Show";
    private Mutex? _instance;
    private EventWaitHandle? _showEvent;
    private TrayIcon? _tray;
    private MainWindow? _window;

    /// <inheritdoc />
    public void Dispose()
    {
        _tray?.Dispose();
        _showEvent?.Dispose();
        _instance?.Dispose();
        GC.SuppressFinalize(this);
    }

    /// <inheritdoc />
    protected override void OnStartup(StartupEventArgs e)
    {
        base.OnStartup(e);
        _instance = new Mutex(initiallyOwned: true, MutexName, out var isFirst);
        if (!isFirst)
        {
            // Another instance owns the tray: ask it to show its window, then leave.
            using var show = EventWaitHandle.OpenExisting(ShowEventName);
            show.Set();
            Shutdown();
            return;
        }

        _showEvent = new EventWaitHandle(false, EventResetMode.AutoReset, ShowEventName);
        var services = new AppServices(() => _window!);
        _window = new MainWindow(services);
        _tray = new TrayIcon(ShowWindow, () => _window.UnlockFromTray(), () => _window.LockFromTray(), ExitApp);
        _window.SessionStateChanged += (_, state) => _tray.Update(state.Unlocked, state.Degraded);
        _window.Start();

        var showEvent = _showEvent;
        new Thread(() =>
        {
            while (showEvent.WaitOne())
            {
                Dispatcher.Invoke(ShowWindow);
            }
        })
        { IsBackground = true, Name = "Hush show-window listener" }.Start();

        if (!e.Args.Contains("--tray", StringComparer.OrdinalIgnoreCase))
        {
            ShowWindow();
        }
    }

    /// <inheritdoc />
    protected override void OnExit(ExitEventArgs e)
    {
        Dispose();
        base.OnExit(e);
    }

    private void ShowWindow()
    {
        if (_window is null)
        {
            return;
        }

        _window.Show();
        if (_window.WindowState == WindowState.Minimized)
        {
            _window.WindowState = WindowState.Normal;
        }

        _window.Activate();
    }

    private void ExitApp()
    {
        _window?.ExitApplication();
        Shutdown();
    }
}
