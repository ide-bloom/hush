using Microsoft.Win32;

namespace Hush.Agent;

/// <summary>
/// Locks the vault when the workstation locks, the user switches or disconnects the session, logs off, or
/// (when enabled) the machine sleeps. <see cref="SystemEvents"/> runs its own hidden window on a dedicated
/// thread when subscribed from a thread without a message loop, which is the case in the broker.
/// </summary>
public sealed class SessionLockMonitor : IDisposable
{
    private readonly Action<string> _lock;
    private readonly Func<bool> _lockOnSleep;

    /// <summary>Starts monitoring.</summary>
    public SessionLockMonitor(Action<string> lockAction, Func<bool> lockOnSleep)
    {
        _lock = lockAction;
        _lockOnSleep = lockOnSleep;
        SystemEvents.SessionSwitch += OnSessionSwitch;
        SystemEvents.PowerModeChanged += OnPowerModeChanged;
        SystemEvents.SessionEnding += OnSessionEnding;
    }

    /// <summary>The lock reason for a session-switch event, or null if it should not lock.</summary>
    public static string? ReasonFor(SessionSwitchReason reason) => reason switch
    {
        SessionSwitchReason.SessionLock => "workstation locked",
        SessionSwitchReason.ConsoleDisconnect => "session switched (console disconnect)",
        SessionSwitchReason.RemoteDisconnect => "remote session disconnected",
        SessionSwitchReason.SessionLogoff => "user logged off",
        SessionSwitchReason.ConsoleConnect or SessionSwitchReason.RemoteConnect => "session switched",
        _ => null,
    };

    /// <inheritdoc />
    public void Dispose()
    {
        SystemEvents.SessionSwitch -= OnSessionSwitch;
        SystemEvents.PowerModeChanged -= OnPowerModeChanged;
        SystemEvents.SessionEnding -= OnSessionEnding;
    }

    private void OnSessionSwitch(object? sender, SessionSwitchEventArgs e)
    {
        if (ReasonFor(e.Reason) is { } reason)
        {
            _lock(reason);
        }
    }

    private void OnPowerModeChanged(object? sender, PowerModeChangedEventArgs e)
    {
        if (e.Mode == PowerModes.Suspend && _lockOnSleep())
        {
            _lock("system suspended");
        }
    }

    private void OnSessionEnding(object? sender, SessionEndingEventArgs e) => _lock("session ending");
}
