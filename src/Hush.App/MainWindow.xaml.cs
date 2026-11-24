using System.ComponentModel;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Threading;
using Hush.App.Infrastructure;
using Hush.App.Views;
using Hush.Core;
using Hush.Core.Protocol;

namespace Hush.App;

/// <summary>The session state shown in the tray and the session card.</summary>
internal sealed record SessionState(bool VaultExists, bool Unlocked, bool Degraded);

/// <summary>Main window: navigation, session card and the four pages.</summary>
internal sealed partial class MainWindow : Window
{
    private readonly AppServices _services;
    private readonly DispatcherTimer _poll = new() { Interval = TimeSpan.FromSeconds(3) };
    private readonly Dictionary<string, UserControl> _pages = [];
    private SessionState _state = new(false, false, false);
    private bool _exiting;

    public MainWindow(AppServices services)
    {
        _services = services;
        InitializeComponent();
        _poll.Tick += async (_, _) => await RefreshStateAsync();
    }

    public event EventHandler<SessionState>? SessionStateChanged;

    public void Start()
    {
        _poll.Start();
        _ = RefreshStateAsync();
        ShowPage("vault");
    }

    public async void UnlockFromTray() => await Ui.TryAsync(this, UnlockAsync);

    public async void LockFromTray() => await Ui.TryAsync(this, LockAsync);

    public void ExitApplication()
    {
        _exiting = true;
        _poll.Stop();
        Close();
    }

    public async Task UnlockAsync()
    {
        await _services.Session.UnlockAsync(force: false, CancellationToken.None);
        await RefreshStateAsync();
    }

    public async Task LockAsync()
    {
        await _services.Session.LockAsync(CancellationToken.None);
        await RefreshStateAsync();
    }

    public async Task RefreshStateAsync()
    {
        // The vault is usually changed from outside the app (hush set, hush migrate), so check it on every poll,
        // independently of whether the agent answers.
        RefreshVaultPage();

        BrokerStatus status;
        try
        {
            status = await _services.Session.StatusAsync(CancellationToken.None);
        }
        catch (HushException ex)
        {
            SessionText.Text = "Agent unavailable";
            SessionDetail.Text = ex.Message;
            return;
        }

        var state = new SessionState(status.VaultExists, status.Unlocked, status.Degraded);
        SessionGlyph.Text = status.Unlocked ? "" : "";
        SessionText.Text = status.Unlocked ? "Unlocked" : "Locked";
        SessionDetail.Text = status.Unlocked && status.IdleRemainingSeconds is { } seconds
            ? $"Locks in {Math.Max(1, seconds / 60)} min if idle, or when you lock Windows."
            : status.LastLockReason is { } reason ? $"Last locked: {reason}." : $"{status.SecretCount} secret(s).";
        SessionButton.Content = status.Unlocked ? "_Lock now" : "_Unlock";
        SessionButton.IsEnabled = status.VaultExists;
        DegradedBanner.Visibility = status.Degraded ? Visibility.Visible : Visibility.Collapsed;
        if (status.DegradedReason is { } why)
        {
            DegradedText.Text = $"Degraded mode: no usable TPM ({why}). The vault key is protected by DPAPI instead of hardware; Windows Hello is still required.";
        }

        NoVaultBanner.Visibility = status.VaultExists ? Visibility.Collapsed : Visibility.Visible;
        if (state != _state)
        {
            _state = state;
            SessionStateChanged?.Invoke(this, state);
        }
    }

    protected override void OnActivated(EventArgs e)
    {
        base.OnActivated(e);
        RefreshVaultPage();
    }

    private void RefreshVaultPage()
    {
        if (!_pages.TryGetValue("vault", out var page))
        {
            return;
        }

        try
        {
            ((VaultView)page).RefreshIfChanged();
        }
        catch (HushException ex)
        {
            // A vault that cannot be read is shown in the session card rather than crashing the poll timer.
            SessionDetail.Text = ex.Message;
        }
    }

    protected override void OnClosing(CancelEventArgs e)
    {
        // Closing the window keeps Hush in the tray; Exit is in the tray menu.
        if (!_exiting)
        {
            e.Cancel = true;
            Hide();
        }

        base.OnClosing(e);
    }

    private async void OnSessionButton(object sender, RoutedEventArgs e) =>
        await Ui.TryAsync(this, _state.Unlocked ? LockAsync : UnlockAsync);

    private void OnNavigate(object sender, SelectionChangedEventArgs e)
    {
        if (Navigation.SelectedItem is ListBoxItem { Tag: string tag } && IsLoaded)
        {
            ShowPage(tag);
        }
    }

    private void ShowPage(string tag)
    {
        if (!_pages.TryGetValue(tag, out var page))
        {
            page = tag switch
            {
                "vault" => new VaultView(_services, this),
                "scan" => new ScanView(_services, this),
                "audit" => new AuditView(_services, this),
                _ => new SettingsView(_services, this),
            };
            _pages[tag] = page;
        }

        Page.Content = page;
        if (page is IPage refreshable)
        {
            _ = refreshable.OnShownAsync();
        }
    }
}

/// <summary>A page that refreshes when it is shown.</summary>
internal interface IPage
{
    Task OnShownAsync();
}
