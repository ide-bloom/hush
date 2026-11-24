using System.Collections.ObjectModel;
using System.Globalization;
using System.Windows;
using System.Windows.Controls;
using Hush.App.Infrastructure;
using Hush.Core.Settings;
using Microsoft.Win32;

namespace Hush.App.Views;

/// <summary>Settings page: idle timeout, lock on sleep, scan roots, start with Windows.</summary>
internal sealed partial class SettingsView : UserControl, IPage
{
    private readonly AppServices _services;
    private readonly MainWindow _owner;
    private readonly ObservableCollection<string> _roots = [];
    private bool _syncing;

    public SettingsView(AppServices services, MainWindow owner)
    {
        _services = services;
        _owner = owner;
        InitializeComponent();
        Roots.ItemsSource = _roots;
    }

    public Task OnShownAsync()
    {
        var settings = HushSettings.Load(_services.Paths);
        _syncing = true;
        IdleSlider.Value = Math.Min(settings.IdleTimeoutMinutes, IdleSlider.Maximum);
        IdleBox.Text = settings.IdleTimeoutMinutes.ToString(CultureInfo.CurrentCulture);
        _syncing = false;
        LockOnSleep.IsChecked = settings.LockOnSleep;
        _roots.Clear();
        foreach (var root in settings.ScanRoots)
        {
            _roots.Add(root);
        }

        StartWithWindows.IsChecked = StartupRegistration.IsEnabled;
        Saved.Text = string.Empty;
        return Task.CompletedTask;
    }

    private void OnSlider(object sender, RoutedPropertyChangedEventArgs<double> e)
    {
        if (!_syncing && IdleBox is not null)
        {
            _syncing = true;
            IdleBox.Text = ((int)e.NewValue).ToString(CultureInfo.CurrentCulture);
            _syncing = false;
        }
    }

    private void OnIdleText(object sender, TextChangedEventArgs e)
    {
        if (!_syncing && int.TryParse(IdleBox.Text, NumberStyles.Integer, CultureInfo.CurrentCulture, out var minutes))
        {
            _syncing = true;
            IdleSlider.Value = Math.Clamp(minutes, IdleSlider.Minimum, IdleSlider.Maximum);
            _syncing = false;
        }
    }

    private void OnAddRoot(object sender, RoutedEventArgs e)
    {
        var dialog = new OpenFolderDialog { Title = "Add a scan root", Multiselect = true };
        if (dialog.ShowDialog(_owner) == true)
        {
            foreach (var folder in dialog.FolderNames.Where(f => !_roots.Contains(f, StringComparer.OrdinalIgnoreCase)))
            {
                _roots.Add(folder);
            }
        }
    }

    private void OnRemoveRoot(object sender, RoutedEventArgs e)
    {
        if (Roots.SelectedItem is string root)
        {
            _roots.Remove(root);
        }
    }

    private async void OnSave(object sender, RoutedEventArgs e)
    {
        if (!int.TryParse(IdleBox.Text, NumberStyles.Integer, CultureInfo.CurrentCulture, out var minutes)
            || minutes is < HushSettings.MinIdleTimeoutMinutes or > HushSettings.MaxIdleTimeoutMinutes)
        {
            MessageBox.Show(_owner, $"The idle timeout must be a whole number of minutes between {HushSettings.MinIdleTimeoutMinutes} and {HushSettings.MaxIdleTimeoutMinutes}.", "Hush", MessageBoxButton.OK, MessageBoxImage.Warning);
            return;
        }

        var saved = await Ui.TryAsync(_owner, async () =>
        {
            new HushSettings { IdleTimeoutMinutes = minutes, LockOnSleep = LockOnSleep.IsChecked == true, ScanRoots = [.. _roots] }.Save(_services.Paths);
            StartupRegistration.Set(StartWithWindows.IsChecked == true);
            await _services.Session.ReloadSettingsAsync(CancellationToken.None);
        });
        Saved.Text = saved ? "Saved." : string.Empty;
        await _owner.RefreshStateAsync();
    }
}
