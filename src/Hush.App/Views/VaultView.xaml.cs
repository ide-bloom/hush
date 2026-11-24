using System.Windows;
using System.Windows.Controls;
using Hush.App.Dialogs;
using Hush.App.Infrastructure;

namespace Hush.App.Views;

/// <summary>Vault page: list, add, edit and delete secrets.</summary>
internal sealed partial class VaultView : UserControl, IPage
{
    private readonly AppServices _services;
    private readonly MainWindow _owner;
    private readonly VaultListModel _model;

    public VaultView(AppServices services, MainWindow owner)
    {
        _services = services;
        _owner = owner;
        _model = new VaultListModel(services.Manager);
        InitializeComponent();
    }

    public Task OnShownAsync() => ReloadAsync();

    /// <summary>Re-reads the vault unconditionally (after an edit made from this page).</summary>
    public Task ReloadAsync()
    {
        _model.Refresh(force: true);
        ApplyFilter();
        return Task.CompletedTask;
    }

    /// <summary>
    /// Picks up changes made by other processes, for example `hush set` in a terminal. Cheap when nothing changed:
    /// it compares the vault file's timestamp and size.
    /// </summary>
    public void RefreshIfChanged()
    {
        if (_model.Refresh())
        {
            ApplyFilter();
        }
    }

    private void ApplyFilter()
    {
        var selected = (Secrets.SelectedItem as SecretRow)?.Ref;
        var rows = _model.Filter(Filter.Text);
        Secrets.ItemsSource = rows;
        Secrets.SelectedItem = rows.FirstOrDefault(r => r.Ref == selected);
        Empty.Visibility = _model.Rows.Count == 0 ? Visibility.Visible : Visibility.Collapsed;
    }

    private void OnFilter(object sender, TextChangedEventArgs e) => ApplyFilter();

    private void OnSelection(object sender, SelectionChangedEventArgs e)
    {
        var selected = Secrets.SelectedItem is SecretRow;
        EditButton.IsEnabled = selected;
        DeleteButton.IsEnabled = selected;
    }

    private async void OnAdd(object sender, RoutedEventArgs e)
    {
        var dialog = new SecretDialog(_services, existing: null) { Owner = _owner };
        if (dialog.ShowDialog() == true)
        {
            await ReloadAsync();
        }
    }

    private async void OnEdit(object sender, RoutedEventArgs e)
    {
        if (Secrets.SelectedItem is not SecretRow row)
        {
            return;
        }

        var dialog = new SecretDialog(_services, row) { Owner = _owner };
        if (dialog.ShowDialog() == true)
        {
            await ReloadAsync();
        }
    }

    private async void OnDelete(object sender, RoutedEventArgs e)
    {
        if (Secrets.SelectedItem is not SecretRow row)
        {
            return;
        }

        var answer = MessageBox.Show(_owner, $"Delete {row.Ref} from the vault? This cannot be undone.", "Delete secret", MessageBoxButton.YesNo, MessageBoxImage.Warning, MessageBoxResult.No);
        if (answer != MessageBoxResult.Yes)
        {
            return;
        }

        if (await Ui.TryAsync(_owner, () => _services.Session.RemoveAsync(row.Ref, CancellationToken.None)))
        {
            await ReloadAsync();
            await _owner.RefreshStateAsync();
        }
    }
}
