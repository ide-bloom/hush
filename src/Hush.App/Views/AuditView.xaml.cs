using System.Globalization;
using System.Windows;
using System.Windows.Controls;
using Hush.App.Infrastructure;
using Hush.Core.Audit;

namespace Hush.App.Views;

/// <summary>One row of the audit table.</summary>
internal sealed record AuditRow(ulong Sequence, string Time, string Action, string Result, string Secrets, string Process, string Detail);

/// <summary>Audit page: filterable log and chain verification.</summary>
internal sealed partial class AuditView : UserControl, IPage
{
    private const string AllActions = "All actions";
    private readonly AppServices _services;
    private readonly MainWindow _owner;
    private List<AuditRow> _rows = [];

    public AuditView(AppServices services, MainWindow owner)
    {
        _services = services;
        _owner = owner;
        InitializeComponent();
    }

    public Task OnShownAsync()
    {
        Load();
        return Task.CompletedTask;
    }

    private void Load()
    {
        var records = new AuditLog(_services.Paths.AuditLog).ReadAll();
        _rows = records.AsEnumerable().Reverse().Select(r => new AuditRow(
            r.Sequence,
            r.Timestamp.ToLocalTime().ToString("yyyy-MM-dd HH:mm:ss", CultureInfo.InvariantCulture),
            r.Action,
            r.Result,
            string.Join(", ", r.Secrets),
            Describe(r),
            (r.Detail ?? string.Empty) + (r.Deferred ? " [deferred]" : string.Empty))).ToList();

        var selected = ActionFilter.SelectedItem as string;
        ActionFilter.ItemsSource = new[] { AllActions }.Concat(_rows.Select(r => r.Action).Distinct(StringComparer.Ordinal).Order(StringComparer.Ordinal)).ToList();
        ActionFilter.SelectedItem = selected ?? AllActions;
        ApplyFilter();
    }

    private void ApplyFilter()
    {
        var action = ActionFilter.SelectedItem as string;
        var text = TextFilter.Text.Trim();
        Entries.ItemsSource = _rows
            .Where(r => action is null or AllActions || r.Action == action)
            .Where(r => text.Length == 0
                || r.Secrets.Contains(text, StringComparison.OrdinalIgnoreCase)
                || r.Process.Contains(text, StringComparison.OrdinalIgnoreCase)
                || r.Detail.Contains(text, StringComparison.OrdinalIgnoreCase))
            .ToList();
    }

    private void OnFilterChanged(object sender, RoutedEventArgs e)
    {
        if (IsLoaded)
        {
            ApplyFilter();
        }
    }

    private void OnRefresh(object sender, RoutedEventArgs e) => Load();

    private async void OnVerify(object sender, RoutedEventArgs e)
    {
        await Ui.TryAsync(_owner, async () =>
        {
            var result = await _services.Session.VerifyAuditAsync(CancellationToken.None);
            Indicator.Visibility = Visibility.Visible;
            if (result.IsValid)
            {
                Indicator.Background = (System.Windows.Media.Brush)FindResource("SystemFillColorSuccessBackgroundBrush");
                IndicatorGlyph.Text = "";
                IndicatorText.Text = $"Chain intact · {result.EntryCount} entries" + (result.Warnings.Count > 0 ? $" · {result.Warnings.Count} warning(s)" : string.Empty);
                Problems.Visibility = result.Warnings.Count > 0 ? Visibility.Visible : Visibility.Collapsed;
                Problems.Text = string.Join(Environment.NewLine, result.Warnings);
            }
            else
            {
                Indicator.Background = (System.Windows.Media.Brush)FindResource("SystemFillColorCriticalBackgroundBrush");
                IndicatorGlyph.Text = "";
                IndicatorText.Text = $"Chain broken · {result.Problems.Count} problem(s)";
                Problems.Visibility = Visibility.Visible;
                Problems.Text = string.Join(Environment.NewLine, result.Problems);
            }

            Load();
            await _owner.RefreshStateAsync();
        });
    }

    private static string Describe(AuditRecord record)
    {
        var process = record.Process is null ? string.Empty : $"{Path.GetFileName(record.Process)} ({record.Pid})";
        var parent = record.ParentProcess is null ? string.Empty : $" ← {Path.GetFileName(record.ParentProcess)} ({record.ParentPid})";
        return process + parent;
    }
}
