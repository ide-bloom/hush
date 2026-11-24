using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;
using Hush.App.Dialogs;
using Hush.App.Infrastructure;
using Hush.Core.Migration;
using Hush.Core.Protocol;
using Hush.Core.Scanning;
using Hush.Core.Settings;
using Hush.Core.Vault;

namespace Hush.App.Views;

/// <summary>One finding in the scan list.</summary>
internal sealed class FindingRow(Finding finding) : Observable
{
    private bool _selected = finding.Kind == FindingKind.InlineSecret && finding.Risk >= Risk.Medium;

    public Finding Finding { get; } = finding;

    public bool CanMigrate => Finding.Kind == FindingKind.InlineSecret;

    public bool Selected
    {
        get => _selected && CanMigrate;
        set => Set(ref _selected, value);
    }

    public string RiskText => Finding.Kind == FindingKind.ToolTokenFile
        ? "Token files owned by other tools (review, not migratable)"
        : Finding.Risk switch
        {
            Risk.Critical => "Critical",
            Risk.High => "High",
            Risk.Medium => "Medium",
            _ => "Low",
        };

    public string Title => Finding.Kind == FindingKind.ToolTokenFile
        ? $"{Finding.Provider}: OAuth token file"
        : $"{Finding.Provider} {Finding.SecretType}  ·  {Finding.Prefix}••••  ·  {Reports.Name(Finding.Confidence)} confidence";

    public string Location => Finding.Line > 0 ? $"{Finding.FilePath}:{Finding.Line}" : Finding.FilePath;

    public string Note => Finding.RiskNote;
}

/// <summary>Scan page: run a scan, review findings by risk, preview and apply a migration.</summary>
internal sealed partial class ScanView : UserControl
{
    private readonly AppServices _services;
    private readonly MainWindow _owner;
    private ScanResult? _result;
    private List<FindingRow> _rows = [];

    public ScanView(AppServices services, MainWindow owner)
    {
        _services = services;
        _owner = owner;
        InitializeComponent();
    }

    private async void OnScan(object sender, RoutedEventArgs e)
    {
        ScanButton.IsEnabled = false;
        Summary.Text = "Scanning...";
        try
        {
            var settings = HushSettings.Load(_services.Paths);
            _result = await Task.Run(() => new Scanner().Scan(new ScanOptions([], settings.ScanRoots)));
            _rows = _result.BySeverity.Select(f => new FindingRow(f)).ToList();
            var source = (CollectionViewSource)FindResource("Grouped");
            source.Source = _rows;
            Placeholder.Visibility = _rows.Count == 0 ? Visibility.Visible : Visibility.Collapsed;
            Placeholder.Text = "No plaintext secrets found in the scanned locations.";
            var inline = _rows.Count(r => r.CanMigrate);
            Summary.Text = $"{_result.Files.Count} files scanned · {inline} plaintext secret(s) · {_rows.Count - inline} token file(s)";
            MigrateButton.IsEnabled = inline > 0;
        }
        finally
        {
            ScanButton.IsEnabled = true;
        }
    }

    private async void OnPreview(object sender, RoutedEventArgs e)
    {
        if (_result is null)
        {
            return;
        }

        var selected = _rows.Where(r => r.Selected).Select(r => r.Finding).ToList();
        if (selected.Count == 0)
        {
            MessageBox.Show(_owner, "Select at least one finding to migrate.", "Hush", MessageBoxButton.OK, MessageBoxImage.Information);
            return;
        }

        if (!_services.Manager.Exists)
        {
            MessageBox.Show(_owner, "Create a vault first: run 'hush init' in a terminal.", "Hush", MessageBoxButton.OK, MessageBoxImage.Information);
            return;
        }

        // Migration works per file: every selected finding's file is migrated as a whole.
        var files = selected.Select(f => f.FilePath).ToHashSet(StringComparer.OrdinalIgnoreCase);
        var scoped = new ScanResult(selected, _result.Files.Where(f => files.Contains(f.Path)).ToList(), []);
        var existing = _services.Manager.ReadDocument().Entries.Select(x => new SecretRef(x.Scope, x.Name)).ToHashSet();
        var context = new MigrationContext(SecretDetector.Default, new SecretNameAllocator(existing.Contains), HushCommand());
        var plan = new MigrationPlanner(context).Plan(scoped);
        if (plan.IsEmpty)
        {
            MessageBox.Show(_owner, plan.Notes.Count > 0 ? string.Join(Environment.NewLine + Environment.NewLine, plan.Notes) : "Nothing to migrate in the selected files.", "Hush", MessageBoxButton.OK, MessageBoxImage.Information);
            return;
        }

        var preview = new MigrationPreviewWindow(plan) { Owner = _owner };
        if (preview.ShowDialog() != true)
        {
            return;
        }

        await Ui.TryAsync(_owner, async () =>
        {
            var backup = await new MigrationExecutor(_services.Paths).ApplyAsync(plan, new SessionSecretSink(_services.Session), CancellationToken.None);
            var commands = plan.Commands.Count > 0 ? Environment.NewLine + Environment.NewLine + "Use them with:" + Environment.NewLine + string.Join(Environment.NewLine, plan.Commands) : string.Empty;
            MessageBox.Show(_owner, $"Moved {plan.Secrets.Count} secret(s) into the vault and updated {plan.Changes.Count} file(s). Restart migrated MCP clients.{commands}{Environment.NewLine}{Environment.NewLine}Backups: {backup}", "Migration complete", MessageBoxButton.OK, MessageBoxImage.Information);
            OnScan(this, new RoutedEventArgs());
            await _owner.RefreshStateAsync();
        });
    }

    private async void OnUndo(object sender, RoutedEventArgs e)
    {
        var executor = new MigrationExecutor(_services.Paths);
        if (executor.LatestUndoable() is not { } latest)
        {
            MessageBox.Show(_owner, "There is no migration to undo.", "Hush", MessageBoxButton.OK, MessageBoxImage.Information);
            return;
        }

        var answer = MessageBox.Show(_owner, $"Restore {latest.Journal.Files.Count} file(s) from the migration on {latest.Journal.Created.ToLocalTime():g} and remove the {latest.Journal.Secrets.Count} secret(s) it added?", "Undo migration", MessageBoxButton.YesNo, MessageBoxImage.Question);
        if (answer != MessageBoxResult.Yes)
        {
            return;
        }

        await Ui.TryAsync(_owner, async () =>
        {
            var result = await executor.UndoAsync(new SessionSecretSink(_services.Session), force: false, CancellationToken.None);
            MessageBox.Show(_owner, $"Restored {result.Restored.Count} file(s), deleted {result.Deleted.Count}, removed {result.RemovedSecrets.Count} secret(s).", "Hush", MessageBoxButton.OK, MessageBoxImage.Information);
            await _owner.RefreshStateAsync();
        });
    }

    /// <summary>How rewritten MCP configs launch the hush.exe that sits next to the tray app.</summary>
    private static string HushCommand() => Core.Interop.HushCommand.For(Path.Combine(AppContext.BaseDirectory, InstallManifest.CliExecutable));
}
