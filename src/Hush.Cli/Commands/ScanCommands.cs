using System.Text;
using Hush.Cli.Terminal;
using Hush.Core;
using Hush.Core.Migration;
using Hush.Core.Protocol;
using Hush.Core.Scanning;
using Hush.Core.Settings;
using Hush.Core.Vault;

namespace Hush.Cli.Commands;

/// <summary><c>hush scan</c> and <c>hush migrate</c>.</summary>
internal static class ScanCommands
{
    /// <summary>Exit code for <c>hush scan --exit-code</c> when findings exist.</summary>
    public const int FindingsExitCode = 3;

    public static async Task<int> ScanAsync(CliServices s, IReadOnlyList<string> paths, bool json, bool sarif, string? output, bool noDefaults, bool exitCode, CancellationToken ct)
    {
        if (json && sarif)
        {
            throw new HushException(HushErrorCode.InvalidInput, "Choose either --json or --sarif.");
        }

        var result = RunScan(s, paths, noDefaults, ct);
        string text;
        if (json)
        {
            text = Reports.ToJson(result);
        }
        else if (sarif)
        {
            text = Reports.ToSarif(result, s.WorkingDirectory);
        }
        else
        {
            var builder = new StringWriter();
            WriteTable(s.Terminal, builder, result, color: output is null);
            text = builder.ToString();
        }

        if (output is not null)
        {
            await File.WriteAllTextAsync(output, text, new UTF8Encoding(false), ct).ConfigureAwait(false);
            s.Terminal.Error.WriteLine($"Wrote {Path.GetFullPath(output)} ({result.Findings.Count} finding(s)).");
        }
        else
        {
            s.Terminal.Out.Write(text);
        }

        return exitCode && result.Findings.Count > 0 ? FindingsExitCode : 0;
    }

    public static async Task<int> MigrateAsync(CliServices s, IReadOnlyList<string> paths, bool dryRun, bool undo, bool yes, bool force, bool noDefaults, CancellationToken ct)
    {
        var t = s.Terminal;
        var executor = new MigrationExecutor(s.Paths);
        var sink = new SessionSecretSink(s.Session);
        if (undo)
        {
            var result = await executor.UndoAsync(sink, force, ct).ConfigureAwait(false);
            t.Out.WriteLine($"Undid the migration from {Path.GetFileName(result.BackupDirectory)}:");
            foreach (var file in result.Restored)
            {
                t.Out.WriteLine($"  restored  {file}");
            }

            foreach (var file in result.Deleted)
            {
                t.Out.WriteLine($"  deleted   {file}");
            }

            if (result.RemovedSecrets.Count > 0)
            {
                t.Out.WriteLine($"  removed {result.RemovedSecrets.Count} secret(s) from the vault: {string.Join(", ", result.RemovedSecrets)}");
            }

            return 0;
        }

        if (!s.Manager.Exists && !dryRun)
        {
            throw new HushException(HushErrorCode.VaultNotFound, "Create a vault first with 'hush init' (or preview with 'hush migrate --dry-run').");
        }

        var existing = s.Manager.Exists
            ? s.Manager.ReadDocument().Entries.Select(e => new SecretRef(e.Scope, e.Name)).ToHashSet()
            : [];
        var scan = RunScan(s, paths, noDefaults, ct);
        var context = new MigrationContext(SecretDetector.Default, new SecretNameAllocator(r => existing.Contains(r)), s.HushCommand);
        var plan = new MigrationPlanner(context).Plan(scan);

        if (plan.IsEmpty)
        {
            t.Out.WriteLine("Nothing to migrate.");
            WriteNotes(t, plan);
            return 0;
        }

        WriteSummary(t, plan);
        if (dryRun)
        {
            t.Out.WriteLine();
            t.Out.WriteLine(t.Bold("Diff (secret values redacted):"));
            WriteDiff(t, plan.RenderDiff());
            t.Out.WriteLine(t.Dim("Dry run: nothing was changed. Run 'hush migrate' to apply."));
            return 0;
        }

        if (!yes)
        {
            if (!t.CanPrompt)
            {
                throw new HushException(HushErrorCode.InvalidInput, "Pass --yes to apply without a confirmation prompt (or --dry-run to preview).");
            }

            if (!t.Confirm("Apply these changes? Originals are backed up and 'hush migrate --undo' restores them."))
            {
                return 1;
            }
        }

        var backup = await executor.ApplyAsync(plan, sink, ct).ConfigureAwait(false);
        t.Out.WriteLine(t.Green($"Migrated {plan.Secrets.Count} secret(s) and updated {plan.Changes.Count} file(s)."));
        t.Out.WriteLine(t.Dim($"Backups: {backup}"));
        if (plan.Commands.Count > 0)
        {
            t.Out.WriteLine();
            t.Out.WriteLine(t.Bold("Use them with:"));
            foreach (var command in plan.Commands)
            {
                t.Out.WriteLine("  " + command);
            }
        }

        t.Out.WriteLine();
        t.Out.WriteLine("Restart any MCP clients you migrated so they pick up the new configuration.");
        return 0;
    }

    private static ScanResult RunScan(CliServices s, IReadOnlyList<string> paths, bool noDefaults, CancellationToken ct)
    {
        var settings = HushSettings.Load(s.Paths);
        var scanner = new Scanner(SecretDetector.Default, s.ScanEnvironment);
        var resolved = paths.Select(p => Path.GetFullPath(Path.Combine(s.WorkingDirectory, p))).ToList();
        return scanner.Scan(new ScanOptions(resolved, noDefaults ? [] : settings.ScanRoots, IncludeDefaultLocations: !noDefaults), ct);
    }

    internal static void WriteTable(ITerminal t, TextWriter output, ScanResult result, bool color)
    {
        string Paint(Func<ITerminal, string, string> style, string text) => color ? style(t, text) : text;

        var inline = result.BySeverity.Where(f => f.Kind == FindingKind.InlineSecret).ToList();
        var tokens = result.BySeverity.Where(f => f.Kind == FindingKind.ToolTokenFile).ToList();
        output.WriteLine($"Scanned {result.Files.Count} file(s): {inline.Count} plaintext secret(s), {tokens.Count} tool token file(s).");
        foreach (var group in inline.GroupBy(f => f.Risk).OrderByDescending(g => g.Key))
        {
            output.WriteLine();
            var header = $"{group.Key.ToString().ToUpperInvariant()} ({group.Count()})";
            output.WriteLine(group.Key switch
            {
                Risk.Critical or Risk.High => Paint(Style.Red, header),
                Risk.Medium => Paint(Style.Yellow, header),
                _ => Paint(Style.Dim, header),
            });
            foreach (var f in group)
            {
                output.WriteLine($"  {Paint(Style.Bold, $"{f.Provider} {f.SecretType}")}  {f.Prefix}••••  [{Reports.Name(f.Confidence)} confidence]");
                output.WriteLine($"    {f.FilePath}:{f.Line}{(f.Client is null ? string.Empty : $"  ({f.Client})")}");
                output.WriteLine(Paint(Style.Dim, $"    {f.RiskNote}"));
            }
        }

        if (tokens.Count > 0)
        {
            output.WriteLine();
            output.WriteLine(Paint(Style.Cyan, $"TOKEN FILES OWNED BY OTHER TOOLS ({tokens.Count}): not migratable, review and keep sessions short"));
            foreach (var f in tokens)
            {
                output.WriteLine($"  {Paint(Style.Bold, f.Provider)}  {f.FilePath}");
                output.WriteLine(Paint(Style.Dim, $"    {f.RiskNote}"));
            }
        }

        if (result.Errors.Count > 0)
        {
            output.WriteLine();
            output.WriteLine(Paint(Style.Dim, $"Could not read {result.Errors.Count} file(s):"));
            foreach (var error in result.Errors)
            {
                output.WriteLine(Paint(Style.Dim, "  " + error));
            }
        }

        if (inline.Count > 0)
        {
            output.WriteLine();
            output.WriteLine("Next: 'hush migrate --dry-run' to preview moving these into the vault.");
        }
    }

    private static void WriteSummary(ITerminal t, MigrationPlan plan)
    {
        t.Out.WriteLine(t.Bold($"{plan.Secrets.Count} secret(s) will move into the vault:"));
        foreach (var secret in plan.Secrets)
        {
            t.Out.WriteLine($"  {secret.Target,-36} {MigrationPlan.RedactValue(secret.Value),-10} {t.Dim(secret.Source)}");
        }

        t.Out.WriteLine();
        t.Out.WriteLine(t.Bold($"{plan.Changes.Count} file(s) will change:"));
        foreach (var change in plan.Changes)
        {
            t.Out.WriteLine($"  {(change.Original is null ? "create" : "modify")}  {change.Path}");
            t.Out.WriteLine(t.Dim($"          {change.Description}"));
        }

        WriteNotes(t, plan);
    }

    private static void WriteNotes(ITerminal t, MigrationPlan plan)
    {
        if (plan.Notes.Count == 0)
        {
            return;
        }

        t.Out.WriteLine();
        t.Out.WriteLine(t.Bold("Notes:"));
        foreach (var note in plan.Notes)
        {
            t.Out.WriteLine(t.Yellow("  ! ") + note);
        }
    }

    private static void WriteDiff(ITerminal t, string diff)
    {
        foreach (var line in diff.Split('\n'))
        {
            if (line.Length == 0)
            {
                continue;
            }

            t.Out.WriteLine(line[0] switch
            {
                '+' when !line.StartsWith("+++", StringComparison.Ordinal) => t.Green(line),
                '-' when !line.StartsWith("---", StringComparison.Ordinal) => t.Red(line),
                '@' => t.Cyan(line),
                _ => line,
            });
        }
    }
}
