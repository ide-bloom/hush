using Hush.Core.Scanning;

namespace Hush.Core.Migration;

/// <summary>Turns scan results into a <see cref="MigrationPlan"/> without changing anything on disk.</summary>
public sealed class MigrationPlanner
{
    private readonly MigrationContext _context;

    /// <summary>Creates a planner.</summary>
    public MigrationPlanner(MigrationContext context) => _context = context;

    /// <summary>
    /// Plans a migration for the files in <paramref name="scan"/>: every MCP config, plus .env and credential
    /// files that had findings. Files Hush cannot rewrite safely get a note instead.
    /// </summary>
    public MigrationPlan Plan(ScanResult scan)
    {
        ArgumentNullException.ThrowIfNull(scan);
        var withFindings = scan.Findings.Where(f => f.Kind == FindingKind.InlineSecret).Select(f => f.FilePath).ToHashSet(StringComparer.OrdinalIgnoreCase);
        var plans = new List<FilePlan>();

        foreach (var file in scan.Files.Where(f => f.Kind == LocationKind.McpConfig && f.Mcp is not null).OrderBy(f => f.Path, StringComparer.OrdinalIgnoreCase))
        {
            var text = File.ReadAllText(file.Path);
            plans.Add(file.Mcp == McpFormat.CodexToml
                ? CodexTomlMigrator.Plan(file.Path, text, _context)
                : McpJsonMigrator.Plan(file.Path, text, file.Mcp!.Value, _context));
        }

        var envGroups = scan.Files
            .Where(f => f.Kind == LocationKind.DotEnv && withFindings.Contains(f.Path) && !Scanner.IsDotEnvTemplate(Path.GetFileName(f.Path)))
            .GroupBy(f => Path.GetDirectoryName(f.Path)!, StringComparer.OrdinalIgnoreCase)
            .OrderBy(g => g.Key, StringComparer.OrdinalIgnoreCase);
        foreach (var group in envGroups)
        {
            plans.AddRange(DotEnvMigrator.Plan(group.Key, group.Select(f => f.Path).ToList(), _context));
        }

        foreach (var file in scan.Files.Where(f => f.Kind == LocationKind.CredentialFile && withFindings.Contains(f.Path)))
        {
            var name = Path.GetFileName(file.Path).ToLowerInvariant();
            var text = File.ReadAllText(file.Path);
            plans.Add(name switch
            {
                ".npmrc" => NpmrcMigrator.Plan(file.Path, text, _context),
                ".pypirc" => PypircMigrator.Plan(file.Path, text, _context),
                ".git-credentials" => GitCredentialsMigrator.Plan(file.Path, text, _context),
                _ => new FilePlan(null, [$"{file.Path}: Hush cannot rewrite this file safely. Rotate the credential with its issuer and configure the tool to read it from an environment variable via 'hush run'."], []),
            });
        }

        foreach (var path in withFindings)
        {
            var file = scan.Files.FirstOrDefault(f => string.Equals(f.Path, path, StringComparison.OrdinalIgnoreCase));
            if (file?.Kind is LocationKind.ShellHistory)
            {
                plans.Add(new FilePlan(null, [$"{path}: shell history contains secrets. Rotate them, then remove those lines (or delete the file) and use 'hush set' instead of pasting secrets into commands."], []));
            }
            else if (file?.Kind is LocationKind.EditorSettings or LocationKind.Other)
            {
                plans.Add(new FilePlan(null, [$"{path}: contains secrets Hush does not rewrite automatically. Move them with 'hush set NAME' and reference them from the environment."], []));
            }
        }

        return new MigrationPlan(
            plans.Where(p => p.Change is not null).Select(p => p.Change!).ToList(),
            _context.Names.Secrets,
            plans.SelectMany(p => p.Notes).Distinct().ToList(),
            plans.SelectMany(p => p.Commands).Distinct().ToList());
    }
}
