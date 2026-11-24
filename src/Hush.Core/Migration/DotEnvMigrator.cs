using System.Text;
using Hush.Core.Manifest;
using Hush.Core.Text;
using Hush.Core.Vault;

namespace Hush.Core.Migration;

/// <summary>One <c>KEY=VALUE</c> assignment from a .env file.</summary>
public sealed record DotEnvEntry(string Key, [property: Sensitive] string Value, int Line);

/// <summary>
/// Moves the values of a project's <c>.env</c> files into the vault (scoped to the project), writes or
/// extends <c>.hush.toml</c>, replaces each .env with a comment-only stub, and makes sure .env is ignored by Git.
/// <c>.env</c> and <c>.env.local</c> map to the base <c>[env]</c> table; <c>.env.NAME</c> and
/// <c>.env.NAME.local</c> map to profile NAME.
/// </summary>
internal static class DotEnvMigrator
{
    public const string StubMarker = "# This project's secrets were moved into Hush";

    public static IReadOnlyList<FilePlan> Plan(string directory, IReadOnlyList<string> envFiles, MigrationContext context)
    {
        var plans = new List<FilePlan>();
        var manifestPath = ProjectManifest.Locate(directory) ?? Path.Combine(directory, ProjectManifest.FileName);
        var manifestExists = File.Exists(manifestPath);
        var manifestText = manifestExists ? File.ReadAllText(manifestPath) : null;
        var project = manifestText is not null
            ? ProjectManifest.Parse(manifestText, manifestPath).Project
            : SecretRef.Sanitize(Path.GetFileName(Path.GetFullPath(directory)));

        var baseMappings = new SortedDictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        var profileMappings = new SortedDictionary<string, SortedDictionary<string, string>>(StringComparer.OrdinalIgnoreCase);

        // .env first, then .env.local, so local overrides win like they do in dotenv loaders.
        foreach (var file in envFiles.OrderBy(f => Path.GetFileName(f).EndsWith(".local", StringComparison.OrdinalIgnoreCase)).ThenBy(f => f, StringComparer.OrdinalIgnoreCase))
        {
            var text = File.ReadAllText(file);
            if (text.Contains(StubMarker, StringComparison.Ordinal))
            {
                continue;
            }

            var entries = Parse(text).Where(e => e.Value.Length > 0).ToList();
            if (entries.Count == 0)
            {
                continue;
            }

            var profile = ProfileOf(Path.GetFileName(file));
            foreach (var entry in entries)
            {
                var preferred = profile is null ? entry.Key : $"{entry.Key}.{profile}";
                var reference = context.Names.Allocate(project, preferred, entry.Value, $"{file}:{entry.Line} ({entry.Key})");
                var target = profile is null ? baseMappings : (profileMappings.TryGetValue(profile, out var m) ? m : profileMappings[profile] = new(StringComparer.OrdinalIgnoreCase));
                target[entry.Key] = reference.Scope == project ? reference.Name : reference.ToString();
            }

            plans.Add(new FilePlan(
                new FileChange(file, text, Stub(Path.GetFileName(file), entries.Count, TextEdits.NewlineOf(text)), $"Move {entries.Count} value(s) into the vault (scope '{project}') and replace the file with a stub."),
                [],
                []));
        }

        if (plans.Count == 0)
        {
            return plans;
        }

        string updatedManifest;
        if (manifestText is null)
        {
            updatedManifest = ProjectManifest.CreateText(project, baseMappings);
            foreach (var (profile, mappings) in profileMappings)
            {
                updatedManifest = ProjectManifest.AddMappings(updatedManifest, $"profiles.{profile}.env", mappings);
            }
        }
        else
        {
            updatedManifest = ProjectManifest.AddMappings(manifestText, "env", baseMappings);
            foreach (var (profile, mappings) in profileMappings)
            {
                updatedManifest = ProjectManifest.AddMappings(updatedManifest, $"profiles.{profile}.env", mappings);
            }
        }

        if (!string.Equals(updatedManifest, manifestText, StringComparison.Ordinal))
        {
            plans.Add(new FilePlan(
                new FileChange(manifestPath, manifestText, updatedManifest, manifestText is null ? "Create the project manifest (names only, safe to commit)." : "Add the new mappings to the project manifest."),
                [],
                []));
        }

        var gitignore = GitignoreChange(directory);
        if (gitignore is not null)
        {
            plans.Add(new FilePlan(gitignore, [], []));
        }

        var profiles = profileMappings.Keys.ToList();
        var commands = new List<string> { $"cd \"{directory}\"", "hush run -- <your usual command, e.g. npm run dev>" };
        commands.AddRange(profiles.Select(p => $"hush run --profile {p} -- <command>"));
        plans.Add(new FilePlan(null, [], commands));
        return plans;
    }

    /// <summary>Parses .env syntax: comments, <c>export</c>, single/double quotes, multi-line double-quoted values.</summary>
    public static IReadOnlyList<DotEnvEntry> Parse(string text)
    {
        ArgumentNullException.ThrowIfNull(text);
        var entries = new List<DotEnvEntry>();
        var lines = text.Replace("\r\n", "\n", StringComparison.Ordinal).Split('\n');
        for (var i = 0; i < lines.Length; i++)
        {
            var line = lines[i].Trim();
            if (line.Length == 0 || line.StartsWith('#'))
            {
                continue;
            }

            if (line.StartsWith("export ", StringComparison.Ordinal))
            {
                line = line[7..].TrimStart();
            }

            var equals = line.IndexOf('=', StringComparison.Ordinal);
            if (equals <= 0)
            {
                continue;
            }

            var key = line[..equals].Trim();
            if (!key.All(c => char.IsAsciiLetterOrDigit(c) || c is '_' or '.' or '-'))
            {
                continue;
            }

            var startLine = i + 1;
            var rest = line[(equals + 1)..].TrimStart();
            string value;
            if (rest.StartsWith('"'))
            {
                var builder = new StringBuilder();
                var body = rest[1..];
                while (true)
                {
                    var close = FindClosingQuote(body);
                    if (close >= 0)
                    {
                        builder.Append(body[..close]);
                        break;
                    }

                    builder.Append(body).Append('\n');
                    if (++i >= lines.Length)
                    {
                        break;
                    }

                    body = lines[i];
                }

                value = Unescape(builder.ToString());
            }
            else if (rest.StartsWith('\''))
            {
                var close = rest.IndexOf('\'', 1);
                value = close > 0 ? rest[1..close] : rest[1..];
            }
            else
            {
                var comment = rest.IndexOf(" #", StringComparison.Ordinal);
                value = (comment >= 0 ? rest[..comment] : rest).Trim();
            }

            entries.Add(new DotEnvEntry(key, value, startLine));
        }

        return entries;
    }

    /// <summary><c>.env</c>/<c>.env.local</c> → null (base); <c>.env.staging[.local]</c> → "staging".</summary>
    public static string? ProfileOf(string fileName)
    {
        ArgumentNullException.ThrowIfNull(fileName);
        var parts = fileName.Split('.', StringSplitOptions.RemoveEmptyEntries);
        var meaningful = parts.Skip(1).Where(p => !p.Equals("local", StringComparison.OrdinalIgnoreCase)).ToList();
        return meaningful.Count == 0 ? null : SecretRef.Sanitize(meaningful[0].ToLowerInvariant());
    }

    private static string Stub(string fileName, int count, string newline) => string.Join(newline,
        $"{StubMarker} (https://github.com/ide-bloom/hush).",
        $"# {count} value(s) from this {fileName} are now in your encrypted, TPM-bound vault.",
        "# Run commands through Hush to get them as environment variables:",
        "#   hush run -- <command>",
        "# The variable-to-secret mapping is in .hush.toml. 'hush migrate --undo' restores the original file.",
        string.Empty);

    private static FileChange? GitignoreChange(string directory)
    {
        var root = directory;
        for (var current = new DirectoryInfo(directory); current is not null; current = current.Parent)
        {
            if (Directory.Exists(Path.Combine(current.FullName, ".git")) || File.Exists(Path.Combine(current.FullName, ".git")))
            {
                root = current.FullName;
                break;
            }
        }

        var path = Path.Combine(root, ".gitignore");
        var existing = File.Exists(path) ? File.ReadAllText(path) : null;
        var covered = (existing ?? string.Empty).Split('\n').Select(l => l.Trim()).Any(l => l is ".env" or "/.env" or ".env*" or "*.env" or "**/.env");
        if (covered)
        {
            return null;
        }

        var newline = existing is null ? "\n" : TextEdits.NewlineOf(existing);
        var prefix = existing is null || existing.Length == 0 || existing.EndsWith('\n') ? string.Empty : newline;
        var block = $"{prefix}{(existing is { Length: > 0 } ? newline : string.Empty)}# Local env files (values live in Hush; see .hush.toml){newline}.env{newline}.env.*{newline}!.env.example{newline}";
        return new FileChange(path, existing, (existing ?? string.Empty) + block, "Make sure .env files are never committed.");
    }

    private static int FindClosingQuote(string text)
    {
        for (var i = 0; i < text.Length; i++)
        {
            if (text[i] == '\\')
            {
                i++;
            }
            else if (text[i] == '"')
            {
                return i;
            }
        }

        return -1;
    }

    private static string Unescape(string text) => text
        .Replace("\\n", "\n", StringComparison.Ordinal)
        .Replace("\\r", "\r", StringComparison.Ordinal)
        .Replace("\\t", "\t", StringComparison.Ordinal)
        .Replace("\\\"", "\"", StringComparison.Ordinal)
        .Replace("\\\\", "\\", StringComparison.Ordinal);
}
