using System.Text;
using System.Text.RegularExpressions;
using Hush.Core.Text;
using Hush.Core.Vault;

namespace Hush.Core.Migration;

/// <summary>Vault names for Git credentials: scope <c>git</c>, name <c>user@host</c> (sanitized).</summary>
public static class GitCredentialNames
{
    /// <summary>The scope that holds Git credentials.</summary>
    public const string Scope = "git";

    /// <summary>The vault reference for <paramref name="user"/> on <paramref name="host"/>.</summary>
    public static SecretRef For(string user, string host) => new(Scope, SecretRef.Sanitize($"{user}@{host.Replace(':', '_')}"));

    /// <summary>Splits a vault name back into user and host (the last '@' separates them).</summary>
    public static (string User, string Host)? Split(string name)
    {
        ArgumentNullException.ThrowIfNull(name);
        var at = name.LastIndexOf('@');
        return at <= 0 || at == name.Length - 1 ? null : (name[..at], name[(at + 1)..]);
    }
}

/// <summary>
/// <c>.npmrc</c>: each registry credential moves into the vault and is replaced with npm's documented
/// environment-variable expansion (<c>${NPM_TOKEN}</c>), so <c>hush run --secrets NPM_TOKEN -- npm ...</c> works.
/// </summary>
internal static partial class NpmrcMigrator
{
    public static FilePlan Plan(string path, string text, MigrationContext context)
    {
        var edits = new List<TextEdit>();
        var commands = new List<string>();
        foreach (Match match in AuthLine().Matches(text))
        {
            var value = match.Groups["value"].Value.Trim();
            if (value.StartsWith("${", StringComparison.Ordinal) || context.Detector.Rules.IsAllowlisted(value))
            {
                continue;
            }

            var host = match.Groups["host"].Success ? match.Groups["host"].Value : "registry.npmjs.org";
            var kind = match.Groups["kind"].Value.ToLowerInvariant() switch
            {
                "authtoken" => "TOKEN",
                "auth" => "AUTH",
                _ => "PASSWORD",
            };
            var variable = host.Equals("registry.npmjs.org", StringComparison.OrdinalIgnoreCase)
                ? $"NPM_{kind}"
                : $"NPM_{kind}_{Regex.Replace(host.ToUpperInvariant(), "[^A-Z0-9]+", "_").Trim('_')}";
            var reference = context.Names.Allocate(string.Empty, variable, value, $"{path} ({host} _{match.Groups["kind"].Value})");
            var group = match.Groups["value"];
            edits.Add(new TextEdit(group.Index, group.Index + group.Value.TrimEnd().Length, "${" + variable + "}"));
            commands.Add($"hush run --secrets {McpJsonMigrator.Spec(variable, reference)} -- npm publish   # or any npm command that needs {host}");
        }

        if (edits.Count == 0)
        {
            return FilePlan.None;
        }

        return new FilePlan(
            new FileChange(path, text, TextEdits.Apply(text, edits), "Replace registry tokens with ${VAR} references that npm expands from the environment."),
            ["npm reports an error when a ${VAR} used in .npmrc is not set, so run npm commands that read this file through 'hush run'."],
            commands);
    }

    [GeneratedRegex(@"^[ \t]*(?://(?<host>[^/\s:]+)[^\s:]*:)?_(?<kind>authToken|auth|password)[ \t]*=[ \t]*(?<value>[^\r\n]+)", RegexOptions.Multiline | RegexOptions.IgnoreCase)]
    private static partial Regex AuthLine();
}

/// <summary>
/// <c>.pypirc</c>: passwords move into the vault and their lines are removed. twine reads
/// <c>TWINE_PASSWORD</c> from the environment.
/// </summary>
internal static class PypircMigrator
{
    public static FilePlan Plan(string path, string text, MigrationContext context)
    {
        var lines = text.Split('\n');
        var output = new StringBuilder();
        var commands = new List<string>();
        var section = string.Empty;
        var changed = false;
        foreach (var rawLine in lines.Select((l, i) => (Text: l, Index: i)))
        {
            var line = rawLine.Text.TrimEnd('\r').Trim();
            if (line.StartsWith('[') && line.EndsWith(']'))
            {
                section = line[1..^1].Trim();
            }
            else if (section.Length > 0 && line.StartsWith("password", StringComparison.OrdinalIgnoreCase))
            {
                var separator = line.IndexOfAny(['=', ':']);
                var value = separator > 0 ? line[(separator + 1)..].Trim() : string.Empty;
                if (separator > 0 && value.Length > 0 && !context.Detector.Rules.IsAllowlisted(value))
                {
                    var variable = section.Equals("pypi", StringComparison.OrdinalIgnoreCase)
                        ? "TWINE_PASSWORD"
                        : $"TWINE_PASSWORD_{Regex.Replace(section.ToUpperInvariant(), "[^A-Z0-9]+", "_").Trim('_')}";
                    var reference = context.Names.Allocate(string.Empty, variable, value, $"{path} [{section}] password");
                    var repository = section.Equals("pypi", StringComparison.OrdinalIgnoreCase) ? string.Empty : $" -r {section}";
                    commands.Add($"hush run --secrets {McpJsonMigrator.Spec("TWINE_PASSWORD", reference)} -- twine upload{repository} dist/*");
                    changed = true;
                    continue;
                }
            }

            output.Append(rawLine.Text);
            if (rawLine.Index < lines.Length - 1)
            {
                output.Append('\n');
            }
        }

        return changed
            ? new FilePlan(new FileChange(path, text, output.ToString(), "Remove index passwords; twine reads TWINE_PASSWORD from the environment."), [], commands)
            : FilePlan.None;
    }
}

/// <summary>
/// <c>.git-credentials</c>: each stored credential moves into the vault (scope <c>git</c>) and its line is
/// removed. <c>hush git-helper</c> then serves them through Git's credential-helper protocol.
/// </summary>
internal static partial class GitCredentialsMigrator
{
    public static FilePlan Plan(string path, string text, MigrationContext context)
    {
        var lines = text.Split('\n');
        var kept = new List<string>();
        var moved = 0;
        foreach (var raw in lines)
        {
            var match = CredentialLine().Match(raw.TrimEnd('\r'));
            if (!match.Success)
            {
                kept.Add(raw);
                continue;
            }

            var user = Uri.UnescapeDataString(match.Groups["user"].Value);
            var password = Uri.UnescapeDataString(match.Groups["password"].Value);
            var host = match.Groups["host"].Value;
            var preferred = GitCredentialNames.For(user, host);
            context.Names.Allocate(preferred.Scope, preferred.Name, password, $"{path} ({user}@{host})");
            moved++;
        }

        if (moved == 0)
        {
            return FilePlan.None;
        }

        var updated = string.Join('\n', kept);
        return new FilePlan(
            new FileChange(path, text, updated, $"Move {moved} stored Git credential(s) into the vault."),
            ["If 'git config --get-all credential.helper' lists 'store', remove it, or Git will write .git-credentials again."],
            ["git config --global --unset-all credential.helper store", "git config --global --add credential.helper \"hush git-helper\""]);
    }

    [GeneratedRegex(@"^\s*https?://(?<user>[^:@/\s]+):(?<password>[^@\s]+)@(?<host>[^/\s]+)\S*\s*$")]
    private static partial Regex CredentialLine();
}
