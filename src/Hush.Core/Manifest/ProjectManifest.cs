using System.Text;
using Hush.Core.Text;
using Hush.Core.Vault;
using Tomlyn;
using Tomlyn.Model;
using Tomlyn.Parsing;

namespace Hush.Core.Manifest;

/// <summary>One environment variable and the vault secret that fills it.</summary>
/// <param name="Variable">Environment variable name.</param>
/// <param name="Secret">Vault reference.</param>
/// <param name="FallbackToGlobal">If the scoped secret is missing, use the global secret of the same name.</param>
public sealed record EnvBinding(string Variable, SecretRef Secret, bool FallbackToGlobal);

/// <summary>
/// A parsed <c>.hush.toml</c>. It holds names and mappings only, never values, so it is safe to commit.
/// </summary>
/// <example>
/// <code>
/// version = 1
/// project = "myapp"
/// default_profile = "dev"
///
/// [env]
/// DATABASE_URL = "DATABASE_URL"          # myapp/DATABASE_URL, falling back to global DATABASE_URL
/// OPENAI_API_KEY = "/OPENAI_API_KEY"     # explicitly global
///
/// [profiles.staging.env]
/// DATABASE_URL = "DATABASE_URL_STAGING"
/// </code>
/// </example>
public sealed record ProjectManifest(
    string FilePath,
    string Project,
    string? DefaultProfile,
    IReadOnlyDictionary<string, string> Env,
    IReadOnlyDictionary<string, IReadOnlyDictionary<string, string>> Profiles)
{
    /// <summary>The manifest file name.</summary>
    public const string FileName = ".hush.toml";

    /// <summary>
    /// Returns the bindings for <paramref name="profile"/> (or the default profile): the base <c>[env]</c>
    /// table overlaid with <c>[profiles.NAME.env]</c>.
    /// </summary>
    public IReadOnlyList<EnvBinding> Resolve(string? profile)
    {
        var selected = profile ?? DefaultProfile;
        var merged = new Dictionary<string, string>(Env, StringComparer.OrdinalIgnoreCase);
        if (selected is not null)
        {
            if (Profiles.TryGetValue(selected, out var overlay))
            {
                foreach (var (variable, reference) in overlay)
                {
                    merged[variable] = reference;
                }
            }
            else if (profile is not null)
            {
                throw new HushException(
                    HushErrorCode.ManifestInvalid,
                    $"{FilePath} has no profile '{profile}'. Known profiles: {(Profiles.Count == 0 ? "(none)" : string.Join(", ", Profiles.Keys))}.");
            }
        }

        return merged.OrderBy(kv => kv.Key, StringComparer.OrdinalIgnoreCase).Select(kv => Bind(kv.Key, kv.Value)).ToList();
    }

    /// <summary>Interprets a reference string relative to this project's scope.</summary>
    public EnvBinding Bind(string variable, string reference)
    {
        ArgumentNullException.ThrowIfNull(reference);
        if (reference.StartsWith('/'))
        {
            return new EnvBinding(variable, SecretRef.Parse(reference[1..], string.Empty), false);
        }

        if (reference.Contains('/', StringComparison.Ordinal))
        {
            return new EnvBinding(variable, SecretRef.Parse(reference), false);
        }

        return new EnvBinding(variable, SecretRef.Parse(reference, Project), true);
    }

    /// <summary>Searches <paramref name="startDirectory"/> and its parents for a manifest.</summary>
    public static string? Locate(string startDirectory)
    {
        for (var directory = new DirectoryInfo(Path.GetFullPath(startDirectory)); directory is not null; directory = directory.Parent)
        {
            var candidate = Path.Combine(directory.FullName, FileName);
            if (File.Exists(candidate))
            {
                return candidate;
            }
        }

        return null;
    }

    /// <summary>Loads and validates a manifest file.</summary>
    public static ProjectManifest Load(string path) => Parse(File.ReadAllText(path), path);

    /// <summary>Parses manifest text.</summary>
    public static ProjectManifest Parse(string text, string path)
    {
        TomlTable table;
        try
        {
            table = TomlModel.Parse(text);
        }
        catch (TomlException ex)
        {
            throw new HushException(HushErrorCode.ManifestInvalid, $"{path} is not valid TOML: {ex.Message}", ex);
        }

        if (table.TryGetValue("version", out var version) && version is not 1L)
        {
            throw new HushException(HushErrorCode.ManifestInvalid, $"{path}: manifest 'version' must be 1.");
        }

        var project = table.TryGetValue("project", out var p) && p is string projectName && projectName.Length > 0
            ? projectName
            : SecretRef.Sanitize(Path.GetFileName(Path.GetDirectoryName(Path.GetFullPath(path))) ?? "default");
        if (!SecretRef.IsValidPart(project))
        {
            throw new HushException(HushErrorCode.ManifestInvalid, $"{path}: '{project}' is not a valid project name.");
        }

        var defaultProfile = table.TryGetValue("default_profile", out var dp) ? dp as string : null;
        var env = ReadEnvTable(table, "env", path);
        var profiles = new Dictionary<string, IReadOnlyDictionary<string, string>>(StringComparer.OrdinalIgnoreCase);
        if (table.TryGetValue("profiles", out var profilesValue))
        {
            if (profilesValue is not TomlTable profilesTable)
            {
                throw new HushException(HushErrorCode.ManifestInvalid, $"{path}: 'profiles' must be a table.");
            }

            foreach (var (name, value) in profilesTable)
            {
                if (value is not TomlTable profileTable)
                {
                    throw new HushException(HushErrorCode.ManifestInvalid, $"{path}: profile '{name}' must be a table.");
                }

                profiles[name] = ReadEnvTable(profileTable, "env", $"{path} [profiles.{name}]");
            }
        }

        var manifest = new ProjectManifest(path, project, defaultProfile, env, profiles);
        foreach (var profile in profiles.Keys.Append(null))
        {
            _ = manifest.Resolve(profile);
        }

        return manifest;
    }

    /// <summary>Text for a new manifest.</summary>
    public static string CreateText(string project, IEnumerable<KeyValuePair<string, string>> env)
    {
        ArgumentNullException.ThrowIfNull(env);
        var builder = new StringBuilder();
        builder.Append("# Hush project manifest: https://github.com/ide-bloom/hush\r\n");
        builder.Append("# Safe to commit. It names the secrets this project needs; the values live in your Hush vault.\r\n");
        builder.Append("# Run commands with them injected:  hush run -- <command>\r\n\r\n");
        builder.Append("version = 1\r\n");
        builder.Append("project = ").Append(Quote(project)).Append("\r\n\r\n");
        builder.Append("# ENV_VAR = \"SECRET\"        -> <project>/SECRET, falling back to the global SECRET\r\n");
        builder.Append("# ENV_VAR = \"/SECRET\"       -> the global SECRET only\r\n");
        builder.Append("# ENV_VAR = \"scope/SECRET\"  -> a secret in another scope\r\n");
        builder.Append("[env]\r\n");
        foreach (var (variable, reference) in env)
        {
            builder.Append(Key(variable)).Append(" = ").Append(Quote(reference)).Append("\r\n");
        }

        builder.Append("\r\n# Per-profile overrides, selected with 'hush run --profile staging':\r\n");
        builder.Append("# [profiles.staging.env]\r\n");
        builder.Append("# DATABASE_URL = \"DATABASE_URL_STAGING\"\r\n");
        return builder.ToString();
    }

    /// <summary>
    /// Adds mappings to existing manifest text without disturbing anything else: new keys go at the end
    /// of the table <paramref name="tableName"/> (<c>env</c> or <c>profiles.NAME.env</c>, created if missing);
    /// keys that already exist are left alone.
    /// </summary>
    public static string AddMappings(string existingText, string tableName, IEnumerable<KeyValuePair<string, string>> env)
    {
        ArgumentNullException.ThrowIfNull(existingText);
        ArgumentNullException.ThrowIfNull(tableName);
        ArgumentNullException.ThrowIfNull(env);
        var current = Parse(existingText, FileName);
        var existing = tableName == "env"
            ? current.Env
            : current.Profiles.TryGetValue(tableName.Split('.')[1], out var profile) ? profile : new Dictionary<string, string>();
        var additions = env.Where(kv => !existing.ContainsKey(kv.Key)).ToList();
        if (additions.Count == 0)
        {
            return existingText;
        }

        var newline = TextEdits.NewlineOf(existingText);
        var lines = string.Concat(additions.Select(kv => $"{Key(kv.Key)} = {Quote(kv.Value)}{newline}"));
        var document = SyntaxParser.Parse(existingText, FileName, false);
        var table = document.Tables.FirstOrDefault(t => t.Name?.ToString().Trim() == tableName);
        if (table is null)
        {
            var separator = existingText.Length == 0 || existingText.EndsWith('\n') ? newline : newline + newline;
            return existingText + separator + "[" + tableName + "]" + newline + lines;
        }

        var insertAt = table.Items.ChildrenCount > 0
            ? OffsetAfterLine(existingText, table.Items.GetChild(table.Items.ChildrenCount - 1)!.Span.End.Offset)
            : OffsetAfterLine(existingText, table.Span.Start.Offset);
        return existingText[..insertAt] + lines + existingText[insertAt..];
    }

    private static int OffsetAfterLine(string text, int offset)
    {
        var newline = text.IndexOf('\n', Math.Min(offset, text.Length));
        return newline < 0 ? text.Length : newline + 1;
    }

    private static Dictionary<string, string> ReadEnvTable(TomlTable parent, string key, string where)
    {
        var result = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        if (!parent.TryGetValue(key, out var value))
        {
            return result;
        }

        if (value is not TomlTable env)
        {
            throw new HushException(HushErrorCode.ManifestInvalid, $"{where}: '{key}' must be a table of ENV_VAR = \"SECRET\".");
        }

        foreach (var (variable, reference) in env)
        {
            if (reference is not string text || text.Length == 0)
            {
                throw new HushException(HushErrorCode.ManifestInvalid, $"{where}: '{variable}' must map to a secret name string.");
            }

            result[variable] = text;
        }

        return result;
    }

    private static string Key(string key) =>
        key.All(c => char.IsAsciiLetterOrDigit(c) || c is '_' or '-') ? key : Quote(key);

    private static string Quote(string value) => "\"" + value.Replace("\\", "\\\\", StringComparison.Ordinal).Replace("\"", "\\\"", StringComparison.Ordinal) + "\"";
}
