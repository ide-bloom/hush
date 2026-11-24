using System.Text;
using System.Text.RegularExpressions;
using Hush.Core.Scanning;
using Hush.Core.Text;
using Hush.Core.Vault;

namespace Hush.Core.Migration;

/// <summary>A secret that a migration will move into the vault.</summary>
/// <param name="Target">Vault name it will be stored under.</param>
/// <param name="Value">The plaintext value taken from the file.</param>
/// <param name="Source">Where it came from, for display (file and key).</param>
[Sensitive]
public sealed record PlannedSecret(SecretRef Target, [property: Sensitive] string Value, string Source);

/// <summary>A file a migration will create or rewrite.</summary>
/// <param name="Path">The file.</param>
/// <param name="Original">Current content, or null if the file will be created.</param>
/// <param name="Updated">New content.</param>
/// <param name="Description">What changes and why.</param>
public sealed record FileChange(string Path, string? Original, string Updated, string Description);

/// <summary>Everything one <c>hush migrate</c> run will do, computed without touching anything.</summary>
public sealed record MigrationPlan(
    IReadOnlyList<FileChange> Changes,
    IReadOnlyList<PlannedSecret> Secrets,
    IReadOnlyList<string> Notes,
    IReadOnlyList<string> Commands)
{
    /// <summary>True if there is nothing to do.</summary>
    public bool IsEmpty => Changes.Count == 0 && Secrets.Count == 0;

    /// <summary>
    /// A unified diff of every change, with each secret value replaced by its first four characters and
    /// <c>••••</c>, so a dry run is safe to paste into an issue.
    /// </summary>
    public string RenderDiff()
    {
        var builder = new StringBuilder();
        foreach (var change in Changes)
        {
            var before = change.Original is null ? null : Redact(change.Original);
            var after = Redact(change.Updated);
            builder.Append(UnifiedDiff.Create(change.Path, before, after));
        }

        return builder.ToString();
    }

    /// <summary>
    /// Replaces every planned secret value in <paramref name="text"/> with a redacted form, and also anything
    /// else the scanner recognizes (secrets Hush does not migrate, such as HTTP header credentials, can sit in
    /// a diff's context lines).
    /// </summary>
    public string Redact(string text)
    {
        ArgumentNullException.ThrowIfNull(text);
        var values = Secrets.Select(s => s.Value)
            .Concat(SecretDetector.Default.Detect("diff", text).Select(m => m.Value))
            .Where(v => v.Length >= 4)
            .Distinct(StringComparer.Ordinal)
            .OrderByDescending(v => v.Length);
        foreach (var value in values)
        {
            text = text.Replace(value, RedactValue(value), StringComparison.Ordinal);
        }

        return text;
    }

    /// <summary>The first four characters followed by <c>••••</c>.</summary>
    public static string RedactValue(string value)
    {
        ArgumentNullException.ThrowIfNull(value);
        return value.Length <= 4 ? "••••" : value[..4] + "••••";
    }
}

/// <summary>
/// Chooses vault names for migrated secrets: the same value found in several files gets one name; a name
/// already used in the vault or by a different value in this run gets a numeric suffix.
/// </summary>
public sealed class SecretNameAllocator
{
    private readonly Func<SecretRef, bool> _existsInVault;
    private readonly Dictionary<string, SecretRef> _byValue = new(StringComparer.Ordinal);
    private readonly HashSet<string> _taken = new(StringComparer.OrdinalIgnoreCase);
    private readonly List<PlannedSecret> _secrets = [];

    /// <summary>Creates an allocator that avoids names for which <paramref name="existsInVault"/> is true.</summary>
    public SecretNameAllocator(Func<SecretRef, bool> existsInVault) => _existsInVault = existsInVault;

    /// <summary>Secrets allocated so far.</summary>
    public IReadOnlyList<PlannedSecret> Secrets => _secrets;

    /// <summary>Returns the vault reference for <paramref name="value"/>, allocating one if needed.</summary>
    public SecretRef Allocate(string scope, string preferredName, string value, string source)
    {
        var valueKey = scope + "\0" + value;
        if (_byValue.TryGetValue(valueKey, out var existing))
        {
            return existing;
        }

        var baseName = SecretRef.Sanitize(preferredName);
        var candidate = new SecretRef(scope, baseName);
        for (var suffix = 2; _taken.Contains(candidate.ToString()) || _existsInVault(candidate); suffix++)
        {
            candidate = new SecretRef(scope, $"{baseName}_{suffix}");
        }

        _taken.Add(candidate.ToString());
        _byValue[valueKey] = candidate;
        _secrets.Add(new PlannedSecret(candidate, value, source));
        return candidate;
    }
}

/// <summary>Shared services for the format-specific migrators.</summary>
/// <param name="Detector">Secret detector, used to decide which values are secrets.</param>
/// <param name="Names">Name allocator for this run.</param>
/// <param name="HushCommand">How rewritten configs should invoke Hush (<c>hush</c>, or a full path).</param>
public sealed partial record MigrationContext(SecretDetector Detector, SecretNameAllocator Names, string HushCommand)
{
    /// <summary>
    /// True if an environment value should be vaulted: a detector rule matches, or the name looks secret and
    /// the value is not a placeholder or a reference to another variable.
    /// </summary>
    public bool IsSecret(string name, string value)
    {
        ArgumentNullException.ThrowIfNull(name);
        if (string.IsNullOrWhiteSpace(value) || Detector.Rules.IsAllowlisted(value) || value.Contains("${", StringComparison.Ordinal))
        {
            return false;
        }

        if (Detector.Detect("env", $"{name}={value}").Count > 0)
        {
            return true;
        }

        return value.Length >= 8 && SecretishName().IsMatch(name);
    }

    [GeneratedRegex("(?i)(KEY|TOKEN|SECRET|PASSWORD|PASSWD|PWD|CREDENTIAL|AUTH|PAT)")]
    private static partial Regex SecretishName();
}

/// <summary>What one file contributes to a plan.</summary>
internal sealed record FilePlan(FileChange? Change, IReadOnlyList<string> Notes, IReadOnlyList<string> Commands)
{
    public static FilePlan None { get; } = new(null, [], []);
}
