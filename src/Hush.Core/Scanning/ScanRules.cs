using System.Text.RegularExpressions;
using Hush.Core.Text;
using Tomlyn;
using Tomlyn.Model;

namespace Hush.Core.Scanning;

/// <summary>How sure the scanner is that a match is a real secret.</summary>
public enum Confidence
{
    /// <summary>Generic or entropy-based match.</summary>
    Low,

    /// <summary>Provider format matched but could not be fully validated.</summary>
    Medium,

    /// <summary>Provider format matched (and its checksum, when the format has one).</summary>
    High,
}

/// <summary>How bad exposure of the secret would be.</summary>
public enum Risk
{
    /// <summary>Limited impact.</summary>
    Low,

    /// <summary>Meaningful impact.</summary>
    Medium,

    /// <summary>Account or data compromise.</summary>
    High,

    /// <summary>Money, production data, or supply-chain compromise.</summary>
    Critical,
}

/// <summary>One detection rule from rules.toml.</summary>
public sealed record ScanRule(
    string Id,
    string Provider,
    string SecretType,
    Regex Pattern,
    IReadOnlyList<string> Keywords,
    Confidence Confidence,
    Risk Risk,
    string Note,
    string? Checksum,
    double? MinEntropy,
    Regex? PathFilter);

/// <summary>The rule set: provider rules plus the placeholder allowlist.</summary>
public sealed class RuleSet
{
    private static readonly TimeSpan RegexTimeout = TimeSpan.FromMilliseconds(250);

    private RuleSet(IReadOnlyList<ScanRule> rules, IReadOnlySet<string> allowValues, IReadOnlyList<Regex> allowPatterns)
    {
        Rules = rules;
        AllowValues = allowValues;
        AllowPatterns = allowPatterns;
    }

    /// <summary>The rules, in file order.</summary>
    public IReadOnlyList<ScanRule> Rules { get; }

    /// <summary>Exact placeholder values (case-insensitive).</summary>
    public IReadOnlySet<string> AllowValues { get; }

    /// <summary>Placeholder patterns.</summary>
    public IReadOnlyList<Regex> AllowPatterns { get; }

    /// <summary>The rules embedded in Hush.Core.</summary>
    public static RuleSet Embedded { get; } = LoadEmbedded();

    /// <summary>True if <paramref name="value"/> is a known placeholder.</summary>
    public bool IsAllowlisted(string value)
    {
        ArgumentNullException.ThrowIfNull(value);
        var trimmed = value.Trim().Trim('"', '\'');
        return AllowValues.Contains(trimmed) || AllowPatterns.Any(p => p.IsMatch(trimmed));
    }

    /// <summary>Parses rules from TOML text.</summary>
    public static RuleSet Parse(string toml)
    {
        TomlTable root;
        try
        {
            root = TomlModel.Parse(toml);
        }
        catch (TomlException ex)
        {
            throw new HushException(HushErrorCode.InvalidInput, $"The scanner rules are not valid TOML: {ex.Message}", ex);
        }

        var allowValues = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var allowPatterns = new List<Regex>();
        if (root.TryGetValue("allowlist", out var allow) && allow is TomlTable allowTable)
        {
            foreach (var v in Strings(allowTable, "values"))
            {
                allowValues.Add(v);
            }

            allowPatterns.AddRange(Strings(allowTable, "patterns").Select(p => new Regex(p, RegexOptions.CultureInvariant, RegexTimeout)));
        }

        var rules = new List<ScanRule>();
        var ids = new HashSet<string>(StringComparer.Ordinal);
        if (root.TryGetValue("rules", out var rulesValue) && rulesValue is TomlTableArray array)
        {
            foreach (var table in array)
            {
                var id = Required(table, "id");
                if (!ids.Add(id))
                {
                    throw new HushException(HushErrorCode.InvalidInput, $"Duplicate scanner rule id '{id}'.");
                }

                rules.Add(new ScanRule(
                    id,
                    Required(table, "provider"),
                    Required(table, "type"),
                    new Regex(Required(table, "pattern"), RegexOptions.CultureInvariant, RegexTimeout),
                    Strings(table, "keywords"),
                    Enum.Parse<Confidence>(Optional(table, "confidence") ?? "medium", ignoreCase: true),
                    Enum.Parse<Risk>(Optional(table, "risk") ?? "medium", ignoreCase: true),
                    Required(table, "note"),
                    Optional(table, "checksum"),
                    table.TryGetValue("min_entropy", out var e) ? Convert.ToDouble(e, System.Globalization.CultureInfo.InvariantCulture) : null,
                    Optional(table, "path_regex") is { } pathRegex ? new Regex(pathRegex, RegexOptions.CultureInvariant, RegexTimeout) : null));
            }
        }

        return new RuleSet(rules, allowValues, allowPatterns);
    }

    private static RuleSet LoadEmbedded()
    {
        using var stream = typeof(RuleSet).Assembly.GetManifestResourceStream("Hush.Core.Scanning.rules.toml")
            ?? throw new InvalidOperationException("The embedded scanner rules are missing.");
        using var reader = new StreamReader(stream);
        return Parse(reader.ReadToEnd());
    }

    private static string Required(TomlTable table, string key) =>
        Optional(table, key) ?? throw new HushException(HushErrorCode.InvalidInput, $"A scanner rule is missing '{key}'.");

    private static string? Optional(TomlTable table, string key) => table.TryGetValue(key, out var v) ? v as string : null;

    private static string[] Strings(TomlTable table, string key) =>
        table.TryGetValue(key, out var v) && v is TomlArray a ? a.OfType<string>().ToArray() : [];
}
