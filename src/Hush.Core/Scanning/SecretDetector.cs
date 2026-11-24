using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;

namespace Hush.Core.Scanning;

/// <summary>A raw match, including the secret value. Never leaves the process; reports use <see cref="Finding"/>.</summary>
/// <param name="Rule">The rule that matched.</param>
/// <param name="Line">1-based line number.</param>
/// <param name="Column">1-based column of the secret.</param>
/// <param name="Value">The matched secret.</param>
/// <param name="Confidence">Confidence after checksum and entropy adjustments.</param>
[Sensitive]
public sealed record SecretMatch(ScanRule Rule, int Line, int Column, [property: Sensitive] string Value, Confidence Confidence)
{
    /// <summary>The first four characters, which is all Hush ever displays.</summary>
    public string Prefix => Value.Length <= 4 ? new string('•', Value.Length) : Value[..4];

    /// <summary>Stable, non-reversible identifier for this secret at this place.</summary>
    public string Fingerprint(string filePath)
    {
        var input = Encoding.UTF8.GetBytes($"{Rule.Id}\n{filePath.ToUpperInvariant()}\n{Value}");
        return Convert.ToHexStringLower(SHA256.HashData(input))[..24];
    }
}

/// <summary>
/// Runs rules over text, line by line: keyword prefilter, regex, placeholder allowlist, entropy floor,
/// checksum validation. Provider rules come first in rules.toml; a later (generic) rule never reports a
/// span an earlier rule already reported.
/// </summary>
public sealed class SecretDetector
{
    private const int MaxLineLength = 64 * 1024;
    private readonly RuleSet _rules;

    /// <summary>Creates a detector for <paramref name="rules"/>.</summary>
    public SecretDetector(RuleSet rules) => _rules = rules;

    /// <summary>The embedded rules.</summary>
    public static SecretDetector Default { get; } = new(RuleSet.Embedded);

    /// <summary>The rule set.</summary>
    public RuleSet Rules => _rules;

    /// <summary>
    /// Finds secrets in <paramref name="content"/>, read from <paramref name="filePath"/>. Lines a rule could not
    /// finish within its regex timeout are reported in <paramref name="problems"/>, so a skipped line is never silent.
    /// </summary>
    public IReadOnlyList<SecretMatch> Detect(string filePath, string content, ICollection<string>? problems = null)
    {
        ArgumentNullException.ThrowIfNull(content);
        var rules = _rules.Rules.Where(r => r.PathFilter is null || r.PathFilter.IsMatch(filePath)).ToList();
        var matches = new List<SecretMatch>();
        var lineNumber = 0;
        foreach (var rawLine in content.Split('\n'))
        {
            lineNumber++;
            var line = rawLine.TrimEnd('\r');
            if (line.Length == 0)
            {
                continue;
            }

            if (line.Length > MaxLineLength)
            {
                problems?.Add($"{filePath}:{lineNumber}: line longer than {MaxLineLength / 1024} KiB was not scanned.");
                continue;
            }

            var covered = new List<(int Start, int End)>();
            foreach (var rule in rules)
            {
                if (rule.Keywords.Count > 0 && !rule.Keywords.Any(k => line.Contains(k, StringComparison.OrdinalIgnoreCase)))
                {
                    continue;
                }

                MatchCollection found;
                try
                {
                    found = rule.Pattern.Matches(line);
                    _ = found.Count;
                }
                catch (RegexMatchTimeoutException)
                {
                    problems?.Add($"{filePath}:{lineNumber}: rule '{rule.Id}' timed out; this line was not fully scanned.");
                    continue;
                }

                foreach (Match match in found)
                {
                    var group = match.Groups["secret"];
                    var secret = group.Success ? group : (Group)match;
                    var value = secret.Value;
                    var start = secret.Index;
                    var end = secret.Index + secret.Length;
                    if (covered.Any(c => start < c.End && c.Start < end))
                    {
                        continue;
                    }

                    var confidence = Assess(rule, value);
                    if (confidence is null)
                    {
                        continue;
                    }

                    covered.Add((start, end));
                    matches.Add(new SecretMatch(rule, lineNumber, start + 1, value, confidence.Value));
                }
            }
        }

        return matches;
    }

    private Confidence? Assess(ScanRule rule, string value)
    {
        if (_rules.IsAllowlisted(value))
        {
            return null;
        }

        if (rule.MinEntropy is { } floor && Checksums.Entropy(value) < floor)
        {
            return null;
        }

        return Checksums.Validate(rule.Checksum, value) switch
        {
            true => Confidence.High,
            false when rule.Checksum == "jwt" => null,
            false => Confidence.Medium,
            null => rule.Confidence,
        };
    }
}
