using System.Globalization;
using System.Reflection;
using System.Text;
using System.Text.Json;

namespace Hush.Core.Scanning;

/// <summary>Machine-readable scan reports. Like every Hush output, they contain only redacted prefixes.</summary>
public static class Reports
{
    private static readonly JsonWriterOptions Indented = new() { Indented = true };

    /// <summary>The Hush version, for report metadata.</summary>
    public static string ToolVersion { get; } =
        typeof(Reports).Assembly.GetCustomAttribute<AssemblyInformationalVersionAttribute>()?.InformationalVersion.Split('+')[0] ?? "0.0.0";

    /// <summary>A JSON report: summary counts, findings, and files that could not be read.</summary>
    public static string ToJson(ScanResult result)
    {
        ArgumentNullException.ThrowIfNull(result);
        using var buffer = new MemoryStream();
        using (var writer = new Utf8JsonWriter(buffer, Indented))
        {
            writer.WriteStartObject();
            writer.WriteString("tool", "hush");
            writer.WriteString("version", ToolVersion);
            writer.WriteNumber("filesScanned", result.Files.Count);
            writer.WriteStartObject("summary");
            foreach (var risk in Enum.GetValues<Risk>().Reverse())
            {
                writer.WriteNumber(Name(risk), result.Findings.Count(f => f.Risk == risk));
            }

            writer.WriteEndObject();
            writer.WriteStartArray("findings");
            foreach (var f in result.BySeverity)
            {
                writer.WriteStartObject();
                writer.WriteString("kind", f.Kind == FindingKind.ToolTokenFile ? "tool-token-file" : "inline-secret");
                writer.WriteString("ruleId", f.RuleId);
                writer.WriteString("provider", f.Provider);
                writer.WriteString("type", f.SecretType);
                writer.WriteString("file", f.FilePath);
                writer.WriteNumber("line", f.Line);
                writer.WriteNumber("column", f.Column);
                writer.WriteString("prefix", f.Prefix);
                writer.WriteString("confidence", Name(f.Confidence));
                writer.WriteString("risk", Name(f.Risk));
                writer.WriteString("note", f.RiskNote);
                if (f.Client is not null)
                {
                    writer.WriteString("client", f.Client);
                }

                writer.WriteString("location", Name(f.Location));
                writer.WriteString("fingerprint", f.Fingerprint);
                writer.WriteEndObject();
            }

            writer.WriteEndArray();
            writer.WriteStartArray("errors");
            foreach (var error in result.Errors)
            {
                writer.WriteStringValue(error);
            }

            writer.WriteEndArray();
            writer.WriteEndObject();
        }

        return Encoding.UTF8.GetString(buffer.ToArray());
    }

    /// <summary>
    /// A SARIF 2.1.0 log for GitHub code scanning. Files under <paramref name="baseDirectory"/> get URIs
    /// relative to <c>%SRCROOT%</c>; others get absolute <c>file:</c> URIs.
    /// </summary>
    public static string ToSarif(ScanResult result, string baseDirectory)
    {
        ArgumentNullException.ThrowIfNull(result);
        var root = Path.GetFullPath(baseDirectory).TrimEnd(Path.DirectorySeparatorChar) + Path.DirectorySeparatorChar;
        var findings = result.BySeverity.ToList();
        var rules = findings.Select(f => f.RuleId).Distinct(StringComparer.Ordinal).ToList();
        var catalog = RuleSet.Embedded.Rules.ToDictionary(r => r.Id, StringComparer.Ordinal);

        using var buffer = new MemoryStream();
        using (var writer = new Utf8JsonWriter(buffer, Indented))
        {
            writer.WriteStartObject();
            writer.WriteString("$schema", "https://json.schemastore.org/sarif-2.1.0.json");
            writer.WriteString("version", "2.1.0");
            writer.WriteStartArray("runs");
            writer.WriteStartObject();

            writer.WriteStartObject("tool");
            writer.WriteStartObject("driver");
            writer.WriteString("name", "Hush");
            writer.WriteString("informationUri", "https://github.com/ide-bloom/hush");
            writer.WriteString("semanticVersion", ToolVersion);
            writer.WriteStartArray("rules");
            foreach (var id in rules)
            {
                var sample = findings.First(f => f.RuleId == id);
                catalog.TryGetValue(id, out var rule);
                writer.WriteStartObject();
                writer.WriteString("id", id);
                writer.WriteString("name", ToPascal(id));
                writer.WriteStartObject("shortDescription");
                writer.WriteString("text", $"{sample.Provider} {sample.SecretType.ToLowerInvariant()} in plaintext");
                writer.WriteEndObject();
                writer.WriteStartObject("fullDescription");
                writer.WriteString("text", rule?.Note ?? sample.RiskNote);
                writer.WriteEndObject();
                writer.WriteStartObject("help");
                writer.WriteString("text", $"{rule?.Note ?? sample.RiskNote} Move the secret into Hush with 'hush migrate' and inject it with 'hush run'.");
                writer.WriteEndObject();
                writer.WriteStartObject("defaultConfiguration");
                writer.WriteString("level", Level(sample.Risk));
                writer.WriteEndObject();
                writer.WriteStartObject("properties");
                writer.WriteString("security-severity", SecuritySeverity(sample.Risk));
                writer.WriteStartArray("tags");
                writer.WriteStringValue("security");
                writer.WriteStringValue("secret");
                writer.WriteEndArray();
                writer.WriteEndObject();
                writer.WriteEndObject();
            }

            writer.WriteEndArray();
            writer.WriteEndObject();
            writer.WriteEndObject();

            writer.WriteStartObject("originalUriBaseIds");
            writer.WriteStartObject("%SRCROOT%");
            writer.WriteString("uri", new Uri(root).AbsoluteUri);
            writer.WriteEndObject();
            writer.WriteEndObject();

            writer.WriteStartArray("results");
            foreach (var f in findings)
            {
                writer.WriteStartObject();
                writer.WriteString("ruleId", f.RuleId);
                writer.WriteNumber("ruleIndex", rules.IndexOf(f.RuleId));
                writer.WriteString("level", Level(f.Risk));
                writer.WriteStartObject("message");
                writer.WriteString("text", f.Kind == FindingKind.ToolTokenFile
                    ? $"{f.Provider} OAuth token file. {f.RiskNote}"
                    : $"{f.Provider} {f.SecretType.ToLowerInvariant()} ({f.Prefix}…) stored in plaintext. Confidence: {Name(f.Confidence)}.");
                writer.WriteEndObject();
                writer.WriteStartArray("locations");
                writer.WriteStartObject();
                writer.WriteStartObject("physicalLocation");
                writer.WriteStartObject("artifactLocation");
                var full = Path.GetFullPath(f.FilePath);
                if (full.StartsWith(root, StringComparison.OrdinalIgnoreCase))
                {
                    writer.WriteString("uri", full[root.Length..].Replace('\\', '/'));
                    writer.WriteString("uriBaseId", "%SRCROOT%");
                }
                else
                {
                    writer.WriteString("uri", new Uri(full).AbsoluteUri);
                }

                writer.WriteEndObject();
                if (f.Line > 0)
                {
                    writer.WriteStartObject("region");
                    writer.WriteNumber("startLine", f.Line);
                    writer.WriteNumber("startColumn", Math.Max(1, f.Column));
                    writer.WriteEndObject();
                }

                writer.WriteEndObject();
                writer.WriteEndObject();
                writer.WriteEndArray();
                writer.WriteStartObject("partialFingerprints");
                writer.WriteString("hushSecret/v1", f.Fingerprint);
                writer.WriteEndObject();
                writer.WriteStartObject("properties");
                writer.WriteString("confidence", Name(f.Confidence));
                writer.WriteString("risk", Name(f.Risk));
                writer.WriteEndObject();
                writer.WriteEndObject();
            }

            writer.WriteEndArray();
            writer.WriteEndObject();
            writer.WriteEndArray();
            writer.WriteEndObject();
        }

        return Encoding.UTF8.GetString(buffer.ToArray());
    }

    /// <summary>Lowercase name of an enum value, with dashes between words.</summary>
    public static string Name<T>(T value)
        where T : struct, Enum
    {
        var text = value.ToString();
        var builder = new StringBuilder();
        for (var i = 0; i < text.Length; i++)
        {
            if (i > 0 && char.IsUpper(text[i]))
            {
                builder.Append('-');
            }

            builder.Append(char.ToLowerInvariant(text[i]));
        }

        return builder.ToString();
    }

    private static string Level(Risk risk) => risk switch
    {
        Risk.Critical or Risk.High => "error",
        Risk.Medium => "warning",
        _ => "note",
    };

    private static string SecuritySeverity(Risk risk) => (risk switch
    {
        Risk.Critical => 9.5,
        Risk.High => 8.0,
        Risk.Medium => 5.5,
        _ => 3.0,
    }).ToString("0.0", CultureInfo.InvariantCulture);

    private static string ToPascal(string id) =>
        string.Concat(id.Split('-', '/').Where(p => p.Length > 0).Select(p => char.ToUpperInvariant(p[0]) + p[1..]));
}
