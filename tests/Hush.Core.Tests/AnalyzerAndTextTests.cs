using System.Collections.Immutable;
using Hush.Analyzers;
using Hush.Core.Text;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.Diagnostics;
using Xunit;

namespace Hush.Core.Tests;

public sealed class SensitiveLoggingAnalyzerTests
{
    private const string Source = """
        using Microsoft.Extensions.Logging;

        [System.AttributeUsage(System.AttributeTargets.All)]
        sealed class SensitiveAttribute : System.Attribute { }

        [Sensitive]
        sealed class Secret { public string Value = ""; }

        static class Logs
        {
            [LoggerMessage(1, LogLevel.Information, "x {X}")]
            public static void Generated(ILogger logger, Secret x) { }
        }

        sealed class C
        {
            void M(ILogger log, Secret s, [Sensitive] string token, string name)
            {
                log.LogInformation("value {V}", s);
                log.LogInformation("value {V}", s.Value);
                log.LogWarning($"token {token}");
                Logs.Generated(log, s);
                log.LogInformation("name {N}", name);
                System.Console.WriteLine(token);
            }
        }
        """;

    [Fact]
    public async Task Flags_sensitive_values_in_logging_calls_only()
    {
        var references = ((string)AppContext.GetData("TRUSTED_PLATFORM_ASSEMBLIES")!)
            .Split(Path.PathSeparator)
            .Select(p => MetadataReference.CreateFromFile(p))
            .Append(MetadataReference.CreateFromFile(typeof(Microsoft.Extensions.Logging.ILogger).Assembly.Location))
            .ToList();
        var compilation = CSharpCompilation.Create(
            "Sample",
            [CSharpSyntaxTree.ParseText(Source)],
            references,
            new CSharpCompilationOptions(OutputKind.DynamicallyLinkedLibrary));
        Assert.Empty(compilation.GetDiagnostics().Where(d => d.Severity == DiagnosticSeverity.Error));

        var diagnostics = await compilation
            .WithAnalyzers(ImmutableArray.Create<DiagnosticAnalyzer>(new SensitiveLoggingAnalyzer()))
            .GetAnalyzerDiagnosticsAsync();

        var hush = diagnostics.Where(d => d.Id == SensitiveLoggingAnalyzer.DiagnosticId).ToList();
        Assert.Equal(4, hush.Count);
        Assert.All(hush, d => Assert.Equal(DiagnosticSeverity.Error, d.Severity));
    }
}

public sealed class TextTests
{
    [Fact]
    public void Json_span_parser_handles_jsonc_and_reports_spans()
    {
        const string text = """
            // comment
            {
              "a": [1, 2, ], /* block */
              "b": { "c": "d\"e" },
            }
            """;
        var root = Assert.IsType<JsonObjectNode>(JsonSpanParser.Parse(text));
        Assert.Equal(["a", "b"], root.Members.Select(m => m.Name));
        var c = Assert.IsType<JsonStringNode>(root.GetObject("b")!.Get("c")!.Value);
        Assert.Equal("d\"e", c.Value);
        Assert.Equal("\"d\\\"e\"", c.Raw(text));
        Assert.Throws<FormatException>(() => JsonSpanParser.Parse("{\"a\": }"));
    }

    [Fact]
    public void Text_edits_apply_from_the_end_and_reject_overlaps()
    {
        Assert.Equal("Xbc-Y", TextEdits.Apply("abc-d", [new TextEdit(0, 1, "X"), new TextEdit(4, 5, "Y")]));
        Assert.Throws<InvalidOperationException>(() => TextEdits.Apply("abcdef", [new TextEdit(0, 3, "X"), new TextEdit(2, 4, "Y")]));
        Assert.Equal("aXc", TextEdits.Apply("abc", [new TextEdit(1, 1, "X"), new TextEdit(1, 2, string.Empty)]));
    }

    [Fact]
    public void Unified_diff_shows_hunks_with_context()
    {
        var before = string.Join('\n', Enumerable.Range(1, 20).Select(i => $"line {i}")) + "\n";
        var after = before.Replace("line 5\n", "line five\n", StringComparison.Ordinal).Replace("line 18\n", string.Empty, StringComparison.Ordinal);
        var diff = UnifiedDiff.Create("f.txt", before, after);
        Assert.Contains("--- a/f.txt", diff, StringComparison.Ordinal);
        Assert.Contains("-line 5\n+line five\n", diff, StringComparison.Ordinal);
        Assert.Contains("-line 18\n", diff, StringComparison.Ordinal);
        Assert.Equal(2, diff.Split('\n').Count(l => l.StartsWith("@@", StringComparison.Ordinal)));
        Assert.Equal(string.Empty, UnifiedDiff.Create("f", before, before));
        Assert.StartsWith("--- /dev/null", UnifiedDiff.Create("new.txt", null, "hello\n"), StringComparison.Ordinal);
    }
}
