using System.Text;
using Hush.Core.Text;
using Tomlyn;
using Tomlyn.Model;
using Tomlyn.Parsing;
using Tomlyn.Syntax;

namespace Hush.Core.Migration;

/// <summary>
/// Rewrites OpenAI Codex's <c>config.toml</c>: <c>[mcp_servers.NAME]</c> tables with <c>command</c>,
/// <c>args</c> and an <c>env</c> inline table or <c>[mcp_servers.NAME.env]</c> sub-table. Edits are made
/// at the exact source spans, so comments and unrelated keys are untouched.
/// </summary>
internal static class CodexTomlMigrator
{
    public static FilePlan Plan(string path, string text, MigrationContext context)
    {
        TomlTable model;
        DocumentSyntax syntax;
        try
        {
            model = TomlModel.Parse(text);
            syntax = SyntaxParser.Parse(text, path, false);
        }
        catch (TomlException ex)
        {
            return new FilePlan(null, [$"{path}: skipped, not valid TOML ({ex.Message})."], []);
        }

        if (syntax.HasErrors || !model.TryGetValue("mcp_servers", out var serversValue) || serversValue is not TomlTable servers)
        {
            return FilePlan.None;
        }

        var tables = syntax.Tables.OfType<TableSyntaxBase>().ToList();
        var edits = new List<TextEdit>();
        var notes = new List<string>();
        var migrated = new List<string>();
        var newline = TextEdits.NewlineOf(text);

        foreach (var (name, value) in servers)
        {
            if (value is not TomlTable server || !server.TryGetValue("env", out var envValue) || envValue is not TomlTable env)
            {
                continue;
            }

            var secrets = env.Where(kv => kv.Value is string s && context.IsSecret(kv.Key, s)).Select(kv => (Key: kv.Key, Value: (string)kv.Value!)).ToList();
            if (secrets.Count == 0)
            {
                continue;
            }

            var serverTable = tables.FirstOrDefault(t => KeyPath(t.Name) is [ "mcp_servers", var n ] && n == name);
            if (serverTable is null || !server.TryGetValue("command", out var commandValue) || commandValue is not string command)
            {
                notes.Add($"{path}: server '{name}' has inline secrets but its layout is not supported (expected [mcp_servers.{name}] with command); skipped.");
                continue;
            }

            if (Path.GetFileNameWithoutExtension(command).Equals("hush", StringComparison.OrdinalIgnoreCase))
            {
                notes.Add($"{path}: server '{name}' already runs through Hush but still has inline secrets; move them with 'hush set' and remove them by hand.");
                continue;
            }

            var items = serverTable.Items.OfType<KeyValueSyntax>().ToList();
            var commandItem = items.FirstOrDefault(i => KeyPath(i.Key) is ["command"]);
            var argsItem = items.FirstOrDefault(i => KeyPath(i.Key) is ["args"]);
            var envItem = items.FirstOrDefault(i => KeyPath(i.Key) is ["env"]);
            if (commandItem is null)
            {
                continue;
            }

            var specs = new List<string>();
            foreach (var (key, secret) in secrets)
            {
                var reference = context.Names.Allocate(string.Empty, key, secret, $"{path} (mcp_servers.{name}.env.{key})");
                specs.Add(McpJsonMigrator.Spec(key, reference));
            }

            var originalArgs = server.TryGetValue("args", out var a) && a is TomlArray arr ? arr.Select(x => x?.ToString() ?? string.Empty).ToList() : [];
            var newArgs = new List<string> { "run", "--secrets", string.Join(',', specs), "--", command };
            newArgs.AddRange(originalArgs);
            var argsLiteral = "[" + string.Join(", ", newArgs.Select(Quote)) + "]";

            var commandValueNode = commandItem.Value!;
            edits.Add(new TextEdit(commandValueNode.Span.Start.Offset, commandValueNode.Span.End.Offset + 1, Quote(context.HushCommand)));
            if (argsItem is not null)
            {
                edits.Add(new TextEdit(argsItem.Value!.Span.Start.Offset, argsItem.Value.Span.End.Offset + 1, argsLiteral));
            }
            else
            {
                var at = LineEnd(text, commandValueNode.Span.End.Offset);
                edits.Add(new TextEdit(at, at, $"args = {argsLiteral}{newline}"));
            }

            var secretKeys = secrets.Select(s => s.Key).ToHashSet(StringComparer.Ordinal);
            if (envItem is not null)
            {
                var kept = env.Where(kv => !secretKeys.Contains(kv.Key)).ToList();
                if (kept.Count == 0)
                {
                    edits.Add(new TextEdit(LineStart(text, envItem.Span.Start.Offset), LineEnd(text, envItem.Value!.Span.End.Offset), string.Empty));
                }
                else
                {
                    var inline = "{ " + string.Join(", ", kept.Select(kv => $"{BareOrQuoted(kv.Key)} = {Quote(kv.Value?.ToString() ?? string.Empty)}")) + " }";
                    edits.Add(new TextEdit(envItem.Value!.Span.Start.Offset, envItem.Value.Span.End.Offset + 1, inline));
                }
            }
            else
            {
                var envTable = tables.FirstOrDefault(t => KeyPath(t.Name) is ["mcp_servers", var n, "env"] && n == name);
                if (envTable is null)
                {
                    notes.Add($"{path}: could not locate the env table of server '{name}'; skipped.");
                    edits.RemoveRange(edits.Count - 2, 2);
                    continue;
                }

                var envItems = envTable.Items.OfType<KeyValueSyntax>().ToList();
                var removeAll = envItems.All(i => KeyPath(i.Key) is [var k] && secretKeys.Contains(k));
                if (removeAll)
                {
                    // Take the blank line that separated the table from the previous one with it.
                    var start = LineStart(text, envTable.Span.Start.Offset);
                    var previousLine = LineStart(text, Math.Max(0, start - 1));
                    if (start > 0 && string.IsNullOrWhiteSpace(text[previousLine..start]))
                    {
                        start = previousLine;
                    }

                    edits.Add(new TextEdit(start, LineEnd(text, envItems[^1].Value!.Span.End.Offset), string.Empty));
                }
                else
                {
                    foreach (var item in envItems.Where(i => KeyPath(i.Key) is [var k] && secretKeys.Contains(k)))
                    {
                        edits.Add(new TextEdit(LineStart(text, item.Span.Start.Offset), LineEnd(text, item.Value!.Span.End.Offset), string.Empty));
                    }
                }
            }

            migrated.Add($"'{name}'");
        }

        if (edits.Count == 0)
        {
            return new FilePlan(null, notes, []);
        }

        var updated = TextEdits.Apply(text, edits);
        TomlModel.Parse(updated);
        return new FilePlan(
            new FileChange(path, text, updated, $"Launch {string.Join(", ", migrated)} through 'hush run' and remove their inline secrets."),
            notes,
            []);
    }

    private static string[] KeyPath(KeySyntax? key)
    {
        if (key is null)
        {
            return [];
        }

        var parts = new List<string> { KeyPart(key.Key) };
        foreach (var dotted in key.DotKeys)
        {
            parts.Add(KeyPart(dotted.Key));
        }

        return [.. parts];
    }

    private static string KeyPart(BareKeyOrStringValueSyntax? part) => part switch
    {
        BareKeySyntax bare => bare.Key?.Text ?? string.Empty,
        StringValueSyntax quoted => quoted.Value ?? string.Empty,
        _ => string.Empty,
    };

    private static int LineStart(string text, int offset) => text.LastIndexOf('\n', Math.Max(0, offset - 1)) + 1;

    private static int LineEnd(string text, int offset)
    {
        var newline = text.IndexOf('\n', Math.Min(offset, text.Length));
        return newline < 0 ? text.Length : newline + 1;
    }

    private static string BareOrQuoted(string key) => BareKeySyntax.IsBareKey(key) ? key : Quote(key);

    /// <summary>A TOML string: a literal string for Windows paths (no escaping needed), otherwise a basic string.</summary>
    internal static string Quote(string value)
    {
        if (value.Contains('\\', StringComparison.Ordinal) && !value.Contains('\'', StringComparison.Ordinal) && !value.Any(char.IsControl))
        {
            return "'" + value + "'";
        }

        var builder = new StringBuilder("\"");
        foreach (var c in value)
        {
            builder.Append(c switch
            {
                '"' => "\\\"",
                '\\' => "\\\\",
                '\n' => "\\n",
                '\r' => "\\r",
                '\t' => "\\t",
                _ when char.IsControl(c) => $"\\u{(int)c:X4}",
                _ => c.ToString(),
            });
        }

        return builder.Append('"').ToString();
    }
}
