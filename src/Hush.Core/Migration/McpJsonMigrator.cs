using Hush.Core.Scanning;
using Hush.Core.Text;
using Hush.Core.Vault;

namespace Hush.Core.Migration;

/// <summary>
/// Rewrites JSON MCP configs (Claude Desktop, Claude Code, Cursor, VS Code, Windsurf, Gemini CLI). For each
/// stdio server with inline secrets in <c>env</c>, the secrets move to the vault, are removed from <c>env</c>,
/// and the server is launched through <c>hush run --secrets ... -- &lt;original command&gt;</c>. Every other
/// byte of the file, including comments in VS Code's JSONC, is left as it was.
/// </summary>
internal static class McpJsonMigrator
{
    public static FilePlan Plan(string path, string text, McpFormat format, MigrationContext context)
    {
        JsonNode root;
        try
        {
            root = JsonSpanParser.Parse(text);
        }
        catch (FormatException ex)
        {
            return new FilePlan(null, [$"{path}: skipped, not valid JSON ({ex.Message})."], []);
        }

        if (root is not JsonObjectNode rootObject)
        {
            return FilePlan.None;
        }

        var serverMaps = new List<(string Label, JsonObjectNode Servers)>();
        var key = format == McpFormat.VsCodeServersJson ? "servers" : "mcpServers";
        if (rootObject.GetObject(key) is { } topLevel)
        {
            serverMaps.Add((string.Empty, topLevel));
        }

        if (format == McpFormat.ClaudeCodeUserJson && rootObject.GetObject("projects") is { } projects)
        {
            foreach (var project in projects.Members)
            {
                if (project.Value is JsonObjectNode projectObject && projectObject.GetObject("mcpServers") is { } projectServers)
                {
                    serverMaps.Add(($"{project.Name}: ", projectServers));
                }
            }
        }

        var edits = new List<TextEdit>();
        var notes = new List<string>();
        var migrated = new List<string>();
        foreach (var (label, servers) in serverMaps)
        {
            foreach (var member in servers.Members)
            {
                if (member.Value is JsonObjectNode server)
                {
                    PlanServer(path, text, label + member.Name, server, context, edits, notes, migrated);
                }
            }
        }

        if (edits.Count == 0)
        {
            return new FilePlan(null, notes, []);
        }

        var updated = TextEdits.Apply(text, edits);
        JsonSpanParser.Parse(updated);
        return new FilePlan(
            new FileChange(path, text, updated, $"Launch {string.Join(", ", migrated)} through 'hush run' and remove their inline secrets."),
            notes,
            []);
    }

    private static void PlanServer(
        string path,
        string text,
        string serverName,
        JsonObjectNode server,
        MigrationContext context,
        List<TextEdit> edits,
        List<string> notes,
        List<string> migrated)
    {
        if (server.Get("url") is not null && server.Get("command") is null)
        {
            if (server.GetObject("headers") is { } headers && headers.Members.Any(h => h.Value is JsonStringNode s && context.IsSecret(h.Name, s.Value)))
            {
                notes.Add($"{path}: server '{serverName}' is a remote (HTTP) server with a credential in its headers. Hush cannot inject HTTP headers; rotate that credential and use the client's OAuth sign-in or its environment-variable expansion instead.");
            }

            return;
        }

        var env = server.GetObject("env");
        if (env is null)
        {
            return;
        }

        var secretMembers = env.Members
            .Select((m, i) => (Member: m, Index: i))
            .Where(x => x.Member.Value is JsonStringNode s && context.IsSecret(x.Member.Name, s.Value))
            .ToList();
        if (secretMembers.Count == 0)
        {
            return;
        }

        if (server.Get("command") is not { Value: JsonStringNode command } commandMember)
        {
            notes.Add($"{path}: server '{serverName}' has inline secrets but no 'command'; skipped.");
            return;
        }

        if (Path.GetFileNameWithoutExtension(command.Value).Equals("hush", StringComparison.OrdinalIgnoreCase))
        {
            notes.Add($"{path}: server '{serverName}' already runs through Hush but still has inline secrets in 'env'; move them with 'hush set' and remove them by hand.");
            return;
        }

        var argsMember = server.Get("args");
        if (argsMember is not null && argsMember.Value is not JsonArrayNode)
        {
            notes.Add($"{path}: server '{serverName}' has a non-array 'args'; skipped.");
            return;
        }

        var specs = new List<string>();
        foreach (var (member, _) in secretMembers)
        {
            var value = ((JsonStringNode)member.Value).Value;
            var reference = context.Names.Allocate(string.Empty, member.Name, value, $"{path} ({serverName}.env.{member.Name})");
            specs.Add(Spec(member.Name, reference));
        }

        var originalArgs = (argsMember?.Value as JsonArrayNode)?.Items.Select(i => i.Raw(text)).ToList() ?? [];
        var items = new List<string> { "\"run\"", "\"--secrets\"", JsonSpanParser.Quote(string.Join(',', specs)), "\"--\"", command.Raw(text) };
        items.AddRange(originalArgs);

        edits.Add(new TextEdit(command.Start, command.End, JsonSpanParser.Quote(context.HushCommand)));
        if (argsMember is { Value: JsonArrayNode args })
        {
            edits.Add(new TextEdit(args.Start, args.End, FormatArray(text, args, items)));
        }
        else
        {
            var singleLine = !text.AsSpan(server.Start, server.End - server.Start).Contains('\n');
            var insertion = singleLine
                ? $", \"args\": [{string.Join(", ", items)}]"
                : $",{TextEdits.NewlineOf(text)}{TextEdits.IndentAt(text, commandMember.Start)}\"args\": [{string.Join(", ", items)}]";
            edits.Add(new TextEdit(commandMember.End, commandMember.End, insertion));
        }

        var removed = secretMembers.Select(s => s.Index).ToHashSet();
        if (removed.Count == env.Members.Count)
        {
            var envMember = server.Get("env")!;
            var index = server.Members.ToList().IndexOf(envMember);
            edits.AddRange(RemoveMembers(text, server, new HashSet<int> { index }));
        }
        else
        {
            edits.AddRange(RemoveMembers(text, env, removed));
        }

        migrated.Add($"'{serverName}'");
    }

    /// <summary>
    /// Edits that delete the members at <paramref name="indices"/> together with the separators that belong to
    /// them, keeping the object valid (no dangling or missing commas).
    /// </summary>
    internal static IEnumerable<TextEdit> RemoveMembers(string text, JsonObjectNode node, IReadOnlySet<int> indices)
    {
        var members = node.Members;
        var kept = Enumerable.Range(0, members.Count).Where(i => !indices.Contains(i)).ToList();
        if (kept.Count == 0)
        {
            yield return new TextEdit(node.Start + 1, node.End - 1, string.Empty);
            yield break;
        }

        var lastKept = kept[^1];
        foreach (var i in indices.Where(i => i < lastKept).Order())
        {
            yield return new TextEdit(members[i].Start, members[i + 1].Start, string.Empty);
        }

        if (indices.Any(i => i > lastKept))
        {
            yield return new TextEdit(members[lastKept].End, members[^1].End, string.Empty);
        }
    }

    private static string FormatArray(string text, JsonArrayNode original, List<string> items)
    {
        var raw = original.Raw(text);
        if (!raw.Contains('\n', StringComparison.Ordinal) || original.Items.Count == 0)
        {
            return "[" + string.Join(", ", items) + "]";
        }

        var newline = TextEdits.NewlineOf(text);
        var itemIndent = TextEdits.IndentAt(text, original.Items[0].Start);
        var closeIndent = TextEdits.IndentAt(text, original.End - 1);
        return "[" + newline + string.Join("," + newline, items.Select(i => itemIndent + i)) + newline + closeIndent + "]";
    }

    internal static string Spec(string variable, SecretRef reference) =>
        reference.Scope.Length == 0 && reference.Name == variable ? variable : $"{variable}={(reference.Scope.Length == 0 ? "/" + reference.Name : reference.ToString())}";
}
