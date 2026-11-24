using System.Text;
using Hush.Core.Manifest;
using Hush.Core.Migration;
using Hush.Core.Scanning;
using Hush.Core.Text;
using Hush.Core.Vault;
using Hush.Tests.Support;
using Xunit;

namespace Hush.Core.Tests;

public sealed class MigratorTests : IDisposable
{
    private static readonly Dictionary<string, string> Placeholders = new()
    {
        ["{{GITHUB}}"] = FakeTokens.GitHubClassic(101),
        ["{{SLACK}}"] = FakeTokens.Slack(102),
        ["{{BRAVE}}"] = FakeTokens.Random(31, "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789", 103),
        ["{{STRIPE}}"] = FakeTokens.StripeLive(104),
        ["{{HF}}"] = FakeTokens.HuggingFace(105),
        ["{{BEARER}}"] = FakeTokens.Random(40, "abcdef0123456789", 106),
        ["{{OPENAI}}"] = FakeTokens.OpenAi(107),
        ["{{ANTHROPIC}}"] = FakeTokens.Anthropic(108),
    };

    private readonly TempDirectory _temp = new();

    public void Dispose() => _temp.Dispose();

    public static TheoryData<string, string, string> GoldenCases() => new()
    {
        { "claude-desktop", "json", "claude_desktop_config.json" },
        { "claude-code-user", "json", ".claude.json" },
        { "claude-code-project", "json", ".mcp.json" },
        { "cursor", "json", Path.Combine(".cursor", "mcp.json") },
        { "vscode", "jsonc", Path.Combine(".vscode", "mcp.json") },
        { "windsurf", "json", "mcp_config.json" },
        { "gemini", "json", Path.Combine(".gemini", "settings.json") },
        { "codex", "toml", Path.Combine(".codex", "config.toml") },
    };

    [Theory]
    [MemberData(nameof(GoldenCases))]
    public void Mcp_config_migration_matches_golden_file(string name, string extension, string fileName)
    {
        var input = Fill(Golden($"{name}.input.{extension}"));
        var path = _temp.Write(fileName, input);
        var plan = Plan([path]);

        var change = Assert.Single(plan.Changes);
        var expectedPath = $"{name}.expected.{extension}";
        if (Environment.GetEnvironmentVariable("HUSH_UPDATE_GOLDEN") == "1")
        {
            // Golden files keep {{PLACEHOLDERS}} for anything left in place, so no token-shaped value is committed.
            File.WriteAllText(Path.Combine(GoldenSourceDirectory(), expectedPath), Unfill(change.Updated), new UTF8Encoding(false));
        }

        Assert.Equal(Normalize(Fill(Golden(expectedPath))), Normalize(change.Updated));
        Assert.All(plan.Secrets, s => Assert.DoesNotContain(s.Value, change.Updated, StringComparison.Ordinal));
        var diff = plan.RenderDiff();
        foreach (var secret in Placeholders.Values)
        {
            Assert.DoesNotContain(secret, diff, StringComparison.Ordinal);
        }

        Assert.All(plan.Secrets, s => Assert.Contains(s.Value, Placeholders.Values));
    }

    [Fact]
    public void Http_servers_with_header_credentials_get_a_note_instead_of_a_rewrite()
    {
        var path = _temp.Write(".mcp.json", Fill(Golden("claude-code-project.input.json")));
        var plan = Plan([path]);
        Assert.Contains(plan.Notes, n => n.Contains("remote-api", StringComparison.Ordinal) && n.Contains("HTTP", StringComparison.Ordinal));
        Assert.Single(plan.Secrets);
    }

    [Fact]
    public void Same_secret_in_two_files_gets_one_vault_name_and_existing_names_are_avoided()
    {
        var a = _temp.Write("claude_desktop_config.json", Fill(Golden("windsurf.input.json")));
        var b = _temp.Write("mcp_config.json", Fill(Golden("windsurf.input.json")));
        var existing = new HashSet<SecretRef> { new(string.Empty, "GITHUB_PERSONAL_ACCESS_TOKEN") };
        var plan = Plan([a, b], existing);
        var secret = Assert.Single(plan.Secrets);
        Assert.Equal("GITHUB_PERSONAL_ACCESS_TOKEN_2", secret.Target.Name);
        Assert.All(plan.Changes, c => Assert.Contains("GITHUB_PERSONAL_ACCESS_TOKEN=/GITHUB_PERSONAL_ACCESS_TOKEN_2", c.Updated, StringComparison.Ordinal));
    }

    [Fact]
    public void Dotenv_migration_creates_manifest_stub_and_gitignore()
    {
        Directory.CreateDirectory(_temp.Combine("shop", ".git"));
        var token = FakeTokens.OpenAi(300);
        var url = FakeTokens.PostgresUrl(301);
        _temp.Write(Path.Combine("shop", ".env"), $"# local settings\nOPENAI_API_KEY={token}\nexport DATABASE_URL=\"{url}\"\nPORT=3000 # dev port\nEMPTY=\n");
        _temp.Write(Path.Combine("shop", ".env.staging"), $"DATABASE_URL='{FakeTokens.PostgresUrl(302)}'\n");
        _temp.Write(Path.Combine("shop", ".env.example"), "OPENAI_API_KEY=your-api-key-here\n");

        var scan = new Scanner(environment: ScanEnvironment.Under(_temp.Path)).Scan(new ScanOptions([], [_temp.Path], IncludeDefaultLocations: false));
        var context = new MigrationContext(SecretDetector.Default, new SecretNameAllocator(_ => false), "hush");
        var plan = new MigrationPlanner(context).Plan(scan);

        Assert.Equal(["shop/DATABASE_URL", "shop/DATABASE_URL.staging", "shop/OPENAI_API_KEY", "shop/PORT"], plan.Secrets.Select(s => s.Target.ToString()).Order(StringComparer.Ordinal));
        Assert.Equal(url, plan.Secrets.Single(s => s.Target.Name == "DATABASE_URL").Value);

        var stub = plan.Changes.Single(c => c.Path.EndsWith(Path.DirectorySeparatorChar + ".env", StringComparison.Ordinal));
        Assert.All(stub.Updated.Split('\n', StringSplitOptions.RemoveEmptyEntries), line => Assert.StartsWith("#", line, StringComparison.Ordinal));
        Assert.DoesNotContain(plan.Changes, c => c.Path.EndsWith(".env.example", StringComparison.Ordinal));

        var manifestChange = plan.Changes.Single(c => c.Path.EndsWith(ProjectManifest.FileName, StringComparison.Ordinal));
        var manifest = ProjectManifest.Parse(manifestChange.Updated, manifestChange.Path);
        Assert.Equal("shop", manifest.Project);
        Assert.Equal("OPENAI_API_KEY", manifest.Env["OPENAI_API_KEY"]);
        Assert.Equal("DATABASE_URL.staging", manifest.Profiles["staging"]["DATABASE_URL"]);
        Assert.DoesNotContain(token, manifestChange.Updated, StringComparison.Ordinal);

        var gitignore = plan.Changes.Single(c => c.Path.EndsWith(".gitignore", StringComparison.Ordinal));
        Assert.Contains("\n.env\n", "\n" + gitignore.Updated, StringComparison.Ordinal);
        Assert.Contains(plan.Commands, c => c.Contains("hush run --profile staging", StringComparison.Ordinal));
    }

    [Fact]
    public void Dotenv_migration_updates_an_existing_manifest_without_touching_its_content()
    {
        const string existing = "# my notes\nversion = 1\nproject = \"api\"\n\n[env]\nKEEP = \"KEEP\" # hand-written\n";
        _temp.Write(Path.Combine("api", ProjectManifest.FileName), existing);
        _temp.Write(Path.Combine("api", "src", ".env"), $"NEW_TOKEN={FakeTokens.Npm(310)}\nKEEP=ignored-because-mapped\n");

        var scan = new Scanner(environment: ScanEnvironment.Under(_temp.Path)).Scan(new ScanOptions([], [_temp.Path], IncludeDefaultLocations: false));
        var plan = new MigrationPlanner(new MigrationContext(SecretDetector.Default, new SecretNameAllocator(_ => false), "hush")).Plan(scan);

        var manifest = plan.Changes.Single(c => c.Path.EndsWith(ProjectManifest.FileName, StringComparison.Ordinal));
        Assert.Equal(_temp.Combine("api", ProjectManifest.FileName), manifest.Path);
        Assert.StartsWith(existing, manifest.Updated, StringComparison.Ordinal);
        var parsed = ProjectManifest.Parse(manifest.Updated, manifest.Path);
        Assert.Equal("KEEP", parsed.Env["KEEP"]);
        Assert.Equal("NEW_TOKEN", parsed.Env["NEW_TOKEN"]);
        Assert.All(plan.Secrets, s => Assert.Equal("api", s.Target.Scope));
    }

    [Fact]
    public void Dotenv_parser_handles_quotes_comments_and_multiline_values()
    {
        var entries = DotEnvMigrator.Parse("A=1\n# c\nexport B=\"two\\nlines\"\nC='lit $X'\nD=\"multi\nline\"\nE=plain # comment\n");
        Assert.Equal(["A", "B", "C", "D", "E"], entries.Select(e => e.Key));
        Assert.Equal("two\nlines", entries[1].Value);
        Assert.Equal("lit $X", entries[2].Value);
        Assert.Equal("multi\nline", entries[3].Value);
        Assert.Equal("plain", entries[4].Value);
        Assert.Equal("staging", DotEnvMigrator.ProfileOf(".env.staging.local"));
        Assert.Null(DotEnvMigrator.ProfileOf(".env.local"));
    }

    [Fact]
    public void Npmrc_pypirc_and_git_credentials_are_rewritten()
    {
        var npm = FakeTokens.Npm(400);
        var pypi = FakeTokens.Pypi(401);
        var git = FakeTokens.GitHubClassic(402);
        var npmrc = _temp.Write(".npmrc", $"registry=https://registry.npmjs.org/\n//registry.npmjs.org/:_authToken={npm}\n");
        var pypirc = _temp.Write(".pypirc", $"[distutils]\nindex-servers = pypi\n\n[pypi]\nusername = __token__\npassword = {pypi}\n");
        var creds = _temp.Write(".git-credentials", $"https://octo%40example.com:{git}@github.com\nhttps://example.org\n");

        var plan = Plan([npmrc, pypirc, creds]);
        Assert.Contains("//registry.npmjs.org/:_authToken=${NPM_TOKEN}", plan.Changes.Single(c => c.Path == npmrc).Updated, StringComparison.Ordinal);
        Assert.DoesNotContain("password", plan.Changes.Single(c => c.Path == pypirc).Updated, StringComparison.Ordinal);
        Assert.Equal("https://example.org\n", plan.Changes.Single(c => c.Path == creds).Updated);
        Assert.Contains(plan.Secrets, s => s.Target.ToString() == "git/octo@example.com@github.com" && s.Value == git);
        Assert.Contains(plan.Commands, c => c.Contains("hush git-helper", StringComparison.Ordinal));
        Assert.Contains(plan.Commands, c => c.Contains("twine upload", StringComparison.Ordinal));
        Assert.Contains(plan.Commands, c => c.Contains("--secrets NPM_TOKEN -- npm", StringComparison.Ordinal));
    }

    [Fact]
    public async Task Apply_backs_up_and_undo_restores_files_and_removes_secrets()
    {
        var original = Fill(Golden("claude-desktop.input.json"));
        var path = _temp.Write("claude_desktop_config.json", original);
        var plan = Plan([path]);
        var sink = new RecordingSink();
        var executor = new MigrationExecutor(_temp.HushPaths);

        var backup = await executor.ApplyAsync(plan, sink, CancellationToken.None);
        Assert.Equal(plan.Secrets.Select(s => s.Target), sink.Stored);
        Assert.Equal(plan.Changes[0].Updated, File.ReadAllText(path));
        Assert.True(Directory.EnumerateFiles(backup, "*.bak").Any());

        var undone = await executor.UndoAsync(sink, force: false, CancellationToken.None);
        Assert.Equal(original, File.ReadAllText(path));
        Assert.Equal([path], undone.Restored);
        Assert.Equal(sink.Stored, sink.Removed);
        await Assert.ThrowsAsync<HushException>(() => executor.UndoAsync(sink, false, CancellationToken.None));
    }

    [Fact]
    public async Task Undo_refuses_to_clobber_later_edits_unless_forced()
    {
        var path = _temp.Write("claude_desktop_config.json", Fill(Golden("cursor.input.json")));
        var plan = Plan([path]);
        var executor = new MigrationExecutor(_temp.HushPaths);
        await executor.ApplyAsync(plan, new RecordingSink(), CancellationToken.None);
        File.AppendAllText(path, "\n");
        await Assert.ThrowsAsync<HushException>(() => executor.UndoAsync(new RecordingSink(), false, CancellationToken.None));
        await executor.UndoAsync(new RecordingSink(), force: true, CancellationToken.None);
    }

    [Fact]
    public async Task Apply_refuses_when_the_file_changed_after_planning()
    {
        var path = _temp.Write("claude_desktop_config.json", Fill(Golden("cursor.input.json")));
        var plan = Plan([path]);
        File.AppendAllText(path, " ");
        var sink = new RecordingSink();
        await Assert.ThrowsAsync<HushException>(() => new MigrationExecutor(_temp.HushPaths).ApplyAsync(plan, sink, CancellationToken.None));
        Assert.Empty(sink.Stored);
    }

    [Fact]
    public void Removing_json_members_keeps_the_object_valid()
    {
        const string text = "{ \"a\": 1, \"b\": 2, \"c\": 3, \"d\": 4 }";
        var node = (JsonObjectNode)JsonSpanParser.Parse(text);
        foreach (var set in new[] { new[] { 0 }, [1], [3], [0, 1], [2, 3], [0, 3], [1, 2], [0, 1, 2, 3] })
        {
            var updated = TextEdits.Apply(text, McpJsonMigrator.RemoveMembers(text, node, set.ToHashSet()));
            var parsed = (JsonObjectNode)JsonSpanParser.Parse(updated);
            Assert.Equal(new[] { "a", "b", "c", "d" }.Where((_, i) => !set.Contains(i)), parsed.Members.Select(m => m.Name));
        }
    }

    private MigrationPlan Plan(IReadOnlyList<string> paths, IReadOnlySet<SecretRef>? existing = null)
    {
        var scan = new Scanner(environment: ScanEnvironment.Under(_temp.Path)).Scan(new ScanOptions(paths, [], IncludeDefaultLocations: false));
        var context = new MigrationContext(SecretDetector.Default, new SecretNameAllocator(r => existing?.Contains(r) ?? false), "hush");
        return new MigrationPlanner(context).Plan(scan);
    }

    private static string Fill(string template) =>
        Placeholders.Aggregate(template, (text, kv) => text.Replace(kv.Key, kv.Value, StringComparison.Ordinal));

    private static string Unfill(string text) =>
        Placeholders.Aggregate(text, (current, kv) => current.Replace(kv.Value, kv.Key, StringComparison.Ordinal));

    private static string Golden(string name) => File.ReadAllText(Path.Combine(AppContext.BaseDirectory, "Golden", "Migrator", name));

    private static string Normalize(string text) => text.Replace("\r\n", "\n", StringComparison.Ordinal);

    private static string GoldenSourceDirectory()
    {
        for (var directory = new DirectoryInfo(AppContext.BaseDirectory); directory is not null; directory = directory.Parent)
        {
            var candidate = Path.Combine(directory.FullName, "tests", "Hush.Core.Tests", "Golden", "Migrator");
            if (Directory.Exists(candidate))
            {
                return candidate;
            }
        }

        throw new DirectoryNotFoundException("Golden source directory not found.");
    }

    private sealed class RecordingSink : ISecretSink
    {
        public List<SecretRef> Stored { get; } = [];

        public List<SecretRef> Removed { get; } = [];

        public Task StoreAsync(IReadOnlyList<PlannedSecret> secrets, CancellationToken cancellationToken)
        {
            Stored.AddRange(secrets.Select(s => s.Target));
            return Task.CompletedTask;
        }

        public Task RemoveAsync(IReadOnlyList<SecretRef> secrets, CancellationToken cancellationToken)
        {
            Removed.AddRange(secrets);
            return Task.CompletedTask;
        }
    }
}
