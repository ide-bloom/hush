using System.Text.Json;
using Hush.Core.Scanning;
using Hush.Tests.Support;
using Xunit;

namespace Hush.Core.Tests;

public sealed class ScannerTests : IDisposable
{
    private readonly TempDirectory _temp = new();

    public void Dispose() => _temp.Dispose();

    /// <summary>One generated fixture per rule: (rule id, file the line is in, line).</summary>
    private static readonly (string Rule, string File, string Line)[] Fixtures =
    [
        ("openai-api-key", "fixture.env", $"OPENAI_API_KEY={FakeTokens.OpenAi()}"),
        ("openai-project-key", "fixture.env", $"OPENAI_API_KEY={FakeTokens.OpenAiProject()}"),
        ("anthropic-api-key", "fixture.env", $"ANTHROPIC_API_KEY={FakeTokens.Anthropic()}"),
        ("google-api-key", "fixture.env", $"GEMINI_API_KEY={FakeTokens.Google()}"),
        ("huggingface-token", "fixture.env", $"HF_TOKEN={FakeTokens.HuggingFace()}"),
        ("github-pat-classic", "hosts.yml", $"token: {FakeTokens.GitHubClassic()}"),
        ("github-pat-fine-grained", "fixture.env", $"GH_TOKEN={FakeTokens.GitHubFineGrained()}"),
        ("github-oauth-token", "hosts.yml", $"oauth_token: {FakeTokens.GitHubOAuth()}"),
        ("gitlab-pat", "fixture.env", $"GITLAB_TOKEN={FakeTokens.GitLab()}"),
        ("slack-token", "fixture.env", $"SLACK_BOT_TOKEN={FakeTokens.Slack()}"),
        ("slack-webhook", "config.toml", $"url = \"{FakeTokens.SlackWebhook()}\""),
        ("discord-bot-token", "fixture.env", $"DISCORD_BOT_TOKEN={FakeTokens.DiscordBot()}"),
        ("discord-webhook", "history.txt", $"curl -X POST {FakeTokens.DiscordWebhook()}"),
        ("twilio-api-key", "fixture.env", $"TWILIO_API_KEY={FakeTokens.TwilioKeySid()}"),
        ("twilio-auth-token", "fixture.env", $"TWILIO_AUTH_TOKEN={FakeTokens.Twilio()}"),
        ("sendgrid-api-key", "fixture.env", $"SENDGRID_API_KEY={FakeTokens.SendGrid()}"),
        ("stripe-live-key", "fixture.env", $"STRIPE_SECRET_KEY={FakeTokens.StripeLive()}"),
        ("stripe-test-key", "fixture.env", $"STRIPE_SECRET_KEY={FakeTokens.StripeTest()}"),
        ("aws-access-key-id", "credentials", $"aws_access_key_id = {FakeTokens.AwsKeyId()}"),
        ("aws-secret-access-key", "credentials", $"aws_secret_access_key = {FakeTokens.AwsSecret()}"),
        ("azure-storage-connection-string", "appsettings.json", $"DefaultEndpointsProtocol=https;AccountName=acct;AccountKey={FakeTokens.AzureStorageKey()};EndpointSuffix=core.windows.net"),
        ("azure-ad-client-secret", "fixture.env", $"AZURE_CLIENT_SECRET={FakeTokens.AzureClientSecret()}"),
        ("azure-openai-key", "fixture.env", $"AZURE_OPENAI_API_KEY={FakeTokens.AzureOpenAi()}"),
        ("gcp-service-account", "sa.json", $"  \"private_key_id\": \"{FakeTokens.GcpKeyId()}\","),
        ("npm-token", "fixture.env", $"NPM_TOKEN={FakeTokens.Npm()}"),
        ("npmrc-auth", Path.Combine("C:", "Users", "dev", ".npmrc"), "//registry.example.com/:_authToken=" + FakeTokens.Password(35)),
        ("pypi-token", "fixture.env", $"PYPI_TOKEN={FakeTokens.Pypi()}"),
        ("pypirc-password", Path.Combine("C:", "Users", "dev", ".pypirc"), "password = " + FakeTokens.Password(36)),
        ("docker-config-auth", Path.Combine("C:", "Users", "dev", ".docker", "config.json"), $"      \"auth\": \"{FakeTokens.DockerAuth()}\""),
        ("database-connection-string", "fixture.env", $"DATABASE_URL={FakeTokens.PostgresUrl()}"),
        ("git-credentials", Path.Combine("C:", "Users", "dev", ".git-credentials"), $"https://octo:{FakeTokens.Password(37)}@github.com"),
        ("kubeconfig-credential", Path.Combine("C:", "Users", "dev", ".kube", "config"), $"    token: {FakeTokens.Bearer(38)}"),
        ("private-key", "id_rsa", FakeTokens.PrivateKeyHeader()),
        ("jwt", "request.http", $"X-Session: {FakeTokens.Jwt()}"),
        ("bearer-token", "mcp.json", $"\"Authorization\": \"Bearer {FakeTokens.Bearer()}\""),
        ("generic-secret-assignment", "settings.yaml", $"my_service_api_key: {FakeTokens.Password(77)}"),
    ];

    public static TheoryData<string, string, string> ProviderFixtures()
    {
        var data = new TheoryData<string, string, string>();
        foreach (var (rule, file, line) in Fixtures)
        {
            data.Add(rule, file, line);
        }

        return data;
    }

    [Theory]
    [MemberData(nameof(ProviderFixtures))]
    public void Every_rule_detects_its_generated_fixture(string ruleId, string file, string line)
    {
        var matches = SecretDetector.Default.Detect(file, line);
        Assert.Contains(matches, m => m.Rule.Id == ruleId);
    }

    [Fact]
    public void Every_embedded_rule_has_a_fixture() =>
        Assert.Empty(RuleSet.Embedded.Rules.Select(r => r.Id).Except(Fixtures.Select(f => f.Rule)));

    [Theory]
    [InlineData("mysql")]
    [InlineData("mongodb")]
    public void Connection_strings_cover_mysql_and_mongo(string scheme)
    {
        var url = scheme == "mysql" ? FakeTokens.MySqlUrl() : FakeTokens.MongoUrl();
        var match = Assert.Single(SecretDetector.Default.Detect("f.env", $"DB={url}"));
        Assert.Equal("database-connection-string", match.Rule.Id);
    }

    [Fact]
    public void Oversized_files_and_overlong_lines_are_reported_not_silently_skipped()
    {
        _temp.Write("huge.env", new string('a', 6 * 1024 * 1024));
        _temp.Write("long-line.env", new string('b', 70 * 1024) + "\n");
        var result = new Scanner(environment: ScanEnvironment.Under(_temp.Path)).Scan(new ScanOptions([_temp.Combine("huge.env"), _temp.Combine("long-line.env")], [], IncludeDefaultLocations: false));
        Assert.Contains(result.Errors, e => e.Contains("huge.env", StringComparison.Ordinal) && e.Contains("not scanned", StringComparison.Ordinal));
        Assert.Contains(result.Errors, e => e.Contains("long-line.env:1", StringComparison.Ordinal));
    }

    [Fact]
    public void Github_checksum_raises_confidence_and_bad_checksums_lower_it()
    {
        var good = SecretDetector.Default.Detect("f", FakeTokens.GitHubClassic()).Single();
        var bad = SecretDetector.Default.Detect("f", FakeTokens.GitHubBadChecksum()).Single();
        Assert.Equal(Confidence.High, good.Confidence);
        Assert.Equal(Confidence.Medium, bad.Confidence);
        Assert.True(Checksums.ValidateCrc32Token(FakeTokens.Npm()));
    }

    [Theory]
    [InlineData("OPENAI_API_KEY=your-api-key-here")]
    [InlineData("API_KEY=${OPENAI_API_KEY}")]
    [InlineData("SECRET_TOKEN=<your token>")]
    [InlineData("password = changeme")]
    [InlineData("TOKEN=xxxxxxxxxxxxxxxxxxxxxxxx")]
    [InlineData("API_KEY=%MY_KEY%")]
    [InlineData("const name = 'hello world';")]
    public void Placeholders_and_ordinary_text_are_not_reported(string line) =>
        Assert.Empty(SecretDetector.Default.Detect("f.env", line));

    [Fact]
    public void Generic_rule_needs_entropy()
    {
        Assert.Empty(SecretDetector.Default.Detect("f", "api_key = aaaaaaaabbbbbbbbcccc"));
        var match = Assert.Single(SecretDetector.Default.Detect("f", $"my_service_api_key = {FakeTokens.Password(77)}"));
        Assert.Equal("generic-secret-assignment", match.Rule.Id);
        Assert.Equal(Confidence.Low, match.Confidence);
    }

    [Fact]
    public void Generic_rule_does_not_double_report_provider_matches()
    {
        var matches = SecretDetector.Default.Detect("f", $"OPENAI_API_KEY={FakeTokens.OpenAi()}");
        Assert.Single(matches);
    }

    [Fact]
    public void Path_scoped_rules_only_apply_to_their_files()
    {
        var line = "//registry.npmjs.org/:_authToken=" + FakeTokens.Password(5);
        Assert.Contains(SecretDetector.Default.Detect(@"C:\Users\x\.npmrc", line), m => m.Rule.Id == "npmrc-auth");
        Assert.DoesNotContain(SecretDetector.Default.Detect(@"C:\Users\x\notes.txt", line), m => m.Rule.Id == "npmrc-auth");
    }

    [Fact]
    public void Findings_are_redacted_to_four_characters()
    {
        var token = FakeTokens.Anthropic();
        _temp.Write(Path.Combine("proj", ".env"), $"ANTHROPIC_API_KEY={token}\n");
        var result = new Scanner(environment: ScanEnvironment.Under(_temp.Path)).Scan(new ScanOptions([], [_temp.Path], IncludeDefaultLocations: false));
        var finding = Assert.Single(result.Findings);
        Assert.Equal(token[..4], finding.Prefix);
        Assert.Equal(1, finding.Line);
        Assert.Equal(LocationKind.DotEnv, finding.Location);

        foreach (var report in new[] { Reports.ToJson(result), Reports.ToSarif(result, _temp.Path) })
        {
            Assert.DoesNotContain(token, report, StringComparison.Ordinal);
            Assert.DoesNotContain(token[..12], report, StringComparison.Ordinal);
        }
    }

    [Fact]
    public void Default_locations_cover_mcp_configs_credentials_history_and_token_files()
    {
        var env = ScanEnvironment.Under(_temp.Path);
        _temp.Write(Path.Combine("appdata", "Claude", "claude_desktop_config.json"), McpJson("mcpServers", "gh", "GITHUB_TOKEN", FakeTokens.GitHubClassic()));
        _temp.Write(Path.Combine("home", ".cursor", "mcp.json"), McpJson("mcpServers", "x", "OPENAI_API_KEY", FakeTokens.OpenAi()));
        _temp.Write(Path.Combine("home", ".codex", "config.toml"), $"[mcp_servers.s]\ncommand = \"s\"\nenv = {{ HF_TOKEN = \"{FakeTokens.HuggingFace()}\" }}\n");
        _temp.Write(Path.Combine("home", ".git-credentials"), $"https://me:{FakeTokens.GitHubClassic(40)}@github.com\n");
        _temp.Write(Path.Combine("appdata", "Microsoft", "Windows", "PowerShell", "PSReadLine", "ConsoleHost_history.txt"), $"$env:STRIPE_KEY='{FakeTokens.StripeLive()}'\n");
        _temp.Write(Path.Combine("home", ".claude", ".credentials.json"), "{\"claudeAiOauth\":{}}");
        _temp.Write(Path.Combine("localappdata", "Packages", "Claude_abc123", "LocalCache", "Roaming", "Claude", "claude_desktop_config.json"), McpJson("mcpServers", "a", "ANTHROPIC_API_KEY", FakeTokens.Anthropic()));

        var result = new Scanner(environment: env).Scan(new ScanOptions([], [], IncludeDefaultLocations: true));
        var clients = result.Findings.Where(f => f.Kind == FindingKind.InlineSecret).Select(f => f.Client).ToHashSet();
        Assert.Contains("Claude Desktop", clients);
        Assert.Contains("Claude Desktop (Store)", clients);
        Assert.Contains("Cursor", clients);
        Assert.Contains("OpenAI Codex", clients);
        Assert.Contains("Git", clients);
        Assert.Contains("PowerShell", clients);
        var token = Assert.Single(result.Findings, f => f.Kind == FindingKind.ToolTokenFile);
        Assert.Equal("Claude Code", token.Provider);
        Assert.Contains("revoke", token.RiskNote, StringComparison.OrdinalIgnoreCase);
        Assert.Contains(result.Files, f => f.Mcp == McpFormat.CodexToml);
    }

    [Fact]
    public void Project_roots_find_env_files_and_project_mcp_configs_but_skip_dependencies()
    {
        _temp.Write(Path.Combine("app", ".env.local"), $"TOKEN={FakeTokens.Npm()}\n");
        _temp.Write(Path.Combine("app", ".vscode", "mcp.json"), McpJson("servers", "x", "K", FakeTokens.SendGrid()));
        _temp.Write(Path.Combine("app", "node_modules", "pkg", ".env"), $"TOKEN={FakeTokens.Npm(9)}\n");
        var result = new Scanner(environment: ScanEnvironment.Under(_temp.Path)).Scan(new ScanOptions([], [_temp.Path], IncludeDefaultLocations: false));
        Assert.Equal(2, result.Findings.Count);
        Assert.DoesNotContain(result.Findings, f => f.FilePath.Contains("node_modules", StringComparison.Ordinal));
        Assert.Contains(result.Files, f => f.Mcp == McpFormat.VsCodeServersJson);
    }

    [Fact]
    public void Sarif_output_is_valid_2_1_0_with_relative_uris()
    {
        _temp.Write(Path.Combine("repo", "config", "settings.yaml"), $"slack: {FakeTokens.Slack()}\n");
        var result = new Scanner(environment: ScanEnvironment.Under(_temp.Path)).Scan(new ScanOptions([_temp.Combine("repo")], [], IncludeDefaultLocations: false));
        using var sarif = JsonDocument.Parse(Reports.ToSarif(result, _temp.Combine("repo")));
        var root = sarif.RootElement;
        Assert.Equal("2.1.0", root.GetProperty("version").GetString());
        var run = root.GetProperty("runs")[0];
        Assert.Equal("Hush", run.GetProperty("tool").GetProperty("driver").GetProperty("name").GetString());
        var location = run.GetProperty("results")[0].GetProperty("locations")[0].GetProperty("physicalLocation");
        Assert.Equal("config/settings.yaml", location.GetProperty("artifactLocation").GetProperty("uri").GetString());
        Assert.Equal(1, location.GetProperty("region").GetProperty("startLine").GetInt32());
        Assert.Equal("slack-token", run.GetProperty("tool").GetProperty("driver").GetProperty("rules")[0].GetProperty("id").GetString());
    }

    [Fact]
    public void Embedded_rules_cover_every_required_provider()
    {
        var providers = RuleSet.Embedded.Rules.Select(r => r.Provider).ToHashSet(StringComparer.OrdinalIgnoreCase);
        foreach (var required in new[] { "OpenAI", "Anthropic", "Google AI / Google Cloud", "GitHub", "GitLab", "Slack", "Discord", "Stripe", "AWS", "Azure", "Google Cloud", "npm", "PyPI", "Hugging Face", "Twilio", "SendGrid", "Database", "Cryptography", "Generic" })
        {
            Assert.Contains(required, providers);
        }
    }

    private static string McpJson(string root, string server, string key, string value) =>
        "{\"" + root + "\":{\"" + server + "\":{\"command\":\"" + server + "\",\"env\":{\"" + key + "\":\"" + value + "\"}}}}";
}
