using System.Text.Json;
using Hush.Cli.Commands;
using Hush.Core.Manifest;
using Hush.Core.Vault;
using Hush.Tests.Support;
using Xunit;

namespace Hush.Cli.Tests;

public sealed class CliEndToEndTests : IDisposable
{
    private readonly CliHarness _h = new();

    public void Dispose() => _h.Dispose();

    private static void OkOther(CliHarness other, int code) => Assert.True(code == 0, $"exit {code}: {other.Error}");

    private void Ok(int code) => Assert.True(code == 0, $"exit {code}: {_h.Error}");

    private async Task InitAsync()
    {
        Ok(await _h.RunAsync("init"));
        Assert.Matches(@"([0-9A-Z]{4}-){8}[0-9A-Z]{4}", _h.Out);
    }

    private async Task SetAsync(string name, string value, params string[] extra)
    {
        var code = await _h.RunAsync(new FakeTerminal { Input = value + "\n" }, ["set", name, .. extra]);
        Assert.True(code == 0, _h.Error);
    }

    [Fact]
    public async Task Init_shows_the_recovery_key_and_unlocks_the_session()
    {
        await InitAsync();
        Assert.Contains("Vault created and unlocked", _h.Out, StringComparison.Ordinal);
        Assert.True(_h.Broker.IsUnlocked);
        Assert.Equal(1, await _h.RunAsync("init"));
        Assert.Contains("already exists", _h.Error, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Init_asks_to_confirm_the_recovery_key_when_interactive()
    {
        var terminal = new FakeTerminal().Answer("nope", "still-wrong", "wrong-again");
        Ok(await _h.RunAsync(terminal, "init"));
        Assert.Contains("make sure you have the recovery key", _h.Error, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Set_reads_stdin_and_list_never_shows_values()
    {
        await InitAsync();
        await SetAsync("API_KEY", "list-must-not-show-this");
        await SetAsync("DB", "x", "--scope", "shop", "--policy", "always-prompt");

        Ok(await _h.RunAsync("list"));
        Assert.Contains("API_KEY", _h.Out, StringComparison.Ordinal);
        Assert.Contains("always-prompt", _h.Out, StringComparison.Ordinal);
        Assert.DoesNotContain("list-must-not-show-this", _h.Out, StringComparison.Ordinal);

        Ok(await _h.RunAsync("list", "--json"));
        using var json = JsonDocument.Parse(_h.Out);
        Assert.Equal(2, json.RootElement.GetArrayLength());
    }

    [Fact]
    public async Task Set_from_a_hidden_prompt_requires_matching_confirmation()
    {
        await InitAsync();
        Assert.Equal(2, await _h.RunAsync(new FakeTerminal().Answer("one", "two"), "set", "K"));
        Assert.Contains("do not match", _h.Error, StringComparison.Ordinal);
        Ok(await _h.RunAsync(new FakeTerminal().Answer("same", "same"), "set", "K"));
    }

    [Fact]
    public async Task Run_injects_secrets_from_the_option_and_from_the_manifest()
    {
        await InitAsync();
        await SetAsync("TOKEN", "from-the-vault");
        await SetAsync("DATABASE_URL", "scoped-db", "--scope", "project");

        Ok(await _h.RunAsync("run", "--secrets", "TOKEN,ALIAS=TOKEN", "--mask", "--", "cmd.exe", "/d", "/c", "echo [%TOKEN%][%ALIAS%]"));
        Assert.Contains("[••••][••••]", _h.ChildText, StringComparison.Ordinal);

        File.WriteAllText(Path.Combine(_h.Project, ProjectManifest.FileName), "version = 1\nproject = \"project\"\n[env]\nDB = \"DATABASE_URL\"\nTOKEN = \"TOKEN\"\n");
        var output = _h.Temp.Combine("child.txt");
        Ok(await _h.RunAsync("run", "--", "cmd.exe", "/d", "/c", $"echo %DB%;%TOKEN%> {output}"));
        Assert.Equal("scoped-db;from-the-vault", File.ReadAllText(output).Trim());
    }

    [Fact]
    public async Task Run_propagates_the_exit_code_and_audits_the_read()
    {
        await InitAsync();
        await SetAsync("TOKEN", "v");
        Assert.Equal(42, await _h.RunAsync("run", "--secrets", "TOKEN", "--", "cmd.exe", "/d", "/c", "exit 42"));
        Ok(await _h.RunAsync("audit", "--filter", "secret.read"));
        Assert.Contains("TOKEN", _h.Out, StringComparison.Ordinal);
        Assert.Contains("run: cmd.exe", _h.Out, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Run_without_secrets_or_manifest_is_a_usage_error()
    {
        await InitAsync();
        Assert.Equal(2, await _h.RunAsync("run", "--", "cmd.exe", "/c", "exit 0"));
        Assert.Contains(".hush.toml", _h.Error, StringComparison.Ordinal);
        Assert.Equal(1, await _h.RunAsync("run", "--secrets", "MISSING", "--", "cmd.exe", "/c", "exit 0"));
        Assert.Contains("Not in the vault", _h.Error, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Get_requires_an_explicit_mode_and_confirmation_to_reveal()
    {
        await InitAsync();
        await SetAsync("TOKEN", "revealed-value");
        Assert.Equal(2, await _h.RunAsync("get", "TOKEN"));
        Assert.Equal(2, await _h.RunAsync("get", "TOKEN", "--reveal"));
        Assert.Equal(1, await _h.RunAsync(new FakeTerminal().Answer("n"), "get", "TOKEN", "--reveal"));
        Assert.DoesNotContain("revealed-value", _h.Out, StringComparison.Ordinal);
        Ok(await _h.RunAsync(new FakeTerminal().Answer("y"), "get", "TOKEN", "--reveal"));
        Assert.Contains("revealed-value", _h.Out, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Rm_requires_confirmation_or_yes()
    {
        await InitAsync();
        await SetAsync("GONE", "v");
        Assert.Equal(2, await _h.RunAsync("rm", "GONE"));
        Ok(await _h.RunAsync("rm", "GONE", "--yes"));
        Assert.Equal(1, await _h.RunAsync("rm", "GONE", "--yes"));
    }

    [Fact]
    public async Task Lock_status_and_unlock_report_the_session_state()
    {
        await InitAsync();
        Ok(await _h.RunAsync("status"));
        Assert.Contains("unlocked", _h.Out, StringComparison.Ordinal);
        Ok(await _h.RunAsync("lock"));
        Assert.False(_h.Broker.IsUnlocked);
        Ok(await _h.RunAsync("status", "--json"));
        using (var json = JsonDocument.Parse(_h.Out))
        {
            Assert.False(json.RootElement.GetProperty("unlocked").GetBoolean());
            Assert.Equal(10, json.RootElement.GetProperty("idleTimeoutMinutes").GetInt32());
        }

        Ok(await _h.RunAsync("unlock"));
        Assert.True(_h.Broker.IsUnlocked);
    }

    [Fact]
    public async Task Cancelled_unlocks_are_audited_as_deferred_entries()
    {
        await InitAsync();
        Ok(await _h.RunAsync("lock"));
        _h.Provider.CancelNextPrompt = true;
        Assert.Equal(130, await _h.RunAsync("unlock"));
        Assert.True(File.Exists(_h.Temp.HushPaths.PendingAudit));

        Ok(await _h.RunAsync("unlock"));
        var records = new Core.Audit.AuditLog(_h.Temp.HushPaths.AuditLog).ReadAll();
        Assert.Contains(records, r => r.Action == "session.unlock" && r.Result == "cancelled" && r.Deferred);
        Ok(await _h.RunAsync("audit", "--verify"));
    }

    [Fact]
    public async Task Production_hush_exe_refuses_a_vault_created_by_the_test_provider()
    {
        await InitAsync();
        var hush = Path.Combine(AppContext.BaseDirectory, "hush.exe");
        var start = new System.Diagnostics.ProcessStartInfo(hush, "rotate --yes")
        {
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            RedirectStandardInput = true,
            UseShellExecute = false,
        };
        start.Environment[Core.HushPaths.HomeVariable] = _h.Temp.HushPaths.Home;
        using var process = System.Diagnostics.Process.Start(start)!;
        var error = await process.StandardError.ReadToEndAsync();
        await process.WaitForExitAsync();

        Assert.Equal(1, process.ExitCode);
        Assert.Contains("created by the Hush test suite", error, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Degraded_vaults_show_the_warning_on_every_command()
    {
        _h.Provider.SecondFactor = Core.Keys.SecondFactorKind.Dpapi;
        await InitAsync();
        Assert.Contains("degraded", _h.Error, StringComparison.OrdinalIgnoreCase);
        Ok(await _h.RunAsync("list"));
        Assert.Contains("degraded", _h.Error, StringComparison.OrdinalIgnoreCase);
        Ok(await _h.RunAsync("status"));
        Assert.Contains("DEGRADED", _h.Out, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Audit_verify_reports_an_intact_and_a_tampered_chain()
    {
        await InitAsync();
        await SetAsync("A", "1");
        Ok(await _h.RunAsync("audit", "--verify"));
        Assert.Contains("Audit chain intact", _h.Out, StringComparison.Ordinal);

        var lines = File.ReadAllLines(_h.Temp.HushPaths.AuditLog).ToList();
        lines.RemoveAt(1);
        File.WriteAllLines(_h.Temp.HushPaths.AuditLog, lines);
        Assert.Equal(1, await _h.RunAsync("audit", "--verify"));
        Assert.Contains("BROKEN", _h.Out, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Export_and_import_move_secrets_with_the_recovery_key()
    {
        Ok(await _h.RunAsync("init"));
        var recovery = System.Text.RegularExpressions.Regex.Match(_h.Out, @"([0-9A-Z]{4}-){8}[0-9A-Z]{4}").Value;
        await SetAsync("MOVE_ME", "portable-value");
        var export = _h.Temp.Combine("backup.hushx");
        Ok(await _h.RunAsync("export", "--encrypted", export));
        Assert.DoesNotContain("portable-value", File.ReadAllText(export), StringComparison.Ordinal);

        using var other = new CliHarness();
        OkOther(other, await other.RunAsync("init"));
        Assert.Equal(1, await other.RunAsync(new FakeTerminal().Answer(new string('0', 36)), "import", export));
        OkOther(other, await other.RunAsync(new FakeTerminal().Answer(recovery), "import", export));
        Assert.Contains("Imported 1", other.Out, StringComparison.Ordinal);
        var output = other.Temp.Combine("moved.txt");
        OkOther(other, await other.RunAsync("run", "--secrets", "MOVE_ME", "--", "cmd.exe", "/d", "/c", $"echo %MOVE_ME%> {output}"));
        Assert.Equal("portable-value", File.ReadAllText(output).Trim());
    }

    [Fact]
    public async Task Recover_and_rotate_work_through_the_cli()
    {
        Ok(await _h.RunAsync("init"));
        var recovery = System.Text.RegularExpressions.Regex.Match(_h.Out, @"([0-9A-Z]{4}-){8}[0-9A-Z]{4}").Value;
        await SetAsync("KEEP", "kept");
        _h.Provider.ResetHello();

        Ok(await _h.RunAsync(new FakeTerminal().Answer(recovery), "recover"));
        Assert.Contains("Recovered", _h.Out, StringComparison.Ordinal);
        Ok(await _h.RunAsync("rotate", "--yes"));
        var newKey = System.Text.RegularExpressions.Regex.Match(_h.Out, @"([0-9A-Z]{4}-){8}[0-9A-Z]{4}").Value;
        Assert.NotEqual(recovery, newKey);
        Ok(await _h.RunAsync("run", "--secrets", "KEEP", "--mask", "--", "cmd.exe", "/d", "/c", "echo %KEEP%"));
        Assert.Contains("••••", _h.ChildText, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Scan_and_migrate_rewrite_a_planted_mcp_config()
    {
        await InitAsync();
        var token = FakeTokens.GitHubClassic(900);
        var config = _h.Temp.Write(Path.Combine("fake-profile", "appdata", "Claude", "claude_desktop_config.json"),
            "{\n  \"mcpServers\": {\n    \"github\": {\n      \"command\": \"npx\",\n      \"args\": [\"-y\", \"@modelcontextprotocol/server-github\"],\n      \"env\": { \"GITHUB_PERSONAL_ACCESS_TOKEN\": \"" + token + "\" }\n    }\n  }\n}\n");

        Assert.Equal(ScanCommands.FindingsExitCode, await _h.RunAsync("scan", "--exit-code"));
        Assert.Contains("GitHub", _h.Out, StringComparison.Ordinal);
        Assert.DoesNotContain(token, _h.Out, StringComparison.Ordinal);

        Ok(await _h.RunAsync("migrate", "--dry-run"));
        Assert.Contains("+      \"command\": \"hush\"", _h.Out, StringComparison.Ordinal);
        Assert.DoesNotContain(token, _h.Out, StringComparison.Ordinal);
        Assert.Contains(token, File.ReadAllText(config), StringComparison.Ordinal);

        Ok(await _h.RunAsync("migrate", "--yes"));
        Assert.DoesNotContain(token, File.ReadAllText(config), StringComparison.Ordinal);
        Assert.Contains("\"--secrets\", \"GITHUB_PERSONAL_ACCESS_TOKEN\"", File.ReadAllText(config), StringComparison.Ordinal);

        var output = _h.Temp.Combine("gh.txt");
        Ok(await _h.RunAsync("run", "--secrets", "GITHUB_PERSONAL_ACCESS_TOKEN", "--", "cmd.exe", "/d", "/c", $"echo %GITHUB_PERSONAL_ACCESS_TOKEN%> {output}"));
        Assert.Equal(token, File.ReadAllText(output).Trim());

        Ok(await _h.RunAsync("migrate", "--undo"));
        Assert.Contains(token, File.ReadAllText(config), StringComparison.Ordinal);
        Assert.Equal(1, await _h.RunAsync("run", "--secrets", "GITHUB_PERSONAL_ACCESS_TOKEN", "--", "cmd.exe", "/c", "exit 0"));
    }

    [Fact]
    public async Task Scan_writes_sarif_reports()
    {
        _h.Temp.Write(Path.Combine("project", "app.config"), "sendgrid=" + FakeTokens.SendGrid(901) + "\n");
        var report = _h.Temp.Combine("hush.sarif");
        Ok(await _h.RunAsync("scan", ".", "--no-defaults", "--sarif", "--output", report));
        using var sarif = JsonDocument.Parse(File.ReadAllText(report));
        Assert.Equal("app.config", sarif.RootElement.GetProperty("runs")[0].GetProperty("results")[0].GetProperty("locations")[0].GetProperty("physicalLocation").GetProperty("artifactLocation").GetProperty("uri").GetString());
    }

    [Fact]
    public async Task Init_project_creates_a_manifest()
    {
        Ok(await _h.RunAsync("init", "--project"));
        var manifest = ProjectManifest.Load(Path.Combine(_h.Project, ProjectManifest.FileName));
        Assert.Equal("project", manifest.Project);
        Assert.Equal(2, await _h.RunAsync("init", "--project"));
    }

    [Fact]
    public async Task Config_changes_settings_and_validates_them()
    {
        Ok(await _h.RunAsync("config"));
        Assert.Contains("idle-timeout   10", _h.Out, StringComparison.Ordinal);
        Ok(await _h.RunAsync("config", "idle-timeout", "15"));
        Ok(await _h.RunAsync("config", "idle-timeout"));
        Assert.Equal("15", _h.Out.Trim());
        Assert.Equal(2, await _h.RunAsync("config", "idle-timeout", "0"));
        Assert.Equal(2, await _h.RunAsync("config", "colour", "blue"));
    }

    [Fact]
    public async Task Git_helper_serves_vaulted_credentials()
    {
        await InitAsync();
        await SetAsync("octo@github.com", "git-password", "--scope", "git");
        Ok(await _h.RunAsync(new FakeTerminal { Input = "protocol=https\nhost=github.com\n\n" }, "git-helper", "get"));
        Assert.Equal("username=octo\npassword=git-password\n", _h.Out);

        Ok(await _h.RunAsync(new FakeTerminal { Input = "protocol=https\nhost=gitlab.com\nusername=octo\n\n" }, "git-helper", "get"));
        Assert.Equal(string.Empty, _h.Out);
        Ok(await _h.RunAsync(new FakeTerminal { Input = "protocol=https\nhost=github.com\nusername=octo\npassword=x\n\n" }, "git-helper", "store"));
        Assert.Equal(string.Empty, _h.Out);
    }

    [Fact]
    public void Git_helper_lookup_matches_user_and_host()
    {
        var document = new VaultDocument
        {
            FormatVersion = 1,
            Flags = VaultAttributes.None,
            VaultId = Guid.NewGuid(),
            Salt = new byte[32],
            Challenge = new byte[32],
            Created = DateTimeOffset.UtcNow,
            Updated = DateTimeOffset.UtcNow,
            Generation = 1,
            AuditSequence = 0,
            AuditHead = new byte[32],
            Factors = null,
            WrappedAuditKey = [],
            WrappedKeys = [],
            Entries = [new VaultEntry(Guid.NewGuid(), 1, "git", "me@git.example.com_8443", SecretPolicy.Session, DateTimeOffset.UtcNow, DateTimeOffset.UtcNow, null, [])],
        };
        Assert.NotNull(GitHelperCommand.FindCredential(document, "git.example.com:8443", null));
        Assert.NotNull(GitHelperCommand.FindCredential(document, "git.example.com:8443", "me"));
        Assert.Null(GitHelperCommand.FindCredential(document, "git.example.com:8443", "you"));
        Assert.Equal("v", GitHelperCommand.ParseAttributes("host=h\nk=v\n\nignored=1")["k"]);
    }
}
