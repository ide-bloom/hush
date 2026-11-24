using System.CommandLine;
using Hush.Agent;
using Hush.Cli.Commands;
using Hush.Cli.Terminal;
using Hush.Core;
using Hush.Core.Protocol;

namespace Hush.Cli;

/// <summary>Builds the command tree and runs it.</summary>
internal static class CliApp
{
    private static readonly HashSet<string> NoBanner = new(StringComparer.Ordinal) { "agent", "git-helper", "init", "status" };

    public static async Task<int> RunAsync(string[] args, CliServices services, CancellationToken cancellationToken = default)
    {
        var root = Build(services);
        var parse = root.Parse(args, new ParserConfiguration { ResponseFileTokenReplacer = null });
        if (parse.Errors.Count == 0 && !NoBanner.Contains(parse.CommandResult.Command.Name))
        {
            WarnIfDegraded(services);
        }

        try
        {
            return await parse.InvokeAsync(new InvocationConfiguration { EnableDefaultExceptionHandler = false }, cancellationToken).ConfigureAwait(false);
        }
        catch (HushException ex)
        {
            services.Terminal.Error.WriteLine(services.Terminal.Red("hush: ") + ex.Message);
            return ex.Code switch
            {
                HushErrorCode.InvalidInput or HushErrorCode.ManifestInvalid => 2,
                HushErrorCode.HelloCancelled => 130,
                _ => 1,
            };
        }
        catch (OperationCanceledException)
        {
            services.Terminal.Error.WriteLine("hush: cancelled.");
            return 130;
        }
    }

    internal static RootCommand Build(CliServices s)
    {
        var root = new RootCommand("Hush: TPM- and Windows Hello-bound secrets for developers and AI agents.");

        // init
        var initProject = new Option<bool>("--project") { Description = "Create a .hush.toml manifest in the current directory instead of a vault." };
        var init = new Command("init", "Create the vault, enroll Windows Hello and the TPM, and show the recovery key once.") { initProject };
        init.SetAction((r, ct) => VaultCommands.InitAsync(s, r.GetValue(initProject), ct));

        // status
        var statusJson = new Option<bool>("--json") { Description = "Machine-readable output." };
        var status = new Command("status", "Vault health, factors, lock state, timeout and number of secrets.") { statusJson };
        status.SetAction((r, ct) => VaultCommands.StatusAsync(s, r.GetValue(statusJson), ct));

        var unlock = new Command("unlock", "Unlock the session with Windows Hello.");
        unlock.SetAction((_, ct) => VaultCommands.UnlockAsync(s, ct));
        var lockCommand = new Command("lock", "Lock the session now.");
        lockCommand.SetAction((_, ct) => VaultCommands.LockAsync(s, ct));

        // set
        var setName = new Argument<string>("NAME") { Description = "Secret name, optionally scope/NAME." };
        var setPolicy = new Option<string?>("--policy") { Description = "session (default) or always-prompt (Windows Hello on every use)." };
        setPolicy.AcceptOnlyFromAmong("session", "always-prompt");
        var setScope = new Option<string?>("--scope") { Description = "Project scope (default: global)." };
        var set = new Command("set", "Store a secret. The value is read from a hidden prompt or stdin, never from the command line.") { setName, setPolicy, setScope };
        set.SetAction((r, ct) => VaultCommands.SetAsync(s, r.GetValue(setName)!, r.GetValue(setPolicy), r.GetValue(setScope), ct));

        // get
        var getName = new Argument<string>("NAME") { Description = "Secret name, optionally scope/NAME." };
        var getScope = new Option<string?>("--scope") { Description = "Project scope." };
        var getCopy = new Option<bool>("--copy") { Description = "Copy to the clipboard (kept out of history and cloud sync; cleared after 30 s)." };
        var getReveal = new Option<bool>("--reveal") { Description = "Print the value (asks for confirmation)." };
        var get = new Command("get", "Copy or reveal one secret.") { getName, getScope, getCopy, getReveal };
        get.SetAction((r, ct) => VaultCommands.GetAsync(s, r.GetValue(getName)!, r.GetValue(getScope), r.GetValue(getCopy), r.GetValue(getReveal), ct));

        // list
        var listScope = new Option<string?>("--scope") { Description = "Only this scope." };
        var listJson = new Option<bool>("--json") { Description = "Machine-readable output." };
        var list = new Command("list", "Names, scopes, policies and last use. Never values.") { listScope, listJson };
        list.Aliases.Add("ls");
        list.SetAction(r => VaultCommands.List(s, r.GetValue(listScope), r.GetValue(listJson)));

        // rm
        var rmName = new Argument<string>("NAME") { Description = "Secret name, optionally scope/NAME." };
        var rmScope = new Option<string?>("--scope") { Description = "Project scope." };
        var rmYes = new Option<bool>("--yes", "-y") { Description = "Do not ask for confirmation." };
        var rm = new Command("rm", "Delete a secret.") { rmName, rmScope, rmYes };
        rm.SetAction((r, ct) => VaultCommands.RemoveAsync(s, r.GetValue(rmName)!, r.GetValue(rmScope), r.GetValue(rmYes), ct));

        // run
        var runSecrets = new Option<string?>("--secrets") { Description = "Comma-separated NAME or VAR=NAME items (default: the project's .hush.toml)." };
        var runProfile = new Option<string?>("--profile") { Description = "Manifest profile, e.g. staging (default: default_profile or HUSH_PROFILE)." };
        var runMask = new Option<bool>("--mask") { Description = "Replace secret values in the child's stdout/stderr with ••••." };
        var runCommand = new Argument<string[]>("command") { Description = "The command to run, after --.", Arity = ArgumentArity.ZeroOrMore };
        var run = new Command("run", "Run a command with secrets added to its environment.") { runSecrets, runProfile, runMask, runCommand };
        run.SetAction((r, ct) => RunCommand.RunAsync(s, r.GetValue(runSecrets), r.GetValue(runProfile), r.GetValue(runMask), r.GetValue(runCommand) ?? [], ct));

        // scan
        var scanPaths = new Argument<string[]>("paths") { Description = "Extra files or directories to scan.", Arity = ArgumentArity.ZeroOrMore };
        var scanJson = new Option<bool>("--json") { Description = "JSON output." };
        var scanSarif = new Option<bool>("--sarif") { Description = "SARIF 2.1.0 output for GitHub code scanning." };
        var scanOutput = new Option<string?>("--output", "-o") { Description = "Write the report to a file." };
        var scanNoDefaults = new Option<bool>("--no-defaults") { Description = "Scan only the given paths (not the well-known locations)." };
        var scanExitCode = new Option<bool>("--exit-code") { Description = $"Exit with code {ScanCommands.FindingsExitCode} when anything is found (for CI)." };
        var scan = new Command("scan", "Find plaintext secrets and report them redacted.") { scanPaths, scanJson, scanSarif, scanOutput, scanNoDefaults, scanExitCode };
        scan.SetAction((r, ct) => ScanCommands.ScanAsync(s, r.GetValue(scanPaths) ?? [], r.GetValue(scanJson), r.GetValue(scanSarif), r.GetValue(scanOutput), r.GetValue(scanNoDefaults), r.GetValue(scanExitCode), ct));

        // migrate
        var migratePaths = new Argument<string[]>("paths") { Description = "Extra files or directories to migrate.", Arity = ArgumentArity.ZeroOrMore };
        var migrateDryRun = new Option<bool>("--dry-run") { Description = "Show what would change, as a redacted unified diff." };
        var migrateUndo = new Option<bool>("--undo") { Description = "Restore the files from the last migration and remove the secrets it added." };
        var migrateYes = new Option<bool>("--yes", "-y") { Description = "Apply without asking." };
        var migrateForce = new Option<bool>("--force") { Description = "With --undo: restore even if files were edited since." };
        var migrateNoDefaults = new Option<bool>("--no-defaults") { Description = "Only the given paths." };
        var migrate = new Command("migrate", "Move scan findings into the vault and rewrite configs to use Hush.") { migratePaths, migrateDryRun, migrateUndo, migrateYes, migrateForce, migrateNoDefaults };
        migrate.SetAction((r, ct) => ScanCommands.MigrateAsync(s, r.GetValue(migratePaths) ?? [], r.GetValue(migrateDryRun), r.GetValue(migrateUndo), r.GetValue(migrateYes), r.GetValue(migrateForce), r.GetValue(migrateNoDefaults), ct));

        // audit
        var auditVerify = new Option<bool>("--verify") { Description = "Verify the HMAC chain against the head stored in the vault." };
        var auditLast = new Option<int>("--last", "-n") { Description = "Number of entries to show.", DefaultValueFactory = _ => 50 };
        var auditFilter = new Option<string?>("--filter") { Description = "Only entries whose action, secret or process contains this text." };
        var audit = new Command("audit", "Show the audit log.") { auditVerify, auditLast, auditFilter };
        audit.SetAction((r, ct) => AuditCommand.RunAsync(s, r.GetValue(auditVerify), r.GetValue(auditLast), r.GetValue(auditFilter), ct));

        var recover = new Command("recover", "Restore access with the recovery key and enroll new Windows Hello and TPM factors.");
        recover.SetAction((_, ct) => VaultCommands.RecoverAsync(s, ct));

        var rotateYes = new Option<bool>("--yes", "-y") { Description = "Do not ask for confirmation." };
        var rotate = new Command("rotate", "Re-encrypt every secret under a new vault key and issue a new recovery key.") { rotateYes };
        rotate.SetAction((r, ct) => VaultCommands.RotateAsync(s, r.GetValue(rotateYes), ct));

        var exportFile = new Option<string>("--encrypted") { Description = "Destination file. Exports are always encrypted with the recovery key.", Required = true };
        var export = new Command("export", "Write an encrypted backup that opens with the recovery key on any PC.") { exportFile };
        export.SetAction((r, ct) => VaultCommands.ExportAsync(s, r.GetValue(exportFile)!, ct));

        var importFile = new Argument<string>("file") { Description = "A file written by 'hush export'." };
        var importOverwrite = new Option<bool>("--overwrite") { Description = "Replace secrets that already exist." };
        var import = new Command("import", "Import an encrypted export (asks for its recovery key).") { importFile, importOverwrite };
        import.SetAction((r, ct) => VaultCommands.ImportAsync(s, r.GetValue(importFile)!, r.GetValue(importOverwrite), ct));

        var configKey = new Argument<string?>("key") { Description = "idle-timeout, lock-on-sleep or scan-roots.", Arity = ArgumentArity.ZeroOrOne };
        var configValue = new Argument<string?>("value") { Description = "New value.", Arity = ArgumentArity.ZeroOrOne };
        var config = new Command("config", "Show or change settings.") { configKey, configValue };
        config.SetAction((r, ct) => VaultCommands.ConfigAsync(s, r.GetValue(configKey), r.GetValue(configValue), ct));

        var agentStop = new Option<bool>("--stop") { Description = "Lock and stop the running agent." };
        var agent = new Command("agent", "Run the session broker (started automatically when needed).") { agentStop };
        agent.SetAction(async (r, ct) =>
        {
            if (!r.GetValue(agentStop))
            {
                return await AgentHost.RunAsync(ct).ConfigureAwait(false);
            }

            if (await s.TryAgentStatusAsync(ct).ConfigureAwait(false) is null)
            {
                s.Terminal.Out.WriteLine("The agent is not running.");
                return 0;
            }

            (await s.Transport(false).SendAsync(new BrokerRequest { Op = BrokerOps.Shutdown }, ct).ConfigureAwait(false)).EnsureSuccess();
            s.Terminal.Out.WriteLine("Agent stopped.");
            return 0;
        });

        var gitOperation = new Argument<string>("operation") { Description = "get, store or erase (called by Git)." };
        var gitHelper = new Command("git-helper", "Git credential helper serving vaulted credentials.") { gitOperation };
        gitHelper.SetAction((r, ct) => GitHelperCommand.RunAsync(s, r.GetValue(gitOperation)!, ct));

        foreach (var command in new[] { init, status, unlock, lockCommand, set, get, list, rm, run, scan, migrate, audit, recover, rotate, export, import, config, agent, gitHelper })
        {
            root.Add(command);
        }

        return root;
    }

    private static void WarnIfDegraded(CliServices s)
    {
        if (!s.Manager.Exists)
        {
            return;
        }

        try
        {
            var document = s.Manager.ReadDocument();
            if (document.IsDegraded)
            {
                VaultCommands.WriteDegradedWarning(s.Terminal, document.Factors?.DegradedReason);
            }
        }
        catch (HushException ex)
        {
            // An unreadable vault is reported by the command itself with full context; the banner only notes it.
            s.Terminal.Error.WriteLine(s.Terminal.Dim($"(could not read the vault header: {ex.Message})"));
        }
    }
}
