using System.Globalization;
using System.Text;
using System.Text.Json;
using Hush.Cli.Terminal;
using Hush.Core;
using Hush.Core.Crypto;
using Hush.Core.Manifest;
using Hush.Core.Protocol;
using Hush.Core.Settings;
using Hush.Core.Vault;

namespace Hush.Cli.Commands;

/// <summary>init, status, unlock, lock, set, get, list, rm, recover, rotate, export, import, config.</summary>
internal static class VaultCommands
{
    private const int ClipboardSeconds = 30;

    public static async Task<int> InitAsync(CliServices s, bool project, CancellationToken ct)
    {
        var t = s.Terminal;
        if (project)
        {
            return InitProject(s);
        }

        if (s.Manager.Exists)
        {
            throw new HushException(HushErrorCode.VaultAlreadyExists, $"A vault already exists at {s.Manager.Store.Path}. Use 'hush status' to inspect it.");
        }

        t.Out.WriteLine(t.Bold("Creating your Hush vault."));
        t.Out.WriteLine("Windows Hello will ask you to verify three times: once to create the vault key, then twice to");
        t.Out.WriteLine("confirm its signatures are stable enough to derive an encryption key from.");
        t.Out.WriteLine();
        var creation = await s.Manager.CreateAsync(s.Prompt("Create your Hush vault"), new SynchronousProgress(m => t.Error.WriteLine(t.Dim(m))), ct).ConfigureAwait(false);
        using var vault = creation.Vault;
        using var recovery = creation.RecoveryKey;

        if (vault.Document.IsDegraded)
        {
            WriteDegradedWarning(t, vault.Document.Factors?.DegradedReason);
        }

        ShowRecoveryKey(t, recovery, "This is the ONLY way back in if Windows Hello is reset, the TPM is cleared, or you move to a new PC.");
        ConfirmRecoveryKeySaved(t, recovery);

        await s.Session.HandOverAsync(vault, ct).ConfigureAwait(false);
        t.Out.WriteLine(t.Green("Vault created and unlocked."));
        t.Out.WriteLine($"  Vault:   {s.Manager.Store.Path}");
        t.Out.WriteLine($"  Factors: {FactorsText(vault.Document)}");
        t.Out.WriteLine();
        t.Out.WriteLine("Next: 'hush scan' to find plaintext secrets, 'hush migrate' to move them in, 'hush run -- <cmd>' to use them.");
        return 0;
    }

    public static async Task<int> StatusAsync(CliServices s, bool json, CancellationToken ct)
    {
        var t = s.Terminal;
        var agent = await s.TryAgentStatusAsync(ct).ConfigureAwait(false);
        var settings = HushSettings.Load(s.Paths);
        VaultDocument? document = s.Manager.Exists ? s.Manager.ReadDocument() : null;

        if (json)
        {
            using var buffer = new MemoryStream();
            using (var w = new Utf8JsonWriter(buffer, new JsonWriterOptions { Indented = true }))
            {
                w.WriteStartObject();
                w.WriteBoolean("vaultExists", document is not null);
                w.WriteString("vaultPath", s.Manager.Store.Path);
                if (document is not null)
                {
                    w.WriteString("secondFactor", document.Factors?.SecondFactor.ToString().ToLowerInvariant());
                    w.WriteBoolean("degraded", document.IsDegraded);
                    if (document.Factors?.DegradedReason is { } reason)
                    {
                        w.WriteString("degradedReason", reason);
                    }

                    w.WriteNumber("secrets", document.Entries.Count);
                    w.WriteString("created", document.Created.ToString("O", CultureInfo.InvariantCulture));
                }

                w.WriteBoolean("agentRunning", agent is not null);
                w.WriteBoolean("unlocked", agent?.Unlocked ?? false);
                if (agent?.IdleRemainingSeconds is { } remaining)
                {
                    w.WriteNumber("idleRemainingSeconds", remaining);
                }

                w.WriteNumber("idleTimeoutMinutes", settings.IdleTimeoutMinutes);
                w.WriteBoolean("lockOnSleep", settings.LockOnSleep);
                w.WriteEndObject();
            }

            t.Out.WriteLine(Encoding.UTF8.GetString(buffer.ToArray()));
            return 0;
        }

        if (document is null)
        {
            t.Out.WriteLine($"No vault yet ({s.Manager.Store.Path}). Run 'hush init'.");
            return 0;
        }

        t.Out.WriteLine($"{t.Bold("Vault")}      {s.Manager.Store.Path}");
        t.Out.WriteLine($"{t.Bold("Factors")}    {FactorsText(document)}");
        if (document.IsDegraded)
        {
            t.Out.WriteLine($"{t.Bold("Health")}     {t.Yellow("DEGRADED")}: {document.Factors?.DegradedReason ?? "no usable TPM"}");
        }
        else
        {
            t.Out.WriteLine($"{t.Bold("Health")}     {t.Green("OK")}: hardware-bound to this PC");
        }

        var session = agent switch
        {
            null => t.Dim("locked (agent not running)"),
            { Unlocked: true } a => t.Green("unlocked") + (a.IdleRemainingSeconds is { } r ? $", locks in {FormatDuration(TimeSpan.FromSeconds(r))} if idle" : string.Empty),
            { } a => t.Dim("locked") + (a.LastLockReason is { } why ? t.Dim($" ({why})") : string.Empty),
        };
        t.Out.WriteLine($"{t.Bold("Session")}    {session}");
        t.Out.WriteLine($"{t.Bold("Timeout")}    {settings.IdleTimeoutMinutes} min idle; locks on workstation lock{(settings.LockOnSleep ? ", sleep" : string.Empty)} and session switch");
        t.Out.WriteLine($"{t.Bold("Secrets")}    {document.Entries.Count}");
        return 0;
    }

    public static async Task<int> UnlockAsync(CliServices s, CancellationToken ct)
    {
        var t = s.Terminal;
        var unlocked = await s.Session.UnlockAsync(force: false, ct).ConfigureAwait(false);
        var settings = HushSettings.Load(s.Paths);
        t.Out.WriteLine(unlocked
            ? t.Green($"Unlocked. Locks after {settings.IdleTimeoutMinutes} min idle, or when you lock Windows.")
            : "Already unlocked.");
        return 0;
    }

    public static async Task<int> LockAsync(CliServices s, CancellationToken ct)
    {
        var agent = await s.TryAgentStatusAsync(ct).ConfigureAwait(false);
        if (agent is null || !agent.Unlocked)
        {
            s.Terminal.Out.WriteLine("Already locked.");
            return 0;
        }

        await s.Session.LockAsync(ct).ConfigureAwait(false);
        s.Terminal.Out.WriteLine("Locked.");
        return 0;
    }

    public static async Task<int> SetAsync(CliServices s, string name, string? policyText, string? scope, CancellationToken ct)
    {
        var t = s.Terminal;
        var reference = SecretRef.Parse(name, scope);
        var policy = policyText is null ? (SecretPolicy?)null : PolicyNames.Parse(policyText);
        string value;
        if (t.IsInputRedirected)
        {
            value = TrimOneNewline(t.ReadAllInput());
        }
        else
        {
            var first = t.ReadSecret($"Value for {reference}: ") ?? throw new HushException(HushErrorCode.InvalidInput, "Cancelled.");
            var second = t.ReadSecret("Repeat to confirm: ") ?? throw new HushException(HushErrorCode.InvalidInput, "Cancelled.");
            if (!string.Equals(first, second, StringComparison.Ordinal))
            {
                throw new HushException(HushErrorCode.InvalidInput, "The two values do not match. Nothing was saved.");
            }

            value = first;
        }

        if (value.Length == 0)
        {
            throw new HushException(HushErrorCode.InvalidInput, "The value is empty. Nothing was saved.");
        }

        await s.Session.SetAsync(reference, value, policy, ct).ConfigureAwait(false);
        t.Out.WriteLine(t.Green($"Saved {reference}") + (policy == SecretPolicy.AlwaysPrompt ? " (always-prompt: every use needs Windows Hello)" : string.Empty));
        return 0;
    }

    public static async Task<int> GetAsync(CliServices s, string name, string? scope, bool copy, bool reveal, CancellationToken ct)
    {
        var t = s.Terminal;
        if (!copy && !reveal)
        {
            throw new HushException(HushErrorCode.InvalidInput, "Choose --copy (clipboard, cleared after 30 s) or --reveal (print). To use a secret in a program, prefer 'hush run'.");
        }

        var reference = SecretRef.Parse(name, scope);
        if (reveal)
        {
            if (!t.CanPrompt)
            {
                throw new HushException(HushErrorCode.InvalidInput, "--reveal needs a console to confirm. Use 'hush run' to pass the secret to a program instead.");
            }

            if (!t.Confirm($"Print the value of {reference} to the terminal? It can end up in scrollback, logs or screen shares."))
            {
                t.Error.WriteLine("Not revealed.");
                return 1;
            }
        }

        var values = await s.Session.RevealAsync([new EnvBinding(reference.Name, reference, false)], copy ? "get --copy" : "get --reveal", requirePresence: false, ct).ConfigureAwait(false);
        var value = values.Single().Value;
        if (copy)
        {
            var sequence = Hush.Core.Interop.SecureClipboard.SetText(value);
            await s.Session.ScheduleClipboardClearAsync(sequence, ClipboardSeconds, ct).ConfigureAwait(false);
            t.Out.WriteLine($"Copied {reference} to the clipboard (kept out of clipboard history and cloud sync). It will be cleared in {ClipboardSeconds} seconds.");
        }

        if (reveal)
        {
            t.Out.WriteLine(value);
        }

        return 0;
    }

    public static int List(CliServices s, string? scope, bool json)
    {
        var t = s.Terminal;
        if (!s.Manager.Exists)
        {
            throw new HushException(HushErrorCode.VaultNotFound, "No vault found. Run 'hush init' first.");
        }

        var entries = s.Manager.ReadDocument().Entries
            .Where(e => scope is null || string.Equals(e.Scope, scope, StringComparison.OrdinalIgnoreCase))
            .OrderBy(e => e.QualifiedName, StringComparer.OrdinalIgnoreCase)
            .ToList();

        if (json)
        {
            using var buffer = new MemoryStream();
            using (var w = new Utf8JsonWriter(buffer, new JsonWriterOptions { Indented = true }))
            {
                w.WriteStartArray();
                foreach (var e in entries)
                {
                    w.WriteStartObject();
                    w.WriteString("name", e.Name);
                    w.WriteString("scope", e.Scope);
                    w.WriteString("policy", PolicyNames.Format(e.Policy));
                    w.WriteString("updated", e.Updated.ToString("O", CultureInfo.InvariantCulture));
                    if (e.LastUsed is { } used)
                    {
                        w.WriteString("lastUsed", used.ToString("O", CultureInfo.InvariantCulture));
                    }

                    w.WriteEndObject();
                }

                w.WriteEndArray();
            }

            t.Out.WriteLine(Encoding.UTF8.GetString(buffer.ToArray()));
            return 0;
        }

        if (entries.Count == 0)
        {
            t.Out.WriteLine("The vault is empty. Add a secret with 'hush set NAME' or run 'hush migrate'.");
            return 0;
        }

        var nameWidth = Math.Max(4, entries.Max(e => e.Name.Length));
        var scopeWidth = Math.Max(5, entries.Max(e => e.Scope.Length));
        t.Out.WriteLine(t.Bold($"{"NAME".PadRight(nameWidth)}  {"SCOPE".PadRight(scopeWidth)}  {"POLICY",-13}  LAST USED"));
        foreach (var e in entries)
        {
            var policy = PolicyNames.Format(e.Policy);
            t.Out.WriteLine($"{e.Name.PadRight(nameWidth)}  {(e.Scope.Length == 0 ? "(global)" : e.Scope).PadRight(scopeWidth)}  {policy,-13}  {(e.LastUsed is { } used ? Relative(used) : "never")}");
        }

        t.Out.WriteLine(t.Dim($"{entries.Count} secret(s). Values are never listed."));
        return 0;
    }

    public static async Task<int> RemoveAsync(CliServices s, string name, string? scope, bool yes, CancellationToken ct)
    {
        var t = s.Terminal;
        var reference = SecretRef.Parse(name, scope);
        if (!yes)
        {
            if (!t.CanPrompt)
            {
                throw new HushException(HushErrorCode.InvalidInput, "Pass --yes to delete without a confirmation prompt.");
            }

            if (!t.Confirm($"Delete {reference} from the vault? This cannot be undone."))
            {
                return 1;
            }
        }

        var removed = await s.Session.RemoveAsync(reference, ct).ConfigureAwait(false);
        if (!removed)
        {
            throw new HushException(HushErrorCode.SecretNotFound, $"'{reference}' is not in the vault.");
        }

        t.Out.WriteLine($"Deleted {reference}.");
        return 0;
    }

    public static async Task<int> RecoverAsync(CliServices s, CancellationToken ct)
    {
        var t = s.Terminal;
        if (!s.Manager.Exists)
        {
            throw new HushException(HushErrorCode.VaultNotFound, $"No vault at {s.Manager.Store.Path}. Copy your vault.hush there first, or create a new vault and use 'hush import' with an export file.");
        }

        using var key = ReadRecoveryKey(t);
        t.Out.WriteLine("Enrolling new Windows Hello and TPM factors for this PC...");
        var agent = await s.TryAgentStatusAsync(ct).ConfigureAwait(false);
        if (agent?.Unlocked == true)
        {
            await s.Session.LockAsync(ct).ConfigureAwait(false);
        }

        using var vault = await s.Manager.RecoverAsync(key, s.Prompt("Re-enroll your Hush vault"), new SynchronousProgress(m => t.Error.WriteLine(t.Dim(m))), ct).ConfigureAwait(false);
        if (vault.Document.IsDegraded)
        {
            WriteDegradedWarning(t, vault.Document.Factors?.DegradedReason);
        }

        await s.Session.HandOverAsync(vault, ct).ConfigureAwait(false);
        t.Out.WriteLine(t.Green($"Recovered. {vault.Document.Entries.Count} secret(s) are available and the vault is bound to this PC again."));
        t.Out.WriteLine("Your recovery key is unchanged; keep it safe. To issue a new one, run 'hush rotate'.");
        return 0;
    }

    public static async Task<int> RotateAsync(CliServices s, bool yes, CancellationToken ct)
    {
        var t = s.Terminal;
        if (!yes && !t.Confirm("Rotate the vault key? Every secret is re-encrypted and a NEW recovery key replaces the old one."))
        {
            return 1;
        }

        var creation = await s.Manager.RotateAsync(s.Prompt("Rotate your Hush vault key"), ct).ConfigureAwait(false);
        using var vault = creation.Vault;
        using var recovery = creation.RecoveryKey;
        ShowRecoveryKey(t, recovery, "Your previous recovery key no longer works. Exports made before this rotation still open with the old key.");
        ConfirmRecoveryKeySaved(t, recovery);
        await s.Session.HandOverAsync(vault, ct).ConfigureAwait(false);
        t.Out.WriteLine(t.Green($"Rotated. {vault.Document.Entries.Count} secret(s) re-encrypted under a new key."));
        return 0;
    }

    public static async Task<int> ExportAsync(CliServices s, string path, CancellationToken ct)
    {
        await s.Session.ExportAsync(path, ct).ConfigureAwait(false);
        s.Terminal.Out.WriteLine($"Wrote {Path.GetFullPath(path)}.");
        s.Terminal.Out.WriteLine("It is encrypted and opens only with your recovery key (on any PC), via 'hush import'.");
        return 0;
    }

    public static async Task<int> ImportAsync(CliServices s, string path, bool overwrite, CancellationToken ct)
    {
        var t = s.Terminal;
        if (!s.Manager.Exists)
        {
            throw new HushException(HushErrorCode.VaultNotFound, "Create a vault on this PC first with 'hush init', then import.");
        }

        var bytes = await File.ReadAllBytesAsync(path, ct).ConfigureAwait(false);
        using var key = ReadRecoveryKey(t, "Recovery key of the vault that made this export: ");
        using var portable = VaultManager.OpenPortable(bytes, key);
        var (imported, skipped) = await s.Session.ImportAsync(portable, overwrite, ct).ConfigureAwait(false);
        t.Out.WriteLine(t.Green($"Imported {imported} secret(s).") + (skipped > 0 ? $" Skipped {skipped} that already exist (use --overwrite to replace them)." : string.Empty));
        return 0;
    }

    public static async Task<int> ConfigAsync(CliServices s, string? key, string? value, CancellationToken ct)
    {
        var t = s.Terminal;
        var settings = HushSettings.Load(s.Paths);
        if (key is null)
        {
            t.Out.WriteLine($"idle-timeout   {settings.IdleTimeoutMinutes} (minutes)");
            t.Out.WriteLine($"lock-on-sleep  {settings.LockOnSleep.ToString().ToLowerInvariant()}");
            t.Out.WriteLine($"scan-roots     {string.Join(';', settings.ScanRoots)}");
            return 0;
        }

        if (value is null)
        {
            t.Out.WriteLine(key switch
            {
                "idle-timeout" => settings.IdleTimeoutMinutes.ToString(CultureInfo.InvariantCulture),
                "lock-on-sleep" => settings.LockOnSleep.ToString().ToLowerInvariant(),
                "scan-roots" => string.Join(';', settings.ScanRoots),
                _ => throw UnknownKey(key),
            });
            return 0;
        }

        settings = key switch
        {
            "idle-timeout" => settings with { IdleTimeoutMinutes = int.TryParse(value, NumberStyles.Integer, CultureInfo.InvariantCulture, out var minutes) ? minutes : throw new HushException(HushErrorCode.InvalidInput, "idle-timeout is a number of minutes.") },
            "lock-on-sleep" => settings with { LockOnSleep = bool.TryParse(value, out var flag) ? flag : throw new HushException(HushErrorCode.InvalidInput, "lock-on-sleep is true or false.") },
            "scan-roots" => settings with { ScanRoots = value.Split(';', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries) },
            _ => throw UnknownKey(key),
        };
        settings.Save(s.Paths);
        if (await s.TryAgentStatusAsync(ct).ConfigureAwait(false) is not null)
        {
            await s.Session.ReloadSettingsAsync(ct).ConfigureAwait(false);
        }

        t.Out.WriteLine($"Saved {key}.");
        return 0;
    }

    public static void WriteDegradedWarning(ITerminal t, string? reason)
    {
        ArgumentNullException.ThrowIfNull(t);
        t.Error.WriteLine(t.Yellow("WARNING: degraded mode. No usable TPM was found, so the vault key is protected by DPAPI instead of"));
        t.Error.WriteLine(t.Yellow("hardware. Windows Hello is still required, but a copy of the vault plus your Windows account"));
        t.Error.WriteLine(t.Yellow($"credentials is enough to attack it offline.{(reason is null ? string.Empty : " Reason: " + reason)}"));
    }

    private static int InitProject(CliServices s)
    {
        var t = s.Terminal;
        var path = Path.Combine(s.WorkingDirectory, ProjectManifest.FileName);
        if (File.Exists(path))
        {
            throw new HushException(HushErrorCode.InvalidInput, $"{path} already exists.");
        }

        var project = SecretRef.Sanitize(Path.GetFileName(Path.GetFullPath(s.WorkingDirectory)));
        File.WriteAllText(path, ProjectManifest.CreateText(project, []));
        t.Out.WriteLine($"Created {path} (project scope '{project}').");
        t.Out.WriteLine($"Add mappings under [env], store values with 'hush set NAME --scope {project}', then 'hush run -- <command>'.");
        return 0;
    }

    private static void ShowRecoveryKey(ITerminal t, RecoveryKey key, string explanation)
    {
        var text = key.ToDisplayString();
        var width = text.Length + 4;
        t.Out.WriteLine();
        t.Out.WriteLine(t.Bold("YOUR RECOVERY KEY (shown once):"));
        t.Out.WriteLine("  +" + new string('-', width) + "+");
        t.Out.WriteLine("  |  " + t.Bold(text) + "  |");
        t.Out.WriteLine("  +" + new string('-', width) + "+");
        t.Out.WriteLine(explanation);
        t.Out.WriteLine("Write it down or put it in a password manager. Hush cannot show it again.");
        t.Out.WriteLine();
    }

    private static void ConfirmRecoveryKeySaved(ITerminal t, RecoveryKey key)
    {
        if (!t.CanPrompt)
        {
            return;
        }

        var groups = key.ToDisplayString().Split('-');
        for (var attempt = 0; attempt < 3; attempt++)
        {
            var answer = t.ReadLine($"To confirm you saved it, type the last group ({new string('?', groups[^1].Length)}): ");
            if (answer is null)
            {
                return;
            }

            if (string.Equals(answer.Trim(), groups[^1], StringComparison.OrdinalIgnoreCase))
            {
                return;
            }

            t.Error.WriteLine("That does not match. Check what you wrote down.");
        }

        t.Error.WriteLine(t.Yellow("Continuing, but make sure you have the recovery key before you rely on this vault."));
    }

    private static RecoveryKey ReadRecoveryKey(ITerminal t, string prompt = "Recovery key: ")
    {
        var text = t.IsInputRedirected && !t.CanPrompt ? t.ReadAllInput() : t.ReadSecret(prompt);
        if (string.IsNullOrWhiteSpace(text))
        {
            throw new HushException(HushErrorCode.InvalidRecoveryKey, "No recovery key entered.");
        }

        return RecoveryKey.Parse(text);
    }

    private static string FactorsText(VaultDocument document) => document.Factors?.SecondFactor switch
    {
        Core.Keys.SecondFactorKind.Tpm => "Windows Hello + TPM",
        Core.Keys.SecondFactorKind.Dpapi => "Windows Hello + DPAPI (degraded: no TPM)",
        Core.Keys.SecondFactorKind.Test => "test provider",
        _ => "none (portable export)",
    };

    private static string TrimOneNewline(string text) =>
        text.EndsWith("\r\n", StringComparison.Ordinal) ? text[..^2] : text.EndsWith('\n') ? text[..^1] : text;

    private static string Relative(DateTimeOffset time)
    {
        var age = DateTimeOffset.UtcNow - time;
        return age < TimeSpan.FromMinutes(1) ? "just now" : FormatDuration(age) + " ago";
    }

    internal static string FormatDuration(TimeSpan span) => span.TotalMinutes < 1
        ? $"{(int)span.TotalSeconds}s"
        : span.TotalHours < 1 ? $"{(int)span.TotalMinutes} min"
        : span.TotalDays < 1 ? $"{(int)span.TotalHours} h"
        : $"{(int)span.TotalDays} d";

    private static HushException UnknownKey(string key) =>
        new(HushErrorCode.InvalidInput, $"Unknown setting '{key}'. Settings: idle-timeout, lock-on-sleep, scan-roots.");
}

/// <summary>IProgress that reports on the calling thread (Progress&lt;T&gt; posts to the thread pool, which reorders console output).</summary>
internal sealed class SynchronousProgress(Action<string> report) : IProgress<string>
{
    public void Report(string value) => report(value);
}
