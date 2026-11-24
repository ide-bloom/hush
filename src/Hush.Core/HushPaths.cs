namespace Hush.Core;

/// <summary>
/// Well-known file locations. Everything lives under <c>%LOCALAPPDATA%\Hush</c> unless the
/// <c>HUSH_HOME</c> environment variable points elsewhere (used by tests and portable setups).
/// </summary>
public sealed record HushPaths(string Home)
{
    /// <summary>Name of the environment variable that overrides <see cref="Home"/>.</summary>
    public const string HomeVariable = "HUSH_HOME";

    /// <summary>The vault file.</summary>
    public string Vault => Path.Combine(Home, "vault.hush");

    /// <summary>Lock file that serializes vault writers across processes.</summary>
    public string VaultLock => Path.Combine(Home, "vault.lock");

    /// <summary>The append-only, hash-chained audit log.</summary>
    public string AuditLog => Path.Combine(Home, "audit.jsonl");

    /// <summary>Events recorded while no audit key was available; folded into the chain at the next unlock.</summary>
    public string PendingAudit => Path.Combine(Home, "audit.pending.jsonl");

    /// <summary>User settings (idle timeout, scan roots, and so on).</summary>
    public string Settings => Path.Combine(Home, "settings.json");

    /// <summary>Folder for timestamped migration backups.</summary>
    public string Backups => Path.Combine(Home, "backups");

    /// <summary>Folder for diagnostic logs. Logs never contain secret values.</summary>
    public string Logs => Path.Combine(Home, "logs");

    /// <summary>Resolves the paths for the current user.</summary>
    public static HushPaths Default()
    {
        var overridden = Environment.GetEnvironmentVariable(HomeVariable);
        if (!string.IsNullOrWhiteSpace(overridden))
        {
            return new HushPaths(Path.GetFullPath(overridden));
        }

        var local = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
        return new HushPaths(Path.Combine(local, "Hush"));
    }

    /// <summary>Creates <see cref="Home"/> if it does not exist yet.</summary>
    public void EnsureHome() => Directory.CreateDirectory(Home);
}
