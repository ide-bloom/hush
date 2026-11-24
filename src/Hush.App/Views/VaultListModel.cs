using System.Globalization;
using Hush.App.Infrastructure;
using Hush.Core.Vault;

namespace Hush.App.Views;

/// <summary>One row of the vault table.</summary>
internal sealed record SecretRow(string Name, string Scope, SecretPolicy Policy, DateTimeOffset Updated, DateTimeOffset? LastUsed)
{
    public string ScopeText => Scope.Length == 0 ? "(global)" : Scope;

    public string PolicyText => Policy == SecretPolicy.AlwaysPrompt ? "Always prompt" : "Session";

    public string LastUsedText => Ui.Relative(LastUsed);

    public string UpdatedText => Updated.ToLocalTime().ToString("g", CultureInfo.CurrentCulture);

    public SecretRef Ref => new(Scope, Name);
}

/// <summary>
/// The Vault page's data, kept in sync with vault.hush. The vault is usually changed by other processes (the CLI,
/// the broker), so the model compares the file's stamp on every <see cref="Refresh"/> and re-reads it when it moved.
/// It has no WPF dependencies so it can be tested directly.
/// </summary>
internal sealed class VaultListModel(VaultManager manager)
{
    private static readonly (DateTime, long) NeverRead = (DateTime.MinValue, long.MinValue);
    private (DateTime LastWriteUtc, long Length) _stamp = NeverRead;

    /// <summary>All secrets, sorted by scope then name.</summary>
    public IReadOnlyList<SecretRow> Rows { get; private set; } = [];

    /// <summary>
    /// Re-reads the vault if it changed since the last read (or always, with <paramref name="force"/>). Returns true
    /// when <see cref="Rows"/> was reloaded.
    /// </summary>
    public bool Refresh(bool force = false)
    {
        var stamp = manager.Store.Stamp();
        if (!force && stamp == _stamp)
        {
            return false;
        }

        _stamp = stamp;
        Rows = manager.Exists
            ? manager.ReadDocument().Entries
                .Select(e => new SecretRow(e.Name, e.Scope, e.Policy, e.Updated, e.LastUsed))
                .OrderBy(r => r.Scope, StringComparer.OrdinalIgnoreCase)
                .ThenBy(r => r.Name, StringComparer.OrdinalIgnoreCase)
                .ToList()
            : [];
        return true;
    }

    /// <summary>Rows whose name or scope contains <paramref name="text"/> (all rows for empty text).</summary>
    public IReadOnlyList<SecretRow> Filter(string? text)
    {
        var query = text?.Trim() ?? string.Empty;
        return query.Length == 0
            ? Rows
            : Rows.Where(r => r.Name.Contains(query, StringComparison.OrdinalIgnoreCase) || r.Scope.Contains(query, StringComparison.OrdinalIgnoreCase)).ToList();
    }
}
