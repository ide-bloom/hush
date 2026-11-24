using Hush.App.Views;
using Hush.Core.Vault;
using Hush.Tests.Support;
using Xunit;

namespace Hush.App.Tests;

public sealed class VaultListModelTests : IDisposable
{
    private readonly TempDirectory _temp = new();
    private readonly TestKeyProvider _provider = new();

    public void Dispose() => _temp.Dispose();

    private async Task<UnlockedVault> CreateVaultAsync()
    {
        var creation = await new VaultManager(_temp.HushPaths, _provider).CreateAsync(TestPrompt.Any, null, CancellationToken.None);
        creation.RecoveryKey.Dispose();
        return creation.Vault;
    }

    /// <summary>
    /// Regression: the tray app read the vault once (when it was still empty right after 'hush init') and never
    /// noticed 'hush set' from a terminal, so the Vault page said "The vault is empty" while 'hush list' and the
    /// Audit page showed the secret.
    /// </summary>
    [Fact]
    public async Task Secrets_added_by_another_process_after_the_first_load_appear_on_the_next_refresh()
    {
        using var vault = await CreateVaultAsync();

        // The tray app's own manager, as in the app: a separate instance reading the same file.
        var model = new VaultListModel(new VaultManager(_temp.HushPaths, _provider));
        Assert.True(model.Refresh());
        Assert.Empty(model.Rows);

        // 'hush set TEST_KEY' goes through a different process; here, a different vault handle.
        vault.Set(new SecretRef(string.Empty, "TEST_KEY"), "value"u8, null, AuditFactory.Event("secret.set"));

        Assert.True(model.Refresh());
        var row = Assert.Single(model.Rows);
        Assert.Equal("TEST_KEY", row.Name);
        Assert.Equal("(global)", row.ScopeText);
        Assert.Equal("Session", row.PolicyText);
    }

    [Fact]
    public async Task Refresh_reports_no_change_when_the_vault_file_did_not_change()
    {
        using var vault = await CreateVaultAsync();
        vault.Set(new SecretRef("shop", "DB"), "v"u8, SecretPolicy.AlwaysPrompt, AuditFactory.Event());
        var model = new VaultListModel(new VaultManager(_temp.HushPaths, _provider));

        Assert.True(model.Refresh());
        Assert.False(model.Refresh());
        Assert.True(model.Refresh(force: true));
        Assert.Equal("Always prompt", Assert.Single(model.Rows).PolicyText);

        Assert.True(vault.Remove(new SecretRef("shop", "DB"), AuditFactory.Event()));
        Assert.True(model.Refresh());
        Assert.Empty(model.Rows);
    }

    [Fact]
    public async Task A_vault_created_while_the_app_is_running_is_picked_up()
    {
        var model = new VaultListModel(new VaultManager(_temp.HushPaths, _provider));
        Assert.True(model.Refresh());
        Assert.Empty(model.Rows);
        Assert.False(model.Refresh());

        using var vault = await CreateVaultAsync();
        vault.Set(new SecretRef(string.Empty, "FIRST"), "v"u8, null, AuditFactory.Event());
        Assert.True(model.Refresh());
        Assert.Equal("FIRST", Assert.Single(model.Rows).Name);
    }

    [Fact]
    public async Task Rows_are_sorted_and_the_search_matches_name_or_scope()
    {
        using var vault = await CreateVaultAsync();
        foreach (var (scope, name) in new[] { ("shop", "STRIPE_KEY"), (string.Empty, "OPENAI_API_KEY"), ("api", "DATABASE_URL") })
        {
            vault.Set(new SecretRef(scope, name), "v"u8, null, AuditFactory.Event());
        }

        var model = new VaultListModel(new VaultManager(_temp.HushPaths, _provider));
        model.Refresh();
        Assert.Equal(["OPENAI_API_KEY", "DATABASE_URL", "STRIPE_KEY"], model.Rows.Select(r => r.Name));
        Assert.Equal(["STRIPE_KEY"], model.Filter("shop").Select(r => r.Name));
        Assert.Equal(["OPENAI_API_KEY"], model.Filter("  openai ").Select(r => r.Name));
        Assert.Equal(3, model.Filter(string.Empty).Count);
        Assert.Empty(model.Filter("nothing-matches"));
    }
}
