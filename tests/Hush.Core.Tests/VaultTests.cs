using System.Text;
using Hush.Core.Audit;
using Hush.Core.Interop;
using Hush.Core.Keys;
using Hush.Core.Vault;
using Hush.Tests.Support;
using Xunit;

namespace Hush.Core.Tests;

public sealed class VaultTests : IDisposable
{
    private readonly TempDirectory _temp = new();
    private readonly TestKeyProvider _provider = new();

    public void Dispose() => _temp.Dispose();

    internal static AuditEvent Audit(string action = "test") => new(action, [], "ok", null, ProcessInspector.Current());

    private VaultManager Manager(IHardwareKeyProvider? provider = null) => new(_temp.HushPaths, provider ?? _provider);

    [Fact]
    public async Task Create_unlock_round_trip_preserves_secrets()
    {
        var manager = Manager();
        var creation = await manager.CreateAsync(TestPrompt.Any, null, CancellationToken.None);
        creation.RecoveryKey.Dispose();
        using (var vault = creation.Vault)
        {
            vault.Set(new SecretRef(string.Empty, "API_KEY"), "value-1"u8, null, Audit());
            vault.Set(new SecretRef("app", "DB"), "value-2"u8, SecretPolicy.AlwaysPrompt, Audit());
        }

        using var reopened = await manager.UnlockAsync(TestPrompt.Any, CancellationToken.None);
        var revealed = reopened.Reveal([new SecretLookup(new SecretRef(string.Empty, "API_KEY"), false), new SecretLookup(new SecretRef("app", "DB"), false)], presenceVerified: true, Audit("read"));
        Assert.Equal(["value-1", "value-2"], revealed.Select(r => r.Value));
        Assert.Equal(SecretPolicy.AlwaysPrompt, reopened.List().Single(s => s.Name == "DB").Policy);
    }

    [Fact]
    public async Task Create_signs_the_challenge_twice_to_prove_determinism()
    {
        var creation = await Manager().CreateAsync(TestPrompt.Any, null, CancellationToken.None);
        creation.Vault.Dispose();
        creation.RecoveryKey.Dispose();
        Assert.Equal(3, _provider.PromptCount); // create + two signatures
    }

    [Fact]
    public async Task Create_refuses_non_deterministic_hello_signatures_and_cleans_up()
    {
        _provider.NonDeterministicSignatures = true;
        var ex = await Assert.ThrowsAsync<HushException>(() => Manager().CreateAsync(TestPrompt.Any, null, CancellationToken.None));
        Assert.Equal(HushErrorCode.HelloNotDeterministic, ex.Code);
        Assert.False(File.Exists(_temp.HushPaths.Vault));
    }

    [Fact]
    public async Task Create_requires_windows_hello()
    {
        _provider.HelloAvailable = false;
        var ex = await Assert.ThrowsAsync<HushException>(() => Manager().CreateAsync(TestPrompt.Any, null, CancellationToken.None));
        Assert.Equal(HushErrorCode.HelloUnavailable, ex.Code);
    }

    [Fact]
    public async Task Create_refuses_to_overwrite_an_existing_vault()
    {
        var creation = await Manager().CreateAsync(TestPrompt.Any, null, CancellationToken.None);
        creation.Vault.Dispose();
        creation.RecoveryKey.Dispose();
        var ex = await Assert.ThrowsAsync<HushException>(() => Manager().CreateAsync(TestPrompt.Any, null, CancellationToken.None));
        Assert.Equal(HushErrorCode.VaultAlreadyExists, ex.Code);
    }

    [Fact]
    public async Task Degraded_mode_is_flagged_when_no_tpm_is_available()
    {
        _provider.SecondFactor = SecondFactorKind.Dpapi;
        var creation = await Manager().CreateAsync(TestPrompt.Any, null, CancellationToken.None);
        creation.RecoveryKey.Dispose();
        using var vault = creation.Vault;
        Assert.True(vault.Document.IsDegraded);
        Assert.Equal(SecondFactorKind.Dpapi, vault.Document.Factors!.SecondFactor);
        Assert.NotNull(vault.Document.Factors.DegradedReason);

        using var reopened = await Manager().UnlockAsync(TestPrompt.Any, CancellationToken.None);
        Assert.True(reopened.Document.IsDegraded);
    }

    [Fact]
    public async Task Rotation_re_encrypts_entries_and_replaces_the_recovery_key()
    {
        var manager = Manager();
        var creation = await manager.CreateAsync(TestPrompt.Any, null, CancellationToken.None);
        using var oldRecovery = creation.RecoveryKey;
        Guid id;
        byte[] oldCiphertext;
        using (var vault = creation.Vault)
        {
            vault.Set(new SecretRef(string.Empty, "TOKEN"), "before-rotation"u8, null, Audit());
            id = vault.Document.Entries[0].Id;
            oldCiphertext = vault.Document.Entries[0].Ciphertext;
        }

        var rotated = await manager.RotateAsync(TestPrompt.Any, CancellationToken.None);
        using var newRecovery = rotated.RecoveryKey;
        using (var vault = rotated.Vault)
        {
            var entry = vault.Document.Entries.Single();
            Assert.Equal(id, entry.Id);
            Assert.NotEqual(oldCiphertext, entry.Ciphertext);
            Assert.Equal("before-rotation", vault.Reveal([new SecretLookup(new SecretRef(string.Empty, "TOKEN"), false)], false, Audit()).Single().Value);
            Assert.True(vault.VerifyAudit().IsValid);
        }

        var ex = Assert.Throws<HushException>(() => manager.UnlockWithRecoveryKey(oldRecovery));
        Assert.Equal(HushErrorCode.InvalidRecoveryKey, ex.Code);
        using var viaNewKey = manager.UnlockWithRecoveryKey(newRecovery);
        Assert.Single(viaNewKey.Document.Entries);
    }

    [Fact]
    public async Task Always_prompt_secrets_require_presence()
    {
        var creation = await Manager().CreateAsync(TestPrompt.Any, null, CancellationToken.None);
        creation.RecoveryKey.Dispose();
        using var vault = creation.Vault;
        vault.Set(new SecretRef(string.Empty, "PROD"), "prod-value"u8, SecretPolicy.AlwaysPrompt, Audit());
        var ex = Assert.Throws<HushException>(() => vault.Reveal([new SecretLookup(new SecretRef(string.Empty, "PROD"), false)], false, Audit()));
        Assert.Equal(HushErrorCode.PresenceRequired, ex.Code);
    }

    [Fact]
    public async Task Presence_signatures_verify_against_the_header_public_key()
    {
        var manager = Manager();
        var creation = await manager.CreateAsync(TestPrompt.Any, null, CancellationToken.None);
        creation.RecoveryKey.Dispose();
        using var vault = creation.Vault;
        var nonce = Encoding.UTF8.GetBytes("broker-nonce-0123456789abcdefghij");
        var signature = await manager.SignPresenceAsync(nonce, TestPrompt.Any, CancellationToken.None);
        Assert.True(VaultManager.VerifyPresence(vault.Document.Factors!, nonce, signature));
        Assert.False(VaultManager.VerifyPresence(vault.Document.Factors!, "another-nonce"u8, signature));
    }

    [Fact]
    public async Task Scoped_lookup_can_fall_back_to_global()
    {
        var creation = await Manager().CreateAsync(TestPrompt.Any, null, CancellationToken.None);
        creation.RecoveryKey.Dispose();
        using var vault = creation.Vault;
        vault.Set(new SecretRef(string.Empty, "SHARED"), "global"u8, null, Audit());
        vault.Set(new SecretRef("app", "OWN"), "scoped"u8, null, Audit());

        var values = vault.Reveal(
            [new SecretLookup(new SecretRef("app", "SHARED"), true), new SecretLookup(new SecretRef("app", "OWN"), true)],
            false,
            Audit());
        Assert.Equal(["global", "scoped"], values.Select(v => v.Value));
        var missing = Assert.Throws<HushException>(() => vault.Reveal([new SecretLookup(new SecretRef("app", "SHARED"), false)], false, Audit()));
        Assert.Equal(HushErrorCode.SecretNotFound, missing.Code);
    }

    [Fact]
    public async Task Updating_a_secret_bumps_its_version_and_remove_deletes_it()
    {
        var creation = await Manager().CreateAsync(TestPrompt.Any, null, CancellationToken.None);
        creation.RecoveryKey.Dispose();
        using var vault = creation.Vault;
        var reference = new SecretRef(string.Empty, "K");
        vault.Set(reference, "one"u8, null, Audit());
        vault.Set(reference, "two"u8, null, Audit());
        Assert.Equal(2u, vault.Document.Entries.Single().Version);
        Assert.True(vault.Remove(reference, Audit()));
        Assert.False(vault.Remove(reference, Audit()));
        Assert.Empty(vault.List());
    }

    [Fact]
    public async Task Copied_vault_cannot_be_unlocked_on_another_machine_without_the_recovery_key()
    {
        var creation = await Manager().CreateAsync(TestPrompt.Any, null, CancellationToken.None);
        using var recovery = creation.RecoveryKey;
        using (var vault = creation.Vault)
        {
            vault.Set(new SecretRef(string.Empty, "K"), "v"u8, null, Audit());
        }

        using var otherPc = new TempDirectory();
        Directory.CreateDirectory(otherPc.HushPaths.Home);
        File.Copy(_temp.HushPaths.Vault, otherPc.HushPaths.Vault);
        var machineB = new TestKeyProvider("machine-B");
        var managerB = new VaultManager(otherPc.HushPaths, machineB);

        var ex = await Assert.ThrowsAsync<HushException>(() => managerB.UnlockAsync(TestPrompt.Any, CancellationToken.None));
        Assert.Equal(HushErrorCode.HelloUnavailable, ex.Code);

        using var recovered = await managerB.RecoverAsync(recovery, TestPrompt.Any, null, CancellationToken.None);
        Assert.Equal("v", recovered.Reveal([new SecretLookup(new SecretRef(string.Empty, "K"), false)], false, Audit()).Single().Value);
        using var unlockedOnB = await managerB.UnlockAsync(TestPrompt.Any, CancellationToken.None);
        Assert.Equal(2u, unlockedOnB.Document.Generation);
    }

    [Fact]
    public async Task Portable_export_round_trips_through_import()
    {
        var creation = await Manager().CreateAsync(TestPrompt.Any, null, CancellationToken.None);
        using var recovery = creation.RecoveryKey;
        byte[] export;
        using (var vault = creation.Vault)
        {
            vault.Set(new SecretRef("app", "A"), "alpha"u8, null, Audit());
            vault.Set(new SecretRef(string.Empty, "B"), "beta"u8, SecretPolicy.AlwaysPrompt, Audit());
            export = vault.BuildPortableExport(Audit("export"));
        }

        using var portable = VaultManager.OpenPortable(export, recovery);
        Assert.Null(portable.Document.Factors);
        Assert.True(portable.Document.Flags.HasFlag(VaultAttributes.Portable));

        using var target = new TempDirectory();
        var other = new VaultManager(target.HushPaths, new TestKeyProvider("machine-C"));
        var created = await other.CreateAsync(TestPrompt.Any, null, CancellationToken.None);
        created.RecoveryKey.Dispose();
        using var destination = created.Vault;
        var items = portable.DecryptAll().Select(x =>
        {
            using (x.Plaintext)
            {
                return new ImportItem(new SecretRef(x.Entry.Scope, x.Entry.Name), x.Entry.Policy, x.Plaintext.Span.ToArray());
            }
        }).ToList();
        Assert.Equal((2, 0), destination.Import(items, overwrite: false, Audit("import")));
        Assert.Equal((0, 2), destination.Import(items, overwrite: false, Audit("import")));
        Assert.Equal("beta", destination.Reveal([new SecretLookup(new SecretRef(string.Empty, "B"), false)], true, Audit()).Single().Value);
    }

    [Fact]
    public async Task Export_cannot_be_opened_with_a_different_recovery_key()
    {
        var creation = await Manager().CreateAsync(TestPrompt.Any, null, CancellationToken.None);
        creation.RecoveryKey.Dispose();
        byte[] export;
        using (var vault = creation.Vault)
        {
            export = vault.BuildPortableExport(Audit("export"));
        }

        using var wrong = Crypto.RecoveryKey.Generate();
        var ex = Assert.Throws<HushException>(() => VaultManager.OpenPortable(export, wrong));
        Assert.Equal(HushErrorCode.InvalidRecoveryKey, ex.Code);
    }

    [Fact]
    public async Task Broker_style_open_with_dek_verifies_the_mac()
    {
        var manager = Manager();
        var creation = await manager.CreateAsync(TestPrompt.Any, null, CancellationToken.None);
        creation.RecoveryKey.Dispose();
        using var vault = creation.Vault;
        using var dek = vault.CopyDek();
        using var reopened = manager.OpenWithDek(dek.Span);
        Assert.Equal(vault.VaultId, reopened.VaultId);

        var wrong = new byte[32];
        var ex = Assert.Throws<HushException>(() => manager.OpenWithDek(wrong));
        Assert.Equal(HushErrorCode.TamperDetected, ex.Code);
    }

    [Fact]
    public async Task A_held_vault_notices_rotation_by_another_process()
    {
        var manager = Manager();
        var creation = await manager.CreateAsync(TestPrompt.Any, null, CancellationToken.None);
        creation.RecoveryKey.Dispose();
        using var held = creation.Vault;
        var rotated = await manager.RotateAsync(TestPrompt.Any, CancellationToken.None);
        rotated.Vault.Dispose();
        rotated.RecoveryKey.Dispose();

        var ex = Assert.Throws<HushException>(() => held.Set(new SecretRef(string.Empty, "X"), "y"u8, null, Audit()));
        Assert.Equal(HushErrorCode.Locked, ex.Code);
    }

    [Fact]
    public void Production_gate_accepts_the_test_provider_only_in_a_test_host()
    {
        Assert.True(TestProviderGate.IsTestHost);
        TestProviderGate.EnsureAllowed(_provider);
    }

    [Fact]
    public async Task Cancelled_hello_prompt_surfaces_as_cancelled()
    {
        var creation = await Manager().CreateAsync(TestPrompt.Any, null, CancellationToken.None);
        creation.Vault.Dispose();
        creation.RecoveryKey.Dispose();
        _provider.CancelNextPrompt = true;
        var ex = await Assert.ThrowsAsync<HushException>(() => Manager().UnlockAsync(TestPrompt.Any, CancellationToken.None));
        Assert.Equal(HushErrorCode.HelloCancelled, ex.Code);
    }
}
