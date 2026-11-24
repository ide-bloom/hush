using Hush.Core.Crypto;
using Hush.Core.Vault;
using Hush.Tests.Support;
using Xunit;

namespace Hush.Core.Tests;

public sealed class TamperAndFormatTests : IDisposable
{
    private readonly TempDirectory _temp = new();
    private readonly TestKeyProvider _provider = new();

    public void Dispose() => _temp.Dispose();

    private async Task<(VaultManager Manager, RecoveryKey Recovery)> CreateWithSecretAsync()
    {
        var manager = new VaultManager(_temp.HushPaths, _provider);
        var creation = await manager.CreateAsync(TestPrompt.Any, null, CancellationToken.None);
        using (var vault = creation.Vault)
        {
            vault.Set(new SecretRef(string.Empty, "SECRET"), "do-not-tamper"u8, null, VaultTests.Audit());
        }

        return (manager, creation.RecoveryKey);
    }

    private void Rewrite(Func<VaultDocument, VaultDocument> change, byte[]? macKeySource = null)
    {
        var bytes = File.ReadAllBytes(_temp.HushPaths.Vault);
        var document = change(VaultCodec.Read(bytes));
        // Re-encode with a random key: the attacker does not know the DEK, so the MAC cannot be right.
        var reencoded = VaultCodec.Write(document, macKeySource ?? new byte[32]);
        File.WriteAllBytes(_temp.HushPaths.Vault, reencoded);
    }

    [Fact]
    public async Task Flipping_any_header_byte_is_detected()
    {
        var (manager, recovery) = await CreateWithSecretAsync();
        using var _ = recovery;
        var bytes = File.ReadAllBytes(_temp.HushPaths.Vault);
        bytes[20] ^= 0x01; // inside the vault id
        File.WriteAllBytes(_temp.HushPaths.Vault, bytes);
        var ex = await Assert.ThrowsAnyAsync<HushException>(() => manager.UnlockAsync(TestPrompt.Any, CancellationToken.None));
        Assert.Contains(ex.Code, new[] { HushErrorCode.TamperDetected, HushErrorCode.TpmFailure });
    }

    [Fact]
    public async Task Changing_a_policy_in_the_entry_table_breaks_the_mac()
    {
        var (manager, recovery) = await CreateWithSecretAsync();
        using var _ = recovery;
        Rewrite(d => d with { Entries = d.Entries.Select(e => e with { Policy = SecretPolicy.AlwaysPrompt }).ToList() });
        var ex = await Assert.ThrowsAsync<HushException>(() => manager.UnlockAsync(TestPrompt.Any, CancellationToken.None));
        Assert.Equal(HushErrorCode.TamperDetected, ex.Code);
    }

    [Fact]
    public async Task Modified_entry_ciphertext_fails_authentication()
    {
        var (manager, recovery) = await CreateWithSecretAsync();
        using var _ = recovery;
        using var vault = await manager.UnlockAsync(TestPrompt.Any, CancellationToken.None);
        using var dek = vault.CopyDek();
        Rewrite(
            d => d with { Entries = d.Entries.Select(e => e with { Ciphertext = Flip(e.Ciphertext, 15) }).ToList() },
            macKeySource: dek.Span.ToArray()); // even an attacker with the MAC key cannot forge the entry
        using var reopened = await manager.UnlockAsync(TestPrompt.Any, CancellationToken.None);
        var ex = Assert.Throws<HushException>(() => reopened.Reveal([new SecretLookup(new SecretRef(string.Empty, "SECRET"), false)], false, VaultTests.Audit()));
        Assert.Equal(HushErrorCode.TamperDetected, ex.Code);
    }

    [Fact]
    public async Task Swapping_entry_versions_is_caught_by_the_aad()
    {
        var (manager, recovery) = await CreateWithSecretAsync();
        using var _ = recovery;
        using var vault = await manager.UnlockAsync(TestPrompt.Any, CancellationToken.None);
        using var dek = vault.CopyDek();
        Rewrite(d => d with { Entries = d.Entries.Select(e => e with { Version = e.Version + 1 }).ToList() }, dek.Span.ToArray());
        using var reopened = await manager.UnlockAsync(TestPrompt.Any, CancellationToken.None);
        Assert.Throws<HushException>(() => reopened.Reveal([new SecretLookup(new SecretRef(string.Empty, "SECRET"), false)], false, VaultTests.Audit()));
    }

    [Fact]
    public async Task Tampered_wrapped_dek_is_rejected()
    {
        var (manager, recovery) = await CreateWithSecretAsync();
        using var _ = recovery;
        Rewrite(d => d with { WrappedKeys = d.WrappedKeys.Select(w => w with { Blob = Flip(w.Blob, 20) }).ToList() });
        var ex = await Assert.ThrowsAsync<HushException>(() => manager.UnlockAsync(TestPrompt.Any, CancellationToken.None));
        Assert.Equal(HushErrorCode.TamperDetected, ex.Code);
        var viaRecovery = Assert.Throws<HushException>(() => manager.UnlockWithRecoveryKey(recovery));
        Assert.Equal(HushErrorCode.InvalidRecoveryKey, viaRecovery.Code);
    }

    [Fact]
    public async Task Truncated_file_is_reported_as_corrupt()
    {
        var (manager, recovery) = await CreateWithSecretAsync();
        using var _ = recovery;
        var bytes = File.ReadAllBytes(_temp.HushPaths.Vault);
        File.WriteAllBytes(_temp.HushPaths.Vault, bytes[..(bytes.Length / 2)]);
        var ex = await Assert.ThrowsAsync<HushException>(() => manager.UnlockAsync(TestPrompt.Any, CancellationToken.None));
        Assert.Equal(HushErrorCode.VaultCorrupt, ex.Code);
    }

    [Fact]
    public void Non_vault_files_and_future_versions_are_rejected()
    {
        Assert.Equal(HushErrorCode.VaultCorrupt, Assert.Throws<HushException>(() => VaultCodec.Read("not a vault at all, just text"u8)).Code);
        var bytes = new byte[64];
        VaultCodec.Magic.CopyTo(bytes);
        bytes[8] = 99;
        var ex = Assert.Throws<HushException>(() => VaultCodec.Read(bytes));
        Assert.Contains("version 99", ex.Message, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Codec_round_trip_is_byte_exact()
    {
        var (_, recovery) = await CreateWithSecretAsync();
        using var _ = recovery;
        var bytes = File.ReadAllBytes(_temp.HushPaths.Vault);
        var document = VaultCodec.Read(bytes);
        var again = VaultCodec.Write(document, new byte[32]);
        Assert.Equal(bytes[..^VaultCodec.MacSize], again[..^VaultCodec.MacSize]);
    }

    [Fact]
    public async Task Exception_messages_never_contain_secret_values()
    {
        var (manager, recovery) = await CreateWithSecretAsync();
        using var _ = recovery;
        using var vault = await manager.UnlockAsync(TestPrompt.Any, CancellationToken.None);
        var ex = Assert.Throws<HushException>(() => vault.Set(new SecretRef(string.Empty, "BAD NAME"), "super-secret-value"u8, null, VaultTests.Audit()));
        Assert.DoesNotContain("super-secret-value", ex.ToString(), StringComparison.Ordinal);
    }

    private static byte[] Flip(byte[] blob, int index)
    {
        var copy = (byte[])blob.Clone();
        copy[Math.Min(index, copy.Length - 1)] ^= 0x80;
        return copy;
    }
}
