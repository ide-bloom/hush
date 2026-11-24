using System.Security.Cryptography;
using Hush.Core.Crypto;
using Hush.Core.Vault;
using Hush.Tests.Support;
using Xunit;

namespace Hush.Core.Tests;

public sealed class CryptoTests
{
    [Fact]
    public void Aead_nonces_are_unique_across_many_seals()
    {
        var key = RandomNumberGenerator.GetBytes(32);
        var nonces = new HashSet<string>(StringComparer.Ordinal);
        for (var i = 0; i < 20_000; i++)
        {
            var blob = Aead.Seal(key, "same plaintext"u8, "same aad"u8);
            Assert.True(nonces.Add(Convert.ToHexString(Aead.NonceOf(blob))));
        }
    }

    [Fact]
    public async Task Entry_nonces_are_unique_within_a_vault()
    {
        using var temp = new TempDirectory();
        var manager = new VaultManager(temp.HushPaths, new TestKeyProvider());
        var creation = await manager.CreateAsync(TestPrompt.Any, null, CancellationToken.None);
        creation.RecoveryKey.Dispose();
        using var vault = creation.Vault;
        for (var i = 0; i < 50; i++)
        {
            vault.Set(new SecretRef(string.Empty, $"S{i}"), "identical"u8, null, VaultTests.Audit());
        }

        vault.Set(new SecretRef(string.Empty, "S0"), "identical"u8, null, VaultTests.Audit());
        var nonces = vault.Document.Entries.Select(e => Convert.ToHexString(Aead.NonceOf(e.Ciphertext))).ToList();
        Assert.Equal(nonces.Count, nonces.Distinct(StringComparer.Ordinal).Count());
        var wrapNonces = vault.Document.WrappedKeys.Select(w => Convert.ToHexString(Aead.NonceOf(w.Blob))).ToList();
        Assert.Equal(wrapNonces.Count, wrapNonces.Distinct(StringComparer.Ordinal).Count());
    }

    [Fact]
    public void Aead_rejects_wrong_aad()
    {
        var key = RandomNumberGenerator.GetBytes(32);
        var blob = Aead.Seal(key, "x"u8, "aad-1"u8);
        Assert.Equal(HushErrorCode.TamperDetected, Assert.Throws<HushException>(() => Aead.Open(key, blob, "aad-2"u8, "test")).Code);
    }

    [Fact]
    public void Secure_buffer_is_zeroed_on_dispose()
    {
        var buffer = SecureBuffer.Random(32);
        var memory = buffer.Memory;
        buffer.Dispose();
        Assert.True(memory.Span.ToArray().All(b => b == 0));
        Assert.Throws<ObjectDisposedException>(() => buffer.Span.Length);
    }

    [Fact]
    public void Recovery_key_display_round_trips_and_has_a_checksum_group()
    {
        using var key = RecoveryKey.Generate();
        var text = key.ToDisplayString();
        Assert.Equal(9, text.Split('-').Length);
        Assert.All(text.Split('-'), g => Assert.Equal(4, g.Length));
        using var parsed = RecoveryKey.Parse(text.ToLowerInvariant().Replace("-", " ", StringComparison.Ordinal));
        Assert.Equal(key.Bytes.ToArray(), parsed.Bytes.ToArray());
    }

    [Fact]
    public void Recovery_key_checksum_catches_typos()
    {
        using var key = RecoveryKey.FromBytes(Enumerable.Range(1, 20).Select(i => (byte)i).ToArray());
        var text = key.ToDisplayString().ToCharArray();
        text[0] = text[0] == 'A' ? 'B' : 'A';
        var ex = Assert.Throws<HushException>(() => RecoveryKey.Parse(new string(text)));
        Assert.Equal(HushErrorCode.InvalidRecoveryKey, ex.Code);
        Assert.Contains("typo", ex.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void Recovery_key_accepts_crockford_confusables()
    {
        using var key = RecoveryKey.FromBytes(new byte[20]);
        var text = key.ToDisplayString(); // all zeros => "0000-..."
        using var parsed = RecoveryKey.Parse(text.Replace('0', 'O'));
        Assert.Equal(key.Bytes.ToArray(), parsed.Bytes.ToArray());
    }

    [Theory]
    [InlineData("")]
    [InlineData("ABCD-EFGH")]
    [InlineData("UUUU-UUUU-UUUU-UUUU-UUUU-UUUU-UUUU-UUUU-UUUU")]
    public void Malformed_recovery_keys_are_rejected(string text) =>
        Assert.Equal(HushErrorCode.InvalidRecoveryKey, Assert.Throws<HushException>(() => RecoveryKey.Parse(text)).Code);

    [Fact]
    public void Crockford_round_trip()
    {
        var data = RandomNumberGenerator.GetBytes(20);
        var encoded = CrockfordBase32.Encode(data);
        var decoded = new byte[20];
        Assert.True(CrockfordBase32.TryDecode(encoded, decoded));
        Assert.Equal(data, decoded);
    }

    [Fact]
    public async Task Recovery_after_hello_reset_and_tpm_clear_restores_access()
    {
        using var temp = new TempDirectory();
        var provider = new TestKeyProvider();
        var manager = new VaultManager(temp.HushPaths, provider);
        var creation = await manager.CreateAsync(TestPrompt.Any, null, CancellationToken.None);
        using var recovery = creation.RecoveryKey;
        string oldTpmKey;
        using (var vault = creation.Vault)
        {
            vault.Set(new SecretRef(string.Empty, "K"), "survives"u8, null, VaultTests.Audit());
            oldTpmKey = vault.Document.Factors!.SecondFactorKeyName;
        }

        provider.ResetHello();
        provider.ClearTpm(oldTpmKey);
        await Assert.ThrowsAsync<HushException>(() => manager.UnlockAsync(TestPrompt.Any, CancellationToken.None));

        var typo = recovery.ToDisplayString().ToCharArray();
        typo[^1] = typo[^1] == '0' ? '1' : '0';
        Assert.Equal(HushErrorCode.InvalidRecoveryKey, Assert.Throws<HushException>(() => RecoveryKey.Parse(new string(typo))).Code);

        using (var recovered = await manager.RecoverAsync(recovery, TestPrompt.Any, null, CancellationToken.None))
        {
            Assert.NotEqual(oldTpmKey, recovered.Document.Factors!.SecondFactorKeyName);
            Assert.True(recovered.VerifyAudit().IsValid);
        }

        using var unlocked = await manager.UnlockAsync(TestPrompt.Any, CancellationToken.None);
        Assert.Equal("survives", unlocked.Reveal([new SecretLookup(new SecretRef(string.Empty, "K"), false)], false, VaultTests.Audit()).Single().Value);
    }
}
