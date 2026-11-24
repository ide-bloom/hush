using System.Text;
using Hush.Core.Audit;
using Hush.Core.Interop;
using Hush.Core.Vault;
using Hush.Tests.Support;
using Xunit;

namespace Hush.Core.Tests;

public sealed class AtomicWriteTests : IDisposable
{
    private readonly TempDirectory _temp = new();

    public void Dispose() => _temp.Dispose();

    private sealed class CrashAfterTempWrite : IAtomicWriteHooks
    {
        public string? TempPath { get; private set; }

        public void AfterTempFileFlushed(string tempPath)
        {
            TempPath = tempPath;
            throw new IOException("Simulated power loss between temp write and replace.");
        }
    }

    [Fact]
    public void A_crash_between_temp_write_and_replace_leaves_the_original_intact()
    {
        var target = _temp.Write("vault.hush", "original content");
        var crash = new CrashAfterTempWrite();
        var store = new VaultStore(target, target + ".lock", crash);

        Assert.Throws<IOException>(() => store.WriteAtomic("new content"u8));

        Assert.Equal("original content", File.ReadAllText(target));
        Assert.True(File.Exists(crash.TempPath));
        Assert.Equal(1, new VaultStore(target, target + ".lock").CleanupStaleTempFiles());
        Assert.False(File.Exists(crash.TempPath));
    }

    [Fact]
    public async Task A_crash_during_a_vault_update_keeps_the_previous_vault_openable()
    {
        var provider = new TestKeyProvider();
        var manager = new VaultManager(_temp.HushPaths, provider);
        var creation = await manager.CreateAsync(TestPrompt.Any, null, CancellationToken.None);
        creation.RecoveryKey.Dispose();
        using (var vault = creation.Vault)
        {
            vault.Set(new SecretRef(string.Empty, "KEEP"), "kept"u8, null, VaultTests.Audit());
        }

        var crashing = new VaultManager(_temp.HushPaths, provider, new VaultStore(_temp.HushPaths.Vault, _temp.HushPaths.VaultLock, new CrashAfterTempWrite()));
        using (var vault = await crashing.UnlockAsync(TestPrompt.Any, CancellationToken.None))
        {
            Assert.Throws<IOException>(() => vault.Set(new SecretRef(string.Empty, "LOST"), "lost"u8, null, VaultTests.Audit()));
        }

        Assert.Single(Directory.EnumerateFiles(_temp.HushPaths.Home, "vault.hush.tmp-*"));
        using var reopened = await manager.UnlockAsync(TestPrompt.Any, CancellationToken.None);
        Assert.Equal(["KEEP"], reopened.List().Select(s => s.Name));
        reopened.Set(new SecretRef(string.Empty, "AFTER"), "x"u8, null, VaultTests.Audit());
        Assert.Empty(Directory.EnumerateFiles(_temp.HushPaths.Home, "vault.hush.tmp-*"));
        var verification = reopened.VerifyAudit();
        Assert.True(verification.IsValid, string.Join("; ", verification.Problems));
        Assert.Empty(verification.Warnings);
        Assert.Contains(new AuditLog(_temp.HushPaths.AuditLog).ReadAll(), r => r.Action == "audit.interrupted");
    }

    [Fact]
    public void Writes_replace_the_whole_file()
    {
        var target = _temp.Write("data.bin", new string('x', 10_000));
        VaultStore.WriteAtomic(target, "short"u8);
        Assert.Equal("short", File.ReadAllText(target));
    }
}

public sealed class AuditTests : IDisposable
{
    private readonly TempDirectory _temp = new();

    public void Dispose() => _temp.Dispose();

    private async Task<UnlockedVault> VaultWithEventsAsync(int events)
    {
        var manager = new VaultManager(_temp.HushPaths, new TestKeyProvider());
        var creation = await manager.CreateAsync(TestPrompt.Any, null, CancellationToken.None);
        creation.RecoveryKey.Dispose();
        for (var i = 0; i < events; i++)
        {
            creation.Vault.Record(new AuditEvent("test.event", [$"S{i}"], "ok", $"event {i}", ProcessInspector.Current()));
        }

        return creation.Vault;
    }

    private string[] Lines() => File.ReadAllLines(_temp.HushPaths.AuditLog);

    private void WriteLines(IEnumerable<string> lines) => File.WriteAllText(_temp.HushPaths.AuditLog, string.Join('\n', lines) + "\n", new UTF8Encoding(false));

    [Fact]
    public async Task Intact_chain_verifies()
    {
        using var vault = await VaultWithEventsAsync(5);
        var result = vault.VerifyAudit();
        Assert.True(result.IsValid, string.Join("; ", result.Problems));
        Assert.Equal(6, result.EntryCount); // vault.create + 5
    }

    [Fact]
    public async Task Entries_record_names_process_and_parent_but_never_values()
    {
        using var vault = await VaultWithEventsAsync(0);
        vault.Set(new SecretRef("app", "TOKEN"), "value-that-must-not-appear"u8, null, VaultTests.Audit("secret.set"));
        var text = File.ReadAllText(_temp.HushPaths.AuditLog);
        Assert.DoesNotContain("value-that-must-not-appear", text, StringComparison.Ordinal);
        var record = new AuditLog(_temp.HushPaths.AuditLog).ReadAll()[^1];
        Assert.Equal(["app/TOKEN"], record.Secrets);
        Assert.Equal(Environment.ProcessId, record.Pid);
        Assert.NotNull(record.Process);
        Assert.NotNull(record.ParentPid);
    }

    [Fact]
    public async Task Edited_entry_is_detected()
    {
        using var vault = await VaultWithEventsAsync(3);
        var lines = Lines();
        lines[2] = lines[2].Replace("event 1", "event X", StringComparison.Ordinal);
        WriteLines(lines);
        var result = vault.VerifyAudit();
        Assert.False(result.IsValid);
        Assert.Contains(result.Problems, p => p.Contains("MAC mismatch", StringComparison.Ordinal));
    }

    [Fact]
    public async Task Deleted_entry_in_the_middle_is_detected()
    {
        using var vault = await VaultWithEventsAsync(3);
        WriteLines(Lines().Where((_, i) => i != 2));
        var result = vault.VerifyAudit();
        Assert.False(result.IsValid);
        Assert.Contains(result.Problems, p => p.Contains("chain link broken", StringComparison.Ordinal) || p.Contains("sequence jumps", StringComparison.Ordinal));
    }

    [Fact]
    public async Task Truncated_tail_is_detected_against_the_vault_head()
    {
        using var vault = await VaultWithEventsAsync(3);
        WriteLines(Lines()[..^2]);
        var result = vault.VerifyAudit();
        Assert.False(result.IsValid);
        Assert.Contains(result.Problems, p => p.Contains("truncated", StringComparison.Ordinal));
    }

    [Fact]
    public async Task Deleting_the_whole_log_is_detected()
    {
        using var vault = await VaultWithEventsAsync(2);
        File.Delete(_temp.HushPaths.AuditLog);
        Assert.False(vault.VerifyAudit().IsValid);
    }

    [Fact]
    public async Task Forged_entry_without_the_key_is_detected()
    {
        using var vault = await VaultWithEventsAsync(1);
        var lines = Lines().ToList();
        var last = new AuditLog(_temp.HushPaths.AuditLog).ReadAll()[^1];
        lines.Add($"{{\"seq\":{last.Sequence + 1},\"ts\":\"2026-01-01T00:00:00.000Z\",\"action\":\"secret.read\",\"secrets\":[],\"result\":\"ok\",\"prev\":\"{last.Mac}\",\"mac\":\"{Convert.ToBase64String(new byte[32])}\"}}");
        WriteLines(lines);
        Assert.False(vault.VerifyAudit().IsValid);
    }

    [Fact]
    public async Task Events_recorded_while_locked_join_the_chain_as_deferred()
    {
        using var vault = await VaultWithEventsAsync(0);
        PendingAudit.Append(_temp.HushPaths.PendingAudit, new AuditEvent("session.unlock", [], "cancelled", "Windows Hello cancelled", ProcessInspector.Current()), DateTimeOffset.UtcNow);
        Assert.Equal(1, vault.FoldPendingAudit());
        Assert.False(File.Exists(_temp.HushPaths.PendingAudit));
        var record = new AuditLog(_temp.HushPaths.AuditLog).ReadAll()[^1];
        Assert.True(record.Deferred);
        Assert.Equal("cancelled", record.Result);
        Assert.True(vault.VerifyAudit().IsValid);
    }
}
