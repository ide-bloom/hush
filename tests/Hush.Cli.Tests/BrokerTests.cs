using Hush.Agent;
using Hush.Core;
using Hush.Core.Diagnostics;
using Hush.Core.Interop;
using Hush.Core.Protocol;
using Hush.Core.Settings;
using Hush.Core.Vault;
using Hush.Tests.Support;
using Microsoft.Win32;
using Xunit;

namespace Hush.Cli.Tests;

public sealed class PeerVerifierTests
{
    private sealed class FakeInspector : IPeerInspector
    {
        public Dictionary<int, string?> Images { get; } = [];

        public Dictionary<string, string> Hashes { get; } = new(StringComparer.OrdinalIgnoreCase);

        public Dictionary<string, string?> Signers { get; } = new(StringComparer.OrdinalIgnoreCase);

        public string? ImagePath(int pid) => Images.GetValueOrDefault(pid);

        public string HashFile(string path) => Hashes.TryGetValue(path, out var hash) ? hash : throw new IOException("missing");

        public string? SignerThumbprint(string path) => Signers.GetValueOrDefault(path);
    }

    private const string Install = @"C:\Program Files\Hush";
    private static readonly string Cli = Path.Combine(Install, "hush.exe");
    private static readonly string Tray = Path.Combine(Install, "HushTray.exe");

    private static (PeerVerifier Verifier, FakeInspector Inspector) Create(string? signer = null)
    {
        var inspector = new FakeInspector();
        inspector.Hashes[Cli] = "aa";
        inspector.Hashes[Tray] = "bb";
        var manifest = InstallManifest.FromValues(Install, new Dictionary<string, string> { ["hush.exe"] = "aa", ["HushTray.exe"] = "bb" }, signer);
        return (new PeerVerifier(manifest, inspector, ["hush.exe", "HushTray.exe"]), inspector);
    }

    [Fact]
    public void Accepts_hush_binaries_from_the_install_directory()
    {
        var (verifier, inspector) = Create();
        inspector.Images[10] = Cli;
        inspector.Images[11] = Tray.ToUpperInvariant();
        Assert.True(verifier.Verify(10).Allowed);
        Assert.True(verifier.Verify(11).Allowed);
    }

    [Fact]
    public void Rejects_binaries_from_another_directory()
    {
        var (verifier, inspector) = Create();
        inspector.Images[10] = @"C:\Users\me\Downloads\hush.exe";
        var result = verifier.Verify(10);
        Assert.False(result.Allowed);
        Assert.Contains("install directory", result.Reason, StringComparison.Ordinal);
    }

    [Fact]
    public void Rejects_other_programs_in_the_install_directory()
    {
        var (verifier, inspector) = Create();
        inspector.Images[10] = Path.Combine(Install, "evil.exe");
        Assert.False(verifier.Verify(10).Allowed);
    }

    [Fact]
    public void Rejects_replaced_binaries_by_hash()
    {
        var (verifier, inspector) = Create();
        inspector.Images[10] = Cli;
        inspector.Hashes[Cli] = "ff";
        var result = verifier.Verify(10);
        Assert.False(result.Allowed);
        Assert.Contains("hash mismatch", result.Reason, StringComparison.Ordinal);
    }

    [Fact]
    public void Requires_the_same_signer_when_the_install_is_signed()
    {
        var (verifier, inspector) = Create(signer: "THUMB");
        inspector.Images[10] = Cli;
        inspector.Signers[Cli] = "OTHER";
        Assert.False(verifier.Verify(10).Allowed);
        inspector.Signers[Cli] = "thumb";
        Assert.True(verifier.Verify(10).Allowed);
        inspector.Signers[Cli] = null;
        Assert.False(verifier.Verify(10).Allowed);
    }

    [Fact]
    public void Rejects_processes_whose_image_cannot_be_read()
    {
        var (verifier, _) = Create();
        Assert.False(verifier.Verify(999).Allowed);
    }

    [Fact]
    public void Pipe_names_are_per_user_and_do_not_expose_the_sid()
    {
        var a = PipeFraming.PipeNameFor("S-1-5-21-1-2-3-1001");
        var b = PipeFraming.PipeNameFor("S-1-5-21-1-2-3-1002");
        Assert.NotEqual(a, b);
        Assert.StartsWith("hush-broker-", a, StringComparison.Ordinal);
        Assert.DoesNotContain("1001", a, StringComparison.Ordinal);
    }
}

public sealed class BrokerServiceTests : IDisposable
{
    private readonly CliHarness _h = new();

    public void Dispose() => _h.Dispose();

    private async Task<UnlockedVault> CreateVaultAsync()
    {
        var creation = await new VaultManager(_h.Temp.HushPaths, _h.Provider).CreateAsync(TestPrompt.Any, null, CancellationToken.None);
        creation.RecoveryKey.Dispose();
        return creation.Vault;
    }

    private Task<BrokerResponse> Send(BrokerRequest request) => _h.Transport.SendAsync(request, CancellationToken.None);

    [Fact]
    public async Task Requests_fail_with_locked_until_a_dek_is_handed_over()
    {
        using var vault = await CreateVaultAsync();
        var locked = await Send(new BrokerRequest { Op = BrokerOps.Reveal, Secrets = [new WireSecretRef(string.Empty, "X")] });
        Assert.Equal(nameof(HushErrorCode.Locked), locked.ErrorCode);

        using var dek = vault.CopyDek();
        (await Send(new BrokerRequest { Op = BrokerOps.Unlock, Dek = Convert.ToBase64String(dek.Span) })).EnsureSuccess();
        Assert.True(_h.Broker.IsUnlocked);

        var wrong = await Send(new BrokerRequest { Op = BrokerOps.Unlock, Dek = Convert.ToBase64String(new byte[32]) });
        Assert.False(wrong.Ok);
    }

    [Fact]
    public async Task Always_prompt_secrets_need_a_fresh_one_time_hello_proof()
    {
        using var vault = await CreateVaultAsync();
        vault.Set(new SecretRef(string.Empty, "PROD"), "prod-secret"u8, SecretPolicy.AlwaysPrompt, AuditFactory.Event());
        var session = new SessionClient(new VaultManager(_h.Temp.HushPaths, _h.Provider), _h.Transport, r => TestPrompt.Any);
        await session.HandOverAsync(vault, CancellationToken.None);

        var request = new BrokerRequest { Op = BrokerOps.Reveal, Secrets = [new WireSecretRef(string.Empty, "PROD")] };
        Assert.Equal(nameof(HushErrorCode.PresenceRequired), (await Send(request)).ErrorCode);

        var proof = await session.ProvePresenceAsync("test", CancellationToken.None);
        var ok = await Send(request with { Presence = proof });
        Assert.Equal("prod-secret", ok.EnsureSuccess().Values!.Single().Value);

        var replay = await Send(request with { Presence = proof });
        Assert.Equal(nameof(HushErrorCode.PresenceRequired), replay.ErrorCode);

        var forged = await Send(request with { Presence = proof with { Signature = Convert.ToBase64String(new byte[256]) } });
        Assert.False(forged.Ok);
    }

    [Fact]
    public async Task Session_client_handles_presence_transparently()
    {
        using var vault = await CreateVaultAsync();
        vault.Set(new SecretRef(string.Empty, "PROD"), "prod-secret"u8, SecretPolicy.AlwaysPrompt, AuditFactory.Event());
        var session = new SessionClient(new VaultManager(_h.Temp.HushPaths, _h.Provider), _h.Transport, r => TestPrompt.Any);
        var prompts = 0;
        session.PromptingForPresence += (_, _) => prompts++;
        var values = await session.RevealAsync([new Core.Manifest.EnvBinding("PROD", new SecretRef(string.Empty, "PROD"), false)], "test", false, CancellationToken.None);
        Assert.Equal("prod-secret", values.Single().Value);
        Assert.Equal(2, prompts); // unlock + presence
    }

    [Fact]
    public async Task Idle_timeout_locks_and_status_polling_does_not_keep_the_session_alive()
    {
        using var vault = await CreateVaultAsync();
        using var dek = vault.CopyDek();
        (await Send(new BrokerRequest { Op = BrokerOps.Unlock, Dek = Convert.ToBase64String(dek.Span) })).EnsureSuccess();

        _h.Time.Advance(TimeSpan.FromMinutes(9));
        await Send(new BrokerRequest { Op = BrokerOps.Status });
        _h.Broker.CheckIdle();
        Assert.True(_h.Broker.IsUnlocked);

        _h.Time.Advance(TimeSpan.FromMinutes(2));
        _h.Broker.CheckIdle();
        Assert.False(_h.Broker.IsUnlocked);
        var status = (await Send(new BrokerRequest { Op = BrokerOps.Status })).Status!;
        Assert.Contains("idle", status.LastLockReason, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Configured_timeout_is_honoured_after_reload()
    {
        using var vault = await CreateVaultAsync();
        new HushSettings { IdleTimeoutMinutes = 1 }.Save(_h.Temp.HushPaths);
        (await Send(new BrokerRequest { Op = BrokerOps.ReloadSettings })).EnsureSuccess();
        using var dek = vault.CopyDek();
        (await Send(new BrokerRequest { Op = BrokerOps.Unlock, Dek = Convert.ToBase64String(dek.Span) })).EnsureSuccess();
        _h.Time.Advance(TimeSpan.FromSeconds(61));
        _h.Broker.CheckIdle();
        Assert.False(_h.Broker.IsUnlocked);
    }

    [Fact]
    public async Task Workstation_lock_and_session_switch_lock_the_vault()
    {
        Assert.Equal("workstation locked", SessionLockMonitor.ReasonFor(SessionSwitchReason.SessionLock));
        Assert.NotNull(SessionLockMonitor.ReasonFor(SessionSwitchReason.ConsoleDisconnect));
        Assert.NotNull(SessionLockMonitor.ReasonFor(SessionSwitchReason.RemoteDisconnect));
        Assert.Null(SessionLockMonitor.ReasonFor(SessionSwitchReason.SessionUnlock));

        using var vault = await CreateVaultAsync();
        using var dek = vault.CopyDek();
        (await Send(new BrokerRequest { Op = BrokerOps.Unlock, Dek = Convert.ToBase64String(dek.Span) })).EnsureSuccess();
        _h.Broker.Lock(SessionLockMonitor.ReasonFor(SessionSwitchReason.SessionLock)!);
        Assert.False(_h.Broker.IsUnlocked);
        Assert.Contains(new AuditLogReader(_h.Temp.HushPaths).Actions(), a => a == "session.lock");
    }

    [Fact]
    public async Task Real_named_pipe_round_trip_with_acl_and_peer_verification()
    {
        using var vault = await CreateVaultAsync();
        var self = ProcessInspector.CurrentExecutablePath();
        var inspector = new SystemPeerInspector();
        var verifier = new PeerVerifier(InstallManifest.Capture(self, inspector, [Path.GetFileName(self)]), inspector, [Path.GetFileName(self)]);
        var pipeName = "hush-test-" + Guid.NewGuid().ToString("N");
        var server = new BrokerServer(_h.Broker, verifier, pipeName, new FileLogger(_h.Temp.Combine("logs"), "pipe"));
        using var stop = new CancellationTokenSource();
        var serving = server.RunAsync(stop.Token);

        var transport = new NamedPipeBrokerTransport(pipeName, verifier, launcher: null);
        var status = (await transport.SendAsync(new BrokerRequest { Op = BrokerOps.Status }, CancellationToken.None)).EnsureSuccess().Status!;
        Assert.True(status.VaultExists);
        Assert.Equal(Environment.ProcessId, status.BrokerPid);

        // A second server on the same name must not be able to take over (FILE_FLAG_FIRST_PIPE_INSTANCE).
        var squatter = new BrokerServer(_h.Broker, verifier, pipeName, new FileLogger(_h.Temp.Combine("logs"), "pipe"));
        var ex = await Assert.ThrowsAsync<HushException>(() => squatter.RunAsync(CancellationToken.None));
        Assert.Equal(HushErrorCode.BrokerUnavailable, ex.Code);

        // A client that fails verification gets a refusal, not service.
        var strict = new PeerVerifier(InstallManifest.FromValues(@"C:\elsewhere", new Dictionary<string, string>(), null), inspector, ["hush.exe"]);
        var rejecting = new BrokerServer(_h.Broker, strict, pipeName + "-strict", new FileLogger(_h.Temp.Combine("logs"), "pipe"));
        var servingStrict = rejecting.RunAsync(stop.Token);
        var refused = await new NamedPipeBrokerTransport(pipeName + "-strict", verifier, null).SendAsync(new BrokerRequest { Op = BrokerOps.Status }, CancellationToken.None);
        Assert.Equal(nameof(HushErrorCode.PeerVerificationFailed), refused.ErrorCode);

        await stop.CancelAsync();
        await serving;
        await servingStrict;
    }

    [Fact]
    public async Task Missing_broker_is_reported_when_launching_is_disabled()
    {
        var transport = new NamedPipeBrokerTransport("hush-test-absent-" + Guid.NewGuid().ToString("N"), new PeerVerifier(InstallManifest.FromValues(".", new Dictionary<string, string>(), null), new SystemPeerInspector(), []), null);
        var ex = await Assert.ThrowsAsync<HushException>(() => transport.SendAsync(new BrokerRequest { Op = BrokerOps.Status }, CancellationToken.None));
        Assert.Equal(HushErrorCode.BrokerUnavailable, ex.Code);
    }

    private sealed class AuditLogReader(HushPaths paths)
    {
        public IEnumerable<string> Actions() => new Core.Audit.AuditLog(paths.AuditLog).ReadAll().Select(r => r.Action);
    }
}
