using Hush.Core;
using Hush.Core.Diagnostics;
using Hush.Core.Interop;
using Hush.Core.Keys;
using Hush.Core.Protocol;
using Hush.Core.Settings;
using Hush.Core.Vault;
using Microsoft.Extensions.Logging;

namespace Hush.Agent;

/// <summary>Runs the broker: pipe server, idle timer and session-lock monitor.</summary>
public static partial class AgentHost
{
    private static readonly TimeSpan IdleCheckInterval = TimeSpan.FromSeconds(5);

    /// <summary>Runs until cancelled or until a client asks it to shut down. Returns a process exit code.</summary>
    public static async Task<int> RunAsync(CancellationToken cancellationToken)
    {
        var paths = HushPaths.Default();
        paths.EnsureHome();
        var logger = FileLogger.For(paths, "agent");
        var manager = new VaultManager(paths, new PlatformKeyProvider());
        using var service = new BrokerService(manager, () => HushSettings.Load(paths), logger);
        using var stop = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        service.ShutdownRequested += (_, _) => stop.Cancel();

        var inspector = new SystemPeerInspector();
        var self = ProcessInspector.CurrentExecutablePath();
        var verifier = new PeerVerifier(InstallManifest.Capture(self, inspector), inspector, [InstallManifest.CliExecutable, InstallManifest.TrayExecutable]);
        var server = new BrokerServer(service, verifier, PipeFraming.PipeNameForCurrentUser(), logger);

        using var monitor = new SessionLockMonitor(service.Lock, () => service.Settings.LockOnSleep);
        Log.Started(logger, Environment.ProcessId);
        var idle = IdleLoopAsync(service, stop.Token);
        try
        {
            await server.RunAsync(stop.Token).ConfigureAwait(false);
        }
        catch (HushException ex) when (ex.Code == HushErrorCode.BrokerUnavailable)
        {
            Log.AlreadyRunning(logger, ex.Message);
            return 2;
        }
        finally
        {
            await stop.CancelAsync().ConfigureAwait(false);
            await idle.ConfigureAwait(false);
            Log.Stopped(logger);
        }

        return 0;
    }

    private static async Task IdleLoopAsync(BrokerService service, CancellationToken cancellationToken)
    {
        using var timer = new PeriodicTimer(IdleCheckInterval);
        try
        {
            while (await timer.WaitForNextTickAsync(cancellationToken).ConfigureAwait(false))
            {
                service.CheckIdle();
            }
        }
        catch (OperationCanceledException)
        {
            // Normal shutdown.
        }
    }

    private static partial class Log
    {
        [LoggerMessage(30, LogLevel.Information, "Hush agent started (pid {Pid})")]
        public static partial void Started(ILogger logger, int pid);

        [LoggerMessage(31, LogLevel.Information, "Hush agent stopped")]
        public static partial void Stopped(ILogger logger);

        [LoggerMessage(32, LogLevel.Warning, "Hush agent not started: {Reason}")]
        public static partial void AlreadyRunning(ILogger logger, string reason);
    }
}
