using System.ComponentModel;
using System.Diagnostics;
using System.IO.Pipes;
using System.Runtime.InteropServices;
using Hush.Core.Interop;

namespace Hush.Core.Protocol;

/// <summary>Sends one request to the session broker and returns its response.</summary>
public interface IBrokerTransport
{
    /// <summary>Sends <paramref name="request"/>.</summary>
    Task<BrokerResponse> SendAsync(BrokerRequest request, CancellationToken cancellationToken);
}

/// <summary>Starts the session broker when it is not running.</summary>
public interface IBrokerLauncher
{
    /// <summary>Starts the broker process.</summary>
    void Launch();
}

/// <summary>Launches <c>hush.exe agent</c> from the install directory, detached and hidden.</summary>
public sealed class ProcessBrokerLauncher : IBrokerLauncher
{
    private readonly string _hushExecutable;

    /// <summary>Creates a launcher for <paramref name="hushExecutable"/>.</summary>
    public ProcessBrokerLauncher(string hushExecutable) => _hushExecutable = hushExecutable;

    /// <summary>A launcher for the hush.exe next to the running executable.</summary>
    public static ProcessBrokerLauncher ForInstall() =>
        new(Path.Combine(AppContext.BaseDirectory, InstallManifest.CliExecutable));

    /// <inheritdoc />
    public void Launch()
    {
        if (!File.Exists(_hushExecutable))
        {
            throw new HushException(HushErrorCode.BrokerUnavailable, $"Cannot start the Hush agent: {_hushExecutable} was not found.");
        }

        // ShellExecute (rather than CreateProcess with inherited handles) matters: the broker outlives this
        // process and must not hold our stdout/stderr pipes open, or a parent waiting for EOF would hang.
        using var process = Process.Start(new ProcessStartInfo(_hushExecutable, "agent")
        {
            UseShellExecute = true,
            WindowStyle = ProcessWindowStyle.Hidden,
            WorkingDirectory = Path.GetDirectoryName(_hushExecutable)!,
        });
    }
}

/// <summary>
/// Talks to the broker over its named pipe. The pipe is opened with <see cref="PipeOptions.CurrentUserOnly"/>
/// and the server process is verified to be a Hush binary from this install before anything is sent,
/// because unlock requests carry the DEK.
/// </summary>
public sealed class NamedPipeBrokerTransport : IBrokerTransport
{
    private static readonly TimeSpan FirstConnectTimeout = TimeSpan.FromMilliseconds(400);
    private static readonly TimeSpan LaunchConnectTimeout = TimeSpan.FromSeconds(10);
    private readonly string _pipeName;
    private readonly IPeerVerifier _serverVerifier;
    private readonly IBrokerLauncher? _launcher;

    /// <summary>Creates a transport.</summary>
    public NamedPipeBrokerTransport(string pipeName, IPeerVerifier serverVerifier, IBrokerLauncher? launcher)
    {
        _pipeName = pipeName;
        _serverVerifier = serverVerifier;
        _launcher = launcher;
    }

    /// <summary>A transport for the current user that verifies the broker against this install.</summary>
    public static NamedPipeBrokerTransport ForCurrentUser(bool launchIfNeeded = true)
    {
        var inspector = new SystemPeerInspector();
        var self = ProcessInspector.CurrentExecutablePath();
        var manifest = InstallManifest.Capture(self, inspector);
        var verifier = new PeerVerifier(manifest, inspector, [InstallManifest.CliExecutable]);
        return new NamedPipeBrokerTransport(PipeFraming.PipeNameForCurrentUser(), verifier, launchIfNeeded ? ProcessBrokerLauncher.ForInstall() : null);
    }

    /// <inheritdoc />
    public async Task<BrokerResponse> SendAsync(BrokerRequest request, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(request);
        var restartedStaleBroker = false;
        while (true)
        {
            using var pipe = await ConnectAsync(cancellationToken).ConfigureAwait(false);
            var serverPid = ServerProcessId(pipe);
            var verification = _serverVerifier.Verify(serverPid);
            if (!verification.Allowed)
            {
                throw new HushException(HushErrorCode.PeerVerificationFailed, $"Refusing to talk to the process serving the Hush pipe: {verification.Reason}");
            }

            await PipeFraming.WriteAsync(pipe, request, BrokerJsonContext.Default.BrokerRequest, cancellationToken).ConfigureAwait(false);
            var response = await PipeFraming.ReadAsync(pipe, BrokerJsonContext.Default.BrokerResponse, cancellationToken).ConfigureAwait(false)
                ?? throw new HushException(HushErrorCode.BrokerUnavailable, "The Hush agent closed the connection without answering.");

            // A broker started before an update rejects the new binaries (hash mismatch). It is verified to be
            // our own install's hush.exe, so stopping it and starting a fresh one is safe.
            if (!response.Ok && response.ErrorCode == nameof(HushErrorCode.PeerVerificationFailed) && !restartedStaleBroker && _launcher is not null)
            {
                restartedStaleBroker = true;
                StopProcess(serverPid);
                continue;
            }

            return response;
        }
    }

    private async Task<NamedPipeClientStream> ConnectAsync(CancellationToken cancellationToken)
    {
        var pipe = NewClient();
        try
        {
            await pipe.ConnectAsync(FirstConnectTimeout, cancellationToken).ConfigureAwait(false);
            return pipe;
        }
        catch (TimeoutException)
        {
            await pipe.DisposeAsync().ConfigureAwait(false);
        }

        if (_launcher is null)
        {
            throw new HushException(HushErrorCode.BrokerUnavailable, "The Hush agent is not running.");
        }

        _launcher.Launch();
        pipe = NewClient();
        try
        {
            await pipe.ConnectAsync(LaunchConnectTimeout, cancellationToken).ConfigureAwait(false);
            return pipe;
        }
        catch (TimeoutException ex)
        {
            await pipe.DisposeAsync().ConfigureAwait(false);
            throw new HushException(HushErrorCode.BrokerUnavailable, "The Hush agent did not start in time.", ex);
        }
    }

    private NamedPipeClientStream NewClient() =>
        new(".", _pipeName, PipeDirection.InOut, PipeOptions.Asynchronous | PipeOptions.CurrentUserOnly);

    private static int ServerProcessId(NamedPipeClientStream pipe)
    {
        if (!NativeMethods.GetNamedPipeServerProcessId(pipe.SafePipeHandle, out var pid))
        {
            throw new HushException(HushErrorCode.PeerVerificationFailed, "Cannot identify the process serving the Hush pipe.", new Win32Exception(Marshal.GetLastPInvokeError()));
        }

        return (int)pid;
    }

    private static void StopProcess(int pid)
    {
        using var process = Process.GetProcessById(pid);
        process.Kill();
        process.WaitForExit(TimeSpan.FromSeconds(5));
    }
}
