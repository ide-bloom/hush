using System.ComponentModel;
using System.IO.Pipes;
using System.Security.AccessControl;
using System.Security.Principal;
using Hush.Core;
using Hush.Core.Interop;
using Hush.Core.Protocol;
using Microsoft.Extensions.Logging;

namespace Hush.Agent;

/// <summary>
/// The named-pipe front end of the broker. The pipe name is derived from the user's SID, its ACL grants
/// access to the current user only (and explicitly denies network logons), the first instance is created
/// with FILE_FLAG_FIRST_PIPE_INSTANCE so another process cannot squat the name, and every connecting process
/// is verified (path, SHA-256, signer) before its request is read.
/// </summary>
public sealed partial class BrokerServer
{
    private static readonly TimeSpan RequestTimeout = TimeSpan.FromSeconds(30);

    // Non-zero buffers so a refusal written to a client that is still sending its request cannot deadlock.
    private const int PipeBufferSize = 64 * 1024;
    private readonly BrokerService _service;
    private readonly IPeerVerifier _clientVerifier;
    private readonly string _pipeName;
    private readonly ILogger _logger;

    /// <summary>Creates a server.</summary>
    public BrokerServer(BrokerService service, IPeerVerifier clientVerifier, string pipeName, ILogger logger)
    {
        _service = service;
        _clientVerifier = clientVerifier;
        _pipeName = pipeName;
        _logger = logger;
    }

    /// <summary>Serves connections until <paramref name="cancellationToken"/> is cancelled.</summary>
    public async Task RunAsync(CancellationToken cancellationToken)
    {
        var security = CreateSecurity();
        var first = true;
        var connections = new List<Task>();
        while (!cancellationToken.IsCancellationRequested)
        {
            NamedPipeServerStream pipe;
            try
            {
                pipe = NamedPipeServerStreamAcl.Create(
                    _pipeName,
                    PipeDirection.InOut,
                    NamedPipeServerStream.MaxAllowedServerInstances,
                    PipeTransmissionMode.Byte,
                    PipeOptions.Asynchronous | (first ? PipeOptions.FirstPipeInstance : PipeOptions.None),
                    PipeBufferSize,
                    PipeBufferSize,
                    security);
            }
            catch (UnauthorizedAccessException ex) when (first)
            {
                throw new HushException(HushErrorCode.BrokerUnavailable, "Another process already owns the Hush pipe (is the Hush agent already running?).", ex);
            }
            catch (IOException ex) when (first)
            {
                throw new HushException(HushErrorCode.BrokerUnavailable, "Another process already owns the Hush pipe (is the Hush agent already running?).", ex);
            }

            first = false;
            try
            {
                await pipe.WaitForConnectionAsync(cancellationToken).ConfigureAwait(false);
            }
            catch (OperationCanceledException)
            {
                await pipe.DisposeAsync().ConfigureAwait(false);
                break;
            }

            connections.RemoveAll(t => t.IsCompleted);
            connections.Add(ServeAsync(pipe, cancellationToken));
        }

        await Task.WhenAll(connections).ConfigureAwait(false);
    }

    private async Task ServeAsync(NamedPipeServerStream pipe, CancellationToken cancellationToken)
    {
        await using (pipe.ConfigureAwait(false))
        {
            using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            timeout.CancelAfter(RequestTimeout);
            try
            {
                var pid = PipeIdentity.ClientProcessId(pipe.SafePipeHandle);
                var verification = _clientVerifier.Verify(pid);
                if (!verification.Allowed)
                {
                    Log.ClientRejected(_logger, pid, verification.ImagePath ?? "(unknown)", verification.Reason);
                    await PipeFraming.WriteAsync(
                        pipe,
                        BrokerResponse.Failure(HushErrorCode.PeerVerificationFailed, $"The Hush agent refused this client: {verification.Reason}"),
                        BrokerJsonContext.Default.BrokerResponse,
                        timeout.Token).ConfigureAwait(false);
                    return;
                }

                var request = await PipeFraming.ReadAsync(pipe, BrokerJsonContext.Default.BrokerRequest, timeout.Token).ConfigureAwait(false);
                if (request is null)
                {
                    return;
                }

                var response = await _service.HandleAsync(request, ProcessInspector.Describe(pid), timeout.Token).ConfigureAwait(false);
                await PipeFraming.WriteAsync(pipe, response, BrokerJsonContext.Default.BrokerResponse, timeout.Token).ConfigureAwait(false);
            }
            catch (Exception ex) when (ex is IOException or OperationCanceledException or InvalidDataException or Win32Exception or System.Text.Json.JsonException)
            {
                Log.ConnectionFailed(_logger, ex.GetType().Name, ex.Message);
            }
        }
    }

    private static PipeSecurity CreateSecurity()
    {
        using var identity = WindowsIdentity.GetCurrent();
        var user = identity.User ?? throw new InvalidOperationException("The current user has no SID.");
        var security = new PipeSecurity();
        security.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);
        security.SetOwner(user);
        security.AddAccessRule(new PipeAccessRule(user, PipeAccessRights.ReadWrite | PipeAccessRights.CreateNewInstance | PipeAccessRights.Synchronize, AccessControlType.Allow));
        security.AddAccessRule(new PipeAccessRule(new SecurityIdentifier(WellKnownSidType.NetworkSid, null), PipeAccessRights.FullControl, AccessControlType.Deny));
        return security;
    }

    private static partial class Log
    {
        [LoggerMessage(20, LogLevel.Warning, "Rejected pipe client {Pid} ({Image}): {Reason}")]
        public static partial void ClientRejected(ILogger logger, int pid, string image, string reason);

        [LoggerMessage(21, LogLevel.Debug, "Pipe connection ended with {Error}: {Message}")]
        public static partial void ConnectionFailed(ILogger logger, string error, string message);
    }
}
