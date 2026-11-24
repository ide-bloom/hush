using Hush.Cli.Terminal;
using Hush.Core;
using Hush.Core.Interop;
using Hush.Core.Keys;
using Hush.Core.Protocol;
using Hush.Core.Scanning;
using Hush.Core.Vault;

namespace Hush.Cli;

/// <summary>Everything a command needs. Tests substitute the provider, transport and terminal.</summary>
internal sealed class CliServices
{
    private VaultManager? _manager;
    private SessionClient? _session;

    public required HushPaths Paths { get; init; }

    public required ITerminal Terminal { get; init; }

    public required IHardwareKeyProvider Provider { get; init; }

    /// <summary>Creates the transport to the broker; the flag says whether to start the broker if needed.</summary>
    public required Func<bool, IBrokerTransport> Transport { get; init; }

    /// <summary>Builds the owner window for a Windows Hello prompt.</summary>
    public required Func<string, PromptContext> Prompt { get; init; }

    public required ScanEnvironment ScanEnvironment { get; init; }

    /// <summary>How rewritten MCP configs should invoke Hush.</summary>
    public required string HushCommand { get; init; }

    public string WorkingDirectory { get; init; } = Environment.CurrentDirectory;

    public Stream StandardOutput { get; init; } = Console.OpenStandardOutput();

    public Stream StandardError { get; init; } = Console.OpenStandardError();

    public VaultManager Manager => _manager ??= new VaultManager(Paths, Provider);

    public SessionClient Session
    {
        get
        {
            if (_session is null)
            {
                _session = new SessionClient(Manager, Transport(true), Prompt);
                _session.PromptingForPresence += (_, reason) => Terminal.Error.WriteLine(Terminal.Cyan($"Windows Hello: {reason}. Confirm in the Windows Security prompt..."));
            }

            return _session;
        }
    }

    /// <summary>Asks a running broker for its status without starting one. Null if it is not running.</summary>
    public async Task<BrokerStatus?> TryAgentStatusAsync(CancellationToken cancellationToken)
    {
        try
        {
            var response = await Transport(false).SendAsync(new BrokerRequest { Op = BrokerOps.Status }, cancellationToken).ConfigureAwait(false);
            return response.EnsureSuccess().Status;
        }
        catch (HushException ex) when (ex.Code == HushErrorCode.BrokerUnavailable)
        {
            return null;
        }
    }

    public static CliServices CreateDefault()
    {
        var terminal = new SystemTerminal();
        return new CliServices
        {
            Paths = HushPaths.Default(),
            Terminal = terminal,
            Provider = new PlatformKeyProvider(),
            Transport = launch => NamedPipeBrokerTransport.ForCurrentUser(launch),
            Prompt = reason => new PromptContext(PromptOwner.ForConsole(), reason),
            ScanEnvironment = ScanEnvironment.Current(),
            HushCommand = Core.Interop.HushCommand.For(ProcessInspector.CurrentExecutablePath()),
        };
    }
}
