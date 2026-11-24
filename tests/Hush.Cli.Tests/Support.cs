using Hush.Agent;
using Hush.Cli.Terminal;
using Hush.Core.Diagnostics;
using Hush.Core.Interop;
using Hush.Core.Protocol;
using Hush.Core.Scanning;
using Hush.Core.Settings;
using Hush.Core.Vault;
using Hush.Tests.Support;

namespace Hush.Cli.Tests;

/// <summary>Talks to a <see cref="BrokerService"/> in the same process, as the current process.</summary>
internal sealed class InProcessTransport(BrokerService service) : IBrokerTransport
{
    public Task<BrokerResponse> SendAsync(BrokerRequest request, CancellationToken cancellationToken) =>
        service.HandleAsync(request, ProcessInspector.Current(), cancellationToken);
}

/// <summary>A scripted terminal.</summary>
internal sealed class FakeTerminal : ITerminal
{
    private readonly Queue<string?> _answers = new();

    public StringWriter OutWriter { get; } = new();

    public StringWriter ErrorWriter { get; } = new();

    public TextWriter Out => OutWriter;

    public TextWriter Error => ErrorWriter;

    public string? Input { get; set; }

    public bool IsInputRedirected => Input is not null;

    public bool CanPrompt { get; set; }

    public bool UseColor => false;

    public FakeTerminal Answer(params string?[] answers)
    {
        foreach (var answer in answers)
        {
            _answers.Enqueue(answer);
        }

        CanPrompt = true;
        return this;
    }

    public string ReadAllInput()
    {
        var input = Input ?? string.Empty;
        Input = null;
        return input;
    }

    public string? ReadSecret(string prompt) => _answers.Count > 0 ? _answers.Dequeue() : null;

    public string? ReadLine(string prompt) => _answers.Count > 0 ? _answers.Dequeue() : null;

    public bool Confirm(string prompt) => ReadLine(prompt) is "y" or "yes";
}

/// <summary>A clock tests can move.</summary>
internal sealed class ManualTime : TimeProvider
{
    private DateTimeOffset _now = new(2026, 11, 1, 9, 0, 0, TimeSpan.Zero);

    public override DateTimeOffset GetUtcNow() => _now;

    public void Advance(TimeSpan by) => _now += by;
}

/// <summary>A complete CLI environment: test key provider, in-process broker, fake terminal, temp folders.</summary>
internal sealed class CliHarness : IDisposable
{
    public CliHarness()
    {
        Temp = new TempDirectory();
        Provider = new TestKeyProvider();
        Time = new ManualTime();
        var manager = new VaultManager(Temp.HushPaths, Provider);
        Broker = new BrokerService(manager, () => HushSettings.Load(Temp.HushPaths), new FileLogger(Temp.Combine("logs"), "test"), Time);
        Transport = new InProcessTransport(Broker);
        Project = Temp.Combine("project");
        Directory.CreateDirectory(Project);
    }

    public TempDirectory Temp { get; }

    public TestKeyProvider Provider { get; }

    public ManualTime Time { get; }

    public BrokerService Broker { get; }

    public InProcessTransport Transport { get; }

    public string Project { get; }

    public FakeTerminal Terminal { get; private set; } = new();

    public MemoryStream ChildOutput { get; private set; } = new();

    public async Task<int> RunAsync(params string[] args) => await RunAsync(new FakeTerminal(), args);

    public async Task<int> RunAsync(FakeTerminal terminal, params string[] args)
    {
        Terminal = terminal;
        ChildOutput = new MemoryStream();
        var services = new CliServices
        {
            Paths = Temp.HushPaths,
            Terminal = terminal,
            Provider = Provider,
            Transport = _ => Transport,
            Prompt = TestPromptFactory,
            ScanEnvironment = ScanEnvironment.Under(Temp.Combine("fake-profile")),
            HushCommand = "hush",
            WorkingDirectory = Project,
            StandardOutput = ChildOutput,
            StandardError = ChildOutput,
        };
        return await CliApp.RunAsync(args, services, CancellationToken.None);
    }

    public string Out => Terminal.OutWriter.ToString();

    public string Error => Terminal.ErrorWriter.ToString();

    public string ChildText => System.Text.Encoding.UTF8.GetString(ChildOutput.ToArray());

    public void Dispose()
    {
        Broker.Dispose();
        Temp.Dispose();
    }

    private static Core.Keys.PromptContext TestPromptFactory(string reason) => Core.Keys.PromptContext.Headless(reason);
}
