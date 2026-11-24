using System.Text;
using Hush.Cli.Running;
using Hush.Tests.Support;
using Xunit;

namespace Hush.Cli.Tests;

public sealed class RunTests : IDisposable
{
    private readonly TempDirectory _temp = new();

    public void Dispose() => _temp.Dispose();

    private static RunRequest Cmd(string script, Dictionary<string, string> env, bool mask) =>
        new("cmd.exe", ["/d", "/c", script], env, mask);

    [Fact]
    public async Task Secrets_are_injected_into_the_child_environment()
    {
        var output = _temp.Combine("env.txt");
        var env = new Dictionary<string, string> { ["HUSH_TEST_SECRET"] = "injected-value-123" };
        var code = await ProcessRunner.RunAsync(Cmd($"echo %HUSH_TEST_SECRET%> {output}", env, mask: false), Stream.Null, Stream.Null, CancellationToken.None);
        Assert.Equal(0, code);
        Assert.Equal("injected-value-123", File.ReadAllText(output).Trim());
    }

    [Fact]
    public async Task Injected_values_do_not_leak_into_the_parent_environment()
    {
        var env = new Dictionary<string, string> { ["HUSH_TEST_PARENT_LEAK"] = "child-only" };
        await ProcessRunner.RunAsync(Cmd("exit 0", env, mask: false), Stream.Null, Stream.Null, CancellationToken.None);
        Assert.Null(Environment.GetEnvironmentVariable("HUSH_TEST_PARENT_LEAK"));
    }

    [Theory]
    [InlineData(0)]
    [InlineData(1)]
    [InlineData(7)]
    [InlineData(255)]
    public async Task The_child_exit_code_is_returned(int exitCode)
    {
        var code = await ProcessRunner.RunAsync(Cmd($"exit {exitCode}", [], mask: false), Stream.Null, Stream.Null, CancellationToken.None);
        Assert.Equal(exitCode, code);
    }

    [Fact]
    public async Task Mask_replaces_secret_values_in_stdout_and_stderr()
    {
        var secret = FakeTokens.StripeLive(50);
        var stdout = new MemoryStream();
        var stderr = new MemoryStream();
        var env = new Dictionary<string, string> { ["STRIPE_KEY"] = secret };
        var code = await ProcessRunner.RunAsync(Cmd("echo out:%STRIPE_KEY% & echo err:%STRIPE_KEY% 1>&2 & exit 3", env, mask: true), stdout, stderr, CancellationToken.None);

        Assert.Equal(3, code);
        var outText = Encoding.UTF8.GetString(stdout.ToArray());
        var errText = Encoding.UTF8.GetString(stderr.ToArray());
        Assert.Contains("out:••••", outText, StringComparison.Ordinal);
        Assert.Contains("err:••••", errText, StringComparison.Ordinal);
        Assert.DoesNotContain(secret, outText + errText, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Unknown_commands_fail_clearly()
    {
        var ex = await Assert.ThrowsAsync<Core.HushException>(() => ProcessRunner.RunAsync(new RunRequest("definitely-not-a-real-command-hush", [], new Dictionary<string, string>(), false), Stream.Null, Stream.Null, CancellationToken.None));
        Assert.Contains("not found", ex.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void Executables_resolve_through_path_and_pathext()
    {
        Assert.EndsWith("cmd.exe", ProcessRunner.ResolveExecutable("cmd")!, StringComparison.OrdinalIgnoreCase);
        var script = _temp.Write("tool.cmd", "@echo off\r\n");
        Assert.Equal(script, ProcessRunner.ResolveExecutable(script[..^4]), StringComparer.OrdinalIgnoreCase);
    }
}

public sealed class MaskingFilterTests
{
    private static string Filter(IEnumerable<string> secrets, params string[] chunks)
    {
        var filter = new MaskingFilter(secrets);
        var output = new MemoryStream();
        foreach (var chunk in chunks)
        {
            filter.Write(Encoding.UTF8.GetBytes(chunk), output);
        }

        filter.Flush(output);
        return Encoding.UTF8.GetString(output.ToArray());
    }

    [Fact]
    public void Masks_whole_values() => Assert.Equal("key=•••• done", Filter(["s3cr3t-value"], "key=s3cr3t-value done"));

    [Fact]
    public void Masks_values_split_across_writes() => Assert.Equal("a•••• b", Filter(["s3cr3t-value"], "as3cr", "3t-va", "lue b"));

    [Fact]
    public void Masks_several_values_and_repeats() => Assert.Equal("•••• •••• ••••", Filter(["alpha-1", "beta-22"], "alpha-1 beta-22 alpha-1"));

    [Fact]
    public void Prefers_the_longest_overlapping_value() => Assert.Equal("[••••]", Filter(["abcd", "abcdefgh"], "[abcdefgh]"));

    [Fact]
    public void Releases_partial_prefixes_that_never_complete() => Assert.Equal("s3cr3t-", Filter(["s3cr3t-value"], "s3cr3t-"));

    [Fact]
    public void Ignores_values_too_short_to_mask_safely() => Assert.Equal("a b c", Filter(["a", "bc"], "a b c"));

    [Fact]
    public void Passes_non_ascii_output_through_unchanged() => Assert.Equal("héllo •••• wörld", Filter(["tøken-ü1"], "héllo tøken-ü1 wörld"));
}
