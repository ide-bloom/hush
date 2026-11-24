using System.Runtime.InteropServices;
using Hush.Core.Interop;
using Hush.Tests.Support;
using Xunit;

namespace Hush.Core.Tests;

public sealed partial class InteropTests : IDisposable
{
    private readonly TempDirectory _temp = new();

    public void Dispose() => _temp.Dispose();

    [Fact]
    public void Copied_secrets_are_excluded_from_history_and_cloud_sync_and_cleared_only_if_unchanged()
    {
        var value = FakeTokens.Password(500);
        uint sequence;
        try
        {
            sequence = SecureClipboard.SetText(value);
        }
        catch (HushException ex)
        {
            // Service sessions (some CI agents) have no clipboard; this test needs an interactive desktop.
            Assert.Skip($"No clipboard in this session: {ex.Message}");
            return;
        }

        foreach (var format in new[] { "ExcludeClipboardContentFromMonitorProcessing", "CanIncludeInClipboardHistory", "CanUploadToCloudClipboard" })
        {
            Assert.True(IsClipboardFormatAvailable(RegisterClipboardFormatW(format)), format);
        }

        Assert.False(SecureClipboard.ClearIfUnchanged(sequence - 1));
        Assert.True(SecureClipboard.ClearIfUnchanged(sequence));
        Assert.False(IsClipboardFormatAvailable(13)); // CF_UNICODETEXT is gone
    }

    [Fact]
    public void Hush_command_is_the_bare_name_only_when_path_resolves_to_the_same_binary()
    {
        var first = _temp.Write(Path.Combine("a", "hush.exe"), "x");
        var second = _temp.Write(Path.Combine("b", "hush.exe"), "y");
        var original = Environment.GetEnvironmentVariable("PATH");
        try
        {
            Environment.SetEnvironmentVariable("PATH", Path.GetDirectoryName(first) + ";" + Path.GetDirectoryName(second));
            Assert.Equal("hush", HushCommand.For(first));
            Assert.Equal(second, HushCommand.For(second));
            Environment.SetEnvironmentVariable("PATH", _temp.Combine("empty"));
            Assert.Equal(first, HushCommand.For(first));
        }
        finally
        {
            Environment.SetEnvironmentVariable("PATH", original);
        }
    }

    [LibraryImport("user32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool IsClipboardFormatAvailable(uint format);

    [LibraryImport("user32.dll", StringMarshalling = StringMarshalling.Utf16)]
    private static partial uint RegisterClipboardFormatW(string format);
}
