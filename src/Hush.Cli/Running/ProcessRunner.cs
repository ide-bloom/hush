using System.ComponentModel;
using System.Diagnostics;
using System.Runtime.InteropServices;
using Hush.Core;
using Microsoft.Win32.SafeHandles;

namespace Hush.Cli.Running;

/// <summary>What <c>hush run</c> launches.</summary>
/// <param name="Command">Program name or path.</param>
/// <param name="Arguments">Arguments, passed through unchanged.</param>
/// <param name="Environment">Variables to add to (or override in) the child's environment.</param>
/// <param name="Mask">Replace secret values in the child's stdout/stderr with ••••.</param>
internal sealed record RunRequest(string Command, IReadOnlyList<string> Arguments, IReadOnlyDictionary<string, string> Environment, bool Mask);

/// <summary>
/// Launches the child process with secrets added to its environment and returns its exit code. Without
/// <c>--mask</c> the child inherits the console handles directly, so interactive programs behave exactly as
/// if run without Hush. With <c>--mask</c>, stdout and stderr are piped through <see cref="MaskingFilter"/>.
/// The child shares the console, so Ctrl+C reaches it directly; Hush ignores Ctrl+C itself and waits for the
/// child. The child is placed in a kill-on-close job object so it cannot outlive Hush.
/// </summary>
internal static partial class ProcessRunner
{
    private static readonly TimeSpan MaskFlushDelay = TimeSpan.FromMilliseconds(100);

    public static async Task<int> RunAsync(RunRequest request, Stream stdout, Stream stderr, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(request);
        var executable = ResolveExecutable(request.Command)
            ?? throw new HushException(HushErrorCode.InvalidInput, $"'{request.Command}' was not found on PATH.");

        var startInfo = new ProcessStartInfo(executable)
        {
            UseShellExecute = false,
            RedirectStandardOutput = request.Mask,
            RedirectStandardError = request.Mask,
            RedirectStandardInput = false,
        };
        foreach (var argument in request.Arguments)
        {
            startInfo.ArgumentList.Add(argument);
        }

        foreach (var (name, value) in request.Environment)
        {
            startInfo.Environment[name] = value;
        }

        ConsoleCancelEventHandler ignoreCtrlC = (_, e) => e.Cancel = true;
        Console.CancelKeyPress += ignoreCtrlC;
        try
        {
            using var process = Process.Start(startInfo) ?? throw new HushException(HushErrorCode.Unknown, $"Could not start '{request.Command}'.");
            using var job = KillOnCloseJob.TryAssign(process);
            var pumps = new List<Task>();
            if (request.Mask)
            {
                var secrets = request.Environment.Values.ToList();
                pumps.Add(PumpAsync(process.StandardOutput.BaseStream, stdout, new MaskingFilter(secrets), cancellationToken));
                pumps.Add(PumpAsync(process.StandardError.BaseStream, stderr, new MaskingFilter(secrets), cancellationToken));
            }

            await process.WaitForExitAsync(cancellationToken).ConfigureAwait(false);
            await Task.WhenAll(pumps).ConfigureAwait(false);
            return process.ExitCode;
        }
        finally
        {
            Console.CancelKeyPress -= ignoreCtrlC;
        }
    }

    /// <summary>
    /// Resolves a command the way a shell would: absolute or relative paths as given, otherwise each PATH
    /// directory with each PATHEXT extension (so <c>npm</c> finds <c>npm.cmd</c>).
    /// </summary>
    public static string? ResolveExecutable(string command)
    {
        ArgumentNullException.ThrowIfNull(command);
        var extensions = (Environment.GetEnvironmentVariable("PATHEXT") ?? ".COM;.EXE;.BAT;.CMD")
            .Split(';', StringSplitOptions.RemoveEmptyEntries);
        var hasExtension = Path.HasExtension(command);

        IEnumerable<string> Candidates(string basePath)
        {
            if (hasExtension)
            {
                yield return basePath;
            }

            foreach (var extension in extensions)
            {
                yield return basePath + extension.ToLowerInvariant();
            }
        }

        if (command.Contains('\\', StringComparison.Ordinal) || command.Contains('/', StringComparison.Ordinal))
        {
            return Candidates(Path.GetFullPath(command)).FirstOrDefault(File.Exists);
        }

        var directories = new List<string> { Environment.CurrentDirectory };
        directories.AddRange((Environment.GetEnvironmentVariable("PATH") ?? string.Empty).Split(';', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries));
        foreach (var directory in directories)
        {
            string combined;
            try
            {
                combined = Path.Combine(directory.Trim('"'), command);
            }
            catch (ArgumentException)
            {
                // A malformed PATH entry (illegal characters); shells skip those too.
                continue;
            }

            var found = Candidates(combined).FirstOrDefault(File.Exists);
            if (found is not null)
            {
                return found;
            }
        }

        return null;
    }

    private static async Task PumpAsync(Stream source, Stream destination, MaskingFilter filter, CancellationToken cancellationToken)
    {
        var buffer = new byte[8192];
        while (true)
        {
            var read = source.ReadAsync(buffer, cancellationToken).AsTask();
            if (filter.HasPending && await Task.WhenAny(read, Task.Delay(MaskFlushDelay, cancellationToken)).ConfigureAwait(false) != read)
            {
                // The child paused mid-way through something that looked like the start of a secret; it was not
                // one (yet), so let interactive output through rather than stalling it.
                filter.Flush(destination);
            }

            var count = await read.ConfigureAwait(false);
            if (count == 0)
            {
                filter.Flush(destination);
                return;
            }

            filter.Write(buffer.AsSpan(0, count), destination);
        }
    }

    /// <summary>A job object with JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE holding the child.</summary>
    private sealed partial class KillOnCloseJob : IDisposable
    {
        private const int JobObjectExtendedLimitInformation = 9;
        private const uint KillOnJobClose = 0x2000;
        private readonly SafeFileHandle _handle;

        private KillOnCloseJob(SafeFileHandle handle) => _handle = handle;

        public static KillOnCloseJob? TryAssign(Process process)
        {
            var handle = CreateJobObjectW(0, null);
            if (handle.IsInvalid)
            {
                return null;
            }

            var info = new JOBOBJECT_EXTENDED_LIMIT_INFORMATION();
            info.BasicLimitInformation.LimitFlags = KillOnJobClose;
            if (!SetInformationJobObject(handle, JobObjectExtendedLimitInformation, ref info, Marshal.SizeOf<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>())
                || !AssignProcessToJobObject(handle, process.SafeHandle))
            {
                var error = new Win32Exception(Marshal.GetLastPInvokeError());
                handle.Dispose();
                Trace.TraceWarning($"hush run: could not place the child in a job object ({error.Message}); it may outlive hush if hush is killed.");
                return null;
            }

            return new KillOnCloseJob(handle);
        }

        // Disposing after the child exited is harmless; disposing early (hush is exiting) kills the child tree.
        public void Dispose() => _handle.Dispose();

        [StructLayout(LayoutKind.Sequential)]
        private struct JOBOBJECT_BASIC_LIMIT_INFORMATION
        {
            public long PerProcessUserTimeLimit;
            public long PerJobUserTimeLimit;
            public uint LimitFlags;
            public nuint MinimumWorkingSetSize;
            public nuint MaximumWorkingSetSize;
            public uint ActiveProcessLimit;
            public nuint Affinity;
            public uint PriorityClass;
            public uint SchedulingClass;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct IO_COUNTERS
        {
            public ulong ReadOperationCount;
            public ulong WriteOperationCount;
            public ulong OtherOperationCount;
            public ulong ReadTransferCount;
            public ulong WriteTransferCount;
            public ulong OtherTransferCount;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct JOBOBJECT_EXTENDED_LIMIT_INFORMATION
        {
            public JOBOBJECT_BASIC_LIMIT_INFORMATION BasicLimitInformation;
            public IO_COUNTERS IoInfo;
            public nuint ProcessMemoryLimit;
            public nuint JobMemoryLimit;
            public nuint PeakProcessMemoryUsed;
            public nuint PeakJobMemoryUsed;
        }

        [LibraryImport("kernel32.dll", SetLastError = true, StringMarshalling = StringMarshalling.Utf16)]
        private static partial SafeFileHandle CreateJobObjectW(nint attributes, string? name);

        [LibraryImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static partial bool SetInformationJobObject(SafeFileHandle job, int infoClass, ref JOBOBJECT_EXTENDED_LIMIT_INFORMATION info, int length);

        [LibraryImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static partial bool AssignProcessToJobObject(SafeFileHandle job, SafeProcessHandle process);
    }
}
