using System.Diagnostics;
using System.Runtime.InteropServices;

namespace Hush.Core.Interop;

/// <summary>Who asked for something: a process, its image and its parent.</summary>
/// <param name="Pid">Process id.</param>
/// <param name="Path">Full image path, if it could be read.</param>
/// <param name="ParentPid">Parent process id, if known.</param>
/// <param name="ParentPath">Parent image path, if it could be read (the parent may have exited).</param>
public sealed record ProcessIdentity(int Pid, string? Path, int? ParentPid, string? ParentPath);

/// <summary>Reads image paths and parent ids of other processes with least-privilege access.</summary>
public static class ProcessInspector
{
    /// <summary>The identity of the current process.</summary>
    public static ProcessIdentity Current() => Describe(Environment.ProcessId);

    /// <summary>Describes <paramref name="pid"/>; fields that cannot be read are null.</summary>
    public static ProcessIdentity Describe(int pid)
    {
        var path = ImagePath(pid);
        var parent = ParentPid(pid);
        return new ProcessIdentity(pid, path, parent, parent is { } p ? ImagePath(p) : null);
    }

    /// <summary>Full image path of <paramref name="pid"/>, or null if the process is gone or protected.</summary>
    public static string? ImagePath(int pid)
    {
        using var handle = NativeMethods.OpenProcess(NativeMethods.PROCESS_QUERY_LIMITED_INFORMATION, false, (uint)pid);
        if (handle.IsInvalid)
        {
            return null;
        }

        Span<char> buffer = stackalloc char[1024];
        var size = (uint)buffer.Length;
        unsafe
        {
            fixed (char* ptr = buffer)
            {
                return NativeMethods.QueryFullProcessImageName(handle, 0, ptr, ref size) ? new string(buffer[..(int)size]) : null;
            }
        }
    }

    /// <summary>Parent process id of <paramref name="pid"/>, or null if it cannot be read.</summary>
    public static int? ParentPid(int pid)
    {
        using var handle = NativeMethods.OpenProcess(NativeMethods.PROCESS_QUERY_LIMITED_INFORMATION, false, (uint)pid);
        if (handle.IsInvalid)
        {
            return null;
        }

        var status = NativeMethods.NtQueryInformationProcess(handle, 0, out var info, Marshal.SizeOf<NativeMethods.PROCESS_BASIC_INFORMATION>(), out _);
        return status == 0 ? (int)info.InheritedFromUniqueProcessId : null;
    }

    /// <summary>Full path of the running executable.</summary>
    public static string CurrentExecutablePath() =>
        Environment.ProcessPath ?? Process.GetCurrentProcess().MainModule?.FileName ?? throw new InvalidOperationException("Cannot determine the executable path.");
}
