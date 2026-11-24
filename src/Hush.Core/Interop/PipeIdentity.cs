using System.ComponentModel;
using System.Runtime.InteropServices;

namespace Hush.Core.Interop;

/// <summary>Identifies the process on the other end of a named pipe.</summary>
public static class PipeIdentity
{
    /// <summary>The client process id of a connected server pipe (GetNamedPipeClientProcessId).</summary>
    public static int ClientProcessId(SafeHandle pipe)
    {
        if (!NativeMethods.GetNamedPipeClientProcessId(pipe, out var pid))
        {
            throw new Win32Exception(Marshal.GetLastPInvokeError());
        }

        return (int)pid;
    }
}
