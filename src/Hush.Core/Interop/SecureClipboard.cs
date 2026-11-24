using System.ComponentModel;
using System.Runtime.InteropServices;

namespace Hush.Core.Interop;

/// <summary>
/// Clipboard access for secrets. Text is published together with the documented exclusion formats so it
/// stays out of Windows clipboard history (Win+V) and is not synced to other devices:
/// <c>ExcludeClipboardContentFromMonitorProcessing</c>, <c>CanIncludeInClipboardHistory</c> = 0 and
/// <c>CanUploadToCloudClipboard</c> = 0.
/// </summary>
public static class SecureClipboard
{
    /// <summary>Copies <paramref name="text"/>; returns the clipboard sequence number afterwards.</summary>
    public static uint SetText([Sensitive] string text)
    {
        ArgumentNullException.ThrowIfNull(text);
        return WithClipboard(() =>
        {
            if (!NativeMethods.EmptyClipboard())
            {
                throw Failure("empty the clipboard");
            }

            SetData(NativeMethods.CF_UNICODETEXT, Utf16WithTerminator(text));
            SetData(NativeMethods.RegisterClipboardFormat("ExcludeClipboardContentFromMonitorProcessing"), [0, 0, 0, 0]);
            SetData(NativeMethods.RegisterClipboardFormat("CanIncludeInClipboardHistory"), [0, 0, 0, 0]);
            SetData(NativeMethods.RegisterClipboardFormat("CanUploadToCloudClipboard"), [0, 0, 0, 0]);
            return true;
        }) ? NativeMethods.GetClipboardSequenceNumber() : 0;
    }

    /// <summary>
    /// Empties the clipboard only if nothing was copied since <paramref name="sequence"/>, so Hush never
    /// wipes something the user copied afterwards. Returns true if it cleared.
    /// </summary>
    public static bool ClearIfUnchanged(uint sequence)
    {
        if (NativeMethods.GetClipboardSequenceNumber() != sequence)
        {
            return false;
        }

        return WithClipboard(() => NativeMethods.EmptyClipboard());
    }

    private static bool WithClipboard(Func<bool> action)
    {
        // SetClipboardData fails when the clipboard was opened without an owner window, so use a
        // message-only window for the duration of the operation.
        var window = NativeMethods.CreateWindowEx(0, "STATIC", null, 0, 0, 0, 0, 0, NativeMethods.HWND_MESSAGE, 0, 0, 0);
        if (window == 0)
        {
            throw Failure("create a clipboard owner window");
        }

        try
        {
            var opened = false;
            for (var attempt = 0; attempt < 20 && !opened; attempt++)
            {
                opened = NativeMethods.OpenClipboard(window);
                if (!opened)
                {
                    Thread.Sleep(25);
                }
            }

            if (!opened)
            {
                throw Failure("open the clipboard (another application is holding it)");
            }

            try
            {
                return action();
            }
            finally
            {
                NativeMethods.CloseClipboard();
            }
        }
        finally
        {
            NativeMethods.DestroyWindow(window);
        }
    }

    private static void SetData(uint format, byte[] data)
    {
        var memory = NativeMethods.GlobalAlloc(NativeMethods.GMEM_MOVEABLE, (nuint)data.Length);
        if (memory == 0)
        {
            throw Failure("allocate clipboard memory");
        }

        var locked = NativeMethods.GlobalLock(memory);
        if (locked == 0)
        {
            NativeMethods.GlobalFree(memory);
            throw Failure("lock clipboard memory");
        }

        try
        {
            Marshal.Copy(data, 0, locked, data.Length);
        }
        finally
        {
            NativeMethods.GlobalUnlock(memory);
            Array.Clear(data);
        }

        if (NativeMethods.SetClipboardData(format, memory) == 0)
        {
            NativeMethods.GlobalFree(memory);
            throw Failure("set clipboard data");
        }
    }

    private static byte[] Utf16WithTerminator(string text)
    {
        var bytes = new byte[(text.Length + 1) * 2];
        System.Text.Encoding.Unicode.GetBytes(text, 0, text.Length, bytes, 0);
        return bytes;
    }

    private static HushException Failure(string action) =>
        new(HushErrorCode.Unknown, $"Could not {action}.", new Win32Exception(Marshal.GetLastPInvokeError()));
}
