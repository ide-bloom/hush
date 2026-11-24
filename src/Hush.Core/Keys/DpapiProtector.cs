using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using Hush.Core.Crypto;
using Hush.Core.Interop;

namespace Hush.Core.Keys;

/// <summary>
/// Degraded-mode protection for <c>S_tpm</c> with DPAPI in the current-user scope. DPAPI ties the blob
/// to the Windows account but not to the hardware, which is why vaults using it are flagged as degraded.
/// </summary>
internal static class DpapiProtector
{
    public static byte[] Protect(ReadOnlySpan<byte> secret, string keyName)
    {
        var entropy = Entropy(keyName);
        var input = GC.AllocateArray<byte>(secret.Length, pinned: true);
        secret.CopyTo(input);
        try
        {
            unsafe
            {
                fixed (byte* inPtr = input)
                fixed (byte* entropyPtr = entropy)
                {
                    var inBlob = new NativeMethods.DATA_BLOB { cbData = input.Length, pbData = (nint)inPtr };
                    var entropyBlob = new NativeMethods.DATA_BLOB { cbData = entropy.Length, pbData = (nint)entropyPtr };
                    if (!NativeMethods.CryptProtectData(ref inBlob, "Hush", ref entropyBlob, 0, 0, NativeMethods.CRYPTPROTECT_UI_FORBIDDEN, out var outBlob))
                    {
                        throw new HushException(HushErrorCode.TpmFailure, "DPAPI could not protect the vault factor.", new Win32Exception(Marshal.GetLastPInvokeError()));
                    }

                    try
                    {
                        var result = new byte[outBlob.cbData];
                        Marshal.Copy(outBlob.pbData, result, 0, outBlob.cbData);
                        return result;
                    }
                    finally
                    {
                        NativeMethods.LocalFree(outBlob.pbData);
                    }
                }
            }
        }
        finally
        {
            CryptographicOperations.ZeroMemory(input);
        }
    }

    public static SecureBuffer Unprotect(ReadOnlySpan<byte> sealedSecret, string keyName)
    {
        var entropy = Entropy(keyName);
        var input = sealedSecret.ToArray();
        unsafe
        {
            fixed (byte* inPtr = input)
            fixed (byte* entropyPtr = entropy)
            {
                var inBlob = new NativeMethods.DATA_BLOB { cbData = input.Length, pbData = (nint)inPtr };
                var entropyBlob = new NativeMethods.DATA_BLOB { cbData = entropy.Length, pbData = (nint)entropyPtr };
                if (!NativeMethods.CryptUnprotectData(ref inBlob, 0, ref entropyBlob, 0, 0, NativeMethods.CRYPTPROTECT_UI_FORBIDDEN, out var outBlob))
                {
                    throw new HushException(HushErrorCode.TpmFailure, "DPAPI could not unprotect the vault factor (different Windows account or machine?).", new Win32Exception(Marshal.GetLastPInvokeError()));
                }

                try
                {
                    var result = new SecureBuffer(outBlob.cbData);
                    new ReadOnlySpan<byte>((void*)outBlob.pbData, outBlob.cbData).CopyTo(result.Span);
                    new Span<byte>((void*)outBlob.pbData, outBlob.cbData).Clear();
                    return result;
                }
                finally
                {
                    NativeMethods.LocalFree(outBlob.pbData);
                }
            }
        }
    }

    private static byte[] Entropy(string keyName) => Encoding.UTF8.GetBytes("hush/dpapi/v1/" + keyName);
}
