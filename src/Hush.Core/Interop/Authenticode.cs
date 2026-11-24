using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace Hush.Core.Interop;

/// <summary>Authenticode checks with WinVerifyTrust (no UI, no network revocation lookups).</summary>
public static partial class Authenticode
{
    private const uint WTD_UI_NONE = 2;
    private const uint WTD_REVOKE_NONE = 0;
    private const uint WTD_CHOICE_FILE = 1;
    private const uint WTD_STATEACTION_VERIFY = 1;
    private const uint WTD_STATEACTION_CLOSE = 2;
    private const uint WTD_REVOCATION_CHECK_NONE = 0x10;
    private const uint WTD_CACHE_ONLY_URL_RETRIEVAL = 0x1000;
    private static readonly Guid GenericVerifyV2 = new("00AAC56B-CD44-11d0-8CC2-00C04FC295EE");

    /// <summary>
    /// Returns the SHA-256 thumbprint of the signing certificate if <paramref name="path"/> carries a valid
    /// Authenticode signature that chains to a trusted root, otherwise null (unsigned or invalid).
    /// </summary>
    public static string? GetValidSignerThumbprint(string path)
    {
        if (!IsSignatureValid(path))
        {
            return null;
        }

        try
        {
#pragma warning disable SYSLIB0057 // CreateFromSignedFile is the supported way to read the Authenticode signer; WinVerifyTrust validated it above.
            using var signer = X509Certificate.CreateFromSignedFile(path);
#pragma warning restore SYSLIB0057
            return signer.GetCertHashString(HashAlgorithmName.SHA256);
        }
        catch (CryptographicException)
        {
            // No readable signer certificate means "not validly signed", which is exactly what null reports.
            return null;
        }
    }

    private static unsafe bool IsSignatureValid(string path)
    {
        fixed (char* pathPtr = path)
        {
            var fileInfo = new WINTRUST_FILE_INFO
            {
                cbStruct = (uint)sizeof(WINTRUST_FILE_INFO),
                pcwszFilePath = (nint)pathPtr,
            };
            var data = new WINTRUST_DATA
            {
                cbStruct = (uint)sizeof(WINTRUST_DATA),
                dwUIChoice = WTD_UI_NONE,
                fdwRevocationChecks = WTD_REVOKE_NONE,
                dwUnionChoice = WTD_CHOICE_FILE,
                pFile = (nint)(&fileInfo),
                dwStateAction = WTD_STATEACTION_VERIFY,
                // Hush never touches the network: no revocation checks, and chain building uses the local cache only.
                dwProvFlags = WTD_REVOCATION_CHECK_NONE | WTD_CACHE_ONLY_URL_RETRIEVAL,
            };
            var action = GenericVerifyV2;
            var result = WinVerifyTrust(-1, ref action, ref data);
            data.dwStateAction = WTD_STATEACTION_CLOSE;
            _ = WinVerifyTrust(-1, ref action, ref data);
            return result == 0;
        }
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct WINTRUST_FILE_INFO
    {
        public uint cbStruct;
        public nint pcwszFilePath;
        public nint hFile;
        public nint pgKnownSubject;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct WINTRUST_DATA
    {
        public uint cbStruct;
        public nint pPolicyCallbackData;
        public nint pSIPClientData;
        public uint dwUIChoice;
        public uint fdwRevocationChecks;
        public uint dwUnionChoice;
        public nint pFile;
        public uint dwStateAction;
        public nint hWVTStateData;
        public nint pwszURLReference;
        public uint dwProvFlags;
        public uint dwUIContext;
        public nint pSignatureSettings;
    }

    [LibraryImport("wintrust.dll")]
    private static partial int WinVerifyTrust(nint window, ref Guid action, ref WINTRUST_DATA data);
}
