using System.Runtime.InteropServices.WindowsRuntime;
using Windows.Security.Credentials;
using Windows.Security.Cryptography.Core;
using Windows.UI;

namespace Hush.Core.Keys;

/// <summary>
/// Windows Hello key credentials via <see cref="KeyCredentialManager"/>. On Windows 11 24H2 and later
/// (build 26100+) the window-handle overloads are used so the Hello dialog is owned by, and appears in
/// front of, the terminal or app that asked for it. Earlier builds fall back to the windowless calls.
/// </summary>
internal static class WindowsHello
{
    private const int WindowApiBuild = 26100;

    public static async Task<string?> CheckAsync(CancellationToken cancellationToken)
    {
        var supported = await KeyCredentialManager.IsSupportedAsync().AsTask(cancellationToken).ConfigureAwait(false);
        return supported
            ? null
            : "Windows Hello is not set up. Open Settings > Accounts > Sign-in options and set up a PIN, face or fingerprint.";
    }

    public static async Task<HelloKey> CreateAsync(string name, PromptContext prompt, CancellationToken cancellationToken)
    {
        KeyCredentialRetrievalResult result;
        if (prompt.OwnerWindow != 0 && OperatingSystem.IsWindowsVersionAtLeast(10, 0, WindowApiBuild))
        {
            result = await KeyCredentialManager
                .RequestCreateForWindowAsync(ToWindowId(prompt.OwnerWindow), name, KeyCredentialCreationOption.ReplaceExisting)
                .AsTask(cancellationToken)
                .ConfigureAwait(false);
        }
        else
        {
            result = await KeyCredentialManager
                .RequestCreateAsync(name, KeyCredentialCreationOption.ReplaceExisting)
                .AsTask(cancellationToken)
                .ConfigureAwait(false);
        }

        ThrowIfFailed(result.Status, "create the Windows Hello key");
        var publicKey = result.Credential.RetrievePublicKey(CryptographicPublicKeyBlobType.X509SubjectPublicKeyInfo);
        return new HelloKey(name, publicKey.ToArray());
    }

    public static async Task<byte[]> SignAsync(string name, ReadOnlyMemory<byte> data, PromptContext prompt, CancellationToken cancellationToken)
    {
        var opened = await KeyCredentialManager.OpenAsync(name).AsTask(cancellationToken).ConfigureAwait(false);
        ThrowIfFailed(opened.Status, "open the Windows Hello key");

        var buffer = data.ToArray().AsBuffer();
        KeyCredentialOperationResult signed;
        if (prompt.OwnerWindow != 0 && OperatingSystem.IsWindowsVersionAtLeast(10, 0, WindowApiBuild))
        {
            signed = await opened.Credential
                .RequestSignForWindowAsync(ToWindowId(prompt.OwnerWindow), buffer)
                .AsTask(cancellationToken)
                .ConfigureAwait(false);
        }
        else
        {
            signed = await opened.Credential.RequestSignAsync(buffer).AsTask(cancellationToken).ConfigureAwait(false);
        }

        ThrowIfFailed(signed.Status, "sign with Windows Hello");
        return signed.Result.ToArray();
    }

    public static async Task DeleteAsync(string name, CancellationToken cancellationToken)
    {
        var opened = await KeyCredentialManager.OpenAsync(name).AsTask(cancellationToken).ConfigureAwait(false);
        if (opened.Status == KeyCredentialStatus.NotFound)
        {
            return;
        }

        await KeyCredentialManager.DeleteAsync(name).AsTask(cancellationToken).ConfigureAwait(false);
    }

    private static WindowId ToWindowId(nint window) => new((ulong)window);

    private static void ThrowIfFailed(KeyCredentialStatus status, string action)
    {
        switch (status)
        {
            case KeyCredentialStatus.Success:
                return;
            case KeyCredentialStatus.UserCanceled:
                throw new HushException(HushErrorCode.HelloCancelled, "Windows Hello verification was cancelled.");
            case KeyCredentialStatus.UserPrefersPassword:
                throw new HushException(HushErrorCode.HelloCancelled, "Windows Hello verification was declined (the user chose a password).");
            case KeyCredentialStatus.NotFound:
                throw new HushException(
                    HushErrorCode.HelloUnavailable,
                    "The Windows Hello key for this vault no longer exists (Windows Hello was reset?). Use 'hush recover' with your recovery key.");
            case KeyCredentialStatus.SecurityDeviceLocked:
                throw new HushException(HushErrorCode.HelloUnavailable, "The security device is locked out after too many attempts. Try again later.");
            default:
                throw new HushException(HushErrorCode.HelloUnavailable, $"Could not {action} ({status}).");
        }
    }
}
