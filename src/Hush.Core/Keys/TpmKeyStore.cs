using System.Security.Cryptography;
using Hush.Core.Crypto;

namespace Hush.Core.Keys;

/// <summary>
/// The TPM factor: a non-exportable RSA-2048 key in the Microsoft Platform Crypto Provider. Encryption
/// uses the exported public key in software (always available); decryption happens inside the TPM.
/// </summary>
internal static class TpmKeyStore
{
    private static readonly CngProvider PlatformProvider = new("Microsoft Platform Crypto Provider");

    /// <summary>Returns null if the TPM provider can be used, or the reason it cannot.</summary>
    public static string? Probe()
    {
        try
        {
            // Opening the provider fails with NTE_DEVICE_NOT_FOUND / NTE_NOT_SUPPORTED when there is no usable TPM.
            _ = CngKey.Exists("hush-tpm-probe", PlatformProvider);
            return null;
        }
        catch (CryptographicException ex)
        {
            return $"The Microsoft Platform Crypto Provider is not available ({ex.Message.Trim()}).";
        }
    }

    public static byte[] CreateAndSeal(string keyName, ReadOnlySpan<byte> secret)
    {
        try
        {
            var parameters = new CngKeyCreationParameters
            {
                Provider = PlatformProvider,
                KeyUsage = CngKeyUsages.Decryption,
                ExportPolicy = CngExportPolicies.None,
                KeyCreationOptions = CngKeyCreationOptions.OverwriteExistingKey,
            };
            parameters.Parameters.Add(new CngProperty("Length", BitConverter.GetBytes(2048), CngPropertyOptions.None));

            using var key = CngKey.Create(CngAlgorithm.Rsa, keyName, parameters);
            using var tpmRsa = new RSACng(key);
            using var publicRsa = RSA.Create();
            publicRsa.ImportParameters(tpmRsa.ExportParameters(includePrivateParameters: false));
            var sealedSecret = publicRsa.Encrypt(secret.ToArray(), RSAEncryptionPadding.OaepSHA256);

            // Prove the round trip now: some TPMs reject OAEP-SHA256, and we would rather fall back at
            // creation time than strand a vault.
            var check = tpmRsa.Decrypt(sealedSecret, RSAEncryptionPadding.OaepSHA256);
            var matches = CryptographicOperations.FixedTimeEquals(check, secret);
            CryptographicOperations.ZeroMemory(check);
            if (!matches)
            {
                throw new HushException(HushErrorCode.TpmFailure, "The TPM returned a different value during the self-test.");
            }

            return sealedSecret;
        }
        catch (CryptographicException ex)
        {
            Exception cause = ex;
            try
            {
                Delete(keyName);
            }
            catch (CryptographicException cleanupError)
            {
                // Surface both: the creation failure, and that a half-created key may remain.
                cause = new AggregateException(ex, cleanupError);
            }

            throw new HushException(HushErrorCode.TpmFailure, $"The TPM could not create the vault key ({ex.Message.Trim()}).", cause);
        }
    }

    public static SecureBuffer Open(string keyName, ReadOnlySpan<byte> sealedSecret)
    {
        try
        {
            if (!CngKey.Exists(keyName, PlatformProvider))
            {
                throw new HushException(
                    HushErrorCode.TpmFailure,
                    "The TPM key for this vault is missing. The TPM may have been cleared or this is a different machine; use 'hush recover'.");
            }

            using var key = CngKey.Open(keyName, PlatformProvider);
            using var rsa = new RSACng(key);
            var plain = rsa.Decrypt(sealedSecret.ToArray(), RSAEncryptionPadding.OaepSHA256);
            var result = SecureBuffer.CopyOf(plain);
            CryptographicOperations.ZeroMemory(plain);
            return result;
        }
        catch (CryptographicException ex)
        {
            throw new HushException(HushErrorCode.TpmFailure, $"The TPM refused to decrypt the vault factor ({ex.Message.Trim()}).", ex);
        }
    }

    public static void Delete(string keyName)
    {
        if (CngKey.Exists(keyName, PlatformProvider))
        {
            using var key = CngKey.Open(keyName, PlatformProvider);
            key.Delete();
        }
    }
}
