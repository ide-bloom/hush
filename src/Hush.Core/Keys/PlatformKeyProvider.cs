using Hush.Core.Crypto;

namespace Hush.Core.Keys;

/// <summary>
/// The production provider: Windows Hello for presence, the TPM (or DPAPI in degraded mode) for the
/// machine binding.
/// </summary>
public sealed class PlatformKeyProvider : IHardwareKeyProvider
{
    /// <inheritdoc />
    public KeyProviderKind Kind => KeyProviderKind.Platform;

    /// <inheritdoc />
    public Task<string?> CheckHelloAsync(CancellationToken cancellationToken) => WindowsHello.CheckAsync(cancellationToken);

    /// <inheritdoc />
    public SecondFactorChoice ChooseSecondFactor()
    {
        var problem = TpmKeyStore.Probe();
        return problem is null
            ? new SecondFactorChoice(SecondFactorKind.Tpm, null)
            : new SecondFactorChoice(SecondFactorKind.Dpapi, problem);
    }

    /// <inheritdoc />
    public Task<HelloKey> CreateHelloKeyAsync(string name, PromptContext prompt, CancellationToken cancellationToken) =>
        WindowsHello.CreateAsync(name, prompt, cancellationToken);

    /// <inheritdoc />
    public Task<byte[]> SignWithHelloAsync(string name, ReadOnlyMemory<byte> data, PromptContext prompt, CancellationToken cancellationToken) =>
        WindowsHello.SignAsync(name, data, prompt, cancellationToken);

    /// <inheritdoc />
    public Task DeleteHelloKeyAsync(string name, CancellationToken cancellationToken) => WindowsHello.DeleteAsync(name, cancellationToken);

    /// <inheritdoc />
    public byte[] SealSecondFactor(SecondFactorKind kind, string keyName, ReadOnlySpan<byte> secret) => kind switch
    {
        SecondFactorKind.Tpm => TpmKeyStore.CreateAndSeal(keyName, secret),
        SecondFactorKind.Dpapi => DpapiProtector.Protect(secret, keyName),
        _ => throw new HushException(HushErrorCode.TestProviderRefused, $"The platform provider cannot use a '{kind}' factor."),
    };

    /// <inheritdoc />
    public SecureBuffer OpenSecondFactor(SecondFactorKind kind, string keyName, ReadOnlySpan<byte> sealedSecret) => kind switch
    {
        SecondFactorKind.Tpm => TpmKeyStore.Open(keyName, sealedSecret),
        SecondFactorKind.Dpapi => DpapiProtector.Unprotect(sealedSecret, keyName),
        _ => throw new HushException(HushErrorCode.TestProviderRefused, $"This vault was created with a '{kind}' factor, which production Hush refuses to open."),
    };

    /// <inheritdoc />
    public void DeleteSecondFactor(SecondFactorKind kind, string keyName)
    {
        if (kind == SecondFactorKind.Tpm)
        {
            TpmKeyStore.Delete(keyName);
        }
    }
}
