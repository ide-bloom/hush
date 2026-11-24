using System.Collections.Concurrent;
using System.Security.Cryptography;
using System.Text;
using Hush.Core;
using Hush.Core.Crypto;
using Hush.Core.Keys;

[assembly: HushTestHost]

namespace Hush.Tests.Support;

/// <summary>
/// Deterministic software stand-in for Windows Hello and the TPM. Each instance is one "machine": its
/// second-factor key is derived from <paramref name="machineSecret"/>, so a vault created on one instance
/// cannot be opened by another, just like a vault copied to a different PC.
/// </summary>
public sealed class TestKeyProvider(string machineSecret = "machine-A") : IHardwareKeyProvider
{
    private readonly ConcurrentDictionary<string, RSA> _helloKeys = new(StringComparer.Ordinal);
    private readonly ConcurrentDictionary<string, bool> _deletedFactors = new(StringComparer.Ordinal);

    public KeyProviderKind Kind => KeyProviderKind.Test;

    /// <summary>Simulates a PC without Windows Hello set up.</summary>
    public bool HelloAvailable { get; set; } = true;

    /// <summary>Simulates randomized (PSS) Hello signatures, which cannot derive a stable key.</summary>
    public bool NonDeterministicSignatures { get; set; }

    /// <summary>Simulates the user cancelling the next prompt.</summary>
    public bool CancelNextPrompt { get; set; }

    /// <summary>Second factor this "machine" offers (Test = TPM stand-in, Dpapi = degraded).</summary>
    public SecondFactorKind SecondFactor { get; set; } = SecondFactorKind.Test;

    /// <summary>Number of Hello prompts shown.</summary>
    public int PromptCount { get; private set; }

    public Task<string?> CheckHelloAsync(CancellationToken cancellationToken) =>
        Task.FromResult(HelloAvailable ? null : "Windows Hello is not set up (test).");

    public SecondFactorChoice ChooseSecondFactor() =>
        SecondFactor == SecondFactorKind.Dpapi ? new SecondFactorChoice(SecondFactorKind.Dpapi, "No TPM (test).") : new SecondFactorChoice(SecondFactorKind.Test, null);

    public Task<HelloKey> CreateHelloKeyAsync(string name, PromptContext prompt, CancellationToken cancellationToken)
    {
        Prompt();
        var rsa = RSA.Create(2048);
        _helloKeys[name] = rsa;
        return Task.FromResult(new HelloKey(name, rsa.ExportSubjectPublicKeyInfo()));
    }

    public Task<byte[]> SignWithHelloAsync(string name, ReadOnlyMemory<byte> data, PromptContext prompt, CancellationToken cancellationToken)
    {
        Prompt();
        if (!_helloKeys.TryGetValue(name, out var rsa))
        {
            throw new HushException(HushErrorCode.HelloUnavailable, "The Windows Hello key for this vault no longer exists (test).");
        }

        var padding = NonDeterministicSignatures ? RSASignaturePadding.Pss : RSASignaturePadding.Pkcs1;
        return Task.FromResult(rsa.SignData(data.Span, HashAlgorithmName.SHA256, padding));
    }

    public Task DeleteHelloKeyAsync(string name, CancellationToken cancellationToken)
    {
        if (_helloKeys.TryRemove(name, out var rsa))
        {
            rsa.Dispose();
        }

        return Task.CompletedTask;
    }

    /// <summary>Simulates resetting Windows Hello: every Hello key disappears.</summary>
    public void ResetHello()
    {
        foreach (var name in _helloKeys.Keys.ToList())
        {
            _ = DeleteHelloKeyAsync(name, CancellationToken.None);
        }
    }

    /// <summary>Simulates clearing the TPM.</summary>
    public void ClearTpm(string keyName) => _deletedFactors[keyName] = true;

    public byte[] SealSecondFactor(SecondFactorKind kind, string keyName, ReadOnlySpan<byte> secret)
    {
        _deletedFactors.TryRemove(keyName, out _);
        return kind switch
        {
            SecondFactorKind.Test => Aead.Seal(MachineKey(keyName), secret, Encoding.UTF8.GetBytes(keyName)),
            SecondFactorKind.Dpapi => DpapiProtector.Protect(secret, keyName),
            _ => throw new HushException(HushErrorCode.TpmFailure, $"The test provider cannot seal a {kind} factor."),
        };
    }

    public SecureBuffer OpenSecondFactor(SecondFactorKind kind, string keyName, ReadOnlySpan<byte> sealedSecret)
    {
        if (_deletedFactors.ContainsKey(keyName))
        {
            throw new HushException(HushErrorCode.TpmFailure, "The TPM key for this vault is missing (test).");
        }

        try
        {
            return kind switch
            {
                SecondFactorKind.Test => Aead.Open(MachineKey(keyName), sealedSecret, Encoding.UTF8.GetBytes(keyName), "TPM factor"),
                SecondFactorKind.Dpapi => DpapiProtector.Unprotect(sealedSecret, keyName),
                _ => throw new HushException(HushErrorCode.TpmFailure, $"The test provider cannot open a {kind} factor."),
            };
        }
        catch (HushException ex) when (ex.Code == HushErrorCode.TamperDetected)
        {
            throw new HushException(HushErrorCode.TpmFailure, "The TPM refused to decrypt the vault factor (different machine, test).", ex);
        }
    }

    public void DeleteSecondFactor(SecondFactorKind kind, string keyName) => _deletedFactors[keyName] = true;

    private byte[] MachineKey(string keyName) =>
        HKDF.DeriveKey(HashAlgorithmName.SHA256, Encoding.UTF8.GetBytes(machineSecret), 32, Encoding.UTF8.GetBytes(keyName), "hush-test-tpm"u8.ToArray());

    private void Prompt()
    {
        PromptCount++;
        if (CancelNextPrompt)
        {
            CancelNextPrompt = false;
            throw new HushException(HushErrorCode.HelloCancelled, "Windows Hello verification was cancelled (test).");
        }
    }
}
