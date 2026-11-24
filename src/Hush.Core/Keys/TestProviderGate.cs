using System.Reflection;

namespace Hush.Core.Keys;

/// <summary>
/// Marks an assembly as a Hush test host. Only when the process's entry assembly carries this attribute
/// will Hush accept a <see cref="KeyProviderKind.Test"/> provider or open a vault created by one.
/// </summary>
[AttributeUsage(AttributeTargets.Assembly)]
public sealed class HushTestHostAttribute : Attribute;

/// <summary>Refuses test key providers in production processes.</summary>
public static class TestProviderGate
{
    /// <summary>True when the entry assembly is marked with <see cref="HushTestHostAttribute"/>.</summary>
    public static bool IsTestHost { get; } =
        Assembly.GetEntryAssembly()?.GetCustomAttribute<HushTestHostAttribute>() is not null;

    /// <summary>Throws unless <paramref name="provider"/> is a platform provider or this is a test host.</summary>
    public static void EnsureAllowed(IHardwareKeyProvider provider)
    {
        ArgumentNullException.ThrowIfNull(provider);
        if (provider.Kind == KeyProviderKind.Test && !IsTestHost)
        {
            throw new HushException(
                HushErrorCode.TestProviderRefused,
                "The software test key provider is only allowed inside the Hush test suite.");
        }
    }
}
