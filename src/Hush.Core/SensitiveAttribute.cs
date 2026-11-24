namespace Hush.Core;

/// <summary>
/// Marks a type, member or parameter that carries secret material. The HUSH001 analyzer fails the
/// build if such a value is passed to a logging call.
/// </summary>
[AttributeUsage(
    AttributeTargets.Class | AttributeTargets.Struct | AttributeTargets.Field | AttributeTargets.Property | AttributeTargets.Parameter,
    Inherited = true,
    AllowMultiple = false)]
public sealed class SensitiveAttribute : Attribute;
