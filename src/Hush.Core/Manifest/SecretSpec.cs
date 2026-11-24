using Hush.Core.Vault;

namespace Hush.Core.Manifest;

/// <summary>Parses the <c>--secrets</c> option of <c>hush run</c>.</summary>
public static class SecretSpec
{
    /// <summary>
    /// Parses a comma-separated list. Each item is <c>NAME</c> (injected as the variable NAME) or
    /// <c>VAR=NAME</c>; NAME may be <c>scope/NAME</c> or <c>/NAME</c> for an explicit global secret. Inside a
    /// project with a manifest, a bare NAME means the project's secret, falling back to the global one.
    /// </summary>
    public static IReadOnlyList<EnvBinding> Parse(string list, ProjectManifest? manifest)
    {
        ArgumentNullException.ThrowIfNull(list);
        var bindings = new List<EnvBinding>();
        foreach (var raw in list.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
        {
            var equals = raw.IndexOf('=', StringComparison.Ordinal);
            var variable = equals >= 0 ? raw[..equals].Trim() : null;
            var reference = equals >= 0 ? raw[(equals + 1)..].Trim() : raw;
            if (reference.Length == 0 || (variable is not null && variable.Length == 0))
            {
                throw new HushException(HushErrorCode.InvalidInput, $"'{raw}' is not a valid --secrets item. Use NAME or VAR=NAME.");
            }

            var binding = manifest is not null
                ? manifest.Bind(variable ?? LastSegment(reference), reference)
                : new EnvBinding(variable ?? LastSegment(reference), SecretRef.Parse(reference.TrimStart('/')), false);
            if (!IsValidVariable(binding.Variable))
            {
                throw new HushException(HushErrorCode.InvalidInput, $"'{binding.Variable}' is not a valid environment variable name.");
            }

            bindings.Add(binding);
        }

        if (bindings.Count == 0)
        {
            throw new HushException(HushErrorCode.InvalidInput, "--secrets is empty.");
        }

        return bindings;
    }

    /// <summary>True if <paramref name="name"/> can be used as an environment variable name.</summary>
    public static bool IsValidVariable(string name) =>
        name.Length is > 0 and <= 255 && !name.Contains('=', StringComparison.Ordinal) && name.All(c => !char.IsControl(c) && !char.IsWhiteSpace(c));

    private static string LastSegment(string reference)
    {
        var slash = reference.LastIndexOf('/');
        return slash >= 0 ? reference[(slash + 1)..] : reference;
    }
}
