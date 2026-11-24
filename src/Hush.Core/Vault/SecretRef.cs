using System.Text.RegularExpressions;

namespace Hush.Core.Vault;

/// <summary>
/// A reference to a vaulted secret: <c>NAME</c> (global) or <c>scope/NAME</c>. Names and scopes use
/// letters, digits, <c>_</c>, <c>.</c>, <c>-</c> and <c>@</c> (the last so Git credentials can be named
/// <c>user@host</c>).
/// </summary>
public readonly partial record struct SecretRef(string Scope, string Name)
{
    /// <summary>Maximum length of a name or scope.</summary>
    public const int MaxLength = 128;

    /// <summary>Display form.</summary>
    public override string ToString() => Format(Scope, Name);

    /// <summary>Formats a scope and name.</summary>
    public static string Format(string scope, string name) => scope.Length == 0 ? name : $"{scope}/{name}";

    /// <summary>Parses <c>NAME</c> or <c>scope/NAME</c>; an explicit scope overrides the prefix.</summary>
    public static SecretRef Parse(string text, string? scope = null)
    {
        ArgumentNullException.ThrowIfNull(text);
        var slash = text.IndexOf('/', StringComparison.Ordinal);
        var parsedScope = slash >= 0 ? text[..slash] : string.Empty;
        var name = slash >= 0 ? text[(slash + 1)..] : text;
        var result = new SecretRef(scope ?? parsedScope, name);
        result.Validate();
        return result;
    }

    /// <summary>Throws <see cref="HushException"/> if the name or scope is not valid.</summary>
    public void Validate()
    {
        if (!IsValidPart(Name))
        {
            throw new HushException(HushErrorCode.InvalidInput, $"'{Name}' is not a valid secret name. Use letters, digits, '_', '.', '-' or '@' (max {MaxLength}).");
        }

        if (Scope.Length > 0 && !IsValidPart(Scope))
        {
            throw new HushException(HushErrorCode.InvalidInput, $"'{Scope}' is not a valid scope. Use letters, digits, '_', '.', '-' or '@' (max {MaxLength}).");
        }
    }

    /// <summary>True if <paramref name="part"/> is a valid name or scope.</summary>
    public static bool IsValidPart(string part) => part.Length is > 0 and <= MaxLength && PartPattern().IsMatch(part);

    /// <summary>Turns arbitrary text (a directory name, a server name) into a valid scope or name.</summary>
    public static string Sanitize(string text)
    {
        ArgumentNullException.ThrowIfNull(text);
        var cleaned = InvalidChars().Replace(text.Trim(), "-").Trim('-');
        if (cleaned.Length == 0)
        {
            cleaned = "default";
        }

        return cleaned.Length > MaxLength ? cleaned[..MaxLength] : cleaned;
    }

    [GeneratedRegex("^[A-Za-z0-9_.@-]+$")]
    private static partial Regex PartPattern();

    [GeneratedRegex("[^A-Za-z0-9_.@-]+")]
    private static partial Regex InvalidChars();
}
