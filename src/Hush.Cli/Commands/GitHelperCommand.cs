using Hush.Core.Manifest;
using Hush.Core.Migration;
using Hush.Core.Vault;

namespace Hush.Cli.Commands;

/// <summary>
/// <c>hush git-helper</c>: a Git credential helper (https://git-scm.com/docs/gitcredentials). Configure it with
/// <c>git config --global credential.helper "hush git-helper"</c>. Only <c>get</c> does anything: credentials
/// are added to the vault by <c>hush migrate</c> or <c>hush set user@host --scope git</c>, never by Git.
/// </summary>
internal static class GitHelperCommand
{
    public static async Task<int> RunAsync(CliServices s, string operation, CancellationToken ct)
    {
        var input = ParseAttributes(s.Terminal.ReadAllInput());
        if (!operation.Equals("get", StringComparison.OrdinalIgnoreCase))
        {
            // store/erase: Git reports outcomes to every helper; Hush deliberately ignores them.
            return 0;
        }

        if (!input.TryGetValue("host", out var host) || host.Length == 0 || !s.Manager.Exists)
        {
            return 0;
        }

        input.TryGetValue("username", out var username);
        var reference = FindCredential(s.Manager.ReadDocument(), host, username);
        if (reference is null)
        {
            return 0;
        }

        var values = await s.Session.RevealAsync([new EnvBinding("GIT_PASSWORD", reference.Value, false)], $"git-helper: {host}", requirePresence: false, ct).ConfigureAwait(false);
        var user = GitCredentialNames.Split(reference.Value.Name)?.User ?? username ?? string.Empty;
        s.Terminal.Out.Write($"username={user}\npassword={values[0].Value}\n");
        return 0;
    }

    public static Dictionary<string, string> ParseAttributes(string text)
    {
        ArgumentNullException.ThrowIfNull(text);
        var result = new Dictionary<string, string>(StringComparer.Ordinal);
        foreach (var line in text.Replace("\r\n", "\n", StringComparison.Ordinal).Split('\n'))
        {
            if (line.Length == 0)
            {
                break;
            }

            var equals = line.IndexOf('=', StringComparison.Ordinal);
            if (equals > 0)
            {
                result[line[..equals]] = line[(equals + 1)..];
            }
        }

        return result;
    }

    /// <summary>Finds <c>git/user@host</c>, or the first credential for the host when Git did not name a user.</summary>
    public static SecretRef? FindCredential(VaultDocument document, string host, string? username)
    {
        ArgumentNullException.ThrowIfNull(document);
        if (!string.IsNullOrEmpty(username))
        {
            var exact = GitCredentialNames.For(username, host);
            return document.Entries.Any(e => string.Equals(e.Scope, exact.Scope, StringComparison.OrdinalIgnoreCase) && string.Equals(e.Name, exact.Name, StringComparison.OrdinalIgnoreCase))
                ? exact
                : null;
        }

        var sanitizedHost = SecretRef.Sanitize(host.Replace(':', '_'));
        var match = document.Entries
            .Where(e => string.Equals(e.Scope, GitCredentialNames.Scope, StringComparison.OrdinalIgnoreCase))
            .FirstOrDefault(e => string.Equals(GitCredentialNames.Split(e.Name)?.Host, sanitizedHost, StringComparison.OrdinalIgnoreCase));
        return match is null ? null : new SecretRef(match.Scope, match.Name);
    }
}
