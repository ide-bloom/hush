using Hush.Cli.Running;
using Hush.Core;
using Hush.Core.Manifest;

namespace Hush.Cli.Commands;

/// <summary><c>hush run</c>: resolve the secrets a command needs, then launch it with them in its environment.</summary>
internal static class RunCommand
{
    public static async Task<int> RunAsync(CliServices s, string? secrets, string? profile, bool mask, IReadOnlyList<string> command, CancellationToken ct)
    {
        if (command.Count == 0)
        {
            throw new HushException(HushErrorCode.InvalidInput, "Nothing to run. Usage: hush run [--secrets A,B] -- <command> [args...]");
        }

        var bindings = ResolveBindings(s.WorkingDirectory, secrets, profile);
        var values = await s.Session.RevealAsync(bindings, $"run: {Path.GetFileName(command[0])}", requirePresence: false, ct).ConfigureAwait(false);
        var environment = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        for (var i = 0; i < bindings.Count; i++)
        {
            environment[bindings[i].Variable] = values[i].Value;
        }

        return await ProcessRunner.RunAsync(new RunRequest(command[0], command.Skip(1).ToList(), environment, mask), s.StandardOutput, s.StandardError, ct).ConfigureAwait(false);
    }

    /// <summary>Bindings from <c>--secrets</c> if given, otherwise from the nearest <c>.hush.toml</c>.</summary>
    public static IReadOnlyList<EnvBinding> ResolveBindings(string workingDirectory, string? secrets, string? profile)
    {
        var manifestPath = ProjectManifest.Locate(workingDirectory);
        var manifest = manifestPath is null ? null : ProjectManifest.Load(manifestPath);
        if (secrets is not null)
        {
            return SecretSpec.Parse(secrets, manifest);
        }

        if (manifest is null)
        {
            throw new HushException(
                HushErrorCode.InvalidInput,
                "No secrets to inject: pass --secrets NAME[,NAME...] or add a .hush.toml to this project ('hush init --project').");
        }

        var bindings = manifest.Resolve(profile ?? Environment.GetEnvironmentVariable("HUSH_PROFILE"));
        if (bindings.Count == 0)
        {
            throw new HushException(HushErrorCode.ManifestInvalid, $"{manifest.FilePath} does not map any secrets yet. Add ENV_VAR = \"SECRET\" lines under [env].");
        }

        return bindings;
    }
}
