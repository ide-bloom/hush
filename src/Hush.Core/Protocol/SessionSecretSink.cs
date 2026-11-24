using Hush.Core.Migration;
using Hush.Core.Vault;

namespace Hush.Core.Protocol;

/// <summary>Stores migrated secrets through the session broker; used by both the CLI and the tray app.</summary>
public sealed class SessionSecretSink : ISecretSink
{
    private readonly SessionClient _session;

    /// <summary>Creates a sink that writes through <paramref name="session"/>.</summary>
    public SessionSecretSink(SessionClient session) => _session = session;

    /// <inheritdoc />
    public async Task StoreAsync(IReadOnlyList<PlannedSecret> secrets, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(secrets);
        foreach (var secret in secrets)
        {
            await _session.SetAsync(secret.Target, secret.Value, null, cancellationToken).ConfigureAwait(false);
        }
    }

    /// <inheritdoc />
    public async Task RemoveAsync(IReadOnlyList<SecretRef> secrets, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(secrets);
        foreach (var secret in secrets)
        {
            await _session.RemoveAsync(secret, cancellationToken).ConfigureAwait(false);
        }
    }
}
