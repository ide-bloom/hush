using System.Security.Cryptography;
using Hush.Core.Interop;

namespace Hush.Core.Protocol;

/// <summary>Reads facts about other processes and files. Abstracted so verification logic is testable.</summary>
public interface IPeerInspector
{
    /// <summary>Full image path of a process, or null.</summary>
    string? ImagePath(int pid);

    /// <summary>Lowercase hex SHA-256 of a file.</summary>
    string HashFile(string path);

    /// <summary>Thumbprint of a valid Authenticode signer, or null if unsigned or invalid.</summary>
    string? SignerThumbprint(string path);
}

/// <summary>The real inspector.</summary>
public sealed class SystemPeerInspector : IPeerInspector
{
    /// <inheritdoc />
    public string? ImagePath(int pid) => ProcessInspector.ImagePath(pid);

    /// <inheritdoc />
    public string HashFile(string path)
    {
        using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
        return Convert.ToHexStringLower(SHA256.HashData(stream));
    }

    /// <inheritdoc />
    public string? SignerThumbprint(string path) => Authenticode.GetValidSignerThumbprint(path);
}

/// <summary>Outcome of verifying a pipe peer.</summary>
/// <param name="Allowed">True if the peer is a trusted Hush binary.</param>
/// <param name="ImagePath">The peer's image path, if it could be read.</param>
/// <param name="Reason">Why the peer was accepted or rejected.</param>
public sealed record PeerVerification(bool Allowed, string? ImagePath, string Reason);

/// <summary>Decides whether a process on the other end of the broker pipe is trusted.</summary>
public interface IPeerVerifier
{
    /// <summary>Verifies the process with id <paramref name="pid"/>.</summary>
    PeerVerification Verify(int pid);
}

/// <summary>
/// The Hush binaries of one install, captured when the verifying process starts: their names, SHA-256
/// hashes, and the Authenticode signer when the install is signed.
/// </summary>
public sealed class InstallManifest
{
    /// <summary>The CLI (and broker) executable.</summary>
    public const string CliExecutable = "hush.exe";

    /// <summary>The tray app executable. It cannot be named Hush.exe next to hush.exe because NTFS names are case-insensitive.</summary>
    public const string TrayExecutable = "HushTray.exe";

    private readonly Dictionary<string, string> _hashes;

    private InstallManifest(string directory, Dictionary<string, string> hashes, string? requiredSigner)
    {
        Directory = directory;
        _hashes = hashes;
        RequiredSigner = requiredSigner;
    }

    /// <summary>The install directory.</summary>
    public string Directory { get; }

    /// <summary>When the running binary is signed, peers must be signed by the same certificate.</summary>
    public string? RequiredSigner { get; }

    /// <summary>Binary names and their hashes.</summary>
    public IReadOnlyDictionary<string, string> Hashes => _hashes;

    /// <summary>Captures the install that <paramref name="selfPath"/> belongs to.</summary>
    public static InstallManifest Capture(string selfPath, IPeerInspector inspector, IEnumerable<string>? names = null)
    {
        ArgumentNullException.ThrowIfNull(inspector);
        var directory = Path.GetDirectoryName(ResolveLinks(selfPath))!;
        var hashes = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        foreach (var name in names ?? [CliExecutable, TrayExecutable])
        {
            var path = Path.Combine(directory, name);
            if (File.Exists(path))
            {
                hashes[name] = inspector.HashFile(path);
            }
        }

        return new InstallManifest(directory, hashes, inspector.SignerThumbprint(selfPath));
    }

    /// <summary>
    /// The final target of <paramref name="path"/> if it is a symbolic link (winget installs portable apps behind
    /// links in WinGet\Links), otherwise its full path. Process image paths are always final targets.
    /// </summary>
    public static string ResolveLinks(string path)
    {
        var full = Path.GetFullPath(path);
        try
        {
            return File.ResolveLinkTarget(full, returnFinalTarget: true)?.FullName ?? full;
        }
        catch (IOException)
        {
            // A broken or unreadable link: verify against the path as given, which then fails closed if it is wrong.
            return full;
        }
    }

    /// <summary>Creates a manifest from known values (tests and diagnostics).</summary>
    public static InstallManifest FromValues(string directory, IReadOnlyDictionary<string, string> hashes, string? requiredSigner) =>
        new(Path.GetFullPath(directory), new Dictionary<string, string>(hashes, StringComparer.OrdinalIgnoreCase), requiredSigner);
}

/// <summary>
/// Accepts a peer only if its image (1) lives in the same install directory, (2) is one of the Hush
/// binaries, (3) has the SHA-256 recorded at startup, and (4) when the install is signed, carries a valid
/// signature from the same signer.
/// </summary>
public sealed class PeerVerifier : IPeerVerifier
{
    private readonly InstallManifest _manifest;
    private readonly IPeerInspector _inspector;
    private readonly HashSet<string> _allowedNames;

    /// <summary>Creates a verifier that accepts the given binary names from <paramref name="manifest"/>.</summary>
    public PeerVerifier(InstallManifest manifest, IPeerInspector inspector, IEnumerable<string> allowedNames)
    {
        _manifest = manifest;
        _inspector = inspector;
        _allowedNames = new HashSet<string>(allowedNames, StringComparer.OrdinalIgnoreCase);
    }

    /// <inheritdoc />
    public PeerVerification Verify(int pid)
    {
        var path = _inspector.ImagePath(pid);
        if (path is null)
        {
            return new PeerVerification(false, null, $"Cannot read the image of process {pid}.");
        }

        var full = InstallManifest.ResolveLinks(path);
        var directory = Path.GetDirectoryName(full);
        var name = Path.GetFileName(full);
        if (!string.Equals(directory, _manifest.Directory, StringComparison.OrdinalIgnoreCase))
        {
            return new PeerVerification(false, full, $"'{full}' is not in the Hush install directory '{_manifest.Directory}'.");
        }

        if (!_allowedNames.Contains(name))
        {
            return new PeerVerification(false, full, $"'{name}' is not a Hush binary allowed on this pipe.");
        }

        if (!_manifest.Hashes.TryGetValue(name, out var expectedHash))
        {
            return new PeerVerification(false, full, $"'{name}' was not present when this Hush process started.");
        }

        string actualHash;
        try
        {
            actualHash = _inspector.HashFile(full);
        }
        catch (IOException ex)
        {
            return new PeerVerification(false, full, $"Cannot hash '{full}': {ex.Message}");
        }
        catch (UnauthorizedAccessException ex)
        {
            return new PeerVerification(false, full, $"Cannot hash '{full}': {ex.Message}");
        }

        if (!string.Equals(actualHash, expectedHash, StringComparison.OrdinalIgnoreCase))
        {
            return new PeerVerification(false, full, $"'{name}' changed since this Hush process started (hash mismatch). Restart Hush after an update.");
        }

        if (_manifest.RequiredSigner is { } signer)
        {
            var peerSigner = _inspector.SignerThumbprint(full);
            if (!string.Equals(peerSigner, signer, StringComparison.OrdinalIgnoreCase))
            {
                return new PeerVerification(false, full, $"'{name}' is not signed by the same publisher as this Hush install.");
            }
        }

        return new PeerVerification(true, full, "Verified Hush binary.");
    }
}
