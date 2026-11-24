namespace Hush.Core.Scanning;

/// <summary>Whether a finding is an inline secret Hush can migrate, or another tool's token file.</summary>
public enum FindingKind
{
    /// <summary>A plaintext secret inside a file Hush can rewrite.</summary>
    InlineSecret,

    /// <summary>An OAuth token file owned by another tool; reported with guidance only.</summary>
    ToolTokenFile,
}

/// <summary>A redacted scan result. It never contains a full secret: only its first four characters.</summary>
public sealed record Finding(
    string RuleId,
    string Provider,
    string SecretType,
    string FilePath,
    int Line,
    int Column,
    string Prefix,
    Confidence Confidence,
    Risk Risk,
    string RiskNote,
    FindingKind Kind,
    string? Client,
    LocationKind Location,
    string Fingerprint);

/// <summary>A file the scanner read, with what it knows about its layout.</summary>
public sealed record ScannedFile(string Path, LocationKind Kind, string? Client, McpFormat? Mcp);

/// <summary>The result of a scan.</summary>
public sealed record ScanResult(IReadOnlyList<Finding> Findings, IReadOnlyList<ScannedFile> Files, IReadOnlyList<string> Errors)
{
    /// <summary>Findings ordered most severe first.</summary>
    public IEnumerable<Finding> BySeverity =>
        Findings.OrderByDescending(f => f.Risk).ThenByDescending(f => f.Confidence).ThenBy(f => f.FilePath, StringComparer.OrdinalIgnoreCase).ThenBy(f => f.Line);
}

/// <summary>What to scan.</summary>
/// <param name="Paths">Extra files or directories passed by the user. Directories are scanned completely.</param>
/// <param name="ProjectRoots">Roots searched for <c>.env*</c> files and project MCP configs.</param>
/// <param name="IncludeDefaultLocations">Also scan the well-known user files and token files.</param>
public sealed record ScanOptions(IReadOnlyList<string> Paths, IReadOnlyList<string> ProjectRoots, bool IncludeDefaultLocations = true);

/// <summary>Finds plaintext secrets on the machine and reports them redacted.</summary>
public sealed class Scanner
{
    private const long MaxFileBytes = 5 * 1024 * 1024;
    private const int MaxRootDepth = 6;
    private const int MaxExplicitDepth = 12;

    private static readonly HashSet<string> SkippedDirectories = new(StringComparer.OrdinalIgnoreCase)
    {
        "node_modules", ".git", ".hg", ".svn", "bin", "obj", ".venv", "venv", "env", "__pycache__", "target", "dist", "build",
        "packages", ".gradle", ".idea", ".vs", ".next", ".nuxt", "vendor", "AppData", ".cache", "coverage", "TestResults",
    };

    private static readonly HashSet<string> BinaryExtensions = new(StringComparer.OrdinalIgnoreCase)
    {
        ".exe", ".dll", ".pdb", ".so", ".dylib", ".png", ".jpg", ".jpeg", ".gif", ".ico", ".webp", ".bmp", ".zip", ".7z", ".gz", ".tgz",
        ".tar", ".rar", ".pdf", ".woff", ".woff2", ".ttf", ".otf", ".mp3", ".mp4", ".mov", ".wasm", ".class", ".jar", ".nupkg", ".hush",
        ".db", ".sqlite", ".bin", ".pfx", ".snk",
    };

    private readonly SecretDetector _detector;
    private readonly ScanEnvironment _environment;

    /// <summary>Creates a scanner.</summary>
    public Scanner(SecretDetector? detector = null, ScanEnvironment? environment = null)
    {
        _detector = detector ?? SecretDetector.Default;
        _environment = environment ?? ScanEnvironment.Current();
    }

    /// <summary>Runs a scan.</summary>
    public ScanResult Scan(ScanOptions options, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(options);
        var findings = new List<Finding>();
        var files = new Dictionary<string, ScannedFile>(StringComparer.OrdinalIgnoreCase);
        var errors = new List<string>();

        void Add(ScannedFile file, string exposure)
        {
            if (files.ContainsKey(file.Path))
            {
                return;
            }

            files[file.Path] = file;
            ScanFile(file, exposure, findings, errors);
        }

        if (options.IncludeDefaultLocations)
        {
            foreach (var location in ScanLocations.UserFiles)
            {
                cancellationToken.ThrowIfCancellationRequested();
                foreach (var path in _environment.Expand(location.PathTemplate))
                {
                    Add(new ScannedFile(path, location.Kind, location.Client, location.Mcp), location.Exposure);
                }
            }

            foreach (var token in ScanLocations.TokenFiles)
            {
                foreach (var path in _environment.Expand(token.PathTemplate))
                {
                    findings.Add(new Finding(
                        $"token-file/{token.Tool.ToLowerInvariant().Replace(' ', '-')}",
                        token.Tool,
                        "OAuth token file owned by the tool",
                        path,
                        0,
                        0,
                        string.Empty,
                        Confidence.High,
                        Risk.High,
                        $"{token.Grants} To revoke or rotate: {token.Revoke} {ScanLocations.TokenFileWhy}",
                        FindingKind.ToolTokenFile,
                        token.Tool,
                        LocationKind.CredentialFile,
                        Convert.ToHexStringLower(System.Security.Cryptography.SHA256.HashData(System.Text.Encoding.UTF8.GetBytes("token-file\n" + path.ToUpperInvariant())))[..24]));
                }
            }
        }

        foreach (var root in options.ProjectRoots.Where(Directory.Exists))
        {
            foreach (var file in WalkProjectRoot(root, errors, cancellationToken))
            {
                Add(file, file.Kind == LocationKind.DotEnv
                    ? ".env files sit next to code that AI agents read and are a top target for infostealers."
                    : "Project MCP configs are often committed and are read by every agent working in the repository.");
            }
        }

        foreach (var path in options.Paths)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var full = Path.GetFullPath(path);
            if (File.Exists(full))
            {
                Add(Classify(full), "A plaintext secret in a file.");
            }
            else if (Directory.Exists(full))
            {
                foreach (var file in WalkDirectory(full, MaxExplicitDepth, errors, cancellationToken))
                {
                    Add(Classify(file), "A plaintext secret in a file.");
                }
            }
            else
            {
                errors.Add($"{full}: not found.");
            }
        }

        return new ScanResult(findings, files.Values.ToList(), errors);
    }

    /// <summary>Classifies a file by its name and location.</summary>
    public static ScannedFile Classify(string path)
    {
        var name = Path.GetFileName(path);
        if (IsDotEnv(name))
        {
            return new ScannedFile(path, LocationKind.DotEnv, null, null);
        }

        foreach (var project in ScanLocations.ProjectFiles)
        {
            if (path.EndsWith(Path.DirectorySeparatorChar + project.RelativePath, StringComparison.OrdinalIgnoreCase)
                || string.Equals(name, project.RelativePath, StringComparison.OrdinalIgnoreCase))
            {
                return new ScannedFile(path, LocationKind.McpConfig, project.Client, project.Mcp);
            }
        }

        var parent = Path.GetFileName(Path.GetDirectoryName(path)) ?? string.Empty;
        var grandparent = Path.GetFileName(Path.GetDirectoryName(Path.GetDirectoryName(path))) ?? string.Empty;
        if (name.Equals("mcp.json", StringComparison.OrdinalIgnoreCase) && parent.Equals("User", StringComparison.OrdinalIgnoreCase)
            && grandparent.StartsWith("Code", StringComparison.OrdinalIgnoreCase))
        {
            return new ScannedFile(path, LocationKind.McpConfig, "VS Code", McpFormat.VsCodeServersJson);
        }

        return name.ToLowerInvariant() switch
        {
            "claude_desktop_config.json" or "mcp_config.json" => new ScannedFile(path, LocationKind.McpConfig, null, McpFormat.McpServersJson),
            ".claude.json" => new ScannedFile(path, LocationKind.McpConfig, "Claude Code", McpFormat.ClaudeCodeUserJson),
            "mcp.json" => new ScannedFile(path, LocationKind.McpConfig, null, McpFormat.McpServersJson),
            "config.toml" when path.Contains(".codex", StringComparison.OrdinalIgnoreCase) => new ScannedFile(path, LocationKind.McpConfig, "OpenAI Codex", McpFormat.CodexToml),
            ".npmrc" or ".pypirc" or ".git-credentials" => new ScannedFile(path, LocationKind.CredentialFile, null, null),
            _ => new ScannedFile(path, LocationKind.Other, null, null),
        };
    }

    /// <summary>True for <c>.env</c>, <c>.env.local</c>, <c>.env.production</c> and similar.</summary>
    public static bool IsDotEnv(string fileName) =>
        fileName.Equals(".env", StringComparison.OrdinalIgnoreCase) || fileName.StartsWith(".env.", StringComparison.OrdinalIgnoreCase);

    /// <summary>True for example/template env files that hold placeholders by convention.</summary>
    public static bool IsDotEnvTemplate(string fileName) =>
        IsDotEnv(fileName) && (fileName.EndsWith(".example", StringComparison.OrdinalIgnoreCase)
            || fileName.EndsWith(".sample", StringComparison.OrdinalIgnoreCase)
            || fileName.EndsWith(".template", StringComparison.OrdinalIgnoreCase)
            || fileName.EndsWith(".dist", StringComparison.OrdinalIgnoreCase)
            || fileName.EndsWith(".defaults", StringComparison.OrdinalIgnoreCase));

    private void ScanFile(ScannedFile file, string exposure, List<Finding> findings, List<string> errors)
    {
        string content;
        try
        {
            var info = new FileInfo(file.Path);
            if (BinaryExtensions.Contains(info.Extension))
            {
                // Binary formats are not text config files; scanning them would only produce noise.
                return;
            }

            if (info.Length > MaxFileBytes)
            {
                errors.Add($"{file.Path}: larger than {MaxFileBytes / (1024 * 1024)} MiB, not scanned.");
                return;
            }

            content = File.ReadAllText(file.Path);
        }
        catch (IOException ex)
        {
            errors.Add($"{file.Path}: {ex.Message}");
            return;
        }
        catch (UnauthorizedAccessException ex)
        {
            errors.Add($"{file.Path}: {ex.Message}");
            return;
        }

        if (content.Contains('\0', StringComparison.Ordinal))
        {
            // NUL bytes mean a binary file with an unexpected extension; not a config file.
            return;
        }

        foreach (var match in _detector.Detect(file.Path, content, errors))
        {
            findings.Add(new Finding(
                match.Rule.Id,
                match.Rule.Provider,
                match.Rule.SecretType,
                file.Path,
                match.Line,
                match.Column,
                match.Prefix,
                match.Confidence,
                match.Rule.Risk,
                $"{match.Rule.Note} {exposure}",
                FindingKind.InlineSecret,
                file.Client,
                file.Kind,
                match.Fingerprint(file.Path)));
        }
    }

    private static IEnumerable<ScannedFile> WalkProjectRoot(string root, List<string> errors, CancellationToken cancellationToken)
    {
        foreach (var directory in Directories(root, MaxRootDepth, skipDotDirectories: true, errors, cancellationToken))
        {
            IEnumerable<string> envFiles;
            try
            {
                envFiles = Directory.EnumerateFiles(directory, ".env*").ToList();
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
            {
                errors.Add($"{directory}: {ex.Message}");
                continue;
            }

            foreach (var env in envFiles.Where(f => IsDotEnv(Path.GetFileName(f))))
            {
                yield return new ScannedFile(env, LocationKind.DotEnv, null, null);
            }

            foreach (var project in ScanLocations.ProjectFiles)
            {
                var candidate = Path.Combine(directory, project.RelativePath);
                if (File.Exists(candidate))
                {
                    yield return new ScannedFile(candidate, LocationKind.McpConfig, project.Client, project.Mcp);
                }
            }
        }
    }

    private static IEnumerable<string> WalkDirectory(string root, int depth, List<string> errors, CancellationToken cancellationToken)
    {
        foreach (var directory in Directories(root, depth, skipDotDirectories: false, errors, cancellationToken))
        {
            IEnumerable<string> entries;
            try
            {
                entries = Directory.EnumerateFiles(directory).ToList();
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
            {
                errors.Add($"{directory}: {ex.Message}");
                continue;
            }

            foreach (var file in entries)
            {
                yield return file;
            }
        }
    }

    private static IEnumerable<string> Directories(string root, int maxDepth, bool skipDotDirectories, List<string> errors, CancellationToken cancellationToken)
    {
        var pending = new Stack<(string Path, int Depth)>();
        pending.Push((root, 0));
        while (pending.Count > 0)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var (path, depth) = pending.Pop();
            yield return path;
            if (depth >= maxDepth)
            {
                continue;
            }

            IEnumerable<string> children;
            try
            {
                children = Directory.EnumerateDirectories(path).ToList();
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
            {
                errors.Add($"{path}: {ex.Message}");
                continue;
            }

            foreach (var child in children)
            {
                var name = Path.GetFileName(child);
                if (SkippedDirectories.Contains(name) || (skipDotDirectories && name.StartsWith('.')))
                {
                    continue;
                }

                if ((File.GetAttributes(child) & FileAttributes.ReparsePoint) != 0)
                {
                    continue;
                }

                pending.Push((child, depth + 1));
            }
        }
    }
}
