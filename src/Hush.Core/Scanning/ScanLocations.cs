namespace Hush.Core.Scanning;

/// <summary>What kind of file a scan location is.</summary>
public enum LocationKind
{
    /// <summary>An MCP client configuration.</summary>
    McpConfig,

    /// <summary>A tool credential file (.npmrc, .git-credentials, ...).</summary>
    CredentialFile,

    /// <summary>Shell history.</summary>
    ShellHistory,

    /// <summary>Editor settings.</summary>
    EditorSettings,

    /// <summary>A <c>.env</c> file.</summary>
    DotEnv,

    /// <summary>Any other file passed explicitly.</summary>
    Other,
}

/// <summary>The layout of an MCP configuration file, which decides how the migrator rewrites it.</summary>
public enum McpFormat
{
    /// <summary>JSON with a top-level <c>mcpServers</c> object (Claude Desktop, Cursor, Windsurf, Gemini CLI, Claude Code project .mcp.json).</summary>
    McpServersJson,

    /// <summary>Claude Code's <c>~/.claude.json</c>: <c>mcpServers</c> at the top level and under <c>projects.&lt;path&gt;</c>.</summary>
    ClaudeCodeUserJson,

    /// <summary>VS Code <c>mcp.json</c> (JSON with comments): a top-level <c>servers</c> object.</summary>
    VsCodeServersJson,

    /// <summary>OpenAI Codex <c>config.toml</c>: <c>[mcp_servers.NAME]</c> tables.</summary>
    CodexToml,
}

/// <summary>A well-known file to scan.</summary>
/// <param name="Client">Product the file belongs to.</param>
/// <param name="PathTemplate">Path with <c>~</c>, <c>%APPDATA%</c>, <c>%LOCALAPPDATA%</c>, <c>%PROGRAMDATA%</c> and at most one <c>*</c> segment.</param>
/// <param name="Kind">Location kind.</param>
/// <param name="Mcp">MCP layout, for MCP configs.</param>
/// <param name="Exposure">Why a secret here is exposed.</param>
public sealed record ScanLocation(string Client, string PathTemplate, LocationKind Kind, McpFormat? Mcp, string Exposure);

/// <summary>A file pattern looked for inside project roots and explicitly scanned directories.</summary>
/// <param name="Client">Product the file belongs to.</param>
/// <param name="RelativePath">Path relative to a project directory.</param>
/// <param name="Mcp">MCP layout.</param>
public sealed record ProjectMcpFile(string Client, string RelativePath, McpFormat Mcp);

/// <summary>An OAuth token file that belongs to another tool and cannot be vaulted without breaking it.</summary>
/// <param name="Tool">The tool.</param>
/// <param name="PathTemplate">Path template (see <see cref="ScanLocation.PathTemplate"/>).</param>
/// <param name="Grants">What the token grants.</param>
/// <param name="Revoke">How to revoke or rotate it.</param>
public sealed record ToolTokenFile(string Tool, string PathTemplate, string Grants, string Revoke);

/// <summary>Where the scanner looks. Kept as data so it is easy to update when clients move their files.</summary>
/// <remarks>
/// Last reviewed in November 2026. If a client moves its files, update this table (and docs/scanner-rules.md);
/// nothing else in Hush hard-codes these paths. Claude Desktop installed
/// from the Microsoft Store (MSIX) reads its config from the package's virtualized AppData, so both paths
/// are listed.
/// </remarks>
public static class ScanLocations
{
    private const string McpExposure = "MCP client configs are plain JSON readable by every process running as you, including AI agents, and are a named target of 2026 infostealers.";
    private const string CredentialExposure = "A plaintext credential file in your profile: any process running as you can read it.";

    /// <summary>User-level files.</summary>
    public static IReadOnlyList<ScanLocation> UserFiles { get; } =
    [
        new("Claude Desktop", @"%APPDATA%\Claude\claude_desktop_config.json", LocationKind.McpConfig, McpFormat.McpServersJson, McpExposure),
        new("Claude Desktop (Store)", @"%LOCALAPPDATA%\Packages\Claude_*\LocalCache\Roaming\Claude\claude_desktop_config.json", LocationKind.McpConfig, McpFormat.McpServersJson, McpExposure),
        new("Claude Code", @"~\.claude.json", LocationKind.McpConfig, McpFormat.ClaudeCodeUserJson, McpExposure),
        new("Claude Code (managed)", @"%PROGRAMDATA%\ClaudeCode\managed-mcp.json", LocationKind.McpConfig, McpFormat.McpServersJson, McpExposure),
        new("Cursor", @"~\.cursor\mcp.json", LocationKind.McpConfig, McpFormat.McpServersJson, McpExposure),
        new("VS Code", @"%APPDATA%\Code\User\mcp.json", LocationKind.McpConfig, McpFormat.VsCodeServersJson, McpExposure),
        new("VS Code Insiders", @"%APPDATA%\Code - Insiders\User\mcp.json", LocationKind.McpConfig, McpFormat.VsCodeServersJson, McpExposure),
        new("Windsurf", @"~\.codeium\windsurf\mcp_config.json", LocationKind.McpConfig, McpFormat.McpServersJson, McpExposure),
        new("OpenAI Codex", @"%CODEX_HOME%\config.toml", LocationKind.McpConfig, McpFormat.CodexToml, McpExposure),
        new("Gemini CLI", @"~\.gemini\settings.json", LocationKind.McpConfig, McpFormat.McpServersJson, McpExposure),

        new("npm", @"~\.npmrc", LocationKind.CredentialFile, null, CredentialExposure),
        new("PyPI", @"~\.pypirc", LocationKind.CredentialFile, null, CredentialExposure),
        new("Git", @"~\.git-credentials", LocationKind.CredentialFile, null, CredentialExposure),
        new("AWS CLI", @"~\.aws\credentials", LocationKind.CredentialFile, null, CredentialExposure),
        new("Docker", @"~\.docker\config.json", LocationKind.CredentialFile, null, CredentialExposure),
        new("GitHub CLI", @"~\.config\gh\hosts.yml", LocationKind.CredentialFile, null, CredentialExposure),
        new("GitHub CLI", @"%APPDATA%\GitHub CLI\hosts.yml", LocationKind.CredentialFile, null, CredentialExposure),
        new("Kubernetes", @"~\.kube\config", LocationKind.CredentialFile, null, CredentialExposure),

        new("PowerShell", @"%APPDATA%\Microsoft\Windows\PowerShell\PSReadLine\*_history.txt", LocationKind.ShellHistory, null,
            "PSReadLine saves every command you type, including secrets pasted on the command line."),

        new("VS Code", @"%APPDATA%\Code\User\settings.json", LocationKind.EditorSettings, null, "Editor settings sync across machines and are read by extensions."),
        new("VS Code Insiders", @"%APPDATA%\Code - Insiders\User\settings.json", LocationKind.EditorSettings, null, "Editor settings sync across machines and are read by extensions."),
        new("Cursor", @"%APPDATA%\Cursor\User\settings.json", LocationKind.EditorSettings, null, "Editor settings are read by extensions and agents."),
        new("Windsurf", @"%APPDATA%\Windsurf\User\settings.json", LocationKind.EditorSettings, null, "Editor settings are read by extensions and agents."),
    ];

    /// <summary>Project-level MCP configs found in project roots.</summary>
    public static IReadOnlyList<ProjectMcpFile> ProjectFiles { get; } =
    [
        new("Claude Code (project)", ".mcp.json", McpFormat.McpServersJson),
        new("Cursor (project)", @".cursor\mcp.json", McpFormat.McpServersJson),
        new("VS Code (workspace)", @".vscode\mcp.json", McpFormat.VsCodeServersJson),
        new("Gemini CLI (project)", @".gemini\settings.json", McpFormat.McpServersJson),
    ];

    /// <summary>OAuth token files owned by other tools.</summary>
    public static IReadOnlyList<ToolTokenFile> TokenFiles { get; } =
    [
        new("Claude Code", @"~\.claude\.credentials.json",
            "OAuth access and refresh tokens for your Claude account: anyone holding them can use Claude Code (and your plan's usage) as you.",
            "Run 'claude' then '/logout' to revoke this session, and sign in again. Review active sessions in your claude.ai account settings."),
        new("OpenAI Codex", @"%CODEX_HOME%\auth.json",
            "ChatGPT sign-in tokens or an OpenAI API key used by the Codex CLI.",
            "Run 'codex logout', then sign in again. If the file held an API key, revoke it at https://platform.openai.com/api-keys."),
        new("Gemini CLI", @"~\.gemini\oauth_creds.json",
            "A Google OAuth refresh token with the scopes the Gemini CLI requested.",
            "Remove 'Gemini CLI' at https://myaccount.google.com/permissions, delete the file, and sign in again."),
        new("GitHub Copilot", @"%LOCALAPPDATA%\github-copilot\apps.json",
            "GitHub OAuth tokens used by Copilot in your editors.",
            "Revoke the 'GitHub Copilot' authorization at https://github.com/settings/applications and sign in again."),
        new("GitHub Copilot", @"%LOCALAPPDATA%\github-copilot\hosts.json",
            "GitHub OAuth tokens used by Copilot in your editors.",
            "Revoke the 'GitHub Copilot' authorization at https://github.com/settings/applications and sign in again."),
        new("Google Cloud SDK", @"%APPDATA%\gcloud\application_default_credentials.json",
            "Application Default Credentials: a refresh token that lets local code call Google Cloud APIs as you.",
            "Run 'gcloud auth application-default revoke', then log in again only when needed."),
    ];

    /// <summary>Why vendor token files matter, shown with every token-file finding.</summary>
    public const string TokenFileWhy =
        "Hush cannot vault this file without breaking the tool that owns it. Infostealers copy these token files because they work from any machine until revoked; keep sessions short and revoke them if this machine is ever compromised.";
}

/// <summary>Folder roots used to expand path templates. Tests point these at a temporary directory.</summary>
public sealed record ScanEnvironment(string Home, string AppData, string LocalAppData, string ProgramData, string CodexHome)
{
    /// <summary>The current user's environment.</summary>
    public static ScanEnvironment Current()
    {
        var home = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        var codexHome = Environment.GetEnvironmentVariable("CODEX_HOME");
        return new ScanEnvironment(
            home,
            Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
            string.IsNullOrWhiteSpace(codexHome) ? Path.Combine(home, ".codex") : codexHome);
    }

    /// <summary>A fake environment rooted at <paramref name="root"/>.</summary>
    public static ScanEnvironment Under(string root) => new(
        Path.Combine(root, "home"),
        Path.Combine(root, "appdata"),
        Path.Combine(root, "localappdata"),
        Path.Combine(root, "programdata"),
        Path.Combine(root, "home", ".codex"));

    /// <summary>Expands a template into existing file paths (a <c>*</c> segment may match several).</summary>
    public IEnumerable<string> Expand(string template)
    {
        ArgumentNullException.ThrowIfNull(template);
        var path = template
            .Replace("%APPDATA%", AppData, StringComparison.OrdinalIgnoreCase)
            .Replace("%LOCALAPPDATA%", LocalAppData, StringComparison.OrdinalIgnoreCase)
            .Replace("%PROGRAMDATA%", ProgramData, StringComparison.OrdinalIgnoreCase)
            .Replace("%CODEX_HOME%", CodexHome, StringComparison.OrdinalIgnoreCase);
        if (path.StartsWith('~'))
        {
            path = Home + path[1..];
        }

        if (!path.Contains('*', StringComparison.Ordinal))
        {
            if (File.Exists(path))
            {
                yield return path;
            }

            yield break;
        }

        var segments = path.Split('\\');
        var starIndex = Array.FindIndex(segments, s => s.Contains('*', StringComparison.Ordinal));
        var parent = string.Join('\\', segments[..starIndex]);
        if (!Directory.Exists(parent))
        {
            yield break;
        }

        var rest = segments[(starIndex + 1)..];
        if (rest.Length == 0)
        {
            foreach (var file in Directory.EnumerateFiles(parent, segments[starIndex]))
            {
                yield return file;
            }

            yield break;
        }

        foreach (var directory in Directory.EnumerateDirectories(parent, segments[starIndex]))
        {
            var candidate = Path.Combine([directory, .. rest]);
            if (File.Exists(candidate))
            {
                yield return candidate;
            }
        }
    }
}
