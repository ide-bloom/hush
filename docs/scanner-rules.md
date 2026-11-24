# Scanner rules

`hush scan` reports plaintext secrets **redacted**: provider, secret type, file, line, the first four characters, a
confidence level and a risk note. It never prints a full secret, and neither do its JSON or SARIF reports.

The rules are data: `src/Hush.Core/Scanning/rules.toml`, embedded in the binary. The scan locations are data too:
`src/Hush.Core/Scanning/ScanLocations.cs`.

## How detection works

For each line of each file:

1. **Keyword prefilter**: a rule only runs if the line contains one of its `keywords` (case-insensitive).
2. **Pattern**: a .NET regular expression (250 ms timeout). If it has a named group `secret`, that group is the
   secret; otherwise the whole match is.
3. **Allowlist**: values that are obviously placeholders are dropped (`your-api-key-here`, `${VAR}`, `<token>`,
   `changeme`, `xxxx...`, `%VAR%`, UPPER_SNAKE_CASE names, and so on).
4. **Entropy floor**: rules with `min_entropy` drop values whose Shannon entropy (bits per character) is lower.
5. **Checksum**: rules with `checksum` validate the format. A valid checksum means *high* confidence; an invalid one
   lowers a token to *medium* (or drops a non-JWT for the `jwt` rule).
6. **De-duplication**: provider rules run before generic ones, and a later rule never reports a span an earlier rule
   already reported.

| Validator | Used by | Check |
|---|---|---|
| `github-crc32` | GitHub classic PATs, GitHub OAuth/app tokens, npm tokens | `prefix_` + 30 base62 characters + 6 base62 characters of the CRC-32 of the random part |
| `jwt` | JWTs | the header decodes (base64url) to a JSON object with an `alg` member |

## Rule fields

```toml
[[rules]]
id = "example-api-key"          # unique, kebab-case; also the SARIF rule id
provider = "Example"            # who issued it
type = "API key"                # what it is
pattern = '\b(?<secret>ex_[A-Za-z0-9]{32})\b'
keywords = ["ex_"]              # cheap prefilter
confidence = "high"             # high | medium | low (before checksum and entropy adjustments)
risk = "critical"               # critical | high | medium | low
note = "What it grants. How to revoke or rotate it."
checksum = "github-crc32"       # optional validator
min_entropy = 3.5               # optional
path_regex = '(?i)\.npmrc$'     # optional: only files whose full path matches
```

Use TOML literal strings (`'...'`) for patterns, or multi-line literal strings (`'''...'''`) when a pattern needs a
single quote. Never put a real or realistic token in this file or in tests: test fixtures are generated at runtime by
`FakeTokens`.

## Rules

| Id | Provider | Detects | Risk |
|---|---|---|---|
| `openai-api-key` | OpenAI | `sk-…` keys containing the `T3BlbkFJ` marker | critical |
| `openai-project-key` | OpenAI | `sk-proj-`, `sk-svcacct-`, `sk-admin-` keys | critical |
| `anthropic-api-key` | Anthropic | `sk-ant-api03-…`, `sk-ant-admin01-…` | critical |
| `google-api-key` | Google AI / Google Cloud | `AIza…` keys (Gemini API, Maps...) | high |
| `huggingface-token` | Hugging Face | `hf_…` | high |
| `github-pat-classic` | GitHub | `ghp_…` with CRC-32 checksum | critical |
| `github-pat-fine-grained` | GitHub | `github_pat_…` | critical |
| `github-oauth-token` | GitHub | `gho_`, `ghu_`, `ghs_`, `ghr_` with checksum | critical |
| `gitlab-pat` | GitLab | `glpat-`, `glrt-`, `gldt-`, `glptt-` | critical |
| `slack-token` | Slack | `xoxb-`, `xoxp-`, `xoxa-`, `xoxr-`, `xoxs-`, `xoxe-` | high |
| `slack-webhook` | Slack | `hooks.slack.com/services/…` | medium |
| `discord-bot-token` | Discord | bot tokens (three dot-separated parts), near the words "discord" or "bot" | high |
| `discord-webhook` | Discord | `discord.com/api/webhooks/…` | medium |
| `twilio-api-key` | Twilio | `SK` + 32 hex | medium |
| `twilio-auth-token` | Twilio | 32 hex assigned to a Twilio token name | high |
| `sendgrid-api-key` | SendGrid | `SG.…` | high |
| `stripe-live-key` | Stripe | `sk_live_`, `rk_live_` | critical |
| `stripe-test-key` | Stripe | `sk_test_`, `rk_test_` | low |
| `aws-access-key-id` | AWS | `AKIA`, `ASIA`, `ABIA`, `ACCA` + 16 | high |
| `aws-secret-access-key` | AWS | 40-character secret assigned to `aws_secret_access_key` | critical |
| `azure-storage-connection-string` | Azure | `AccountKey=` storage keys | critical |
| `azure-ad-client-secret` | Azure | Entra ID client secrets (`…Q~…`) | critical |
| `azure-openai-key` | Azure | keys assigned to Azure OpenAI / Cognitive Services names | high |
| `gcp-service-account` | Google Cloud | `private_key_id` in service-account JSON | critical |
| `npm-token` | npm | `npm_…` with CRC-32 checksum | critical |
| `npmrc-auth` | npm | `_authToken=`, `_auth=`, `_password=` in `.npmrc` | high |
| `pypi-token` | PyPI | `pypi-AgEIcHlwaS5vcmc…` | critical |
| `pypirc-password` | PyPI | `password =` in `.pypirc` | high |
| `docker-config-auth` | Docker | `"auth"` entries in `.docker/config.json` | high |
| `database-connection-string` | Database | `postgres://`, `mysql://`, `mongodb(+srv)://`, `redis://`, `amqp://`, `mssql://`… URLs with a password | critical |
| `git-credentials` | Git | `https://user:token@host` in `.git-credentials` | critical |
| `kubeconfig-credential` | Kubernetes | `token`, `client-key-data`, `password` in `.kube/config` | critical |
| `private-key` | Cryptography | `-----BEGIN … PRIVATE KEY-----` blocks | critical |
| `jwt` | Generic | JSON Web Tokens (validated header) | medium |
| `bearer-token` | Generic | `Bearer <credential>` (for example in MCP HTTP headers) | high |
| `generic-secret-assignment` | Generic | a 16+ character mixed letters-and-digits value assigned to a name containing key, secret, token, password, credential... (entropy ≥ 3.5) | medium |

## Where `hush scan` looks

Every run scans the paths you pass (directories completely, skipping `node_modules`, `.git`, `bin`, `obj`, virtual
environments and similar). Unless you pass `--no-defaults`, it also scans the following.

**Project roots** (from `hush config scan-roots`; defaults: `%USERPROFILE%\source`, `Projects`, `dev`, `code`), up to
six levels deep: `.env` and `.env.*` files, and project MCP configs (`.mcp.json`, `.cursor\mcp.json`,
`.vscode\mcp.json`, `.gemini\settings.json`).

**MCP client configs**:

| Client | Path | Layout |
|---|---|---|
| Claude Desktop | `%APPDATA%\Claude\claude_desktop_config.json` | `mcpServers` |
| Claude Desktop (Microsoft Store) | `%LOCALAPPDATA%\Packages\Claude_*\LocalCache\Roaming\Claude\claude_desktop_config.json` | `mcpServers` |
| Claude Code (user) | `%USERPROFILE%\.claude.json` | `mcpServers`, and `projects.<path>.mcpServers` |
| Claude Code (managed) | `%PROGRAMDATA%\ClaudeCode\managed-mcp.json` | `mcpServers` |
| Claude Code (project) | `<project>\.mcp.json` | `mcpServers` |
| Cursor | `%USERPROFILE%\.cursor\mcp.json`, `<project>\.cursor\mcp.json` | `mcpServers` |
| VS Code | `%APPDATA%\Code\User\mcp.json`, `%APPDATA%\Code - Insiders\User\mcp.json`, `<project>\.vscode\mcp.json` | `servers` (JSONC) |
| Windsurf | `%USERPROFILE%\.codeium\windsurf\mcp_config.json` | `mcpServers` |
| OpenAI Codex | `%CODEX_HOME%\config.toml` (default `%USERPROFILE%\.codex`) | `[mcp_servers.NAME]` |
| Gemini CLI | `%USERPROFILE%\.gemini\settings.json`, `<project>\.gemini\settings.json` | `mcpServers` |

**Credential files**: `~\.npmrc`, `~\.pypirc`, `~\.git-credentials`, `~\.aws\credentials`, `~\.docker\config.json`,
`~\.config\gh\hosts.yml`, `%APPDATA%\GitHub CLI\hosts.yml`, `~\.kube\config`.

**Shell history**: `%APPDATA%\Microsoft\Windows\PowerShell\PSReadLine\*_history.txt` (the console host and the VS Code
host histories).

**Editor settings**: VS Code, VS Code Insiders, Cursor and Windsurf user `settings.json`.

**Token files owned by other tools** (reported, never migrated):

| Tool | Path | Grants |
|---|---|---|
| Claude Code | `~\.claude\.credentials.json` | OAuth tokens for your Claude account (and, in some versions, connected MCP servers) |
| OpenAI Codex | `%CODEX_HOME%\auth.json` | ChatGPT sign-in tokens or an OpenAI API key |
| Gemini CLI | `~\.gemini\oauth_creds.json` | a Google OAuth refresh token |
| GitHub Copilot | `%LOCALAPPDATA%\github-copilot\apps.json`, `hosts.json` | GitHub OAuth tokens |
| Google Cloud SDK | `%APPDATA%\gcloud\application_default_credentials.json` | Application Default Credentials (refresh token) |

The scanner and the README explain how to revoke each one. These files work from any machine until revoked, which is
why 2026 infostealers collect them.

## Output

- **Table** (default): grouped by risk, colored when the terminal supports it (`NO_COLOR` turns colors off).
- **JSON** (`--json`): summary counts, findings with prefix, confidence, risk, note, client and a fingerprint, plus
  files that could not be read.
- **SARIF 2.1.0** (`--sarif`): one rule per rule id, `security-severity` for GitHub's severity mapping, URIs relative to
  `%SRCROOT%` for files under the current directory, and a `hushSecret/v1` partial fingerprint. The fingerprint is a
  truncated SHA-256 of the rule id, the path and the value: stable across runs and not reversible for high-entropy
  secrets.

`--exit-code` makes `hush scan` exit with 3 when it finds anything, for CI:

```yaml
- run: hush scan . --no-defaults --sarif --output hush.sarif
- uses: github/codeql-action/upload-sarif@<sha>
  with: { sarif_file: hush.sarif }
```
