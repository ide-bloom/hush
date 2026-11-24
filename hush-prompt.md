# Hush — Full Build Prompt

Build **Hush**, a Windows secrets manager for developers and AI agents in which every secret is locked behind the machine's TPM and Windows Hello. Deliver it as a complete, production-quality GitHub repository in a single run. Do not stop at a scaffold, an outline, or a partial implementation. Every feature in this document must be implemented, compile cleanly, be covered by tests, and be documented accurately. When a Windows API detail is uncertain, check the official Microsoft documentation before writing the code, and use the approach that actually works on current Windows 11 (24H2, 25H2, 26H1). Use the latest stable versions of every package at build time.

The repository lives at `github.com/ide-bloom/hush`. It is one of three sister projects (Epicurus, Hush, Chaperone) that together form the **Palisade** toolkit for developer security in the AI-agent era. Link the other two in the README (`github.com/ide-bloom/epicurus`, `github.com/ide-bloom/chaperone`).

---

## 1. What Hush is and why it exists

Developer machines are full of plaintext secrets: `.env` files, `.npmrc`, `.git-credentials`, cloud CLI profiles, and, increasingly, MCP server configs with API keys pasted straight into JSON. Two things made this much worse in 2026:

1. **AI coding agents run with the user's full permissions.** They can read `.env` files, SSH keys and API tokens, so one prompt injection is enough to exfiltrate them.
2. **Infostealers now target exactly these files.** Families such as Warden Stealer and Aoki harvest AI-agent tokens, MCP configs and developer credentials.

Hush removes the plaintext. Secrets live in an encrypted vault whose key can only be released on this specific machine (TPM-bound) with the user physically present (Windows Hello: face, fingerprint or PIN). Secrets are injected as environment variables into the single process that needs them and never touch disk in plaintext:

```
hush run -- npm run dev
hush run -- claude
```

---

## 2. Platform and stack

- C# 14 on .NET 10 (LTS). Target `net10.0-windows10.0.22621.0` so WinRT APIs are available. Ship win-x64 and win-arm64 builds.
- **Projects** (one solution, `Hush.sln`):
  - `src/Hush.Core`: vault format, crypto, key providers, scanner, migrators, project manifest, audit log
  - `src/Hush.Cli`: `hush.exe`, built on `System.CommandLine` (latest stable)
  - `src/Hush.Agent`: the session broker that holds the unlocked key in memory (it can be the same exe started with `hush agent`)
  - `src/Hush.App`: WPF tray app using the built-in Fluent theme (`ThemeMode`), following the system light/dark setting
  - `tests/Hush.Core.Tests`, `tests/Hush.Cli.Tests`: xUnit
- **Publish** the CLI and the app as self-contained single-file executables with no .NET install required. Try Native AOT for `hush.exe`; if WinRT interop or trimming makes AOT unreliable, fall back to single-file plus ReadyToRun and document the decision in `docs/architecture.md`.
- **Dependencies:** keep them minimal. Use `System.Security.Cryptography` for AES-GCM, HKDF and SHA-256, and `Tomlyn` (or equivalent) for TOML. Run `dotnet list package --vulnerable` in CI.

---

## 3. Cryptographic design

Implement exactly this design and document it with diagrams in `docs/crypto.md`.

### Key hierarchy
- **DEK (data encryption key):** 32 random bytes. Each secret entry is encrypted with AES-256-GCM under the DEK, using a unique 96-bit nonce and AAD = `vault_id || entry_id || entry_version`.
- **Hello factor:** create a Windows Hello key with `KeyCredentialManager.RequestCreateAsync` (RSA-2048, TPM-backed whenever a TPM exists). At unlock, sign a random 32-byte per-vault challenge stored in the vault header with `RequestSignAsync`. RSASSA-PKCS1-v1_5 is deterministic, so the signature is a stable secret that can only be produced with the user present. Derive `K_hello = HKDF-SHA256(signature, salt=vault_salt, info="hush/hello/v1")`. Verify determinism at vault creation by signing twice and comparing; refuse to create the vault if the signatures differ.
- **TPM factor:** create a non-exportable RSA-2048 key in the `Microsoft Platform Crypto Provider` through NCrypt. At vault creation, generate 32 random bytes `S_tpm`, encrypt it with that key (RSA-OAEP-SHA256), and store the ciphertext in the header. At unlock, decrypt it with the TPM.
- **KEK** = `HKDF-SHA256(K_hello || S_tpm, salt=vault_salt, info="hush/kek/v1")`. The DEK is stored wrapped with AES-256-GCM under the KEK.

Copying the vault file to another machine is useless (no TPM key), and malware running as the user cannot unlock silently (Hello requires presence).

### Recovery
At `hush init`, generate a 160-bit recovery key and display it once, formatted as grouped Crockford Base32 with a checksum group. Store a second wrapping of the DEK under `HKDF(recovery_key, info="hush/recovery/v1")`. The README must state plainly that resetting Windows Hello or clearing the TPM destroys the primary factors, and that the recovery key is then the only way back in. `hush recover` re-enrolls new Hello and TPM factors.

### No-TPM fallback
If no usable TPM exists, fall back to a software key protected with DPAPI. Mark the vault as degraded and show the warning everywhere: the CLI banner, `hush status`, and the app.

### Vault file
`%LOCALAPPDATA%\Hush\vault.hush`, binary format with:
- magic bytes and format version
- vault id, salt, challenge, factor metadata
- wrapped DEK blobs
- entry table
- a header MAC

Writes are atomic: write to a temp file, flush, then replace. Document the format byte by byte in `docs/vault-format.md`.

### Hygiene
Zero key material after use with `CryptographicOperations.ZeroMemory`, keep keys in pinned buffers, never log secrets, and never place secrets in exception messages.

### Abstraction for testing
All hardware access goes through an `IHardwareKeyProvider` interface. Tests use a deterministic software provider, so the suite runs on CI machines without Hello or a TPM. Production code refuses the test provider unless the build is explicitly a test build.

---

## 4. Session broker

After an unlock, `hush agent` holds the DEK in memory so that repeated `hush run` calls don't prompt every time.

**Timeouts.** Idle timeout defaults to 10 minutes and is configurable. The broker also locks immediately when the workstation locks, sleeps, or the user switches sessions (`SystemEvents.SessionSwitch` and power events).

**IPC.** A named pipe whose name includes a hash of the user's SID, with a `PipeSecurity` ACL granting access only to the current user. For every connection:
- Get the client PID with `GetNamedPipeClientProcessId`.
- Verify that the client image is a Hush binary from the same install directory, matched by path and SHA-256 hash, plus the Authenticode signer when the binary is signed.

**Per-secret policy:**
- `session`: the default; served from the unlocked session
- `always-prompt`: requires a fresh Windows Hello confirmation on every use, for high-value secrets such as production keys

**Hello prompt.** Make sure the prompt appears in the foreground even when Hush is called from a console window or a terminal inside an IDE. Use the documented interop approach for desktop apps (a window-handle-based request or an owner window) and test it from Windows Terminal, VS Code's terminal and plain conhost.

---

## 5. Commands

| Command | Behavior |
|---|---|
| `hush init` | Create the vault, enroll Hello and TPM, show the recovery key once. |
| `hush status` | Vault health, factor status (TPM / degraded), lock state, timeout, number of secrets. |
| `hush unlock` / `hush lock` | Manual control of the session. |
| `hush set <NAME> [--policy always-prompt] [--scope <project>]` | Read the value from a hidden prompt or from stdin, never from the command line, so it can't end up in shell history. |
| `hush get <NAME> [--copy]` | `--copy` puts the value on the clipboard, excluded from clipboard history and cloud sync via the documented clipboard format flags, and clears it after 30 seconds. Printing to stdout requires `--reveal` and a confirmation. |
| `hush list` | Names, scopes, policies, last used. Never values. |
| `hush rm <NAME>` | Delete a secret. |
| `hush run [--secrets A,B] [--mask] -- <command> [args]` | Resolve which secrets the command needs (from `--secrets` or the project manifest), launch the child process with them added to its environment, stream stdio through, forward Ctrl+C, and return the child's exit code. `--mask` replaces any occurrence of a secret value in the child's stdout/stderr with `••••`. |
| `hush scan [paths] [--json] [--sarif]` | See Section 6. |
| `hush migrate [--dry-run] [--undo]` | See Section 7. |
| `hush audit [--verify]` | Show the audit log; `--verify` checks the hash chain. |
| `hush recover` | Restore access with the recovery key and re-enroll factors. |
| `hush export --encrypted <file>` / `hush import <file>` | Encrypted backup protected by the recovery key, for moving to a new machine. |

**Project manifest `.hush.toml`.** It is safe to commit because it contains only names and mappings, never values. It lists the secrets a project needs and maps them to environment variable names, optionally per profile (`dev`, `staging`). `hush run` searches for it in the current directory and its parents. `hush init --project` creates one.

---

## 6. Scanner

`hush scan` finds plaintext secrets on the machine and reports them **redacted**: provider, secret type, file, line number, the first four characters, a confidence level, and a risk note. It never prints a full secret.

**Detection** combines provider rules (prefix plus format plus checksum where the provider's format defines one), keyword-anchored generic rules, and entropy, with an allowlist for known placeholders such as `your-api-key-here`.

**Rules** live in an embedded `rules.toml` and cover at least: OpenAI, Anthropic, Google AI, GitHub (classic, fine-grained, OAuth), GitLab, Slack, Discord, Stripe, AWS, Azure, GCP service-account JSON, npm, PyPI, Hugging Face, Twilio, SendGrid, Postgres/MySQL/Mongo connection strings, private key blocks and JWTs.

**Default locations** (also scan any extra paths the user passes):
- `.env*` files under configurable project roots (default: `%USERPROFILE%\source`, `%USERPROFILE%\Projects`, `%USERPROFILE%\dev`, `%USERPROFILE%\code`)
- `~/.npmrc`, `~/.pypirc`, `~/.git-credentials`, `~/.aws/credentials`, `~/.docker/config.json`, `~/.config/gh/hosts.yml`, `~/.kube/config`
- The PowerShell PSReadLine history file
- VS Code user settings
- MCP client configs for Claude Desktop, Claude Code (user and project files), Cursor, VS Code, Windsurf, OpenAI Codex and Gemini CLI. Keep these paths in a single data table that is easy to update, and verify the current locations at build time.

**Token files owned by other tools.** Some agents keep their own OAuth token files, such as Claude Code or Codex credential files, which Hush cannot vault without breaking the tool. Report them separately with clear guidance: what the file grants, how to revoke or rotate it, and why it matters for infostealer exposure. The README states this limitation honestly.

**Output formats:** a human-readable table (colored, grouped by risk), JSON, and SARIF 2.1.0 for GitHub code scanning.

---

## 7. Migrator

`hush migrate` turns scan findings into vaulted secrets. It always supports `--dry-run`, which shows a unified diff of every change. Every change is backed up with a timestamp, and `--undo` restores the last run.

- **MCP configs:** move each inline secret (for example in a server's `env` block) into the vault and rewrite the server's command so it launches through `hush run --secrets NAME -- <original command and args>`. Preserve all JSON or TOML formatting, comments where the format allows them, and unrelated keys.
- **`.env` files:** move the values into the vault, generate or update `.hush.toml`, replace the `.env` with a comment-only stub pointing to Hush, and make sure `.env` is listed in `.gitignore`.
- **`.npmrc` / `.pypirc` / `.git-credentials`:** move tokens into the vault and print the exact command for using them via `hush run` or a credential helper. Where a documented helper mechanism exists, implement `hush` as that helper. For Git, implement a credential helper (`git config credential.helper "hush git-helper"`) that serves vaulted credentials.

---

## 8. Audit log

`%LOCALAPPDATA%\Hush\audit.jsonl`, append-only. Each entry records the timestamp, action, secret names (never values), the requesting process path and PID, its parent process, and the result. Entries are chained: each one includes the HMAC-SHA256 of the previous entry, keyed by a key derived from the DEK. `hush audit --verify` detects tampering or truncation.

---

## 9. Tray app (WPF, Fluent theme)

- **Tray icon:** shows locked/unlocked state, with quick Lock and Unlock actions.
- **Vault view:** names, scopes, policies, last used; add, edit and delete secrets; value fields hidden by default with a reveal that requires Hello.
- **Scan view:** run a scan, browse findings grouped by risk, and migrate selected findings with one click after previewing the diff.
- **Audit view:** a filterable log with a chain-verification indicator.
- **Settings:** idle timeout, lock on sleep, scan roots, start with Windows.

The app is a client of the same broker and core library; there is no duplicated logic. It should look polished and native on Windows 11, with correct DPI scaling and keyboard navigation.

---

## 10. Repository contents

- `README.md`, with these sections:
  - One-line pitch and badges (CI, release, license)
  - Demo GIF placeholder at `docs/media/demo.gif`, with recording instructions
  - Why Hush exists (2026 infostealer and AI-agent context, with links to public research)
  - A 60-second quick start (`hush init`, `hush scan`, `hush migrate`, `hush run`)
  - How it works (a Mermaid diagram of the key hierarchy)
  - Command reference and `.hush.toml` reference
  - MCP integration examples for each supported client
  - Threat model: what Hush protects against (offline theft, silent user-level malware, agents reading plaintext) and what it doesn't (malware that waits for an unlocked session, admin/kernel compromise, secrets after they're injected into a process)
  - FAQ, sister projects, contributing, security, license
- `docs/`: `architecture.md`, `crypto.md`, `vault-format.md`, `threat-model.md`, `scanner-rules.md`
- `CHANGELOG.md`, `SECURITY.md`, `CONTRIBUTING.md`, `CODE_OF_CONDUCT.md`, issue and PR templates, `.editorconfig`, `Directory.Build.props` with nullable enabled, warnings as errors, and analyzers on (`AnalysisLevel` latest-recommended)
- MIT license

---

## 11. Tests

Using xUnit with the software key provider, cover:
- Vault creation, unlock and rotation round-trips
- Tamper detection on the header, entries and wrapped DEK
- Nonce uniqueness
- Recovery-key flow
- Atomic writes, verified by simulating a crash between temp write and replace
- Audit-chain verification, including detection of an edited or deleted entry
- Scanner rules against generated fixtures
- Migrator diffs against golden files for each MCP client format, plus `--undo`
- `.hush.toml` resolution
- `hush run` environment injection, exit-code propagation and output masking
- Pipe client verification logic

**Never commit literal token-shaped strings.** GitHub push protection will block the push and scanners will flag the repo. Build test secrets at runtime from fragments.

---

## 12. CI/CD

GitHub Actions on `windows-latest`, with actions pinned by commit SHA:
- **Every push:** restore, build with warnings as errors, test, a vulnerable-package check, and publish win-x64 and win-arm64.
- **Tags matching `v*`:** zip `hush.exe` and `Hush.exe` (the tray app) with README and LICENSE, generate `SHA256SUMS`, run `actions/attest-build-provenance`, and create a GitHub Release with notes from the CHANGELOG.
- Dependabot for NuGet and GitHub Actions. Also add a `winget` manifest template under `packaging/winget/`.

---

## 13. Code standards

- Clean, idiomatic modern C#: file-scoped namespaces, records for immutable data, `async` all the way down, cancellation tokens on long operations.
- No swallowed exceptions.
- Structured logging with no secret values, ever. Add an analyzer or test that fails if a type marked `[Sensitive]` reaches a logging call.
- XML doc comments on public APIs. Comments explain why, not what.

---

## 14. Definition of done

- `dotnet build -c Release` succeeds with zero warnings, and all tests pass.
- On a Windows 11 machine with Windows Hello set up:
  - `hush init` shows a Hello prompt and the recovery key.
  - `hush scan` finds the planted test secrets.
  - `hush migrate` rewrites an MCP config correctly.
  - `hush run -- <server>` launches with the right environment after one Hello prompt.
  - Locking the workstation locks the vault.
- Copying `vault.hush` to another machine cannot be unlocked without the recovery key.
- The README describes only what actually exists.

Finish with a full pass over every file: remove TODOs, dead code and placeholder text, and fix any mismatch between the documentation and the real behavior.
