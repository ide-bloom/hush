# Changelog

All notable changes to Hush are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and Hush uses [Semantic Versioning](https://semver.org/).
The release workflow publishes the section for each tag as the GitHub release notes.

## [Unreleased]

### Fixed

- Tray app: the Vault page now shows secrets added from outside the app (for example `hush set` in a terminal).
  It used to read the vault once and only reload when the lock state changed, so it could say "The vault is empty"
  while `hush list` showed secrets. The page now re-reads the vault whenever the file changes (checked every few
  seconds) and when the window is activated.

### Added

- Tray app: "Search secrets…" placeholder in the Vault page's search box.

## [0.1.0] - 2026-11-23

First release.

### Added

- **Vault**: secrets encrypted with AES-256-GCM under a DEK that is wrapped under a KEK derived from a deterministic
  Windows Hello signature and a TPM-sealed secret (RSA-OAEP-SHA256, Microsoft Platform Crypto Provider). A second
  wrapping under a 160-bit recovery key, shown once as grouped Crockford Base32 with a checksum group. Atomic,
  MAC-protected binary file format (`docs/vault-format.md`).
- **Degraded mode**: DPAPI fallback when no usable TPM exists, flagged in the vault and shown by every command,
  `hush status` and the tray app.
- **Session broker** (`hush agent`): holds the DEK in memory, locks after an idle timeout (default 10 minutes) and on
  workstation lock, session switch, logoff and (optionally) sleep. Per-user named pipe with an owner-only ACL,
  first-instance protection, and client verification by install directory, SHA-256 and Authenticode signer.
- **Always-prompt secrets**: each use needs a fresh Windows Hello signature over a one-time broker nonce, verified
  against the Hello public key stored in the vault.
- **CLI**: `init`, `status`, `unlock`, `lock`, `set`, `get` (`--copy` kept out of clipboard history and cloud sync and
  cleared after 30 s, `--reveal` with confirmation), `list`, `rm`, `run` (with `--mask`), `scan`, `migrate`, `audit`,
  `recover`, `rotate`, `export --encrypted`, `import`, `config`, `agent`, `git-helper`.
- **Project manifest** `.hush.toml` with project scopes, global fallback and profiles; found in parent directories.
- **Scanner**: 36 rules covering AI providers, source hosts, messaging, payments, cloud, package registries, database
  URLs, private keys, JWTs, bearer tokens and generic assignments, with checksum validation (GitHub, npm),
  entropy floors and a placeholder allowlist. Default locations include MCP configs for Claude Desktop (including the
  Store build), Claude Code, Cursor, VS Code, Windsurf, OpenAI Codex and Gemini CLI, plus credential files,
  PSReadLine history and editor settings. Token files owned by other tools are reported with revocation guidance.
  Table, JSON and SARIF 2.1.0 output.
- **Migrator**: format-preserving rewrites of JSON/JSONC and TOML MCP configs to launch servers through `hush run`,
  `.env` to vault plus `.hush.toml` plus stub plus `.gitignore`, `.npmrc` to `${VAR}` references, `.pypirc` to
  `TWINE_PASSWORD`, `.git-credentials` to the `hush git-helper` credential helper. Redacted `--dry-run` diffs,
  timestamped backups and `--undo`.
- **Audit log**: append-only JSON lines with an HMAC-SHA256 chain; the head is anchored in the vault so truncation is
  detected. Cancelled or failed unlocks are recorded and joined to the chain at the next unlock. `hush audit --verify`.
- **Tray app** (`HushTray.exe`): WPF with the Fluent theme following the system light/dark mode. Lock state in the
  notification area, vault, scan (with migration preview), audit and settings views.
- **HUSH001 analyzer**: fails the build when a `[Sensitive]` value reaches a logging call.
- Native AOT `hush.exe` and self-contained single-file `HushTray.exe` for win-x64 and win-arm64, SHA256SUMS and build
  provenance attestations, a winget manifest template.

[Unreleased]: https://github.com/ide-bloom/hush/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/ide-bloom/hush/releases/tag/v0.1.0
