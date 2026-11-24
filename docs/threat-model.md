# Threat model

Hush exists to remove plaintext secrets from developer machines without making them harder to use. This page says
what that does and does not buy you. If something here is wrong, please report it (see [SECURITY.md](../SECURITY.md)).

## Assets

- API keys, tokens and passwords that developers and AI agents use (the vault entries).
- The DEK, and the factors that release it (Windows Hello key, TPM key, recovery key).
- The integrity of the audit log.

## Adversaries and what Hush does about them

### 1. Offline theft: a stolen laptop disk, a backup, or a copied `vault.hush`

**Protected.** The DEK is wrapped under a KEK that needs both a Windows Hello signature (whose key never leaves the
PC and needs the user) and `S_tpm` (sealed by a non-exportable TPM key). A copy of the file on another machine cannot
produce either. The only other way in is the recovery key, which is not stored anywhere on the machine.

*Degraded mode*: without a TPM, `S_tpm` is protected by DPAPI. An attacker with the vault and the user's Windows
credentials (or DPAPI master keys extracted from a live session) can recover `S_tpm`, but still needs the Windows Hello
signature. Hush flags degraded vaults on every surface.

### 2. Silent user-level malware: an infostealer, a malicious npm postinstall script, a poisoned VS Code extension

**Protected against silent unlock and against plaintext harvesting.**

- `.env` files, MCP configs and credential files no longer hold the secrets (after `hush migrate`), so stealers that
  sweep those paths find stubs and `hush run` commands.
- Unlocking needs Windows Hello, which requires the user to look at the camera, touch the sensor or type the PIN in a
  secure desktop prompt. Malware cannot approve it.
- The broker serves only binaries from its own install directory with the expected hash (and signer, for signed
  builds), over a pipe only the user can open, so another program cannot simply ask for the DEK or for values.

**Not protected**, see below: malware that waits for you to unlock.

### 3. AI coding agents reading plaintext

**Protected against reading secrets from files.** An agent that runs `cat .env`, reads `~/.cursor/mcp.json`, or is
prompt-injected into exfiltrating config files finds no values. Per-server injection
(`"command": "hush", "args": ["run", "--secrets", "X", "--", ...]`) gives each MCP server only the secrets it needs, in
its own environment, instead of giving them to the agent.

### 4. Tampering with the vault or the audit log

**Detected.** The vault's MAC covers every byte, each entry's AES-GCM tag covers its ciphertext and identity
(vault id, entry id, version), and the audit log is an HMAC chain whose head is anchored in the vault. Rolling back
both the vault and the log together to an earlier consistent state is not detected (there is no external monotonic
counter).

## What Hush does not protect against

### Malware that waits for an unlocked session

While the vault is unlocked (up to the idle timeout, default 10 minutes), the broker serves verified Hush binaries
without a new prompt. Malware running as you can run `hush.exe run --secrets X -- <its own program>`, because that is a
legitimate Hush binary asking. Mitigations:

- Mark high-value secrets `always-prompt` (`hush set NAME --policy always-prompt`). Each use then needs a fresh Windows
  Hello confirmation, which malware cannot provide.
- Keep the idle timeout short, and lock Windows when you step away (that locks the vault).
- Read the audit log: every read records the requesting process and its parent.

### Administrator, SYSTEM or kernel compromise

An attacker with administrative rights can read process memory (including the broker's DEK while unlocked), install
drivers, replace binaries in the install directory, or impersonate the user. Hush's guarantees assume the OS is not
compromised at that level.

### Secrets after they are injected

`hush run` puts secrets in a child process's environment. From then on they are as exposed as that process makes them:
other processes running as you can read another process's environment and memory, the program can log them, write
them to disk or send them anywhere, and its children inherit them. `--mask` filters the child's stdout and stderr, but
it is a convenience, not a security boundary: an encoded or partial secret passes through.

Running `hush run -- claude` gives the agent itself the secrets. Prefer per-MCP-server injection, so the agent process
never holds them.

### Memory hygiene limits

The DEK and intermediate keys live in pinned buffers that are zeroed after use. Secret values, however, become .NET
strings on their way into environment blocks, the clipboard and pipe messages, and strings cannot be wiped. A memory
dump of a Hush client during an operation may contain values.

### Other tools' token files

Claude Code, Codex, Gemini CLI, Copilot and the gcloud SDK keep their own OAuth tokens in files Hush cannot vault
without breaking those tools. `hush scan` reports them with what they grant and how to revoke them, but they remain on
disk.

### The clipboard

`hush get --copy` keeps the value out of clipboard history and cloud sync and clears it after 30 seconds (if nothing
else was copied since), but any process can read the clipboard while it holds the value.

### Lost recovery key plus lost factors

If Windows Hello is reset or the TPM is cleared and the recovery key is lost, the vault cannot be opened by anyone,
including you. That is the point.

## Assumptions

- Windows Hello is configured with a PIN, face or fingerprint, and its prompt runs on the secure desktop.
- The TPM is a genuine TPM 2.0 (firmware or discrete) and the Platform Crypto Provider is not compromised.
- The install directory is writable only by the user (or by administrators, for machine-wide installs).
- Release binaries are verified (SHA256SUMS and build provenance) before installation.
