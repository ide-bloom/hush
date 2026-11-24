# Security policy

Hush is a security tool, so we treat vulnerability reports as our top priority.

## Reporting a vulnerability

**Do not open a public issue.** Report privately through
[GitHub Security Advisories](https://github.com/ide-bloom/hush/security/advisories/new).

Please include:

- the Hush version (`hush --version`) and Windows build (`winver`),
- whether the vault uses the TPM or the degraded DPAPI fallback (`hush status`),
- a description of the issue and its impact, and steps or a proof of concept.

Never include real secrets, recovery keys or vault files from a machine you care about. If a reproduction needs a
vault, create a throwaway one with `HUSH_HOME` pointing at a temporary folder.

We aim to acknowledge reports within 3 business days and to ship a fix or mitigation for confirmed high-severity
issues within 30 days. We credit reporters in the release notes unless you ask us not to.

## Supported versions

Only the latest release receives security fixes. The vault format is versioned (see
[docs/vault-format.md](docs/vault-format.md)), and newer releases will continue to read older vaults.

## Scope

In scope: the vault format and cryptography, the hardware key providers, the session broker (pipe ACL, peer
verification, presence proofs), the scanner's redaction guarantees, the migrator's file handling, the audit chain,
the CLI and the tray app.

Out of scope, because the [threat model](docs/threat-model.md) says plainly that Hush does not defend against them:
malware that waits for an unlocked session and asks the broker as a verified Hush binary would; attackers with
administrator or kernel access; and secrets after they have been injected into a process's environment.

## Verifying releases

Each release ships `SHA256SUMS` and GitHub build provenance attestations. Verify a download with:

```powershell
gh attestation verify .\hush-<version>-win-x64.zip --repo ide-bloom/hush
```
