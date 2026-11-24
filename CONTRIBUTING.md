# Contributing to Hush

Thanks for helping. Hush guards people's credentials, so we optimize for correctness and reviewability over speed.

## Build and test

Requirements: Windows 11, the .NET 10 SDK (`global.json` pins the feature band). Native AOT publishing additionally
needs Visual Studio 2022 (or the Build Tools) with the "Desktop development with C++" workload, plus the
"C++ ARM64 build tools" component to build win-arm64 (or publish with `-NoAot`).

```powershell
dotnet build Hush.sln -c Release           # warnings are errors
dotnet test --solution Hush.sln -c Release # xUnit v3 on Microsoft.Testing.Platform
./build/publish.ps1 -Runtimes win-x64       # hush.exe (Native AOT) + HushTray.exe into ./artifacts/win-x64
```

The test suite never touches Windows Hello or the TPM. It uses the deterministic software provider in
`tests/Shared/TestKeyProvider.cs`, and production builds refuse that provider (see `TestProviderGate`). To try the real
thing without touching your own vault, point Hush at a scratch folder:

```powershell
$env:HUSH_HOME = "$env:TEMP\hush-dev"
./artifacts/win-x64/hush.exe init
```

The tray app talks to the broker in `hush.exe agent`, and both binaries must sit in the same folder because the
broker only serves binaries from its own install directory. Run the app from `artifacts/<rid>` after publishing.

## Rules of the road

- **Never commit token-shaped strings**, not even fake ones. Build test secrets at runtime from fragments with
  `FakeTokens`, and keep golden files to `{{PLACEHOLDERS}}`. CI runs `hush scan . --no-defaults --exit-code` on
  the repository, and GitHub push protection will block pushes that contain tokens.
- **Secret values never reach logs, exceptions or output.** Mark new secret-carrying types, members or parameters
  `[Sensitive]`. The HUSH001 analyzer fails the build if one reaches a logging call.
- **Zero key material** with `CryptographicOperations.ZeroMemory` or `SecureBuffer`.
- **No swallowed exceptions.** Handle an exception meaningfully or let it propagate. If a catch is intentional, the
  comment says why.
- **Comments explain why, not what.** Public APIs have XML doc comments.
- **Docs describe only what exists.** If you change behavior, update the README, `docs/` and `CHANGELOG.md` in the
  same pull request.

## Adding a scanner rule

Rules live in `src/Hush.Core/Scanning/rules.toml`; the format is documented in
[docs/scanner-rules.md](docs/scanner-rules.md). Each rule needs a generated fixture in
`tests/Hush.Core.Tests/ScannerTests.cs` (add a generator to `FakeTokens`) and, where the provider documents a
checksum, a validator in `Checksums`.

## Adding an MCP client

Add its paths to the data table in `src/Hush.Core/Scanning/ScanLocations.cs`. If its config layout is new, add a
`McpFormat`, teach the migrator about it, and add a golden pair under `tests/Hush.Core.Tests/Golden/Migrator`.
Regenerate golden files with `HUSH_UPDATE_GOLDEN=1 dotnet test ...`, then review every line of the diff.

## Changes to crypto, the vault format or the broker protocol

Open an issue first. These changes need a design note, updates to `docs/crypto.md` / `docs/vault-format.md`, tamper
tests, and a migration path for existing vaults (bump the format version; never silently reinterpret old files).

## Commit and review

Keep pull requests focused. Fill in the checklist in the PR template. By contributing you agree that your
contributions are licensed under the MIT License and that you follow the [Code of Conduct](CODE_OF_CONDUCT.md).
