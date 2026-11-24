# winget manifest template

These files are a template for submitting Hush to [winget-pkgs](https://github.com/microsoft/winget-pkgs).
For each release:

1. Replace `{{VERSION}}` with the version (no leading `v`).
2. Replace `{{SHA256_X64}}` and `{{SHA256_ARM64}}` with the values from the release's `SHA256SUMS`.
3. Validate with `winget validate --manifest packaging/winget` and test with
   `winget install --manifest packaging/winget`.
4. Copy the three files to `manifests/i/ide-bloom/Hush/<version>/` in a fork of winget-pkgs and open a pull request
   (or use `wingetcreate update ide-bloom.Hush --version <version> --urls <x64 zip> <arm64 zip>`).

The installer type is `zip` with two portable executables, so winget puts `hush` on `PATH` and adds a `HushTray`
alias for the tray app.
