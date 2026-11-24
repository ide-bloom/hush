## What and why

<!-- What does this change, and what problem does it solve? Link the issue if there is one. -->

## Checklist

- [ ] `dotnet build -c Release` passes with zero warnings and `dotnet test --solution Hush.sln -c Release` passes.
- [ ] New behavior has tests (use the software key provider; no real Hello or TPM needed).
- [ ] No literal token-shaped strings were added: test secrets are built at runtime from fragments (`FakeTokens`).
- [ ] No secret values reach logs, exceptions or output (`[Sensitive]` types, redacted prefixes only).
- [ ] Docs updated (README, `docs/`, CHANGELOG) and they describe only what the code does.
- [ ] Changes to the vault format, crypto or broker protocol are reflected in `docs/vault-format.md` / `docs/crypto.md`.
