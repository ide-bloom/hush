# Vault file format (version 1)

`%LOCALAPPDATA%\Hush\vault.hush` (or `%HUSH_HOME%\vault.hush`). Implemented in
`src/Hush.Core/Vault/VaultCodec.cs`. Exports (`hush export --encrypted`) use the same format with the `Portable` flag.

## Conventions

- All integers are **little-endian**.
- `str` = `u16` byte length, then UTF-8 bytes (at most 4096 bytes).
- `blob` = `i32` byte length, then bytes (at most 1 MiB).
- `guid` = 16 bytes in .NET `Guid.TryWriteBytes` layout (the first three fields little-endian).
- `time` = `i64` milliseconds since the Unix epoch, UTC.
- `gcm` = an AES-256-GCM blob stored as a `blob` whose content is `nonce (12) ‖ ciphertext ‖ tag (16)`.

## Fixed header

| Offset | Size | Field | Notes |
|---:|---:|---|---|
| 0 | 8 | magic | ASCII `HUSHVLT` followed by `0x00` |
| 8 | 2 | format version | `1` |
| 10 | 2 | flags | bit 0 `Degraded` (DPAPI instead of TPM), bit 1 `Portable` (export), bit 2 `TestProvider` |
| 12 | 16 | vault id | `guid`, random |
| 28 | 32 | salt | random; salts every HKDF in this vault |
| 60 | 32 | challenge | random; what Windows Hello signs to derive `K_hello` |
| 92 | 8 | created | `time` |
| 100 | 8 | updated | `time` of the last write |
| 108 | 4 | generation | `u32`; starts at 1, incremented by `hush recover` |
| 112 | 8 | audit sequence | `u64`; sequence number of the last audit entry |
| 120 | 32 | audit head | MAC of the last audit entry (all zeros before the first) |
| 152 | 1 | factors present | `1` for a vault, `0` for a portable export |

## Factor block (only if "factors present" is 1)

| Field | Type | Notes |
|---|---|---|
| second factor | `u8` | `1` TPM, `2` DPAPI (degraded), `3` test provider |
| Hello key name | `str` | `hush-<vault id, 32 hex>-g<generation>` |
| Hello public key | `blob` | SubjectPublicKeyInfo (DER) of the Windows Hello key |
| second-factor key name | `str` | name of the TPM key in the Microsoft Platform Crypto Provider (same pattern); also mixed into the DPAPI entropy |
| sealed `S_tpm` | `blob` | RSA-OAEP-SHA256 ciphertext under the TPM key (256 bytes), or a DPAPI blob |
| degraded reason | `str` | why the TPM was not used; empty when not degraded |

## Keys and entries

| Field | Type | Notes |
|---|---|---|
| wrapped audit key | `gcm` | the 32-byte audit HMAC key under the DEK, AAD = `"hush/audit-key/v1" ‖ vault id` |
| wrapped key count | `u8` | 2 for a vault (factors + recovery), 1 for an export (recovery) |
| for each: kind | `u8` | `1` factors KEK, `2` recovery KEK |
| for each: wrapped DEK | `gcm` | the 32-byte DEK, AAD = `"hush/wrap/v1" ‖ vault id ‖ kind` |
| entry count | `i32` | at most 100,000 |

Each entry:

| Field | Type | Notes |
|---|---|---|
| entry id | `guid` | random |
| version | `u32` | 1 at creation, incremented on every value change and on rotation |
| scope | `str` | project scope; empty for a global secret |
| name | `str` | letters, digits, `_ . - @`; at most 128 characters |
| policy | `u8` | `0` session, `1` always-prompt |
| created | `time` | |
| updated | `time` | last value or policy change |
| last used | `time` | `0` if never used |
| ciphertext | `gcm` | UTF-8 value under the DEK, AAD = `vault id ‖ entry id ‖ version (u32 LE)` |

Values are limited to 64 KiB.

## Trailer

| Size | Field | Notes |
|---:|---|---|
| 32 | MAC | HMAC-SHA256 over every preceding byte, keyed by `HKDF-SHA256(DEK, salt, "hush/header-mac/v1")` |

The MAC covers everything, not only the fixed header: factor metadata, wrapped keys, the entry table and the audit
head. Readers parse the file first (to find the wrapped DEK), unwrap the DEK, then verify the MAC before trusting any
field. A reader must reject unknown versions, unknown enum values, out-of-range lengths and trailing data.

## Writes

1. Take the writer lock: `vault.lock` opened with `FileShare.None` and `DeleteOnClose`.
2. Re-read the file and verify its MAC with the held DEK (another process may have written since).
3. Write the new content to `vault.hush.tmp-<random>` with `FILE_FLAG_WRITE_THROUGH` and `FlushFileBuffers`.
4. Replace the vault with `MoveFileEx(MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH)`.

A crash before step 4 leaves the old vault intact plus a stale temp file, which the next write removes while holding the lock. A crash
after step 4 leaves the new vault. Readers never see a partial file. The test suite simulates a crash between steps 3
and 4.

## Related files

| File | Format |
|---|---|
| `audit.jsonl` | one JSON object per line; see [crypto.md](crypto.md#audit-chain) |
| `audit.pending.jsonl` | unauthenticated events recorded while locked, folded into the chain at the next unlock |
| `settings.json` | `{ "idleTimeoutMinutes": 10, "lockOnSleep": true, "scanRoots": [...] }` |
| `backups\<timestamp>\` | migration backups and `journal.json` used by `hush migrate --undo` |
| `logs\*.log` | diagnostic JSON lines; never contain secret values |
