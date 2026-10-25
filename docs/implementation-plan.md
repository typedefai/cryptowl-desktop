# CryptOwl Desktop — Implementation Plan

Cross-platform C++/Qt desktop client for the CryptOwl encrypted vault. This plan
turns the goals below into phases; the vault format itself is specified in
[items.md](items.md) (v3) and [design.md](design.md) and is not re-specified
here.

Status legend: ☐ todo · ◐ in progress · ✅ done

## Goals (v1 scope)

| # | Goal | Mechanism |
| --- | --- | --- |
| 1 | Minimal app: password + note | `password` (S tier) and `plain` (C tier) types over `t_item` |
| 2 | Multiple encryption levels | C/S/T classification; `encrypted_data_id` → per-item DEK |
| 3 | Lock/unlock + security basics | key chain, integrity checks, auto-lock, memory hygiene |
| 4 | Good UX | password-manager layout (see D5) |
| 5 | Diff / version history | `t_item_version` + fingerprint + text diff |

Out of scope for v1: photos/videos (`t_file`), Moments, AI features, mobile
interop beyond the vault format itself.

## Decisions

| # | Area | Decision | Rationale |
| --- | --- | --- | --- |
| D1 | GUI | **Qt Widgets** (`WindowsVista` where available, classic Windows/Fusion fallback; Selawik UI font) | proven for this class of app (KeePassXC); no QML rewrite; compact Vista-like look |
| D2 | App crypto | **vendored mbedTLS 3.6.7** (AES-256-GCM, HMAC-SHA256, SHA-256, CSPRNG) + **vendored phc-winner-argon2** | hermetic, cross-platform, no system OpenSSL; argon2 matches the Android vendored version |
| D3 | HKDF | own RFC 5869 implementation over HMAC-SHA256 | mirrors the reference line-by-line (incl. empty-salt → 32 zero bytes); trivial and vector-locked |
| D4 | SQLCipher | SQLCipher 4.19.0 vendored amalgamation with the OpenSSL 3.0+ provider (developer-installed) | widely deployed/optimized provider; package a compatible OpenSSL runtime; raw key expression `x'<hex>'` only |
| D5 | UX | password-manager layout: sidebar (type filters + pinned) + search-as-you-type + item list + detail/editor | 1Password/Bitwarden pattern; `items.md`'s Explorer style stays the dev-tooling pattern |
| D6 | Tiers on desktop | C = vault unlock; S = per-item DEK, KEK **dev-bound** to SMK (re-prompt to reveal); T = secondary password (Argon2id → TS-KEK → TopSecretKEK) | no biometrics on desktop; matches `items.md` dev binding and `design.md` semantics |
| D7 | Device secret | QtKeychain (macOS Keychain, Windows Credential Store, Linux Secret Service); legacy `<vault>/device_secret` (32 raw / 64 hex) migrated on first unlock | cross-platform secure-store analog to Android Keystore |
| D8 | Byte-exactness | golden vectors pinned in tests; HMAC order `P = HMAC(key=DeviceSecret, msg=password)` | the cross-verification contract with Android/vaultlib |

## Architecture

```
cryptowl_core   static lib, no Qt   — crypto primitives, vault format, repositories
cryptowl_ui     static lib, Qt      — views, dialogs, viewmodels
cryptowl-desktop executable         — thin main()
third_party/    mbedTLS (FetchContent, pinned), argon2 (vendored)
```

Layout: `core/` grows into `core/vault/` (meta, config, SQLCipher, key chain)
and `core/repository/` (t_item, versions) in later phases.

No plaintext at rest; keys live in `ProtectedValue` (zeroized) only; keys never
logged.

## Phases

### P0 — Foundations ◐

- ✅ CMake + Qt Widgets + presets + CI (Linux/macOS/Windows)
- ✅ docs frozen (`docs/`)
- ✅ `cryptowl_core` + `third_party` (mbedTLS pinned, argon2 vendored)
- ☐ placeholder lint config (clang-format) wired into a CI step

### P1 — Crypto core ✅

- ✅ CSPRNG (mbedTLS CTR_DRBG), SHA-256, HMAC-SHA256, AES-256-GCM, Argon2id,
  Crockford Base32 (grouped, hyphenated), `ProtectedValue`, hex helpers
- ✅ golden vectors: `P`, `TMK`, `SMK`, RFC 5869 case 1, AES-GCM wrap of the
  fixed VaultKey, FEK/HFK (empty-salt HKDF), Crockford golden string
- ☐ constant-time compare helper
- ✅ Exit: `ctest` green, all vectors byte-exact

### P2 — Vault bootstrap ◐

- ✅ `vault.meta` v3 read/write, canonical sorted-key JSON, Crockford B32
  fields, MAC verification, and atomic `QSaveFile` writes
- ◐ `config.json` + `config.sig` creation (HMAC with SMK[32:64]);
  verification on open pending
- ◐ key chain: `P` → TMK (Argon2id) → SMK (HKDF, info=vaultId) →
  wrap/unwrap `vault_key:smk`; re-sign rules on password change pending
- ◐ `device_secret`: QtKeychain load/store + legacy file migration; availability depends on the platform secure-store backend
- ◐ SQLCipher create/verify with **raw key expression `x'<hex>'`**; execute
  `docs/schema.sql` (idempotent, fixed at creation); open for item access pending
- ◐ create / open / lock; meta tamper detection and wrong-password failure done;
  `config.sig` verification and DB close pending
- portable-vault test (copy dir, reopen), tamper tests
- Exit: create→lock→unlock round-trip + oracle `oracle_canonical_meta.json` MAC
  reproduces

### P3 — Item model ☐

- `ItemRepository`: list/get/create/update/soft-delete/pin/parent tree over
  `t_item`; type registry (`plain`, `password`)
- S-tier plumbing: `t_data_encrypt_key` + `t_encrypted_data`, DEK per item,
  KEK dev binding (`t_wrapped_key` role=kek wrapper=smk), AAD = record id
- T tier: secondary password setup, TS-KEK, TopSecretKEK wrap/unwrap
- History: `fingerprint = HMAC(HFK, title \0 classification \0 payload)`,
  append `t_item_version`, retention (default 100), restore-as-new-seq
- Text diff (Myers over lines) for `plain` payloads
- Exit: repository + history + tier tests green headless

### P4 — UI ☐

- ✅ Vault home (Cryptomator-style): left vault list with large rows, right
  vault detail with lock/unlock controls; create/open actions (open accepts
  only folders containing `vault.meta`); `QSettings`-persisted recent vaults
  (max 10, remove from list)
- ✅ Password unlock dialog: derive P → TMK → SMK, verify the `vault.meta` MAC,
  unwrap `vault_key:smk`, and hold the key in memory until lock
- ✅ Open/create path dialog: defaults to Documents, editable path field +
  Browse, inline validation; create accepts a new folder under an existing
  parent and rejects non-empty/invalid paths
- ✅ Create vault: master-password confirmation; writes `vault.meta` /
  `config.json` / `config.sig` and stores the device secret in QtKeychain
- ◐ Create/verify the SQLCipher `vault.db`; opening it for item access after
  unlock is pending
- Auto-lock timer
- Browser: sidebar + filter/search + list + detail; C/S/T badges; empty states
- Note editor (C): plain text + markdown preview (`QTextDocument::setMarkdown`)
- Password editor (S): username/url/secret/notes JSON payload, generator,
  reveal re-prompts master password, clipboard policy (password never copied)
- History panel: version list, messages, text diff, restore
- Exit: manual walkthrough of goals 1–5

### P5 — Hardening

- change master password (fast rewrap; re-sign both MACs)
- zeroize-on-lock everywhere; no-secret logging audit
- backup/export `.vbp` (opt-in)
- Windows/macOS packaging (`qt_deploy_*` / windeployqt) and OpenSSL runtime
  bundling

## Verification

- **Golden vectors** (`tests/core/`): fixed inputs from the reference
  implementation (device secret `0x11×32`, password `correct horse battery
  staple`, salts `0x22/0x33×32`, VaultKey `0x44×32`, nonce `0x55×12`);
  `P`/`TMK`/`SMK`/RFC 5869 are taken verbatim from
  `wechat_sns_export/tests/test_vaultlib.py`; the AES-GCM wrap, FEK and HFK
  vectors were generated with the reference venv
  (`wechat_sns_export/.venv/bin/python`).
- **ctest** is the gate; CI runs Linux/macOS/Windows.
- Future: a script that cross-checks a fresh C++-created vault against the
  Python reference (vaultlib) byte-for-byte.
