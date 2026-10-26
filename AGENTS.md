# AGENTS.md

Cross-platform **C++/Qt desktop client** for the CryptOwl encrypted vault — Qt
Widgets, CMake, C++20, desktop only (Linux/macOS/Windows), no QML. The vault
format specification is frozen in [`docs/`](docs/); this repository is
self-contained.

## Commands

- Configure (macOS, local Qt 6.12):
  `cmake -S . -B build/debug -G Ninja -DCMAKE_PREFIX_PATH="$HOME/Qt/6.12.0/macos"`
- Build: `cmake --build build/debug`
- Test (headless): `ctest --test-dir build/debug --output-on-failure`
  (`QT_QPA_PLATFORM=offscreen` is already set per test)
- CI builds against Qt 6.9.3 on Linux/macOS/Windows — keep the
  `find_package(Qt6 6.8 ...)` floor compatible.

## Source of truth

- [docs/items.md](docs/items.md) — **vault format v3**: unified `t_item` model,
  per-item version history, type registry (plain → password → photo → video),
  Cryptomator-style vault home + KeePass-style workspace now (real password
  CRUD and C/S notes), with the registry-driven Explorer UI as the target.
- [docs/schema.sql](docs/schema.sql) — canonical schema. **Fixed at vault
  creation: no `PRAGMA user_version`, no migrations, no ALTER.** Vaults created
  with an older schema are refused, not upgraded.
- [docs/design.md](docs/design.md) — key hierarchy, C/S/T tiers, `vault.meta`
  format, backup (.vbp), memory protection.
- [docs/migrations/](docs/migrations/) — superseded pre-v3 history; never add
  new files there.
- [docs/moments.md](docs/moments.md), [docs/roadmap.md](docs/roadmap.md) —
  feature designs.

If the spec and an implementation disagree, the spec wins (or gets updated
deliberately).

## Crypto invariants (byte-exact contract — do not "clean up")

- `P = HMAC-SHA256(key=DeviceSecret, msg=masterPassword)`. This order is
  deliberate and byte-exact with the other implementations; the opposite order
  is a known historical bug.
- `TMK = Argon2id(P, salt=argon2Salt, m=19456 KiB, t=2, p=1)`; parameters are
  read from `vault.meta.kdf`, never hardcoded.
- `SMK = HKDF-SHA256(TMK, salt=hkdfSalt, info=vaultId, L=64)`;
  `SMK[0:32]` unwraps `VaultKey`, `SMK[32:64]` is the `vault.meta` /
  `config.sig` MAC key.
- `VaultKey` is the SQLCipher raw key and must be passed as the raw-key
  expression `x'<hex>'` — **never as a bare 32-byte blob** (SQLCipher would
  treat that as a passphrase and derive a different key).
- AES-256-GCM everywhere. AAD: wrapped keys = wrapped-key id
  (`role:wrapper`), record payloads = record id, file envelopes = file id,
  thumbnails = `"<file_id>:thumb"`.
- `vault.meta`: v3, canonical sorted-key JSON, MAC excludes its own field,
  binary fields in Crockford Base32 without padding, atomic writes
  (`.tmp` + rename).
- File envelope = `nonce(12) || ciphertext || tag(16)`; C tier key
  `FEK = HKDF-SHA256(VaultKey, info="file")`, S/T tier key = the item's DEK.
  `size_bytes ≤ embed_max_bytes` (default 512 KiB, from `config.json`) is
  embedded in `t_file.content`; larger goes to `attachments/<file_id>`.
- Version fingerprint =
  `HMAC-SHA256(HFK, title \0 classification \0 payload)` with
  `HFK = HKDF-SHA256(VaultKey, info="fingerprint", 32)` (HMAC, not a raw
  digest). Commit messages are not part of the fingerprint.
- Secrets policy: keys never logged, never in exception messages, derived on
  demand, zeroized after use (no `QString` key material if avoidable).

## Conventions

- Qt Widgets only; UI text via `tr()`. Prefer `WindowsVista` where available,
  then classic Windows, then Fusion (set in `main.cpp`). The UI font is the
  bundled Selawik (OFL, `assets/fonts/`), a Segoe UI-compatible face.
- `src/` holds the `cryptowl_ui` static library (testable) + a thin
  `cryptowl-desktop` executable; tests link the library.
- Tests: Qt Test (`Qt6::Test`), registered with `add_test` in
  `tests/CMakeLists.txt`, run through ctest.
- Dependencies are vendored or fetched via hash-pinned `FetchContent`; see
  [`third_party/MANIFEST.md`](third_party/MANIFEST.md). Crypto dependencies:
  mbedTLS 3.6.7 (AES-256-GCM, HMAC-SHA256, SHA-256, CSPRNG), phc-winner-argon2
  (vendored under `third_party/argon2/`, upstream code, do not modify), and
  SQLCipher 5.0.0-beta.1 (vendored amalgamation under
  `third_party/sqlcipher/`). The first configure downloads mbedTLS (~5 MB) and
  QtKeychain 0.17.0 (~68 KB).
- SQLCipher uses the OpenSSL provider. **OpenSSL 3.5.8 LTS is the recommended
  runtime**; OpenSSL 3.0+ must be installed manually on macOS/Windows (Linux:
  `libssl-dev` or equivalent). Always pass the VaultKey as the raw-key
  expression `x'<hex>'`, never as a bare blob.
- Device secrets use QtKeychain (macOS Keychain, Windows Credential Store,
  Linux Secret Service); legacy vault `device_secret` files are migrated on
  unlock and removed after a successful write.
- Third-party icon assets should carry their license (fluent-ui icons per
  items.md when the Explorer UI lands).
