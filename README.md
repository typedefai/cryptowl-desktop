# CryptOwl Desktop

Cross-platform **C++/Qt** desktop client for CryptOwl — a local-first encrypted
vault (notes, passwords, photos, videos). **No plaintext data at rest**: the
vault database is SQLCipher-encrypted, files are AES-256-GCM envelopes, and the
key hierarchy is derived from the master password plus a device secret.

This is a fresh C++ implementation (Qt Widgets, CMake) of the vault format
specified in [`docs/`](docs/) — it replaces the earlier Python prototypes.

## Status

Early scaffold: minimal Qt Widgets application (window, menus, Cryptomator-style
vault home with recent vaults, password unlock against `vault.meta`,
QtKeychain-backed device-secret migration, vault creation with a SQLCipher
`vault.db`, S-tier password CRUD plus confidential/secret notes in a
KeePass-style workspace, and a vault-info dialog, smoke tests) and the
byte-exact **crypto core** (P1) of the vault format. `config.sig` verification
and the remaining item types are next — see
[docs/implementation-plan.md](docs/implementation-plan.md).

> SQLCipher **5.0.0-beta.1** is pre-release and uses v5 defaults; existing
> SQLCipher 4 vault databases are intentionally not compatible.

## Requirements

- CMake ≥ 3.24 and a C++20 compiler (MSVC 2022, clang, gcc)
- Qt 6.8+ with the Widgets module (CI builds against 6.9.3; local development is
  tested with Qt 6.12)
- OpenSSL 3.5.8 LTS recommended (3.0+ accepted) development libraries
  (macOS/Windows: install manually; Linux: `libssl-dev` or equivalent)
- QtKeychain (fetched automatically) for device-secret storage; Linux needs a
  Secret Service or KWallet backend
- Ninja (recommended; ships with the Qt installer under `Tools/Ninja`)

## Build

macOS (Qt installed at `~/Qt/6.12.0/macos`, OpenSSL via Homebrew):

```bash
cmake -S . -B build/debug -G Ninja \
  -DCMAKE_PREFIX_PATH="$HOME/Qt/6.12.0/macos" \
  -DOPENSSL_ROOT_DIR="$(brew --prefix openssl@3)"
cmake --build build/debug
```

Linux (distro Qt, e.g. `qt6-base-dev`, plus `libssl-dev`):

```bash
cmake -S . -B build/debug -G Ninja
cmake --build build/debug
```

Windows (Qt online installer, MSVC; point OpenSSL at your install):

```powershell
cmake -S . -B build/debug `
  -DCMAKE_PREFIX_PATH="C:\Qt\6.9.3\msvc2022_64" `
  -DOPENSSL_ROOT_DIR="C:\Program Files\OpenSSL-Win64"
cmake --build build/debug --config Debug
```

Or use the CMake presets (`debug` / `release`). They read the Qt location from
`QTDIR` (the Qt Creator convention) — or pass `-DCMAKE_PREFIX_PATH=…` directly.
On macOS/Windows, set `OPENSSL_ROOT_DIR` in the environment first:

```bash
export QTDIR="$HOME/Qt/6.12.0/macos"        # Windows: set QTDIR=C:\Qt\6.9.3\msvc2022_64
export OPENSSL_ROOT_DIR="$(brew --prefix openssl@3)"  # Windows: your OpenSSL prefix
cmake --preset debug
cmake --build --preset debug
ctest --preset debug
```

## Test

```bash
ctest --test-dir build/debug --output-on-failure
```

Tests are Qt Test binaries driving the UI headlessly
(`QT_QPA_PLATFORM=offscreen`, already set in the test properties).

### Insecure crypto tracing

Compile-time tracing is **off by default** and is deliberately insecure when
enabled. One flag turns on all flow metadata, raw keys, and plaintext:

```bash
cmake -S . -B build/trace -G Ninja \
  -DCMAKE_PREFIX_PATH="$HOME/Qt/6.12.0/macos" \
  -DCRYPTOWL_TRACE_CRYPTO=ON
cmake --build build/trace

build/trace/src/cryptowl-desktop 2>crypto.log
```

The trace includes:

- Vault key derivation inputs and outputs: salts, device secret, `P`, TMK,
  SMK, VaultKey, KEK, and per-item DEKs
- Every AES-256-GCM operation with key, nonce, AAD, plaintext, ciphertext,
  tag, and status
- Item IDs, data IDs, DEK IDs, type, classification, and payload text/hex
- SQLCipher raw key and an example CLI command

Each AEAD operation is printed as one block, with inputs and outputs aligned
under the operation and hex grouped into 4-byte words:

```text
[cryptowl:crypto] +- AES-256-GCM decrypt  kek.unwrap.smk
[cryptowl:crypto] |  key             32 B  00112233 44556677 8899aabb ccddeeff
[cryptowl:crypto] |                        00112233 44556677 8899aabb ccddeeff
[cryptowl:crypto] |  nonce           12 B  00010203 04050607 08090a0b
[cryptowl:crypto] |  aad              7 B  "kek:smk"
[cryptowl:crypto] |  ciphertext      32 B  ffeeddcc bbaa9988 77665544 33221100
[cryptowl:crypto] |                        ffeeddcc bbaa9988 77665544 33221100
[cryptowl:crypto] |  plaintext       32 B  aabbccdd eeff0011 22334455 66778899
[cryptowl:crypto] |                        aabbccdd eeff0011 22334455 66778899
[cryptowl:crypto] |  tag             16 B  10203040 50607080 90a0b0c0 d0e0f000
[cryptowl:crypto] +- ok
```

Lines are colored when stderr is a terminal. `CRYPTOWL_TRACE_COLOR=always`
forces color (useful in an IDE terminal) and `CRYPTOWL_TRACE_COLOR=never`
disables it; `NO_COLOR` and `TERM=dumb` are also honored. Color is off by
default when redirected to a file, so `2>crypto.log` stays escape-free.

Raw secret lines carry `secret=1` under the same `[cryptowl:crypto]` prefix.
SQLCipher command lines are printed unprefixed so the command can be copied
as-is. Large payload fields are truncated. The master password is never
logged. Treat `crypto.log` as a secret, never use this mode with a real vault,
and never ship or commit a trace-enabled build or its logs.

## Layout

```
├── src/                Qt Widgets application (cryptowl_ui library + executable)
├── assets/             UI fonts (Selawik, OFL)
├── tests/              Qt Test suites, run via ctest
├── docs/               vault format & product design (authoritative spec)
└── .github/workflows/  CI: build + test on Linux / macOS / Windows
```

## Design documents

`docs/` is the authoritative spec — work from it:

| File | Contents |
| --- | --- |
| [docs/items.md](docs/items.md) | **Vault format v3** — unified item model, canonical schema, history, type registry, Explorer-style UI |
| [docs/design.md](docs/design.md) | Key hierarchy, tiers (C/S/T), `vault.meta`, backup, memory protection |
| [docs/schema.sql](docs/schema.sql) | Canonical schema — executed once at vault creation, no migrations |
| [docs/moments.md](docs/moments.md) | Moments feature (timeline, CWO1 media format) |
| [docs/roadmap.md](docs/roadmap.md) | Feature roadmap |
| [docs/migrations/](docs/migrations/) | Historical v1–v4 schemas (pre-v3, reference only) |
| [docs/encryption.svg](docs/encryption.svg) | Key hierarchy diagram |

`docs/schema.sql` is the v3 format: the schema is fixed at vault creation
(no `PRAGMA user_version`, no ALTER/migrations). `docs/migrations/` holds the
superseded pre-v3 history and is kept for reference only.

## Provenance

`docs/` is a snapshot (2026-10-16) of the specification from the `typedefai/cryptowl`
Android repository (branch `android-native`, commit `426ae0f` plus working-tree
edits), frozen here so this project is self-contained.
