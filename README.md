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
QtKeychain-backed device-secret migration, smoke tests) and the byte-exact
**crypto core** (P1) of the vault format. SQLCipher and the vault bootstrap are next —
see [docs/implementation-plan.md](docs/implementation-plan.md).

## Requirements

- CMake ≥ 3.24 and a C++20 compiler (MSVC 2022, clang, gcc)
- Qt 6.8+ with the Widgets module (CI builds against 6.9.3; local development is
  tested with Qt 6.12)
- Ninja (recommended; ships with the Qt installer under `Tools/Ninja`)

## Build

macOS (Qt installed at `~/Qt/6.12.0/macos`):

```bash
cmake -S . -B build/debug -G Ninja -DCMAKE_PREFIX_PATH="$HOME/Qt/6.12.0/macos"
cmake --build build/debug
```

Linux (distro Qt, e.g. `qt6-base-dev`):

```bash
cmake -S . -B build/debug -G Ninja
cmake --build build/debug
```

Windows (Qt online installer, MSVC):

```powershell
cmake -S . -B build/debug -DCMAKE_PREFIX_PATH="C:\Qt\6.9.3\msvc2022_64"
cmake --build build/debug --config Debug
```

Or use the CMake presets (`debug` / `release`). They read the Qt location from
`QTDIR` (the Qt Creator convention) — or pass `-DCMAKE_PREFIX_PATH=…` directly:

```bash
export QTDIR="$HOME/Qt/6.12.0/macos"        # Windows: set QTDIR=C:\Qt\6.9.3\msvc2022_64
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
