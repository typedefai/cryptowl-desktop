# Third-party dependencies

| Dependency | Version | Integration | Source | License |
| --- | --- | --- | --- | --- |
| mbedTLS | 3.6.7 | FetchContent, SHA-256 pinned | <https://github.com/Mbed-TLS/mbedtls/releases/download/mbedtls-3.6.7/mbedtls-3.6.7.tar.bz2> | Apache-2.0 (`mbedTLS-LICENSE.txt`) |
| phc-winner-argon2 | reference implementation, Argon2 v1.3 | vendored under `argon2/` | <https://github.com/P-H-C/phc-winner-argon2> | CC0-1.0 or Apache-2.0 (`argon2/LICENSE`) |
| SQLCipher | 5.0.0-beta.1 | vendored generated amalgamation under `sqlcipher/` | <https://github.com/sqlcipher/sqlcipher/tree/v5.0.0-beta.1> | BSD-3-Clause (`sqlcipher/LICENSE.md`) |
| OpenSSL | 3.5.8 LTS recommended | system/manual install; `find_package(OpenSSL)` | <https://www.openssl.org/> | Apache-2.0 (`OpenSSL-LICENSE.txt`) |
| QtKeychain | 0.17.0 | FetchContent, SHA-256 pinned | <https://github.com/frankosterfeld/qtkeychain/tree/0.17.0> | BSD-3-Clause (`QtKeychain-COPYING.txt`) |

## Rules

- Pin every remote archive by SHA-256; never fetch a moving branch or unhashed tag.
- Keep upstream code unmodified. If a patch is unavoidable, document it here.
- Vendored dependencies are used where upstream has no usable CMake build or
  where a generated artifact must be fixed (SQLCipher's amalgamation), or where
  the source is small and security-critical (Argon2).
- FetchContent is used for dependencies with a usable upstream CMake build or
  small source trees where a pinned download keeps the repository manageable.
- OpenSSL is a system dependency installed by the developer/packager; binary
  distributions must bundle or require a compatible OpenSSL 3.x runtime.
- Keep the upstream license in the repository; binary distributions must also
  include these notices.
