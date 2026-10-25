# SQLCipher

SQLCipher 4.19.0 amalgamation, generated from the upstream source:

```bash
curl -L -o sqlcipher.tar.gz \\
  https://github.com/sqlcipher/sqlcipher/archive/refs/tags/v4.19.0.tar.gz
tar xzf sqlcipher.tar.gz
mkdir build && cd build
../sqlcipher-4.19.0/configure --with-tempstore=yes --disable-tcl
make sqlite3.c
```

The configure step only generates the amalgamation; the CMake build is what
selects SQLCipher's codec and provider macros. `--with-tempstore=yes` makes the
generated defaults match our `SQLITE_TEMP_STORE=2`; `--disable-tcl` is only a
convenience for generating the amalgamation without building Tcl bindings.

The resulting `sqlite3.c`, `sqlite3.h`, and `sqlite3ext.h` are vendored here so
the build is hermetic and does not need Tcl or the SQLCipher autotools build.

The bundled library is built with the SQLCipher LibTomCrypt provider; see
`third_party/CMakeLists.txt`. Upstream license: `LICENSE.md`.
