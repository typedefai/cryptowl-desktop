include(FetchContent)

FetchContent_Declare(mbedtls
    URL https://github.com/Mbed-TLS/mbedtls/releases/download/mbedtls-3.6.7/mbedtls-3.6.7.tar.bz2
    URL_HASH SHA256=a7e8bcbec0e6f761b4af24f25677626b35f762f68eef79c08677a363212d11f6
    DOWNLOAD_EXTRACT_TIMESTAMP TRUE
)

set(ENABLE_PROGRAMS OFF CACHE BOOL "" FORCE)
set(ENABLE_TESTING OFF CACHE BOOL "" FORCE)
set(MBEDTLS_FATAL_WARNINGS OFF CACHE BOOL "" FORCE)
FetchContent_MakeAvailable(mbedtls)

add_library(argon2 STATIC
    argon2/src/argon2.c
    argon2/src/core.c
    argon2/src/encoding.c
    argon2/src/ref.c
    argon2/src/thread.c
    argon2/src/blake2/blake2b.c
)

target_include_directories(argon2 PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/argon2/include)
target_compile_definitions(argon2 PRIVATE _GNU_SOURCE)
set_target_properties(argon2 PROPERTIES C_STANDARD 99 C_STANDARD_REQUIRED ON)

# OS secure storage for the per-vault device secret.
FetchContent_Declare(qtkeychain
    URL https://github.com/frankosterfeld/qtkeychain/archive/refs/tags/0.17.0.tar.gz
    URL_HASH SHA256=3b85c3929034b0a99da777130c34d99f006fcd3a9d56564159399a33fee0e504
    DOWNLOAD_EXTRACT_TIMESTAMP TRUE
)

set(BUILD_SHARED_LIBS OFF)
set(BUILD_TRANSLATIONS OFF CACHE BOOL "" FORCE)
set(BUILD_TEST_APPLICATION OFF CACHE BOOL "" FORCE)
set(BUILD_QTQUICK_DEMO OFF CACHE BOOL "" FORCE)
set(LIBSECRET_SUPPORT OFF CACHE BOOL "" FORCE)
set(BUILD_TESTING OFF)
unset(QTKEYCHAIN_STATIC CACHE)
FetchContent_MakeAvailable(qtkeychain)
