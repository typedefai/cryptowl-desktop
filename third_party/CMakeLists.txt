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

if(APPLE)
    find_package(OpenSSL 3.0 REQUIRED COMPONENTS Crypto
        HINTS /opt/homebrew/opt/openssl@3 /usr/local/opt/openssl@3 /usr/local/openssl)
else()
    find_package(OpenSSL 3.0 REQUIRED COMPONENTS Crypto)
endif()

# The vendored SQLCipher amalgamation is generated with
# --with-tempstore=yes. These are the CMake equivalents of the CFLAGS shown in
# SQLCipher's build documentation; the provider is OpenSSL.
add_library(sqlcipher STATIC sqlcipher/sqlite3.c)
target_include_directories(sqlcipher PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/sqlcipher)
target_compile_definitions(sqlcipher PRIVATE
    SQLITE_TEMP_STORE=2
    SQLITE_THREADSAFE=1
    SQLITE_USE_URI=1
    SQLITE_DIRECT_OVERFLOW_READ=0
    SQLITE_EXTRA_INIT=sqlcipher_extra_init
    SQLITE_EXTRA_SHUTDOWN=sqlcipher_extra_shutdown
    SQLITE_OMIT_LOAD_EXTENSION=1
    SQLCIPHER_CRYPTO_OPENSSL=1
)
if(MSVC)
    target_compile_definitions(sqlcipher PRIVATE _CRT_SECURE_NO_WARNINGS)
endif()
if(UNIX)
    find_package(Threads REQUIRED)
    target_link_libraries(sqlcipher PUBLIC Threads::Threads)
endif()
target_link_libraries(sqlcipher PUBLIC OpenSSL::Crypto)
set_target_properties(sqlcipher PROPERTIES
    C_STANDARD 99
    C_STANDARD_REQUIRED ON
    AUTOMOC OFF
    AUTOUIC OFF
    AUTORCC OFF
)

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
