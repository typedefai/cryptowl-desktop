file(READ "${PROJECT_SOURCE_DIR}/docs/schema.sql" CRYPTOWL_SCHEMA_SQL)
configure_file(
    "${CMAKE_CURRENT_SOURCE_DIR}/cmake/Schema.cpp.in"
    "${CMAKE_CURRENT_BINARY_DIR}/Schema.cpp"
    @ONLY
)

add_library(cryptowl_core STATIC
    crypto/AesGcm.cpp
    crypto/Argon2.cpp
    crypto/Bytes.cpp
    crypto/Crockford32.cpp
    crypto/Hash.cpp
    crypto/ProtectedValue.cpp
    crypto/Random.cpp
    vault/Schema.h
    vault/VaultDatabase.cpp
    "${CMAKE_CURRENT_BINARY_DIR}/Schema.cpp"
)

target_include_directories(cryptowl_core PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})

target_link_libraries(cryptowl_core
    PRIVATE mbedcrypto
    PRIVATE argon2
    PRIVATE sqlcipher
)
