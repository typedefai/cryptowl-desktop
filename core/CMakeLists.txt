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
    crypto/Trace.h
    vault/ItemRepository.h
    vault/ItemRepository.cpp
    vault/Schema.h
    vault/VaultDatabase.cpp
    vault/VaultSession.h
    vault/VaultSession.cpp
    "${CMAKE_CURRENT_BINARY_DIR}/Schema.cpp"
)

target_include_directories(cryptowl_core PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})

target_compile_definitions(cryptowl_core PUBLIC
    CRYPTOWL_TRACE_CRYPTO=$<BOOL:${CRYPTOWL_TRACE_CRYPTO}>
)

if(CRYPTOWL_TRACE_CRYPTO)
    target_sources(cryptowl_core PRIVATE crypto/Trace.cpp)
endif()

target_link_libraries(cryptowl_core
    PRIVATE mbedcrypto
    PRIVATE argon2
    PRIVATE sqlcipher
)
