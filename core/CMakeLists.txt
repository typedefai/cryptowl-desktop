add_library(cryptowl_core STATIC
    crypto/AesGcm.cpp
    crypto/Argon2.cpp
    crypto/Bytes.cpp
    crypto/Crockford32.cpp
    crypto/Hash.cpp
    crypto/ProtectedValue.cpp
    crypto/Random.cpp
)

target_include_directories(cryptowl_core PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})

target_link_libraries(cryptowl_core
    PRIVATE mbedcrypto
    PRIVATE argon2
)
