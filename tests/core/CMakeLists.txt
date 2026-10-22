qt_add_executable(tst_crypto_vectors
    tst_crypto_vectors.cpp
)

target_link_libraries(tst_crypto_vectors PRIVATE cryptowl_core Qt6::Test)

add_test(NAME tst_crypto_vectors COMMAND tst_crypto_vectors)

qt_add_executable(tst_crockford32
    tst_crockford32.cpp
)

target_link_libraries(tst_crockford32 PRIVATE cryptowl_core Qt6::Test)

add_test(NAME tst_crockford32 COMMAND tst_crockford32)
