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

qt_add_executable(tst_vaultdatabase
    tst_vaultdatabase.cpp
)

target_link_libraries(tst_vaultdatabase PRIVATE cryptowl_core Qt6::Test)

add_test(NAME tst_vaultdatabase COMMAND tst_vaultdatabase)

qt_add_executable(tst_itemrepository
    tst_itemrepository.cpp
)

target_link_libraries(tst_itemrepository PRIVATE cryptowl_core Qt6::Test)

add_test(NAME tst_itemrepository COMMAND tst_itemrepository)
