qt_add_executable(tst_crypto_vectors
    tst_crypto_vectors.cpp
)

qt_add_executable(tst_fileenvelope
    tst_fileenvelope.cpp
)

target_link_libraries(tst_fileenvelope PRIVATE cryptowl_core Qt6::Test)

add_test(NAME tst_fileenvelope COMMAND tst_fileenvelope)

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

qt_add_executable(tst_filerepository
    tst_filerepository.cpp
)

target_link_libraries(tst_filerepository PRIVATE cryptowl_core Qt6::Test)

add_test(NAME tst_filerepository COMMAND tst_filerepository)

qt_add_executable(tst_virtualmediafs
    tst_virtualmediafs.cpp
)

target_link_libraries(tst_virtualmediafs PRIVATE cryptowl_core Qt6::Test)

add_test(NAME tst_virtualmediafs COMMAND tst_virtualmediafs)
