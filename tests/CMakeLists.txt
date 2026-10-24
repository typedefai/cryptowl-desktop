add_subdirectory(core)

qt_add_executable(tst_mainwindow
    tst_mainwindow.cpp
)

target_link_libraries(tst_mainwindow PRIVATE cryptowl_ui Qt6::Test)

add_test(NAME tst_mainwindow COMMAND tst_mainwindow)

set_tests_properties(tst_mainwindow PROPERTIES
    ENVIRONMENT "QT_QPA_PLATFORM=offscreen"
)

qt_add_executable(tst_recentvaults
    tst_recentvaults.cpp
)

target_link_libraries(tst_recentvaults PRIVATE cryptowl_ui Qt6::Test)

add_test(NAME tst_recentvaults COMMAND tst_recentvaults)

set_tests_properties(tst_recentvaults PROPERTIES
    ENVIRONMENT "QT_QPA_PLATFORM=offscreen"
)

qt_add_executable(tst_vaultunlocker
    tst_vaultunlocker.cpp
)

target_link_libraries(tst_vaultunlocker PRIVATE cryptowl_ui Qt6::Test)

add_test(NAME tst_vaultunlocker COMMAND tst_vaultunlocker)

set_tests_properties(tst_vaultunlocker PROPERTIES
    ENVIRONMENT "QT_QPA_PLATFORM=offscreen"
)

qt_add_executable(tst_vaultcreator
    tst_vaultcreator.cpp
)

target_link_libraries(tst_vaultcreator PRIVATE cryptowl_ui Qt6::Test)

add_test(NAME tst_vaultcreator COMMAND tst_vaultcreator)
