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

qt_add_executable(tst_vaultpathdialog
    tst_vaultpathdialog.cpp
)

target_link_libraries(tst_vaultpathdialog PRIVATE cryptowl_ui Qt6::Test)

add_test(NAME tst_vaultpathdialog COMMAND tst_vaultpathdialog)

set_tests_properties(tst_vaultpathdialog PROPERTIES
    ENVIRONMENT "QT_QPA_PLATFORM=offscreen"
)

qt_add_executable(tst_vaultview
    tst_vaultview.cpp
)

target_link_libraries(tst_vaultview PRIVATE cryptowl_ui Qt6::Test)

add_test(NAME tst_vaultview COMMAND tst_vaultview)

set_tests_properties(tst_vaultview PROPERTIES
    ENVIRONMENT "QT_QPA_PLATFORM=offscreen"
)

qt_add_executable(tst_vaultinfodialog
    tst_vaultinfodialog.cpp
)

target_link_libraries(tst_vaultinfodialog PRIVATE cryptowl_ui Qt6::Test)

add_test(NAME tst_vaultinfodialog COMMAND tst_vaultinfodialog)

set_tests_properties(tst_vaultinfodialog PROPERTIES
    ENVIRONMENT "QT_QPA_PLATFORM=offscreen"
)
