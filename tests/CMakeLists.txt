qt_add_executable(tst_mainwindow
    tst_mainwindow.cpp
)

target_link_libraries(tst_mainwindow PRIVATE cryptowl_ui Qt6::Test)

add_test(NAME tst_mainwindow COMMAND tst_mainwindow)

set_tests_properties(tst_mainwindow PROPERTIES
    ENVIRONMENT "QT_QPA_PLATFORM=offscreen"
)
