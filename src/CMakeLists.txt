qt_add_library(cryptowl_ui STATIC
    MainWindow.h
    MainWindow.cpp
)

target_include_directories(cryptowl_ui PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(cryptowl_ui PUBLIC Qt6::Widgets)

qt_add_executable(cryptowl-desktop
    main.cpp
)

target_compile_definitions(cryptowl-desktop PRIVATE
    CRYPTOWL_VERSION="${PROJECT_VERSION}"
)

target_link_libraries(cryptowl-desktop PRIVATE cryptowl_ui)

set_target_properties(cryptowl-desktop PROPERTIES
    WIN32_EXECUTABLE TRUE
    MACOSX_BUNDLE TRUE
    MACOSX_BUNDLE_BUNDLE_NAME "CryptOwl Desktop"
    MACOSX_BUNDLE_GUI_IDENTIFIER "com.typedefai.cryptowl.desktop"
    MACOSX_BUNDLE_BUNDLE_VERSION "${PROJECT_VERSION}"
    MACOSX_BUNDLE_SHORT_VERSION_STRING "${PROJECT_VERSION}"
)

install(TARGETS cryptowl-desktop
    BUNDLE DESTINATION .
    RUNTIME DESTINATION bin
)
