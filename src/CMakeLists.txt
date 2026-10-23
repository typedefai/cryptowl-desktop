qt_add_library(cryptowl_ui STATIC
    MainWindow.h
    MainWindow.cpp
    RecentVaultsStore.h
    RecentVaultsStore.cpp
    UnlockVaultDialog.h
    UnlockVaultDialog.cpp
    VaultDirectory.h
    VaultUnlocker.h
    VaultUnlocker.cpp
    WelcomePage.h
    WelcomePage.cpp
)

target_include_directories(cryptowl_ui PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(cryptowl_ui PUBLIC Qt6::Widgets cryptowl_core)

qt_add_executable(cryptowl-desktop
    main.cpp
)

qt_add_resources(cryptowl-desktop "app_fonts"
    PREFIX "/fonts"
    BASE "${PROJECT_SOURCE_DIR}/assets/fonts"
    FILES
        "${PROJECT_SOURCE_DIR}/assets/fonts/selawk.ttf"
        "${PROJECT_SOURCE_DIR}/assets/fonts/selawkb.ttf"
)

target_compile_definitions(cryptowl-desktop PRIVATE
    CRYPTOWL_VERSION="${PROJECT_VERSION}"
)

target_link_libraries(cryptowl-desktop PRIVATE cryptowl_ui)

# Build a plain executable rather than a macOS .app bundle, so it can be
# launched directly from the build tree.
set_target_properties(cryptowl-desktop PROPERTIES
    WIN32_EXECUTABLE TRUE
    MACOSX_BUNDLE FALSE
)

install(TARGETS cryptowl-desktop
    RUNTIME DESTINATION bin
)
