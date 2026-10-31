qt_add_library(cryptowl_ui STATIC
    CreateVaultDialog.h
    CreateVaultDialog.cpp
    DeviceSecretStore.h
    DeviceSecretStore.cpp
    EncryptedContentWidget.h
    EncryptedContentWidget.cpp
    MainWindow.h
    MainWindow.cpp
    NoteEditorDialog.h
    NoteEditorDialog.cpp
    PasswordEditorDialog.h
    PasswordEditorDialog.cpp
    RecentVaultsStore.h
    RecentVaultsStore.cpp
    SecretAccessDialog.h
    SecretAccessDialog.cpp
    TopSecretService.h
    TopSecretService.cpp
    TopSecretDialog.h
    TopSecretDialog.cpp
    UnlockVaultDialog.h
    UnlockVaultDialog.cpp
    VaultCreator.h
    VaultCreator.cpp
    VaultDirectory.h
    VaultInfoDialog.h
    VaultInfoDialog.cpp
    VaultPathDialog.h
    VaultPathDialog.cpp
    VaultUnlocker.h
    VaultUnlocker.cpp
    VaultView.h
    VaultView.cpp
    WelcomePage.h
    WelcomePage.cpp
)

target_include_directories(cryptowl_ui PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(cryptowl_ui PUBLIC Qt6::Widgets cryptowl_core PRIVATE qt6keychain)

qt_add_executable(cryptowl
    main.cpp
)

qt_add_resources(cryptowl "app_fonts"
    PREFIX "/fonts"
    BASE "${PROJECT_SOURCE_DIR}/assets/fonts"
    FILES
        "${PROJECT_SOURCE_DIR}/assets/fonts/selawk.ttf"
        "${PROJECT_SOURCE_DIR}/assets/fonts/selawkb.ttf"
)

target_compile_definitions(cryptowl PRIVATE
    CRYPTOWL_VERSION="${PROJECT_VERSION}"
)

target_link_libraries(cryptowl PRIVATE cryptowl_ui)

# Build a plain executable rather than a macOS .app bundle, so it can be
# launched directly from the build tree.
set_target_properties(cryptowl PROPERTIES
    WIN32_EXECUTABLE TRUE
    MACOSX_BUNDLE FALSE
)

install(TARGETS cryptowl
    RUNTIME DESTINATION bin
)
