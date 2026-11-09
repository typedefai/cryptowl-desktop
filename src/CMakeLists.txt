qt_add_library(cryptowl_ui STATIC
    CreateVaultDialog.h
    CreateVaultDialog.cpp
    DeviceSecretStore.h
    DeviceSecretStore.cpp
    EncryptedContentWidget.h
    EncryptedContentWidget.cpp
    EncryptedMediaDevice.h
    EncryptedMediaDevice.cpp
    PhotoViewDialog.h
    PhotoViewDialog.cpp
    VideoViewDialog.h
    VideoViewDialog.cpp
    MainWindow.h
    MainWindow.cpp
    MediaMountManager.h
    MediaMountManager.cpp
    NoteEditorDialog.h
    NoteEditorDialog.cpp
    PasswordEditorDialog.h
    PasswordEditorDialog.cpp
    PasswordViewDialog.h
    PasswordViewDialog.cpp
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
    vfs/FuseMount.cpp
    WelcomePage.h
    WelcomePage.cpp
)

target_include_directories(cryptowl_ui PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(cryptowl_ui PUBLIC
    Qt6::Widgets
    Qt6::Multimedia
    Qt6::MultimediaWidgets
    cryptowl_core
    PRIVATE qt6keychain
)

if(CRYPTOWL_ENABLE_FUSE)
    find_path(CRYPTOWL_FUSE_INCLUDE_DIR
        NAMES fuse3/fuse.h
        PATHS /usr/local/include /opt/homebrew/include /usr/include
    )
    find_library(CRYPTOWL_FUSE_LIBRARY
        NAMES fuse3
        PATHS /usr/local/lib /opt/homebrew/lib /usr/lib
    )
    if(CRYPTOWL_FUSE_INCLUDE_DIR AND CRYPTOWL_FUSE_LIBRARY)
        message(STATUS "FUSE3 media drive backend enabled: ${CRYPTOWL_FUSE_LIBRARY}")
        target_include_directories(cryptowl_ui PRIVATE ${CRYPTOWL_FUSE_INCLUDE_DIR})
        target_compile_definitions(cryptowl_ui PRIVATE CRYPTOWL_HAS_FUSE=1)
        target_link_libraries(cryptowl_ui PRIVATE ${CRYPTOWL_FUSE_LIBRARY})
    else()
        message(STATUS "FUSE3 not found; native media drive will be unavailable")
    endif()
endif()

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
