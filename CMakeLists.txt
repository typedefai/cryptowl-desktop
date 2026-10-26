cmake_minimum_required(VERSION 3.24)

project(CryptOwlDesktop
    VERSION 0.1.0
    DESCRIPTION "Local-first encrypted vault — cross-platform desktop client (C++/Qt)"
    LANGUAGES C CXX
)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

include(CTest)

option(CRYPTOWL_TRACE_CRYPTO
    "Log AES-GCM flow metadata (never key material or plaintext)"
    OFF)

option(CRYPTOWL_TRACE_SECRETS
    "INSECURE: log raw keys and plaintext (requires trace; never ship)"
    OFF)

if(CRYPTOWL_TRACE_SECRETS AND NOT CRYPTOWL_TRACE_CRYPTO)
    message(FATAL_ERROR
        "CRYPTOWL_TRACE_SECRETS requires CRYPTOWL_TRACE_CRYPTO=ON")
endif()

find_package(Qt6 6.8 REQUIRED COMPONENTS Widgets)

qt_standard_project_setup()

add_subdirectory(third_party)
add_subdirectory(core)
add_subdirectory(src)

if(BUILD_TESTING)
    find_package(Qt6 REQUIRED COMPONENTS Test)
    add_subdirectory(tests)
endif()
