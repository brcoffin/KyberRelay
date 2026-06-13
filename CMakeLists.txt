cmake_minimum_required(VERSION 3.16)
project(kyber-zip C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

# Unify the C runtime across every target on the static CRT (/MT). The bundled
# prebuilt libsodium is built /MT, so the rest of the project (raylib, liboqs,
# curl, our code) must match — otherwise the process ends up with two CRT
# instances and split FILE*/errno state, which breaks fopen() in some targets.
if(MSVC)
    set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")
endif()

# Build type
if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Release)
endif()

# Options
option(KYBER_BUILD_GUI "Build with GUI support (raylib + raygui)" ON)
option(KYBER_BUILD_CLI "Build CLI executable" ON)
option(KYBER_BUILD_TESTS "Build test utilities" OFF)

# --------------------------------------------------------------------------
# Dependencies
# --------------------------------------------------------------------------

# liboqs (ML-KEM)
find_package(liboqs QUIET)
if(NOT liboqs_FOUND)
    include(FetchContent)
    FetchContent_Declare(
        liboqs
        GIT_REPOSITORY https://github.com/open-quantum-safe/liboqs.git
        GIT_TAG        main
    )
    set(OQS_BUILD_ONLY_LIB ON CACHE BOOL "" FORCE)
    set(OQS_MINIMAL_BUILD "KEM_ml_kem" CACHE STRING "" FORCE)
    FetchContent_MakeAvailable(liboqs)
endif()

# libsodium (AES-256-GCM, BLAKE2b KDF, secure memory)
find_package(PkgConfig QUIET)
if(PkgConfig_FOUND)
    pkg_check_modules(SODIUM IMPORTED_TARGET libsodium)
endif()
if(NOT SODIUM_FOUND)
    # Check for local prebuilt libsodium (MSVC)
    if(EXISTS "${CMAKE_SOURCE_DIR}/lib/libsodium-msvc/libsodium/include/sodium.h")
        set(SODIUM_INCLUDE_DIR "${CMAKE_SOURCE_DIR}/lib/libsodium-msvc/libsodium/include")
        # Try v142 (VS2019) first, then v143 (VS2022)
        if(EXISTS "${CMAKE_SOURCE_DIR}/lib/libsodium-msvc/libsodium/x64/Release/v142/static/libsodium.lib")
            set(SODIUM_LIBRARY "${CMAKE_SOURCE_DIR}/lib/libsodium-msvc/libsodium/x64/Release/v142/static/libsodium.lib")
        elseif(EXISTS "${CMAKE_SOURCE_DIR}/lib/libsodium-msvc/libsodium/x64/Release/v143/static/libsodium.lib")
            set(SODIUM_LIBRARY "${CMAKE_SOURCE_DIR}/lib/libsodium-msvc/libsodium/x64/Release/v143/static/libsodium.lib")
        endif()
        message(STATUS "Using local libsodium: ${SODIUM_LIBRARY}")
    else()
        find_path(SODIUM_INCLUDE_DIR sodium.h)
        find_library(SODIUM_LIBRARY NAMES sodium libsodium)
    endif()
    if(NOT SODIUM_INCLUDE_DIR OR NOT SODIUM_LIBRARY)
        message(FATAL_ERROR "libsodium not found. Install it or set SODIUM_INCLUDE_DIR and SODIUM_LIBRARY.")
    endif()
endif()

# libcurl (secure-transfer client) — static, HTTP(S) only.
# On Windows we use the native Schannel TLS backend so there is no OpenSSL
# dependency; elsewhere curl falls back to its default backend.
find_package(CURL QUIET)
if(NOT CURL_FOUND)
    include(FetchContent)
    set(BUILD_CURL_EXE     OFF CACHE BOOL "" FORCE)
    set(BUILD_SHARED_LIBS  OFF CACHE BOOL "" FORCE)
    set(CURL_STATICLIB     ON  CACHE BOOL "" FORCE)
    set(CURL_STATIC_CRT    ON  CACHE BOOL "" FORCE)  # match the project's /MT runtime
    set(HTTP_ONLY          ON  CACHE BOOL "" FORCE)
    set(CURL_ENABLE_SSL    ON  CACHE BOOL "" FORCE)
    set(CURL_USE_LIBPSL    OFF CACHE BOOL "" FORCE)
    set(USE_LIBIDN2        OFF CACHE BOOL "" FORCE)
    set(CURL_USE_LIBSSH2   OFF CACHE BOOL "" FORCE)
    set(CURL_DISABLE_INSTALL ON CACHE BOOL "" FORCE)
    set(BUILD_TESTING      OFF CACHE BOOL "" FORCE)
    if(WIN32)
        set(CURL_USE_SCHANNEL ON CACHE BOOL "" FORCE)
    endif()
    FetchContent_Declare(
        curl
        GIT_REPOSITORY https://github.com/curl/curl.git
        GIT_TAG        curl-8_11_1
    )
    FetchContent_MakeAvailable(curl)
endif()

# miniz (compression) - single file, bundled
if(NOT EXISTS "${CMAKE_SOURCE_DIR}/lib/miniz.c")
    message(STATUS "Downloading miniz...")
    file(DOWNLOAD
        "https://raw.githubusercontent.com/richgel999/miniz/master/miniz.c"
        "${CMAKE_SOURCE_DIR}/lib/miniz.c"
    )
    file(DOWNLOAD
        "https://raw.githubusercontent.com/richgel999/miniz/master/miniz.h"
        "${CMAKE_SOURCE_DIR}/lib/miniz.h"
    )
endif()

# raylib (GUI)
if(KYBER_BUILD_GUI)
    find_package(raylib QUIET)
    if(NOT raylib_FOUND)
        include(FetchContent)
        FetchContent_Declare(
            raylib
            GIT_REPOSITORY https://github.com/raysan5/raylib.git
            GIT_TAG        5.0
        )
        set(BUILD_EXAMPLES OFF CACHE BOOL "" FORCE)
        FetchContent_MakeAvailable(raylib)
    endif()

    # raygui - header-only
    if(NOT EXISTS "${CMAKE_SOURCE_DIR}/lib/raygui.h")
        message(STATUS "Downloading raygui...")
        file(DOWNLOAD
            "https://raw.githubusercontent.com/raysan5/raygui/master/src/raygui.h"
            "${CMAKE_SOURCE_DIR}/lib/raygui.h"
        )
    endif()

    # tinyfiledialogs - single file, native Open/Save dialogs
    if(NOT EXISTS "${CMAKE_SOURCE_DIR}/lib/tinyfiledialogs.c")
        message(STATUS "Downloading tinyfiledialogs...")
        file(DOWNLOAD
            "https://raw.githubusercontent.com/nicbarker/tinyfiledialogs/main/tinyfiledialogs.c"
            "${CMAKE_SOURCE_DIR}/lib/tinyfiledialogs.c"
        )
        file(DOWNLOAD
            "https://raw.githubusercontent.com/nicbarker/tinyfiledialogs/main/tinyfiledialogs.h"
            "${CMAKE_SOURCE_DIR}/lib/tinyfiledialogs.h"
        )
    endif()
endif()

# --------------------------------------------------------------------------
# Core library (shared between CLI and GUI)
# --------------------------------------------------------------------------

set(CORE_SOURCES
    src/crypto.c
    src/compress.c
    src/archive.c
    src/keystore.c
    src/transfer.c
    lib/miniz.c
)

add_library(kyber_core STATIC ${CORE_SOURCES})
target_include_directories(kyber_core PUBLIC
    ${CMAKE_SOURCE_DIR}/include
    ${CMAKE_SOURCE_DIR}/lib
)
target_compile_definitions(kyber_core PUBLIC SODIUM_STATIC)
# CURL_STATICLIB tells curl/curl.h we link the static library (no dllimport).
target_compile_definitions(kyber_core PUBLIC CURL_STATICLIB)
if(SODIUM_FOUND AND TARGET PkgConfig::SODIUM)
    target_link_libraries(kyber_core PUBLIC oqs PkgConfig::SODIUM CURL::libcurl)
else()
    target_include_directories(kyber_core PUBLIC ${SODIUM_INCLUDE_DIR})
    target_link_libraries(kyber_core PUBLIC oqs ${SODIUM_LIBRARY} advapi32 CURL::libcurl)
endif()

# --------------------------------------------------------------------------
# CLI executable
# --------------------------------------------------------------------------

if(KYBER_BUILD_CLI)
    add_executable(kyber-cli
        src/main.c
        src/cli.c
    )
    target_link_libraries(kyber-cli PRIVATE kyber_core)
    target_compile_definitions(kyber-cli PRIVATE KYBER_CLI_MODE)
endif()

# --------------------------------------------------------------------------
# GUI executable
# --------------------------------------------------------------------------

if(KYBER_BUILD_GUI)
    add_executable(kyber-gui
        src/main.c
        src/gui.c
        lib/tinyfiledialogs.c
    )
    target_link_libraries(kyber-gui PRIVATE kyber_core raylib)
    target_compile_definitions(kyber-gui PRIVATE KYBER_GUI_MODE)
    target_include_directories(kyber-gui PRIVATE ${CMAKE_SOURCE_DIR}/lib)

    # Windows: use WinMain entry point to hide console
    if(WIN32)
        target_link_options(kyber-gui PRIVATE "/ENTRY:mainCRTStartup" "/SUBSYSTEM:WINDOWS")
    endif()
endif()

# --------------------------------------------------------------------------
# Tests
# --------------------------------------------------------------------------

if(KYBER_BUILD_TESTS)
    add_executable(transfer_selftest tests/transfer_selftest.c)
    target_link_libraries(transfer_selftest PRIVATE kyber_core)
endif()

# --------------------------------------------------------------------------
# Install
# --------------------------------------------------------------------------

install(TARGETS kyber-cli kyber-gui
    RUNTIME DESTINATION bin
)
