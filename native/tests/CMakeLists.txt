# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT license.

cmake_minimum_required(VERSION 3.13)

project(SEALTest VERSION 4.1.2 LANGUAGES CXX C)

# If not called from root CMakeLists.txt
if(NOT DEFINED SEAL_BUILD_TESTS)
    set(SEAL_BUILD_TESTS ON)

    # Import Microsoft SEAL
    find_package(SEAL 4.1.2 EXACT REQUIRED)

    # Must define these variables and include macros
    set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/${OUTLIB_PATH})
    set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/bin)
    set(SEAL_THIRDPARTY_DIR ${CMAKE_CURRENT_LIST_DIR}/../../thirdparty)
    set(THIRDPARTY_BINARY_DIR ${CMAKE_CURRENT_BINARY_DIR}/thirdparty)
    include(FetchContent)
    mark_as_advanced(FETCHCONTENT_BASE_DIR)
    mark_as_advanced(FETCHCONTENT_FULLY_DISCONNECTED)
    mark_as_advanced(FETCHCONTENT_UPDATES_DISCONNECTED)
    mark_as_advanced(FETCHCONTENT_QUIET)
    list(APPEND CMAKE_MODULE_PATH ${CMAKE_CURRENT_LIST_DIR}/../../cmake)
    include(SEALMacros)
else()
    set(THIRDPARTY_BINARY_DIR ${CMAKE_CURRENT_BINARY_DIR}/../../thirdparty)
endif()

if(NOT DEFINED SEAL_BUILD_DEPS)
    # [option] SEAL_BUILD_DEPS (default: ON)
    # Download and build missing dependencies, throw error if disabled.
    set(SEAL_BUILD_DEPS_OPTION_STR "Automatically download and build unmet dependencies")
    option(SEAL_BUILD_DEPS ${SEAL_BUILD_DEPS_OPTION_STR} ON)
endif()

# if SEAL_BUILD_TESTS is ON, use GoogleTest
if(SEAL_BUILD_TESTS)
    if(SEAL_BUILD_DEPS)
        seal_fetch_thirdparty_content(ExternalGTest)
        add_library(GTest::gtest ALIAS gtest)
    else()
        find_package(GTest 1 CONFIG)
        if(NOT GTest_FOUND)
            message(FATAL_ERROR "GoogleTest: not found")
        else()
            message(STATUS "GoogleTest: found")
        endif()
    endif()

    add_executable(sealtest "")

    add_subdirectory(seal)

    if(TARGET SEAL::seal)
        target_link_libraries(sealtest PRIVATE SEAL::seal GTest::gtest)
    elseif(TARGET SEAL::seal_shared)
        target_link_libraries(sealtest PRIVATE SEAL::seal_shared GTest::gtest)
    else()
        message(FATAL_ERROR "Cannot find target SEAL::seal or SEAL::seal_shared")
    endif()

    # In Debug mode, enable AddressSanitizer (and LeakSanitizer) on Unix-like platforms.
    if(SEAL_DEBUG AND UNIX)
        # On macOS, only AddressSanitizer is enabled.
        # On Linux, LeakSanitizer is enabled by default.
        target_compile_options(sealtest PUBLIC -fsanitize=address)
        target_link_options(sealtest PUBLIC -fsanitize=address)
        if(NOT APPLE)
            message(STATUS "Sanitizers enabled: address, leak")
        else()
            message(STATUS "Sanitizers enabled: address")
        endif()
    endif()
endif()
