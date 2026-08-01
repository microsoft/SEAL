# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT license.

cmake_minimum_required(VERSION 3.22)

project(SEALTest VERSION 4.4.1 LANGUAGES CXX C)

# If not called from root CMakeLists.txt
if(NOT DEFINED SEAL_BUILD_TESTS)
    set(SEAL_BUILD_TESTS ON)

    # Import Microsoft SEAL
    find_package(SEAL 4.4.1 EXACT REQUIRED)

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

    # Keep the C export tests in a separate process because sealc embeds the
    # static C++ library.
    if(TARGET sealc)
        add_executable(sealctest
            ${CMAKE_CURRENT_LIST_DIR}/seal/cabi.cpp
            ${CMAKE_CURRENT_LIST_DIR}/seal/testrunner.cpp)
        target_link_libraries(sealctest PRIVATE sealc GTest::gtest)
    endif()

    # In Debug mode, enable AddressSanitizer (and LeakSanitizer) on Unix-like platforms.
    # SEAL_DEBUG is defined only for single-configuration generators (see the top-level
    # CMakeLists.txt), so multi-configuration generators such as Xcode never reach this
    # block, whichever configuration they are built with.
    if(SEAL_DEBUG AND UNIX)
        # LeakSanitizer is enabled by default alongside AddressSanitizer on Linux. It is
        # unsupported on macOS, where only AddressSanitizer is enabled.
        target_compile_options(sealtest PUBLIC -fsanitize=address)
        target_link_options(sealtest PUBLIC -fsanitize=address)
        if(TARGET sealctest)
            target_compile_options(sealctest PUBLIC -fsanitize=address)
            target_link_options(sealctest PUBLIC -fsanitize=address)
        endif()
        if(NOT APPLE)
            message(STATUS "Sanitizers enabled: address, leak")
        else()
            message(STATUS "Sanitizers enabled: address")
        endif()

        # GCC and non-Apple Clang link the AddressSanitizer runtime as a shared object by
        # default, which requires it to precede every other entry in the initial library
        # list. Link it statically instead so the test binaries carry the runtime
        # themselves and do not depend on load order or on an LD_PRELOAD at launch. Apple
        # platforms ship only a dynamic runtime, so they keep the default.
        if(NOT APPLE)
            if(CMAKE_CXX_COMPILER_ID STREQUAL "GNU")
                set(SEAL_STATIC_SANITIZER_FLAG -static-libasan)
            elseif(CMAKE_CXX_COMPILER_ID MATCHES "Clang")
                set(SEAL_STATIC_SANITIZER_FLAG -static-libsan)
            endif()

            if(DEFINED SEAL_STATIC_SANITIZER_FLAG)
                include(CheckCXXSourceCompiles)
                include(CMakePushCheckState)
                cmake_push_check_state(RESET)
                set(CMAKE_REQUIRED_QUIET TRUE)
                set(CMAKE_REQUIRED_FLAGS "-fsanitize=address")
                set(CMAKE_REQUIRED_LINK_OPTIONS ${SEAL_STATIC_SANITIZER_FLAG})
                check_cxx_source_compiles("int main() { return 0; }" SEAL_STATIC_SANITIZER_RUNTIME)
                cmake_pop_check_state()
            endif()

            if(SEAL_STATIC_SANITIZER_RUNTIME)
                target_link_options(sealtest PUBLIC ${SEAL_STATIC_SANITIZER_FLAG})
                if(TARGET sealctest)
                    target_link_options(sealctest PUBLIC ${SEAL_STATIC_SANITIZER_FLAG})
                endif()
                message(STATUS "Sanitizer runtime: static")
            else()
                message(STATUS "Sanitizer runtime: shared")
            endif()

            unset(SEAL_STATIC_SANITIZER_FLAG)
        endif()
    endif()
endif()
