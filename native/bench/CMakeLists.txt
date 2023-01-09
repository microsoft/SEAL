# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT license.

cmake_minimum_required(VERSION 3.13)

project(SEALBench VERSION 4.1.1 LANGUAGES CXX)

# If not called from root CMakeLists.txt
if(NOT DEFINED SEAL_BUILD_BENCH)
    set(SEAL_BUILD_BENCH ON)

    # Import Microsoft SEAL
    find_package(SEAL 4.1.1 EXACT REQUIRED)

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

# if SEAL_BUILD_BENCH is ON, use GoogleBenchmark
if(SEAL_BUILD_BENCH)
    if(SEAL_BUILD_DEPS)
        seal_fetch_thirdparty_content(ExternalBenchmark)
    else()
        find_package(benchmark REQUIRED)
        if(NOT benchmark_FOUND)
            message(FATAL_ERROR "GoogleBenchmark: not found")
        else()
            message(STATUS "GoogleBenchmark: found")
        endif()
    endif()

    add_executable(sealbench)
    # If we're targeting WASM, add the appropriate link flags
    if(EMSCRIPTEN)
        set_target_properties(sealbench PROPERTIES LINK_FLAGS "-flto -O3 -s WASM=1 -s ALLOW_MEMORY_GROWTH=1 -s MAXIMUM_MEMORY=4GB")
    endif()
    target_sources(sealbench
        PRIVATE
            ${CMAKE_CURRENT_LIST_DIR}/bench.cpp
            ${CMAKE_CURRENT_LIST_DIR}/keygen.cpp
            ${CMAKE_CURRENT_LIST_DIR}/ntt.cpp
            ${CMAKE_CURRENT_LIST_DIR}/bfv.cpp
            ${CMAKE_CURRENT_LIST_DIR}/bgv.cpp
            ${CMAKE_CURRENT_LIST_DIR}/ckks.cpp
    )

    if(TARGET SEAL::seal)
        target_link_libraries(sealbench PRIVATE SEAL::seal benchmark::benchmark)
    elseif(TARGET SEAL::seal_shared)
        target_link_libraries(sealbench PRIVATE SEAL::seal_shared benchmark::benchmark)
    else()
        message(FATAL_ERROR "Cannot find target SEAL::seal or SEAL::seal_shared")
    endif()
endif()
