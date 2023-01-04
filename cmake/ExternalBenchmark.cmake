# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT license.

FetchContent_Declare(
    benchmark
    GIT_REPOSITORY https://github.com/google/benchmark.git
    GIT_TAG        d572f4777349d43653b21d6c2fc63020ab326db2 # 1.7.1
)
FetchContent_GetProperties(benchmark)

if(NOT benchmark)
    FetchContent_Populate(benchmark)

    set(LLVMAR_EXECUTABLE ${CMAKE_AR})
    set(LLVMNM_EXECUTABLE ${CMAKE_NM})
    set(LLVMRANLIB_EXECUTABLE ${CMAKE_RANLIB})
    set(LLVM_FILECHECK_EXE ${CMAKE_CXX_COMPILER_AR}/../FileCheck)
    set(BENCHMARK_ENABLE_GTEST_TESTS OFF CACHE BOOL "" FORCE)
    set(BENCHMARK_ENABLE_INSTALL OFF CACHE BOOL "" FORCE)
    set(BENCHMARK_ENABLE_TESTING OFF CACHE BOOL "" FORCE)
    set(BENCHMARK_ENABLE_LTO OFF CACHE BOOL "" FORCE)
    mark_as_advanced(LIBRT)
    mark_as_advanced(LLVM_FILECHECK_EXE)
    mark_as_advanced(BENCHMARK_BUILD_32_BITS)
    mark_as_advanced(BENCHMARK_DOWNLOAD_DEPENDENCIES)
    mark_as_advanced(BENCHMARK_ENABLE_ASSEMBLY_TESTS)
    mark_as_advanced(BENCHMARK_ENABLE_EXCEPTIONS)
    mark_as_advanced(BENCHMARK_ENABLE_GTEST_TESTS)
    mark_as_advanced(BENCHMARK_ENABLE_INSTALL)
    mark_as_advanced(BENCHMARK_ENABLE_LTO)
    mark_as_advanced(BENCHMARK_ENABLE_TESTING)
    mark_as_advanced(BENCHMARK_USE_LIBCXX)
    mark_as_advanced(FETCHCONTENT_SOURCE_DIR_BENCHMARK)
    mark_as_advanced(FETCHCONTENT_UPDATES_DISCONNECTED_BENCHMARK)

    if(NOT WIN32)
        # Google Benchmark contains unsafe conversions so force -Wno-conversion temporarily
        set(OLD_CMAKE_CXX_FLAGS ${CMAKE_CXX_FLAGS})
        set(CMAKE_CXX_FLAGS "${OLD_CMAKE_CXX_FLAGS} -Wno-conversion")
    endif()

    add_subdirectory(
        ${benchmark_SOURCE_DIR}
        ${THIRDPARTY_BINARY_DIR}/benchmark-src
        EXCLUDE_FROM_ALL)

    if(NOT WIN32)
        set(CMAKE_CXX_FLAGS ${OLD_CMAKE_CXX_FLAGS})
    endif()
endif()
