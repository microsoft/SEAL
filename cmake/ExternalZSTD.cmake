# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT license.

set(ZSTD_BUILD_PROGRAMS OFF CACHE BOOL "" FORCE)
set(ZSTD_BUILD_SHARED OFF CACHE BOOL "" FORCE)
set(ZLIB_BUILD_STATIC ON CACHE BOOL "" FORCE)
set(ZSTD_BUILD_TESTS OFF CACHE BOOL "" FORCE)
set(ZSTD_MULTITHREAD_SUPPORT OFF CACHE BOOL "" FORCE)
mark_as_advanced(ZSTD_BUILD_CONTRIB)
mark_as_advanced(ZSTD_BUILD_PROGRAMS)
mark_as_advanced(ZSTD_BUILD_SHARED)
mark_as_advanced(ZSTD_BUILD_STATIC)
mark_as_advanced(ZSTD_BUILD_TESTS)
mark_as_advanced(ZSTD_LEGACY_SUPPORT)
mark_as_advanced(ZSTD_MULTITHREAD_SUPPORT)
mark_as_advanced(ZSTD_PROGRAMS_LINK_SHARED)
mark_as_advanced(FETCHCONTENT_SOURCE_DIR_ZLIB)
mark_as_advanced(FETCHCONTENT_UPDATES_DISCONNECTED_ZLIB)

add_subdirectory(
    ${CMAKE_SOURCE_DIR}/thirdparty/zstd/build/cmake
    ${CMAKE_BINARY_DIR}/thirdparty/zstd
    EXCLUDE_FROM_ALL)

include_directories(${CMAKE_SOURCE_DIR}/thirdparty/zstd/lib)
include_directories(${CMAKE_SOURCE_DIR}/thirdparty/zstd/lib/common)
include_directories(${CMAKE_SOURCE_DIR}/thirdparty/zstd/lib/compress)
include_directories(${CMAKE_SOURCE_DIR}/thirdparty/zstd/lib/decompress)
include_directories(${CMAKE_SOURCE_DIR}/thirdparty/zstd/lib/deprecated)
include_directories(${CMAKE_SOURCE_DIR}/thirdparty/zstd/lib/dictBuilder)
include_directories(${CMAKE_SOURCE_DIR}/thirdparty/zstd/lib/dll)
include_directories(${CMAKE_SOURCE_DIR}/thirdparty/zstd/lib/legacy)
