# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT license.

FetchContent_Declare(
    zstd
    GIT_REPOSITORY https://github.com/facebook/zstd.git
    GIT_TAG        f8745da6ff1ad1e7bab384bd1f9d742439278e99 # 1.5.7
)
FetchContent_GetProperties(zstd)
if(NOT zstd_POPULATED)
    FetchContent_Populate(zstd)

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
    mark_as_advanced(FETCHCONTENT_SOURCE_DIR_ZSTD)
    mark_as_advanced(FETCHCONTENT_UPDATES_DISCONNECTED_ZSTD)

    add_subdirectory(
        ${zstd_SOURCE_DIR}/build/cmake
        ${zstd_SOURCE_DIR}/../zstd-build
        EXCLUDE_FROM_ALL)
endif()
