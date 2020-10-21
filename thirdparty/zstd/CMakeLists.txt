# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT license.

cmake_minimum_required(VERSION 3.12)

project(ZSTD_DOWNLOAD VERSION 1.4.5)

if(MSVC)
    set(TEMP_BINARY_DIR ${CMAKE_CURRENT_LIST_DIR}/build/${ZSTD_PLATFORM})
else()
    set(TEMP_BINARY_DIR ${CMAKE_CURRENT_LIST_DIR}/build)
endif()

set(ZSTD_CMAKE_ARGS
    -DCMAKE_BUILD_TYPE:STRING=Release
    -DCMAKE_POSITION_INDEPENDENT_CODE=ON
    -DBUILD_TESTING=OFF
    -DZSTD_BUILD_STATIC=ON
    -DZSTD_BUILD_SHARED=ON
    -DZSTD_BUILD_PROGRAMS=OFF
    -DZSTD_MULTITHREAD_SUPPORT=OFF
    -Wno-dev)
if(EXISTS ${CMAKE_CURRENT_LIST_DIR}/cache_init.txt)
    list(APPEND ZSTD_CMAKE_ARGS -C../cache_init.txt)
endif()

include(ExternalProject)
ExternalProject_Add(EP_ZSTD
    TMP_DIR             ${CMAKE_CURRENT_LIST_DIR}/tmp
    STAMP_DIR           ${CMAKE_CURRENT_LIST_DIR}/stamp
    DOWNLOAD_DIR        ""
    SOURCE_DIR          ${CMAKE_CURRENT_LIST_DIR}/src
    SOURCE_SUBDIR       build/cmake
    BINARY_DIR          ${TEMP_BINARY_DIR}
    GIT_REPOSITORY      https://github.com/facebook/zstd.git
    GIT_TAG             v${PROJECT_VERSION}
    GIT_CONFIG          advice.detachedHead=false
    CMAKE_ARGS          ${ZSTD_CMAKE_ARGS}
    INSTALL_COMMAND     ""
    TEST_COMMAND        ""
)
