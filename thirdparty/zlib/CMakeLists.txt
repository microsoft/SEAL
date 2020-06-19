# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT license.

cmake_minimum_required(VERSION 3.12)

project(ZLIB_DOWNLOAD VERSION 1.2.11)

if(MSVC)
    set(TEMP_BINARY_DIR ${CMAKE_CURRENT_LIST_DIR}/build/${ZLIB_PLATFORM})
else()
    set(TEMP_BINARY_DIR ${CMAKE_CURRENT_LIST_DIR}/build)
endif()

set(ZLIB_CMAKE_ARGS -DCMAKE_BUILD_TYPE=Release -DCMAKE_POSITION_INDEPENDENT_CODE=ON -DSKIP_INSTALL_ALL=ON -Wno-dev)
if(EXISTS ${CMAKE_CURRENT_LIST_DIR}/cache_init.txt)
    list(APPEND ZLIB_CMAKE_ARGS -C"${CMAKE_CURRENT_LIST_DIR}/cache_init.txt")
endif()

include(ExternalProject)
ExternalProject_Add(EP_ZLIB
    TMP_DIR             ${CMAKE_CURRENT_LIST_DIR}/tmp
    STAMP_DIR           ${CMAKE_CURRENT_LIST_DIR}/stamp
    DOWNLOAD_DIR        ""
    SOURCE_DIR          ${CMAKE_CURRENT_LIST_DIR}/src
    BINARY_DIR          ${TEMP_BINARY_DIR}
    GIT_REPOSITORY      https://github.com/madler/zlib.git
    GIT_TAG             v${PROJECT_VERSION}
    GIT_CONFIG          advice.detachedHead=false
    CMAKE_ARGS          ${ZLIB_CMAKE_ARGS}
    INSTALL_COMMAND     ""
    TEST_COMMAND        ""
)
