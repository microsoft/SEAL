# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT license.

cmake_minimum_required(VERSION 3.12)

project(ZLIB VERSION 1.2.11 LANGUAGES CXX C)

if(MSVC)
    set(ZLIB_BINARY_DIR ${CMAKE_CURRENT_LIST_DIR}/zlib-build/${ZLIB_PLATFORM})
else()
    set(ZLIB_BINARY_DIR ${CMAKE_CURRENT_LIST_DIR}/zlib-src)
endif()

include(ExternalProject)
ExternalProject_Add(zlib_external
    GIT_REPOSITORY    https://github.com/madler/zlib.git
    GIT_TAG           v1.2.11
    SOURCE_DIR        ${CMAKE_CURRENT_LIST_DIR}/zlib-src
    BINARY_DIR        ${ZLIB_BINARY_DIR}
    CMAKE_ARGS        -DCMAKE_BUILD_TYPE=Release -DCMAKE_POSITION_INDEPENDENT_CODE=ON -DSKIP_INSTALL_ALL=ON
    INSTALL_COMMAND   ""
    TEST_COMMAND      ""
)
