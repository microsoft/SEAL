# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT license.

cmake_minimum_required(VERSION 3.12)

project(MSGSL_DOWNLOAD VERSION 3.0.1)

if(MSVC)
    set(TEMP_BINARY_DIR ${CMAKE_CURRENT_LIST_DIR}/build/${MSGSL_PLATFORM})
else()
    set(TEMP_BINARY_DIR ${CMAKE_CURRENT_LIST_DIR}/build)
endif()

set(MSGSL_CMAKE_ARGS -DCMAKE_BUILD_TYPE=Release -DGSL_TEST=OFF)
if(EXISTS ${CMAKE_CURRENT_LIST_DIR}/cache_init.txt)
    list(APPEND MSGSL_CMAKE_ARGS -C"${CMAKE_CURRENT_LIST_DIR}/cache_init.txt")
endif()

include(ExternalProject)
ExternalProject_Add(EP_MSGSL
    TMP_DIR             ${CMAKE_CURRENT_LIST_DIR}/tmp
    STAMP_DIR           ${CMAKE_CURRENT_LIST_DIR}/stamp
    DOWNLOAD_DIR        ""
    SOURCE_DIR          ${CMAKE_CURRENT_LIST_DIR}/src
    BINARY_DIR          ${TEMP_BINARY_DIR}
    GIT_REPOSITORY      https://github.com/microsoft/GSL.git
    GIT_TAG             v${PROJECT_VERSION}
    GIT_CONFIG          advice.detachedHead=false
    CMAKE_ARGS          ${MSGSL_CMAKE_ARGS}
    INSTALL_COMMAND     ""
    TEST_COMMAND        ""
)
