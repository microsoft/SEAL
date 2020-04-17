# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT license.

cmake_minimum_required(VERSION 3.12)

project(MSGSL_DOWNLOAD VERSION 2.1.0)

include(ExternalProject)
ExternalProject_Add(EP_MSGSL
    TMP_DIR             ${CMAKE_CURRENT_LIST_DIR}/tmp
    STAMP_DIR           ${CMAKE_CURRENT_LIST_DIR}/stamp
    DOWNLOAD_DIR        ""
    SOURCE_DIR          ${CMAKE_CURRENT_LIST_DIR}/src
    BINARY_DIR          ${CMAKE_CURRENT_LIST_DIR}/build
    GIT_REPOSITORY      https://github.com/microsoft/GSL.git
    GIT_TAG             v${PROJECT_VERSION}
    GIT_CONFIG          advice.detachedHead=false
    INSTALL_COMMAND     ""
    TEST_COMMAND        ""
)
