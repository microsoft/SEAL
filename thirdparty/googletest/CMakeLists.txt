# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT license.

cmake_minimum_required(VERSION 3.12)

project(GoogleTest NONE)

include(ExternalProject)
ExternalProject_Add(googletest_external
    GIT_REPOSITORY              https://github.com/google/googletest.git
    GIT_TAG                     release-1.10.0
    SOURCE_DIR                  ${CMAKE_CURRENT_LIST_DIR}/googletest-src
    BINARY_DIR                  ${CMAKE_CURRENT_LIST_DIR}/googletest-build
    CMAKE_ARGS                  -DCMAKE_BUILD_TYPE=Release -DCMAKE_POSITION_INDEPENDENT_CODE=ON
    CONFIGURE_COMMAND           ""
    BUILD_COMMAND               ""
    INSTALL_COMMAND             ""
    TEST_COMMAND                ""
)
