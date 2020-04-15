# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT license.

cmake_minimum_required(VERSION 3.12)

project(GSL VERSION 2.1.0 LANGUAGES CXX C)

include(ExternalProject)
ExternalProject_Add(msgsl_external
    GIT_REPOSITORY    https://github.com/microsoft/GSL.git
    GIT_TAG           v2.1.0
    SOURCE_DIR        ${CMAKE_CURRENT_LIST_DIR}/GSL-src
    CMAKE_ARGS        -DCMAKE_BUILD_TYPE=Release -DGSL_TEST=OFF
    INSTALL_COMMAND   ""
    TEST_COMMAND      ""
)
