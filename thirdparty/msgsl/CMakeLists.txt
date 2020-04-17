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
    CMAKE_ARGS          -DCMAKE_BUILD_TYPE=Release -DGSL_TEST=OFF
    INSTALL_COMMAND     ""
    TEST_COMMAND        ""
)

#  -DCMAKE_TOOLCHAIN_FILE=${CMAKE_TOOLCHAIN_FILE} -DANDROID_ABI=${ANDROID_ABI} -DANDROID_NDK=${ANDROID_NDK} -DANDROID_PLATFORM=${ANDROID_PLATFORM} -DCMAKE_ANDROID_ARCH_ABI=${CMAKE_ANDROID_ARCH_ABI} -DCMAKE_ANDROID_NDK=${CMAKE_ANDROID_NDK} -DCMAKE_MAKE_PROGRAM=${CMAKE_MAKE_PROGRAM} -DCMAKE_SYSTEM_NAME=${CMAKE_SYSTEM_NAME} -DCMAKE_SYSTEM_VERSION=${CMAKE_SYSTEM_VERSION}
