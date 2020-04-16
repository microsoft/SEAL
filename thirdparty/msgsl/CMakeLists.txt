# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT license.

cmake_minimum_required(VERSION 3.12)

project(GSL VERSION 2.1.0 LANGUAGES CXX C)

include(ExternalProject)
ExternalProject_Add(msgsl_external
    GIT_REPOSITORY    https://github.com/microsoft/GSL.git
    GIT_TAG           v2.1.0
    SOURCE_DIR        ${CMAKE_CURRENT_LIST_DIR}/GSL-src
    CMAKE_ARGS        -DCMAKE_BUILD_TYPE=Release -DGSL_TEST=OFF -DCMAKE_TOOLCHAIN_FILE=${CMAKE_TOOLCHAIN_FILE} -DANDROID_ABI=${ANDROID_ABI} -DANDROID_NDK=${ANDROID_NDK} -DANDROID_PLATFORM=${ANDROID_PLATFORM} -DCMAKE_ANDROID_ARCH_ABI=${CMAKE_ANDROID_ARCH_ABI} -DCMAKE_ANDROID_NDK=${CMAKE_ANDROID_NDK} -DCMAKE_MAKE_PROGRAM=${CMAKE_MAKE_PROGRAM} -DCMAKE_SYSTEM_NAME=${CMAKE_SYSTEM_NAME} -DCMAKE_SYSTEM_VERSION=${CMAKE_SYSTEM_VERSION}
    INSTALL_COMMAND   ""
    TEST_COMMAND      ""
)

# Install the header files
if(SEAL_USE_MSGSL)
    install(
        DIRECTORY
            ${CMAKE_CURRENT_LIST_DIR}/GSL-src/include/gsl
        DESTINATION
            ${SEAL_INCLUDES_INSTALL_DIR}
    )
endif()

