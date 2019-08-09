# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT license.

cmake_minimum_required(VERSION 3.10)

project(SEALTest LANGUAGES CXX)

# Executable will be in ../bin
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_SOURCE_DIR}/../bin)

add_executable(sealtest seal/testrunner.cpp)

# Import Microsoft SEAL
find_package(SEAL 3.3.1 EXACT REQUIRED)

# Add source files
add_subdirectory(seal)

# Only build GTest
option(BUILD_GMOCK OFF)
option(INSTALL_GTEST OFF)
mark_as_advanced(BUILD_GMOCK INSTALL_GTEST)

# Add GTest
set(GTEST_DIR "thirdparty/googletest")
if(NOT EXISTS ${GTEST_DIR}/CMakeLists.txt)
    message(FATAL_ERROR "Could not find `${GTEST_DIR}/CMakeLists.txt`. Run `git submodule update --init` and retry.")
endif()
add_subdirectory(${GTEST_DIR})

# Link Microsoft SEAL and GTest
target_link_libraries(sealtest SEAL::seal gtest)
