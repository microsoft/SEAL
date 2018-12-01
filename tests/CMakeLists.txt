# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT license.

cmake_minimum_required(VERSION 3.10)

project(SEALTest VERSION 3.1.0 LANGUAGES CXX)

# Executable will be in ../bin
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_SOURCE_DIR}/../bin)

add_executable(sealtest seal/testrunner.cpp)

# Import SEAL
find_package(SEAL 3.1.0 EXACT REQUIRED)

if(SEAL_ENFORCE_HE_STD_SECURITY)
    message(FATAL_ERROR "SEAL is configured with SEAL_ENFORCE_HE_STD_SECURITY=ON which is incompatible with unit tests")
endif()

# Import Google target_link_libraries
find_library(GTEST gtest)
if (NOT GTEST)
    message(FATAL_ERROR "Failed to find Google Test library required for unit tests")
endif()

# Link SEAL
target_link_libraries(sealtest SEAL::seal gtest)

# Add source files
add_subdirectory(seal)
