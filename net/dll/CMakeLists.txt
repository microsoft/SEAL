# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT license.

cmake_minimum_required(VERSION 3.10)

project(SEALExamples VERSION 3.1.0 LANGUAGES CXX)

# Executable will be in ../lib
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_SOURCE_DIR}/../../lib)

# Create library but add no source files yet
add_library(sealdll SHARED "")

# Import SEAL
find_package(SEAL 3.1.0 EXACT REQUIRED)

# Link SEAL
target_link_libraries(sealdll SEAL::seal)

# Add source files to library
add_subdirectory(seal)

