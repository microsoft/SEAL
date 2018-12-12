# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT license.

cmake_minimum_required(VERSION 3.10)

project(SEALExamples VERSION 3.1.0 LANGUAGES CXX)

# Library will be in ../../lib
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_SOURCE_DIR}/../../lib)

# Create library but add no source files yet
add_library(sealdll SHARED "")

# Import SEAL
find_package(SEAL 3.1.0 EXACT REQUIRED)

# Link SEAL
target_link_libraries(sealdll SEAL::seal)

# Shared library needs to be relocatable
#target_compile_options(sealdll PUBLIC "-fPIC")

# Add source files to library
add_subdirectory(seal)

# Install only the shared library. This library is not meant to be
# used other than by SEALNet.
install(TARGETS sealdll
	LIBRARY DESTINATION lib)
