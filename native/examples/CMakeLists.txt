# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT license.

cmake_minimum_required(VERSION 3.10)

project(SEALExamples VERSION 3.3.1 LANGUAGES CXX)

# Executable will be in ../bin
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_SOURCE_DIR}/../bin)

add_executable(sealexamples examples.cpp)
target_sources(sealexamples
    PRIVATE
        1_bfv_basics.cpp
        2_encoders.cpp
        3_levels.cpp
        4_ckks_basics.cpp
        5_rotation.cpp
        6_performance.cpp
)

# Import Microsoft SEAL
find_package(SEAL 3.3.1 EXACT REQUIRED)

# Link Microsoft SEAL
target_link_libraries(sealexamples SEAL::seal)
