# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT license.

cmake_minimum_required(VERSION 3.12)

project(SEALBench VERSION 3.6.1 LANGUAGES CXX)

find_package(SEAL 3.6.1 EXACT REQUIRED)
find_package(benchmark REQUIRED)

set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/bin)

add_executable(sealbench)

set(CMAKE_BUILD_TYPE "Debug")

target_sources(sealbench
    PRIVATE
        ${CMAKE_CURRENT_LIST_DIR}/bench.cpp
        ${CMAKE_CURRENT_LIST_DIR}/keygen.cpp
        ${CMAKE_CURRENT_LIST_DIR}/bfv.cpp
        ${CMAKE_CURRENT_LIST_DIR}/ckks.cpp
##        ${CMAKE_CURRENT_LIST_DIR}/util.cpp
)

if(TARGET SEAL::seal)
    target_link_libraries(sealbench PRIVATE SEAL::seal)
elseif(TARGET SEAL::seal_shared)
    target_link_libraries(sealbench PRIVATE SEAL::seal_shared)
else()
    message(FATAL_ERROR "Cannot find target SEAL::seal or SEAL::seal_shared")
endif()

target_link_libraries(sealbench PRIVATE benchmark::benchmark)
