# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT license.

cmake_minimum_required(VERSION 3.10)

project(SEALNetNative VERSION 3.3.1 LANGUAGES CXX C)

# Library will be in ../lib
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_SOURCE_DIR}/../lib)

# Create library but add no source files yet
add_library(sealnetnative SHARED "")

# Import Microsoft SEAL
find_package(SEAL 3.3.1 EXACT REQUIRED)

# Check that Microsoft SEAL is build as position-independent code
if (SEAL_LIB_BUILD_TYPE STREQUAL "Static")
    message(FATAL_ERROR "Microsoft SEAL is not built as position-independent code; please set SEAL_LIB_BUILD_TYPE to either \"Static_PIC\" or \"Shared\" and rebuild.")
endif()

# Check that size_t is 64 bits
include(CheckTypeSize)
check_type_size("size_t" SIZET LANGUAGE C)
if(NOT SIZET EQUAL 8)
    message(FATAL_ERROR "Detected sizeof(size_t) == ${SIZET} but SEALNet requires sizeof(size_t) == 8.")
endif()

# Link Microsoft SEAL
target_link_libraries(sealnetnative SEAL::seal)

# For easier adding of CXX compiler flags
include(CheckCXXCompilerFlag)

function(enable_cxx_compiler_flag_if_supported flag)
    string(FIND "${CMAKE_CXX_FLAGS}" "${flag}" flag_already_set)
    if(flag_already_set EQUAL -1)
        message(STATUS "Adding CXX compiler flag: ${flag} ...")
        check_cxx_compiler_flag("${flag}" flag_supported)
        if(flag_supported)
            set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} ${flag}" PARENT_SCOPE)
        endif()
        unset(flag_supported CACHE)
    endif()
endfunction()

# enable_cxx_compiler_flag_if_supported("-Wall")
# enable_cxx_compiler_flag_if_supported("-Wextra")
# enable_cxx_compiler_flag_if_supported("-Wconversion")
# enable_cxx_compiler_flag_if_supported("-Wshadow")
# enable_cxx_compiler_flag_if_supported("-pedantic")

# Add source files to library
add_subdirectory(sealnet)

# Add local include directories for build
target_include_directories(sealnetnative
    PRIVATE $<BUILD_INTERFACE:${SEALNetNative_SOURCE_DIR}>)

# Install the native component of the .NET wrapper library.
install(TARGETS sealnetnative LIBRARY DESTINATION lib)
