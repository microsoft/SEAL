# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT license.

cmake_minimum_required(VERSION 3.12)

project(SEALNetNative VERSION 3.4.5 LANGUAGES CXX C)

# Import Microsoft SEAL
find_package(SEAL 3.4.5 EXACT REQUIRED
    # Providing a path so this can be built without installing Microsoft SEAL
    PATHS ${SEALNetNative_SOURCE_DIR}/../../native/src/cmake
)

# Check that Microsoft SEAL is build as position-independent code
if(SEAL_LIB_BUILD_TYPE STREQUAL "Static")
    message(FATAL_ERROR "Microsoft SEAL is not built as position-independent code; please set SEAL_LIB_BUILD_TYPE to either \"Static_PIC\" or \"Shared\" and rebuild.")
endif()

# Build in Release mode by default; otherwise use selected option
set(SEALNETNATIVE_DEFAULT_BUILD_TYPE "Release")
if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE ${SEALNETNATIVE_DEFAULT_BUILD_TYPE} CACHE
        STRING "Build type" FORCE)
    set_property(CACHE CMAKE_BUILD_TYPE PROPERTY
        STRINGS "Release" "Debug" "MinSizeRel" "RelWithDebInfo")
endif()
message(STATUS "Build type (CMAKE_BUILD_TYPE): ${CMAKE_BUILD_TYPE}")

# Required files and directories
include(GNUInstallDirs)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${SEALNetNative_SOURCE_DIR}/../lib)
set(CMAKE_LIBRARY_RUNTIME_DIRECTORY ${SEALNetNative_SOURCE_DIR}/../bin)

# Check that size_t is 64 bits
include(CheckTypeSize)
check_type_size("size_t" SIZET LANGUAGE C)
if(NOT SIZET EQUAL 8)
    message(FATAL_ERROR "Detected sizeof(size_t) == ${SIZET} but ${PROJECT_NAME} requires sizeof(size_t) == 8.")
endif()

# Create library but add no source files yet
add_library(sealnetnative SHARED "")

# Set SOVERSION for shared library
set_target_properties(sealnetnative PROPERTIES
    SOVERSION ${SEALNetNative_VERSION_MAJOR}.${SEALNetNative_VERSION_MINOR}
    VERSION ${SEALNetNative_VERSION})

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

# Install the native component of the .NET wrapper library
install(TARGETS sealnetnative
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})
