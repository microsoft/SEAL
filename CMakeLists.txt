# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT license.

cmake_minimum_required(VERSION 3.12)

###################################################
# Project SEAL includes the following components: #
#   1. SEAL C++ library                           #
#   2. SEAL C export library                      #
#   3. SEAL C++ examples                          #
#   4. SEAL C++ tests                             #
###################################################

project(SEAL VERSION 3.6.0 LANGUAGES CXX C)

# Check operating system: for Windows, use Visual Studio solution/project files.
if(MSVC)
    if(ALLOW_COMMAND_LINE_BUILD)
        message(STATUS "Configuring for Visual Studio")
    else()
        message(FATAL_ERROR "Please build Microsoft SEAL using the attached Visual Studio solution/project files")
    endif()
endif()

########################
# Global configuration #
########################

# CMake modules
include(CMakeDependentOption)
include(CMakePushCheckState)
include(CheckIncludeFiles)
include(CheckCXXSourceCompiles)
include(CheckCXXSourceRuns)
include(CheckTypeSize)
include (CheckSymbolExists)
# Extra modules
list(APPEND CMAKE_MODULE_PATH ${SEAL_SOURCE_DIR}/cmake)

# Always build position-independent-code
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

# Make the install target depend on the all target (required by vcpkg)
set(CMAKE_SKIP_INSTALL_ALL_DEPENDENCY OFF)

# [option] CMAKE_BUILD_TYPE (default: "Release")
# Build in one of the following modes: Release, Debug, MiniSizeRel, or RelWithDebInfo.
if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE "Release" CACHE STRING "Build type" FORCE)
    set_property(CACHE CMAKE_BUILD_TYPE PROPERTY
        STRINGS "Release" "Debug" "MinSizeRel" "RelWithDebInfo")
endif()
message(STATUS "Build type (CMAKE_BUILD_TYPE): ${CMAKE_BUILD_TYPE}")

# In Debug mode, define SEAL_DEBUG
if(CMAKE_BUILD_TYPE STREQUAL "Debug")
    set(SEAL_DEBUG ON)
    # In Debug mode, enable extra compiler flags.
    include(EnableCXXCompilerFlags)
else()
    set(SEAL_DEBUG OFF)
endif()
message(STATUS "Microsoft SEAL debug mode: ${SEAL_DEBUG}")

# [option] SEAL_USE_CXX17 (default: ON)
# Use C++17, use C++14 otherwise.
set(SEAL_USE_CXX17_OPTION_STR "Use C++17")
option(SEAL_USE_CXX17 ${SEAL_USE_CXX17_OPTION_STR} ON)
# Enable features from C++17 if available, disable features if set to OFF.
include(EnableCXX17)

# Path for outupt
if(ANDROID_ABI)
    # Android compiles several targets at the same time. Need to specify
    # separate directories for separate ABIs.
    set(OUTLIB_PATH "lib/${ANDROID_ABI}")
else()
    set(OUTLIB_PATH "lib")
endif()

# Required files and directories
include(GNUInstallDirs)
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${SEAL_SOURCE_DIR}/${OUTLIB_PATH})
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${SEAL_SOURCE_DIR}/${OUTLIB_PATH})
set(CMAKE_LIBRARY_RUNTIME_DIRECTORY ${SEAL_SOURCE_DIR}/bin)
set(SEAL_TARGETS_FILENAME ${SEAL_SOURCE_DIR}/cmake/SEALTargets.cmake)
set(SEAL_CONFIG_IN_FILENAME ${SEAL_SOURCE_DIR}/cmake/SEALConfig.cmake.in)
set(SEAL_CONFIG_FILENAME ${SEAL_SOURCE_DIR}/cmake/SEALConfig.cmake)
set(SEAL_PKGCONFIG_IN_FILENAME ${SEAL_SOURCE_DIR}/pkgconfig/seal.pc.in)
set(SEAL_PKGCONFIG_FILENAME ${SEAL_SOURCE_DIR}/pkgconfig/seal-${SEAL_VERSION_MAJOR}.${SEAL_VERSION_MINOR}.pc)
set(SEAL_CONFIG_VERSION_FILENAME ${SEAL_SOURCE_DIR}/cmake/SEALConfigVersion.cmake)
set(SEAL_CONFIG_INSTALL_DIR ${CMAKE_INSTALL_LIBDIR}/cmake/SEAL-${SEAL_VERSION_MAJOR}.${SEAL_VERSION_MINOR})
set(SEAL_PKGCONFIG_INSTALL_DIR ${CMAKE_INSTALL_LIBDIR}/pkgconfig)
set(SEAL_INCLUDES_INSTALL_DIR ${CMAKE_INSTALL_INCLUDEDIR}/SEAL-${SEAL_VERSION_MAJOR}.${SEAL_VERSION_MINOR})
set(SEAL_INCLUDES_BUILD_DIR ${SEAL_SOURCE_DIR}/native/src)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${SEAL_SOURCE_DIR}/bin)
set(SEAL_THIRDPARTY_DIR ${SEAL_SOURCE_DIR}/thirdparty)

# Cleaning up artifacts from previous versions
include(CleanArtifacts)

##################################
# Macros for configuring targets #
##################################

# Set the C++ language version
macro(seal_set_language target)
    if(SEAL_USE_CXX17)
        target_compile_features(${target} PUBLIC cxx_std_17)
    else()
        target_compile_features(${target} PUBLIC cxx_std_14)
    endif()
endmacro()

# Set the VERSION property
macro(seal_set_version target)
    set_target_properties(${target} PROPERTIES VERSION ${SEAL_VERSION})
endmacro()

# Set the library filename to reflect version
macro(seal_set_version_filename target)
    set_target_properties(${target} PROPERTIES
        OUTPUT_NAME ${target}-${SEAL_VERSION_MAJOR}.${SEAL_VERSION_MINOR})
endmacro()

# Set the SOVERSION property
macro(seal_set_soversion target)
    set_target_properties(${target} PROPERTIES
        SOVERSION ${SEAL_VERSION_MAJOR}.${SEAL_VERSION_MINOR})
endmacro()

# Set include directories for build and install interfaces
macro(seal_set_include_directories target)
    target_include_directories(${target} PUBLIC
        $<BUILD_INTERFACE:${SEAL_INCLUDES_BUILD_DIR}>
        $<INSTALL_INTERFACE:${SEAL_INCLUDES_INSTALL_DIR}>)
endmacro()

# Link a thread library
macro(seal_link_threads target)
    # Require thread library
    if(NOT TARGET Threads::Threads)
        set(CMAKE_THREAD_PREFER_PTHREAD TRUE)
        set(THREADS_PREFER_PTHREAD_FLAG TRUE)
        find_package(Threads REQUIRED)
    endif()

    # Link Threads
    target_link_libraries(${target} PUBLIC Threads::Threads)
endmacro()

# Include target to given export
macro(seal_install_target target export)
    install(TARGETS ${target} EXPORT ${export}
        ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
        LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
        RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})
endmacro()

# Manually combine archives, using ${CMAKE_LIBRARY_OUTPUT_DIRECTORY} to keep temporary files.
macro(seal_combine_archives target dependency)
    if(CMAKE_HOST_WIN32)
        get_filename_component(CXX_DIR "${CMAKE_CXX_COMPILER}" DIRECTORY)
        set(AR_CMD_PATH "${CXX_DIR}/llvm-ar.exe")
        file(TO_NATIVE_PATH "${AR_CMD_PATH}" AR_CMD_PATH)
        set(DEL_CMD "del")
        set(DEL_CMD_OPTS "")
    else()
        set(AR_CMD_PATH "ar")
        set(DEL_CMD "rm")
        set(DEL_CMD_OPTS "-rf")
    endif()
    add_custom_command(TARGET ${target} POST_BUILD
        COMMAND "${AR_CMD_PATH}" x $<TARGET_FILE:${target}>
        COMMAND "${AR_CMD_PATH}" x $<TARGET_FILE:${dependency}>
        COMMAND "${AR_CMD_PATH}" rcs $<TARGET_FILE:${target}> *.o
        COMMAND ${DEL_CMD} ${DEL_CMD_OPTS} *.o
        WORKING_DIRECTORY ${CMAKE_LIBRARY_OUTPUT_DIRECTORY})
endmacro()

#########################
# External dependencies #
#########################

function(seal_create_cache_entries dir_name)
    set(cce_file_name ${dir_name}/cache_init.txt)
    file(WRITE  "${cce_file_name}" "set(CMAKE_C_COMPILER \"${CMAKE_C_COMPILER}\" CACHE STRING \"\" FORCE)\n")
    file(APPEND "${cce_file_name}" "set(CMAKE_CXX_COMPILER \"${CMAKE_CXX_COMPILER}\" CACHE STRING \"\" FORCE)\n")
    file(APPEND "${cce_file_name}" "set(CMAKE_TOOLCHAIN_FILE \"${CMAKE_TOOLCHAIN_FILE}\" CACHE FILEPATH \"\" FORCE)\n")
    file(APPEND "${cce_file_name}" "set(ANDROID_ABI ${ANDROID_ABI} CACHE STRING \"\" FORCE)\n")
    file(APPEND "${cce_file_name}" "set(ANDROID_NDK \"${ANDROID_NDK}\" CACHE FILEPATH \"\" FORCE)\n")
    file(APPEND "${cce_file_name}" "set(ANDROID_PLATFORM ${ANDROID_PLATFORM} CACHE STRING \"\" FORCE)\n")
    file(APPEND "${cce_file_name}" "set(CMAKE_ANDROID_ARCH_ABI ${CMAKE_ANDROID_ARCH_ABI} CACHE STRING \"\" FORCE)\n")
    file(APPEND "${cce_file_name}" "set(CMAKE_ANDROID_NDK \"${CMAKE_ANDROID_NDK}\" CACHE STRING \"\" FORCE)\n")
    file(APPEND "${cce_file_name}" "set(CMAKE_MAKE_PROGRAM \"${CMAKE_MAKE_PROGRAM}\" CACHE STRING \"\" FORCE)\n")
    file(APPEND "${cce_file_name}" "set(CMAKE_SYSTEM_NAME ${CMAKE_SYSTEM_NAME} CACHE STRING \"\" FORCE)\n")
    file(APPEND "${cce_file_name}" "set(CMAKE_SYSTEM_VERSION ${CMAKE_SYSTEM_VERSION} CACHE STRING \"\" FORCE)\n")
endfunction()

# [option] SEAL_USE_MSGSL
set(SEAL_USE_MSGSL_OPTION_STR "Use Microsoft GSL")
option(SEAL_USE_MSGSL ${SEAL_USE_MSGSL_OPTION_STR} ON)

# Download and configure
if(SEAL_USE_MSGSL AND NOT MSVC)
    message(STATUS "Setting up MSGSL ...")
    if(NOT CMAKE_TOOLCHAIN_FILE)
        execute_process(
            COMMAND ${CMAKE_COMMAND} -G "${CMAKE_GENERATOR}" .
            OUTPUT_QUIET
            RESULT_VARIABLE result
            WORKING_DIRECTORY ${SEAL_THIRDPARTY_DIR}/msgsl)
    else()
        seal_create_cache_entries(${SEAL_THIRDPARTY_DIR}/msgsl)
        if(EXISTS ${SEAL_THIRDPARTY_DIR}/msgsl/CMakeCache.txt)
            # Force regenerating make files. When cross compiling we might be
            # compiling more than one platform at a time.
            file(REMOVE ${SEAL_THIRDPARTY_DIR}/msgsl/CMakeCache.txt)
        endif()
        execute_process(
            COMMAND ${CMAKE_COMMAND} -G "${CMAKE_GENERATOR}" . -Ccache_init.txt
            OUTPUT_QUIET
            RESULT_VARIABLE result
            WORKING_DIRECTORY ${SEAL_THIRDPARTY_DIR}/msgsl)
    endif()
    if(result)
        message(WARNING "Failed to download MSGSL (${result}); disabling `SEAL_USE_MSGSL`")
    endif()
endif()

# Build
if(SEAL_USE_MSGSL AND NOT MSVC)
    execute_process(
        COMMAND ${CMAKE_COMMAND} --build .
        OUTPUT_QUIET
        RESULT_VARIABLE result
        WORKING_DIRECTORY ${SEAL_THIRDPARTY_DIR}/msgsl)
    if(result)
        message(WARNING "Failed to build MSGSL (${result}); disabling `SEAL_USE_MSGSL`")
    endif()
    set(GSL_CXX_STANDARD "14" CACHE STRING "" FORCE)
    mark_as_advanced(GSL_CXX_STANDARD )
    set(GSL_TEST OFF CACHE BOOL "" FORCE)
    mark_as_advanced(GSL_TEST)
endif()

# Set up the targets
if(SEAL_USE_MSGSL AND NOT MSVC)
    add_subdirectory(
        ${SEAL_THIRDPARTY_DIR}/msgsl/src
        EXCLUDE_FROM_ALL)
    set(SEAL_MSGSL_INCLUDE_DIR ${SEAL_THIRDPARTY_DIR}/msgsl/src/include)
endif()

# [option] SEAL_USE_ZLIB
set(SEAL_USE_ZLIB_OPTION_STR "Use ZLIB for compressed serialization")
option(SEAL_USE_ZLIB ${SEAL_USE_ZLIB_OPTION_STR} ON)

# ZLIB has no VERSION given to project(), needs to suppress CMP0048 warning
if(SEAL_USE_ZLIB AND NOT MSVC)
    set(CMAKE_SUPPRESS_DEVELOPER_WARNINGS TRUE CACHE INTERNAL "Suppress CMP0048 warning" FORCE)
endif()

# Download and configure
if(SEAL_USE_ZLIB AND NOT MSVC)
    message(STATUS "Setting up ZLIB ...")
    if(NOT CMAKE_TOOLCHAIN_FILE)
        execute_process(
            COMMAND ${CMAKE_COMMAND} -G "${CMAKE_GENERATOR}" .
            OUTPUT_QUIET
            RESULT_VARIABLE result
            WORKING_DIRECTORY ${SEAL_THIRDPARTY_DIR}/zlib)
    else()
        seal_create_cache_entries(${SEAL_THIRDPARTY_DIR}/zlib)
        if(EXISTS ${SEAL_THIRDPARTY_DIR}/zlib/build/CMakeCache.txt)
            # Force regenerating make files. When cross compiling we might be
            # compiling more than one platform at a time.
            file(REMOVE ${SEAL_THIRDPARTY_DIR}/zlib/build/CMakeCache.txt)
        endif()
        execute_process(
            COMMAND ${CMAKE_COMMAND} -G "${CMAKE_GENERATOR}" . -Ccache_init.txt
            OUTPUT_QUIET
            RESULT_VARIABLE result
            WORKING_DIRECTORY ${SEAL_THIRDPARTY_DIR}/zlib)
    endif()
    if(result)
        message(WARNING "Failed to download ZLIB (${result}); disabling `SEAL_USE_ZLIB`")
    endif()
    mark_as_advanced(AMD64)
    mark_as_advanced(ASM686)
    mark_as_advanced(EXECUTABLE_OUTPUT_PATH)
    mark_as_advanced(CMAKE_INSTALL_PREFIX)
    mark_as_advanced(INSTALL_BIN_DIR)
    mark_as_advanced(INSTALL_INC_DIR)
    mark_as_advanced(INSTALL_LIB_DIR)
    mark_as_advanced(INSTALL_MAN_DIR)
    mark_as_advanced(INSTALL_PKGCONFIG_DIR)
    mark_as_advanced(LIBRARY_OUTPUT_PATH)
    mark_as_advanced(CMAKE_BACKWARDS_COMPATIBILITY)
endif()

# Build
if(SEAL_USE_ZLIB AND NOT MSVC)
    execute_process(COMMAND ${CMAKE_COMMAND} --build .
        OUTPUT_QUIET
        RESULT_VARIABLE result
        WORKING_DIRECTORY ${SEAL_THIRDPARTY_DIR}/zlib)
    if(result)
        message(WARNING "Failed to build ZLIB (${result}); disabling `SEAL_USE_ZLIB`")
    endif()
endif()

# Set up the targets
if(SEAL_USE_ZLIB AND NOT MSVC)
    add_subdirectory(
        ${SEAL_THIRDPARTY_DIR}/zlib/src
        EXCLUDE_FROM_ALL)

    # Set the ZLIB include directories; we have to include also ZLIB binary directory because
    # ZLIB creates a file zconf.h into it, which must be visible to the compiler.
    set(SEAL_ZLIB_INCLUDE_DIRS
        ${CMAKE_CURRENT_BINARY_DIR}/thirdparty/zlib/src
        ${SEAL_THIRDPARTY_DIR}/zlib/src)
    set_target_properties(zlibstatic PROPERTIES
        INTERFACE_INCLUDE_DIRECTORIES "${SEAL_ZLIB_INCLUDE_DIRS}")
endif()

# [option] SEAL_USE_ZSTD
set(SEAL_USE_ZSTD_OPTION_STR "Use Zstandard for compressed serialization")
option(SEAL_USE_ZSTD ${SEAL_USE_ZSTD_OPTION_STR} ON)

# Download and configure
if(SEAL_USE_ZSTD AND NOT MSVC)
    message(STATUS "Setting up Zstandard ...")
    if(NOT CMAKE_TOOLCHAIN_FILE)
        execute_process(
            COMMAND ${CMAKE_COMMAND} -G "${CMAKE_GENERATOR}" .
            OUTPUT_QUIET
            RESULT_VARIABLE result
            WORKING_DIRECTORY ${SEAL_THIRDPARTY_DIR}/zstd)
    else()
        seal_create_cache_entries(${SEAL_THIRDPARTY_DIR}/zstd)
        if(EXISTS ${SEAL_THIRDPARTY_DIR}/zstd/build/CMakeCache.txt)
            # Force regenerating make files. When cross compiling we might be
            # compiling more than one platform at a time.
            file(REMOVE ${SEAL_THIRDPARTY_DIR}/zstd/build/CMakeCache.txt)
        endif()
        execute_process(
            COMMAND ${CMAKE_COMMAND} -G "${CMAKE_GENERATOR}" . -Ccache_init.txt
            OUTPUT_QUIET
            RESULT_VARIABLE result
            WORKING_DIRECTORY ${SEAL_THIRDPARTY_DIR}/zstd)
    endif()
    if(result)
        message(WARNING "Failed to download ZSTD (${result}); disabling `SEAL_USE_ZSTD`")
    endif()
endif()

# Build
if(SEAL_USE_ZSTD AND NOT MSVC)
    execute_process(COMMAND ${CMAKE_COMMAND} --build .
        OUTPUT_QUIET
        RESULT_VARIABLE result
        WORKING_DIRECTORY ${SEAL_THIRDPARTY_DIR}/zstd)
    if(result)
        message(WARNING "Failed to build ZSTD (${result}); disabling `SEAL_USE_ZSTD`")
    endif()
endif()

# Set up the targets
if(SEAL_USE_ZSTD AND NOT MSVC)
    add_subdirectory(
        ${SEAL_THIRDPARTY_DIR}/zstd/src/build/cmake
        EXCLUDE_FROM_ALL)

    # Set the ZSTD include directory
    set(SEAL_ZSTD_INCLUDE_DIR ${SEAL_THIRDPARTY_DIR}/zstd/src/lib)
endif()

# Google Test
# This follows the example in
# https://github.com/google/googletest/blob/release-1.10.0/googletest/README.md.

# Download and configure
if(SEAL_BUILD_TESTS AND NOT MSVC)
    message(STATUS "Setting up Google Test ...")
    execute_process(
        COMMAND ${CMAKE_COMMAND} -G "${CMAKE_GENERATOR}" .
        OUTPUT_QUIET
        RESULT_VARIABLE result
        WORKING_DIRECTORY ${SEAL_THIRDPARTY_DIR}/googletest)
    if(result)
        message(WARNING "Failed to download Google Test (${result}); disabling `SEAL_BUILD_TESTS`")
    endif()
    set(BUILD_GMOCK OFF CACHE BOOL "" FORCE)
    mark_as_advanced(BUILD_GMOCK)
    set(INSTALL_GTEST OFF CACHE BOOL "" FORCE)
    mark_as_advanced(INSTALL_GTEST)
endif()

# Build
if(SEAL_BUILD_TESTS AND NOT MSVC)
    execute_process(COMMAND ${CMAKE_COMMAND} --build .
        OUTPUT_QUIET
        RESULT_VARIABLE result
        WORKING_DIRECTORY ${SEAL_THIRDPARTY_DIR}/googletest)
    if(result)
        message(WARNING "Failed to build Google Test (${result}); disabling `SEAL_BUILD_TESTS`")
    endif()
endif()

# Set up the targets
if(SEAL_BUILD_TESTS AND NOT MSVC)
    set(gtest_force_shared_crt ON CACHE BOOL "" FORCE)
    add_subdirectory(
        ${SEAL_THIRDPARTY_DIR}/googletest/src
        ${SEAL_THIRDPARTY_DIR}/googletest/build
        EXCLUDE_FROM_ALL)
endif()

####################
# SEAL C++ library #
####################

# [option] BUILD_SHARED_LIBS (default: OFF)
# Build a shared library if set to ON. Build a static library regardlessly.
set(BUILD_SHARED_LIBS_STR "Build shared library")
option(BUILD_SHARED_LIBS ${BUILD_SHARED_LIBS_STR} OFF)
if(MSVC AND BUILD_SHARED_LIBS)
    message(WARNING "This build system only supports a static build; disabling `BUILD_SHARED_LIBS`")
    set(BUILD_SHARED_LIBS OFF CACHE BOOL ${BUILD_SHARED_LIBS_STR} FORCE)
endif()

# [option] SEAL_THROW_ON_TRANSPARENT_CIPHERTEXT (default: ON)
# Throw an exception if the second polynomial of a ciphertext is zero.
set(SEAL_THROW_ON_TRANSPARENT_CIPHERTEXT_STR "Throw an exception when a member of Evaluator outputs a transparent ciphertext")
option(SEAL_THROW_ON_TRANSPARENT_CIPHERTEXT ${SEAL_THROW_ON_TRANSPARENT_CIPHERTEXT_STR} ON)
mark_as_advanced(FORCE SEAL_THROW_ON_TRANSPARENT_CIPHERTEXT)

# [option] SEAL_USE_GAUSSIAN (default: OFF)
# Use Gaussian distribution for error if set to ON, use centered binomial otherwise.
set(SEAL_USE_GAUSSIAN_STR "Use Gaussian for error distribution instead of centerd binomial")
option(SEAL_USE_GAUSSIAN ${SEAL_USE_GAUSSIAN_STR} OFF)
mark_as_advanced(FORCE SEAL_USE_GAUSSIAN)

# [option] SEAL_USE_INTRIN (default: ON)
set(SEAL_USE_INTRIN_OPTION_STR "Use intrinsics")
option(SEAL_USE_INTRIN ${SEAL_USE_INTRIN_OPTION_STR} ON)
# Look for header files, use intrinsics if available, set to OFF otherwise.
include(CheckCXXIntrinsicsHeader)

# [option] SEAL_USE_${A_SPECIFIC_INTRIN} (default: ON, advanced)
# Not available if SEAL_USE_INTRIN is OFF.
if(MSVC)
    set(SEAL_USE__UMUL128_OPTION_STR "Use _umul128")
    cmake_dependent_option(SEAL_USE__UMUL128 ${SEAL_USE__UMUL128_OPTION_STR} ON "SEAL_USE_INTRIN" OFF)
    mark_as_advanced(FORCE SEAL_USE__UMUL128)

    set(SEAL_USE__BITSCANREVERSE64_OPTION_STR "Use _BitScanReverse64")
    cmake_dependent_option(SEAL_USE__BITSCANREVERSE64 ${SEAL_USE__BITSCANREVERSE64_OPTION_STR} ON "SEAL_USE_INTRIN" OFF)
    mark_as_advanced(FORCE SEAL_USE__BITSCANREVERSE64)
else()
    set(SEAL_USE___INT128_OPTION_STR "Use __int128")
    cmake_dependent_option(SEAL_USE___INT128 ${SEAL_USE___INT128_OPTION_STR} ON "SEAL_USE_INTRIN" OFF)
    mark_as_advanced(FORCE SEAL_USE___INT128)

    set(SEAL_USE___BUILTIN_CLZLL_OPTION_STR "Use __builtin_clzll")
    cmake_dependent_option(SEAL_USE___BUILTIN_CLZLL ${SEAL_USE___BUILTIN_CLZLL_OPTION_STR} ON "SEAL_USE_INTRIN" OFF)
    mark_as_advanced(FORCE SEAL_USE___BUILTIN_CLZLL)
endif()

set(SEAL_USE__ADDCARRY_U64_OPTION_STR "Use _addcarry_u64")
cmake_dependent_option(SEAL_USE__ADDCARRY_U64 ${SEAL_USE__ADDCARRY_U64_OPTION_STR} ON "SEAL_USE_INTRIN" OFF)
mark_as_advanced(FORCE SEAL_USE__ADDCARRY_U64)

set(SEAL_USE__SUBBORROW_U64_OPTION_STR "Use _subborrow_u64")
cmake_dependent_option(SEAL_USE__SUBBORROW_U64 ${SEAL_USE__SUBBORROW_U64_OPTION_STR} ON "SEAL_USE_INTRIN" OFF)
mark_as_advanced(FORCE SEAL_USE__SUBBORROW_U64)
# Use a specific intrinsic if available, set to OFF otherwise.
include(CheckCXXIntrinsicsSpecific)

# [option] SEAL_USE_${A_SPECIFIC_MEMSET_METHOD} (default: ON, advanced)
set(SEAL_USE_MEMSET_S_OPTION_STR "Use memset_s")
option(SEAL_USE_MEMSET_S ${SEAL_USE_MEMSET_S_OPTION_STR} ON)
mark_as_advanced(FORCE SEAL_USE_MEMSET_S)

set(SEAL_USE_EXPLICIT_BZERO_OPTION_STR "Use explicit_bzero")
option(SEAL_USE_EXPLICIT_BZERO ${SEAL_USE_EXPLICIT_BZERO_OPTION_STR} ON)
mark_as_advanced(FORCE SEAL_USE_EXPLICIT_BZERO)

set(SEAL_USE_EXPLICIT_MEMSET_OPTION_STR "Use explicit_memset")
option(SEAL_USE_EXPLICIT_MEMSET ${SEAL_USE_EXPLICIT_MEMSET_OPTION_STR} ON)
mark_as_advanced(FORCE SEAL_USE_EXPLICIT_MEMSET)
# Use a specific memset method if available, set to OFF otherwise.
include(CheckMemset)

# Create an object library to compile sources only once
add_library(seal_obj OBJECT)

# Add source files to library and header files to install
add_subdirectory(native/src/seal)

# Set C++ language version and include directories for the object library
seal_set_language(seal_obj)
seal_set_include_directories(seal_obj)

if(SEAL_USE_MSGSL AND NOT MSVC)
    target_link_libraries(seal_obj PRIVATE GSL)
endif()

if(SEAL_USE_ZLIB AND NOT MSVC)
    target_link_libraries(seal_obj PRIVATE zlibstatic)
endif()

if(SEAL_USE_ZSTD AND NOT MSVC)
    target_link_libraries(seal_obj PRIVATE libzstd_static)
    target_include_directories(seal_obj PRIVATE $<BUILD_INTERFACE:${SEAL_ZSTD_INCLUDE_DIR}>)
endif()

# Always build the static library
add_library(seal STATIC $<TARGET_OBJECTS:seal_obj>)
seal_set_version(seal)
seal_set_version_filename(seal)
seal_set_language(seal)
seal_set_include_directories(seal)
seal_link_threads(seal)
seal_install_target(seal SEALTargets)

# Conditionally add MSGSL include directory to build interface
if(SEAL_USE_MSGSL AND NOT MSVC)
    target_include_directories(seal PUBLIC $<BUILD_INTERFACE:${SEAL_MSGSL_INCLUDE_DIR}>)
endif()

# Conditionally build the shared library
if(BUILD_SHARED_LIBS)
    add_library(seal_shared SHARED $<TARGET_OBJECTS:seal_obj>)
    set_target_properties(seal_shared PROPERTIES OUTPUT_NAME seal)
    seal_set_version(seal_shared)
    seal_set_soversion(seal_shared)
    seal_set_language(seal_shared)
    seal_set_include_directories(seal_shared)
    seal_link_threads(seal_shared)

    seal_install_target(seal_shared SEALTargets)
endif()

# In UNIX-like platforms combine manually seal and zlibstatic into a single archive
if(SEAL_USE_ZLIB AND NOT MSVC)
    seal_combine_archives(seal zlibstatic)
endif()

# In UNIX-like platforms combine manually seal and libzstd_static into a single archive
if(SEAL_USE_ZSTD AND NOT MSVC)
    seal_combine_archives(seal libzstd_static)
endif()

#########################
# SEAL C export library #
#########################

# Check that size_t is 8 bytes
include(CheckTypeSize)
check_type_size("size_t" SIZET LANGUAGE C)

set(SEAL_BUILD_SEAL_C_OPTION_STR "Build C export library for Microsoft SEAL")
cmake_dependent_option(SEAL_BUILD_SEAL_C ${SEAL_BUILD_SEAL_C_OPTION_STR} OFF "${SIZET} EQUAL 8" OFF)

unset(SIZET CACHE)
unset(HAVE_SIZET CACHE)

# Create shared SEAL_C library but add no source files yet
if(SEAL_BUILD_SEAL_C)
    add_library(sealc SHARED)

    # Add source files to library and header files to install
    add_subdirectory(native/src/seal/c)
    seal_set_version(sealc)
    seal_set_soversion(sealc)
    seal_set_language(sealc)
    seal_set_include_directories(sealc)

    target_link_libraries(sealc PUBLIC seal)

    seal_install_target(sealc SEALTargets)
endif()

#################################
# Installation and CMake config #
#################################

# Create the CMake config file
include(CMakePackageConfigHelpers)
configure_package_config_file(
    ${SEAL_CONFIG_IN_FILENAME} ${SEAL_CONFIG_FILENAME}
    INSTALL_DESTINATION ${SEAL_CONFIG_INSTALL_DIR})

# Install the export
install(
    EXPORT SEALTargets
    NAMESPACE SEAL::
    DESTINATION ${SEAL_CONFIG_INSTALL_DIR})

# Version file; we require exact version match for downstream
write_basic_package_version_file(
    ${SEAL_CONFIG_VERSION_FILENAME}
    VERSION ${SEAL_VERSION}
    COMPATIBILITY SameMinorVersion)

# Install config and module files
install(
    FILES
        ${SEAL_CONFIG_FILENAME}
        ${SEAL_CONFIG_VERSION_FILENAME}
    DESTINATION ${SEAL_CONFIG_INSTALL_DIR})

# Install the pkg-config file
install(
    FILES
        ${SEAL_PKGCONFIG_FILENAME}
    DESTINATION
        ${SEAL_PKGCONFIG_INSTALL_DIR})

# We export SEALTargets from the build tree so it can be used by other projects
# without requiring an install.
export(
    EXPORT SEALTargets
    NAMESPACE SEAL::
    FILE ${SEAL_TARGETS_FILENAME})

# In UNIX-like platforms install MSGSL header files
if(SEAL_USE_MSGSL AND NOT MSVC)
    install(
        DIRECTORY
            ${SEAL_MSGSL_INCLUDE_DIR}/gsl
        DESTINATION
            ${SEAL_INCLUDES_INSTALL_DIR}
    )
endif()

#####################
# SEAL C++ examples #
#####################

# [option] SEAL_BUILD_EXAMPLES
set(SEAL_BUILD_EXAMPLES_OPTION_STR "Build C++ examples for Microsoft SEAL")
option(SEAL_BUILD_EXAMPLES ${SEAL_BUILD_EXAMPLES_OPTION_STR} OFF)

if(SEAL_BUILD_EXAMPLES)
    add_executable(sealexamples)
    add_subdirectory(native/examples)
    target_link_libraries(sealexamples PRIVATE seal)
endif()

##################
# SEAL C++ tests #
##################

# [option] SEAL_BUILD_TESTS
set(SEAL_BUILD_TESTS_OPTION_STR "Build C++ tests for Microsoft SEAL")
option(SEAL_BUILD_TESTS ${SEAL_BUILD_TESTS_OPTION_STR} OFF)

if(SEAL_BUILD_TESTS)
    add_executable(sealtest)
    add_subdirectory(native/tests/seal)
    target_link_libraries(sealtest PRIVATE seal gtest)
endif()

#######################################
# Configure SEALNet and NuGet package #
#######################################

# Set the sealc dynamic library file names to be included in creating
# the NuGet package. When building a multi-platform NuGet package, the
# dynamic library paths need to be specified explicitly in the NuGet
# command. See dotnet/nuget/SEALNet.nuspec.in.

# First create the multi-platform NuSpec file so disable all platform-specific
# library paths
unset(SEAL_WINDOWS_SEAL_C_PATH)
unset(SEAL_LINUX_SEAL_C_PATH)
unset(SEAL_MACOS_SEAL_C_PATH)

# Create SEALNet-multi.nuspec for a multi-platform NuGet package
configure_file(
    ${SEAL_SOURCE_DIR}/dotnet/nuget/SEALNet-multi.nuspec.in
    ${SEAL_SOURCE_DIR}/dotnet/nuget/SEALNet-multi.nuspec
    @ONLY)

set(SEAL_WINDOWS_SEAL_C_PATH "")
set(SEAL_LINUX_SEAL_C_PATH "")
set(SEAL_MACOS_SEAL_C_PATH "")

# Create pkg-config file
configure_file(
     ${SEAL_PKGCONFIG_IN_FILENAME}
     ${SEAL_PKGCONFIG_FILENAME}
     @ONLY)

# Supporting local building of NuGet package
if(MSVC)
    set(SEAL_WINDOWS_SEAL_C_PATH ${SEAL_SOURCE_DIR}/lib/x64/$Configuration$/sealc.dll)
elseif(UNIX)
    set(SEAL_LINUX_SEAL_C_PATH ${SEAL_SOURCE_DIR}/lib/libsealc.so)
elseif(APPLE)
    set(SEAL_MACOS_SEAL_C_PATH ${SEAL_SOURCE_DIR}/lib/libsealc.dylib)
endif()

# Create SEALNet.nuspec for a local NuGet pack from SEALNet.nuspec.in
configure_file(
    ${SEAL_SOURCE_DIR}/dotnet/nuget/SEALNet.nuspec.in
    ${SEAL_SOURCE_DIR}/dotnet/nuget/SEALNet.nuspec
    @ONLY)

# Create SEALNet.targets from SEALNet.targets.in
configure_file(
    ${SEAL_SOURCE_DIR}/dotnet/nuget/SEALNet.targets.in
    ${SEAL_SOURCE_DIR}/dotnet/nuget/SEALNet.targets
    @ONLY)
