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

project(SEAL VERSION 3.5.0 LANGUAGES CXX C)

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

# [Option] CMAKE_BUILD_TYPE
# Build in Release mode by default; otherwise use selected option
if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE "Release" CACHE STRING "Build type" FORCE)
    set_property(CACHE CMAKE_BUILD_TYPE PROPERTY
        STRINGS "Release" "Debug" "MinSizeRel" "RelWithDebInfo")
endif()
message(STATUS "Build type (CMAKE_BUILD_TYPE): ${CMAKE_BUILD_TYPE}")

# [Flag] SEAL_DEBUG
# In Debug mode, enable SEAL_DEBUG
if(CMAKE_BUILD_TYPE STREQUAL "Debug")
    set(SEAL_DEBUG ON)
else()
    set(SEAL_DEBUG OFF)
endif()
message(STATUS "Microsoft SEAL debug mode: ${SEAL_DEBUG}")

# [Option] SEAL_USE_CXX17
# Should we use C++14 or C++17?
set(SEAL_USE_CXX17_OPTION_STR "Use C++17")
option(SEAL_USE_CXX17 ${SEAL_USE_CXX17_OPTION_STR} ON)

# Conditionally enable features from C++17
set(SEAL_USE_STD_BYTE OFF)
set(SEAL_USE_SHARED_MUTEX OFF)
set(SEAL_USE_IF_CONSTEXPR OFF)
set(SEAL_USE_MAYBE_UNUSED OFF)
set(SEAL_USE_NODISCARD OFF)
set(SEAL_LANG_FLAG "-std=c++14")
if(SEAL_USE_CXX17)
    set(SEAL_USE_STD_BYTE ON)
    set(SEAL_USE_SHARED_MUTEX ON)
    set(SEAL_USE_IF_CONSTEXPR ON)
    set(SEAL_USE_MAYBE_UNUSED ON)
    set(SEAL_USE_NODISCARD ON)
    set(SEAL_LANG_FLAG "-std=c++17")
endif()

# [Option] CXX compiler flags
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

# In Debug mode, enable extra compiler flags.
if(SEAL_DEBUG)
  enable_cxx_compiler_flag_if_supported("-Wall")
  enable_cxx_compiler_flag_if_supported("-Wextra")
  enable_cxx_compiler_flag_if_supported("-Wconversion")
  enable_cxx_compiler_flag_if_supported("-Wshadow")
  enable_cxx_compiler_flag_if_supported("-pedantic")
endif()

# Required files and directories
include(GNUInstallDirs)
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${SEAL_SOURCE_DIR}/lib)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${SEAL_SOURCE_DIR}/lib)
set(CMAKE_LIBRARY_RUNTIME_DIRECTORY ${SEAL_SOURCE_DIR}/bin)
set(SEAL_TARGETS_FILENAME ${SEAL_SOURCE_DIR}/cmake/SEALTargets.cmake)
set(SEAL_CONFIG_IN_FILENAME ${SEAL_SOURCE_DIR}/cmake/SEALConfig.cmake.in)
set(SEAL_CONFIG_FILENAME ${SEAL_SOURCE_DIR}/cmake/SEALConfig.cmake)
set(SEAL_CONFIG_VERSION_FILENAME ${SEAL_SOURCE_DIR}/cmake/SEALConfigVersion.cmake)
set(SEAL_CONFIG_INSTALL_DIR ${CMAKE_INSTALL_LIBDIR}/cmake/SEAL-${SEAL_VERSION_MAJOR}.${SEAL_VERSION_MINOR})
set(SEAL_INCLUDES_INSTALL_DIR ${CMAKE_INSTALL_INCLUDEDIR}/SEAL-${SEAL_VERSION_MAJOR}.${SEAL_VERSION_MINOR})
set(SEAL_INCLUDES_BUILD_DIR ${SEAL_SOURCE_DIR}/native/src)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${SEAL_SOURCE_DIR}/bin)

# For extra modules we might have
list(APPEND CMAKE_MODULE_PATH ${SEAL_SOURCE_DIR}/cmake)

include(CMakePushCheckState)
include(CMakeDependentOption)
include(CheckIncludeFiles)
include(CheckCXXSourceRuns)
include(CheckTypeSize)

##################################
# Macros for configuring targets #
##################################

# Set the C++ language version
macro(set_language target)
    if(SEAL_USE_CXX17)
        target_compile_features(${target} PUBLIC cxx_std_17)
    else()
        target_compile_features(${target} PUBLIC cxx_std_14)
    endif()
endmacro()

# Set the VERSION property
macro(set_version target)
    set_target_properties(${target} PROPERTIES VERSION ${SEAL_VERSION})
endmacro()

# Set the library filename to reflect version
macro(set_version_filename target)
    set_target_properties(${target} PROPERTIES
        OUTPUT_NAME ${target}-${SEAL_VERSION_MAJOR}.${SEAL_VERSION_MINOR})
endmacro()

# Set the SOVERSION property
macro(set_soversion target)
    set_target_properties(${target} PROPERTIES
        SOVERSION ${SEAL_VERSION_MAJOR}.${SEAL_VERSION_MINOR})
endmacro()

# Set include directories for build and install interfaces
macro(set_include_directories target)
    target_include_directories(${target} PUBLIC
        $<BUILD_INTERFACE:${SEAL_INCLUDES_BUILD_DIR}>
        $<INSTALL_INTERFACE:${SEAL_INCLUDES_INSTALL_DIR}>)
endmacro()

# Link a thread library
macro(link_threads target)
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
macro(install_target target export)
    install(TARGETS ${target} EXPORT ${export}
        ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
        LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
        RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})
endmacro()

#########################
# External dependencies #
#########################

# Use Microsoft GSL
set(SEAL_USE_MSGSL_OPTION_STR "Use Microsoft GSL")
option(SEAL_USE_MSGSL ${SEAL_USE_MSGSL_OPTION_STR} ON)

if(SEAL_USE_MSGSL AND NOT MSVC)
    add_subdirectory(thirdparty/msgsl)
    ExternalProject_Get_Property(msgsl_external SOURCE_DIR)
    add_library(msgsl IMPORTED INTERFACE)

    # We need to create the include directory so it exists at the time
    # of configuration. Otherwise set_target_properties below will fail.
    set(MSGSL_INCLUDE_DIR ${SOURCE_DIR}/include)
    file(MAKE_DIRECTORY ${MSGSL_INCLUDE_DIR})

    set_target_properties(msgsl PROPERTIES
        INTERFACE_INCLUDE_DIRECTORIES ${MSGSL_INCLUDE_DIR})
    add_dependencies(msgsl msgsl_external)
endif()

# Use ZLIB
set(SEAL_USE_ZLIB_OPTION_STR "Use ZLIB for compressed serialization")
option(SEAL_USE_ZLIB ${SEAL_USE_ZLIB_OPTION_STR} ON)

if(SEAL_USE_ZLIB AND NOT MSVC)
    add_subdirectory(thirdparty/zlib)
    ExternalProject_Get_Property(zlib_external SOURCE_DIR BINARY_DIR)
    add_library(zlibstatic STATIC IMPORTED)

    set(ZLIB_FILENAME "libz.a")
    set(ZLIB_LIBRARY_PATH ${BINARY_DIR}/${ZLIB_FILENAME})
    set_target_properties(zlibstatic PROPERTIES
        IMPORTED_LOCATION ${ZLIB_LIBRARY_PATH})
    set_target_properties(zlibstatic PROPERTIES
        INTERFACE_INCLUDE_DIRECTORIES ${SOURCE_DIR})
    add_dependencies(zlibstatic zlib_external)
endif()

# Use Google Test
if(SEAL_BUILD_TESTS AND NOT MSVC)
    # This follows the example in
    # https://github.com/google/googletest/blob/release-1.10.0/googletest/README.md.

    # Download
    message(STATUS "Setting up Google Test ...")
    execute_process(COMMAND ${CMAKE_COMMAND} -G "${CMAKE_GENERATOR}" .
        OUTPUT_QUIET
        RESULT_VARIABLE result
        WORKING_DIRECTORY thirdparty/googletest)
    if(result)
        message(WARNING "Failed to download Google Test (${result}); disabling `SEAL_BUILD_TESTS`")
    endif()

    set(BUILD_GMOCK OFF CACHE BOOL "" FORCE)
    mark_as_advanced(BUILD_GMOCK)
    set(INSTALL_GTEST OFF CACHE BOOL "" FORCE)
    mark_as_advanced(INSTALL_GTEST)

    # Build
    execute_process(COMMAND ${CMAKE_COMMAND} --build .
        OUTPUT_QUIET
        RESULT_VARIABLE result
        WORKING_DIRECTORY thirdparty/googletest)
    if(result)
        message(WARNING "Failed to build Google Test (${result}); disabling `SEAL_BUILD_TESTS`")
    endif()

    set(gtest_force_shared_crt ON CACHE BOOL "" FORCE)

    # Set up the targets
    add_subdirectory(
        thirdparty/googletest/googletest-src
        thirdparty/googletest/googletest-build
        EXCLUDE_FROM_ALL)
endif()

####################
# SEAL C++ library #
####################

# Should we build also the shared library?
set(BUILD_SHARED_LIBS_STR "Build shared library")
option(BUILD_SHARED_LIBS ${BUILD_SHARED_LIBS_STR} OFF)
if(MSVC AND BUILD_SHARED_LIBS)
    message(WARNING "This build system only supports a static build; disabling `BUILD_SHARED_LIBS`")
    set(BUILD_SHARED_LIBS OFF CACHE BOOL ${BUILD_SHARED_LIBS_STR} FORCE)
endif()

# Always build position-independent-code
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

# Throw on multiply_plain by a zero plaintext
set(SEAL_THROW_ON_TRANSPARENT_CIPHERTEXT_STR "Throw an exception when a member of Evaluator outputs a transparent ciphertext")
option(SEAL_THROW_ON_TRANSPARENT_CIPHERTEXT ${SEAL_THROW_ON_TRANSPARENT_CIPHERTEXT_STR} ON)
mark_as_advanced(FORCE SEAL_THROW_ON_TRANSPARENT_CIPHERTEXT)

# Use intrinsics if available
set(SEAL_USE_INTRIN_OPTION_STR "Use intrinsics")
option(SEAL_USE_INTRIN ${SEAL_USE_INTRIN_OPTION_STR} ON)

# Check for intrin.h or x64intrin.h
if(SEAL_USE_INTRIN)
    if(MSVC)
        set(SEAL_INTRIN_HEADER "intrin.h")
    else()
        set(SEAL_INTRIN_HEADER "x86intrin.h")
    endif()

    check_include_file_cxx(${SEAL_INTRIN_HEADER} HAVE_INTRIN_HEADER)
    if(NOT HAVE_INTRIN_HEADER)
        set(SEAL_USE_INTRIN OFF CACHE BOOL ${SEAL_USE_INTRIN_OPTION_STR} FORCE)
    endif()
endif()

# Specific intrinsics depending on SEAL_USE_INTRIN
if(MSVC)
    set(SEAL_USE__UMUL128_OPTION_STR "Use _umul128")
    cmake_dependent_option(SEAL_USE__UMUL128 ${SEAL_USE__UMUL128_OPTION_STR} ON "SEAL_USE_INTRIN" OFF)

    set(SEAL_USE__BITSCANREVERSE64_OPTION_STR "Use _BitScanReverse64")
    cmake_dependent_option(SEAL_USE__BITSCANREVERSE64 ${SEAL_USE__BITSCANREVERSE64_OPTION_STR} ON "SEAL_USE_INTRIN" OFF)
else()
    set(SEAL_USE___INT128_OPTION_STR "Use __int128")
    cmake_dependent_option(SEAL_USE___INT128 ${SEAL_USE___INT128_OPTION_STR} ON "SEAL_USE_INTRIN" OFF)

    set(SEAL_USE___BUILTIN_CLZLL_OPTION_STR "Use __builtin_clzll")
    cmake_dependent_option(SEAL_USE___BUILTIN_CLZLL ${SEAL_USE___BUILTIN_CLZLL_OPTION_STR} ON "SEAL_USE_INTRIN" OFF)
endif()

set(SEAL_USE__ADDCARRY_U64_OPTION_STR "Use _addcarry_u64")
cmake_dependent_option(SEAL_USE__ADDCARRY_U64 ${SEAL_USE__ADDCARRY_U64_OPTION_STR} ON "SEAL_USE_INTRIN" OFF)

set(SEAL_USE__SUBBORROW_U64_OPTION_STR "Use _subborrow_u64")
cmake_dependent_option(SEAL_USE__SUBBORROW_U64 ${SEAL_USE__SUBBORROW_U64_OPTION_STR} ON "SEAL_USE_INTRIN" OFF)

if(SEAL_USE_INTRIN)
    cmake_push_check_state(RESET)
    set(CMAKE_REQUIRED_QUIET TRUE)
    if(NOT MSVC)
        set(CMAKE_REQUIRED_FLAGS "${CMAKE_REQUIRED_FLAGS} -O0 ${SEAL_LANG_FLAG}")
    endif()

    if(MSVC)
        # Check for presence of _umul128
        if(SEAL_USE__UMUL128)
            check_cxx_source_runs("
                #include <${SEAL_INTRIN_HEADER}>
                int main() {
                    unsigned long long a = 0, b = 0;
                    unsigned long long c;
                    volatile unsigned long long d;
                    d = _umul128(a, b, &c);
                    return 0;
                }"
                USE_UMUL128
            )
            if(NOT USE_UMUL128 EQUAL 1)
                set(SEAL_USE__UMUL128 OFF CACHE BOOL ${SEAL_USE__UMUL128_OPTION_STR} FORCE)
            endif()
        endif()

        # Check for _BitScanReverse64
        if(SEAL_USE__BITSCANREVERSE64)
            check_cxx_source_runs("
                #include <${SEAL_INTRIN_HEADER}>
                int main() {
                    unsigned long a = 0, b = 0;
                    volatile unsigned char res = _BitScanReverse64(&a, b);
                    return 0;
                }"
                USE_BITSCANREVERSE64
            )
            if(NOT USE_BITSCANREVERSE64 EQUAL 1)
                set(SEAL_USE__BITSCANREVERSE64 OFF CACHE BOOL ${SEAL_USE__BITSCANREVERSE64_OPTION_STR} FORCE)
            endif()
        endif()
    else()
        # Check for presence of ___int128
        if(SEAL_USE___INT128)
            check_type_size("__int128" INT128 LANGUAGE CXX)
            if(NOT INT128 EQUAL 16)
                set(SEAL_USE___INT128 OFF CACHE BOOL ${SEAL_USE___INT128_OPTION_STR} FORCE)
            endif()
        endif()

        # Check for __builtin_clzll
        if(SEAL_USE___BUILTIN_CLZLL)
            check_cxx_source_runs("
                int main() {
                    volatile auto res = __builtin_clzll(0);
                    return 0;
                }"
                USE_BUILTIN_CLZLL
            )
            if(NOT USE_BUILTIN_CLZLL EQUAL 1)
                set(SEAL_USE___BUILTIN_CLZLL OFF CACHE BOOL ${SEAL_USE___BUILTIN_CLZLL_OPTION_STR} FORCE)
            endif()
        endif()
    endif()

    # Check for _addcarry_u64
    if(SEAL_USE__ADDCARRY_U64)
        check_cxx_source_runs("
            #include <${SEAL_INTRIN_HEADER}>
            int main() {
                unsigned long long a;
                volatile auto res = _addcarry_u64(0,0,0,&a);
                return 0;
            }"
            USE_ADDCARRY_U64
        )
        if(NOT USE_ADDCARRY_U64 EQUAL 1)
            set(SEAL_USE__ADDCARRY_U64 OFF CACHE BOOL ${SEAL_USE__ADDCARRY_U64_OPTION_STR} FORCE)
        endif()
    endif()

    # Check for _subborrow_u64
    if(SEAL_USE__SUBBORROW_U64)
        check_cxx_source_runs("
            #include <${SEAL_INTRIN_HEADER}>
            int main() {
                unsigned long long a;
                volatile auto res = _subborrow_u64(0,0,0,&a);
                return 0;
            }"
            USE_SUBBORROW_U64
        )
        if(NOT USE_SUBBORROW_U64 EQUAL 1)
            set(SEAL_USE__SUBBORROW_U64 OFF CACHE BOOL ${SEAL_USE__SUBBORROW_U64_OPTION_STR} FORCE)
        endif()
    endif()

    cmake_pop_check_state()
endif()

# Create an object library to compile sources only once
add_library(seal_obj OBJECT)

# Add source files to library and header files to install
add_subdirectory(native/src/seal)

# Set C++ language version and include directories for the object library
set_language(seal_obj)
set_include_directories(seal_obj)

if(SEAL_USE_MSGSL AND NOT MSVC)
    # Make sure Microsoft GSL is downloaded
    target_link_libraries(seal_obj PUBLIC msgsl)
endif()

if(SEAL_USE_ZLIB AND NOT MSVC)
    # Make sure ZLIB is downloaded
    target_link_libraries(seal_obj PRIVATE zlibstatic)
endif()

# Always build the static library
add_library(seal STATIC $<TARGET_OBJECTS:seal_obj>)
set_version(seal)
set_version_filename(seal)
set_language(seal)
set_include_directories(seal)
link_threads(seal)
install_target(seal SEALTargets)

if(SEAL_USE_MSGSL AND NOT MSVC AND NOT CMAKE_HOST_WIN32)
    # In UNIX-like platforms copy Microsoft GSL include files into native/src
    add_custom_command(TARGET seal POST_BUILD
        COMMAND cp -r ${MSGSL_INCLUDE_DIR}/gsl ${SEAL_INCLUDES_BUILD_DIR})
endif()

if(SEAL_USE_ZLIB AND NOT MSVC AND NOT CMAKE_HOST_WIN32)
    # In UNIX-like platforms combine manually seal and zlibstatic
    # into a single archive; not pretty, but works
    add_custom_command(TARGET seal POST_BUILD
        COMMAND ar x $<TARGET_FILE:seal>
        COMMAND ar x ${ZLIB_LIBRARY_PATH}
        COMMAND ar rcs $<TARGET_FILE:seal> *.o
        COMMAND rm -f *.o
        WORKING_DIRECTORY $<TARGET_FILE_DIR:seal>)
endif()

# Conditionally build the shared library
if(BUILD_SHARED_LIBS)
    add_library(seal_shared SHARED $<TARGET_OBJECTS:seal_obj>)
    set_target_properties(seal_shared PROPERTIES OUTPUT_NAME seal)
    set_version(seal_shared)
    set_soversion(seal_shared)
    set_language(seal_shared)
    set_include_directories(seal_shared)
    link_threads(seal_shared)

    if(SEAL_USE_ZLIB AND NOT MSVC)
        # In the shared build we link zlibstatic into the shared library
        target_link_libraries(seal_shared PRIVATE zlibstatic)
    endif()

    install_target(seal_shared SEALTargets)
endif()

#########################
# SEAL C export library #
#########################

# Check that size_t is 8 bytes
include(CheckTypeSize)
check_type_size("size_t" SIZET LANGUAGE C)

set(SEAL_BUILD_SEAL_C_OPTION_STR "Build C export library for Microsoft SEAL")
cmake_dependent_option(SEAL_BUILD_SEAL_C ${SEAL_BUILD_SEAL_C_OPTION_STR} OFF "${SIZET} EQUAL 8" OFF)

# Create shared SEAL_C library but add no source files yet
if(SEAL_BUILD_SEAL_C)
    add_library(sealc SHARED)

    # Add source files to library and header files to install
    add_subdirectory(native/src/seal/c)
    set_version(sealc)
    set_soversion(sealc)
    set_language(sealc)
    set_include_directories(sealc)

    if(SEAL_USE_MSGSL AND NOT MSVC)
        target_include_directories(sealc PUBLIC $<BUILD_INTERFACE:${MSGSL_INCLUDE_DIR}>)
    endif()

    target_link_libraries(sealc PUBLIC seal)

    if(SEAL_USE_ZLIB AND NOT MSVC)
        # Link zlibstatic into the shared SEAL_C library
        target_link_libraries(sealc PRIVATE zlibstatic)
    endif()

    install_target(sealc SEALTargets)
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

# We export SEALTargets from the build tree so it can be used by other projects
# without requiring an install.
export(
    EXPORT SEALTargets
    NAMESPACE SEAL::
    FILE ${SEAL_TARGETS_FILENAME})

#####################
# SEAL C++ examples #
#####################

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
# the NuGet package. When building a multi-platform package, all three
# paths should be included.

set(SEAL_WINDOWS_SEAL_C_PATH_ ${SEAL_SOURCE_DIR}/lib/x64/$Configuration$/sealc.dll)
set(SEAL_LINUX_SEAL_C_PATH_ ${SEAL_SOURCE_DIR}/lib/libsealc.so.${SEAL_VERSION})
set(SEAL_MACOS_SEAL_C_PATH_ ${SEAL_SOURCE_DIR}/lib/libsealc.${SEAL_VERSION}.dylib)

unset(SEAL_WINDOWS_SEAL_C_PATH)
unset(SEAL_LINUX_SEAL_C_PATH)
unset(SEAL_MACOS_SEAL_C_PATH)

if(SEAL_MULTIPLATFORM_NUGET_BUILD)
    set(SEAL_WINDOWS_SEAL_C_PATH ${SEAL_WINDOWS_SEAL_C_PATH_})
    set(SEAL_LINUX_SEAL_C_PATH ${SEAL_LINUX_SEAL_C_PATH_})
    set(SEAL_MACOS_SEAL_C_PATH ${SEAL_MACOS_SEAL_C_PATH_})
else()
    if(MSVC)
        set(SEAL_WINDOWS_SEAL_C_PATH ${SEAL_WINDOWS_SEAL_C_PATH_})
    elseif(UNIX)
        set(SEAL_LINUX_SEAL_C_PATH ${SEAL_LINUX_SEAL_C_PATH_})
    elseif(APPLE)
        set(SEAL_MACOS_SEAL_C_PATH ${SEAL_MACOS_SEAL_C_PATH_})
    endif()
endif()

# Create SEALNet.nuspec from SEALNet.nuspec.in
configure_file(
    ${SEAL_SOURCE_DIR}/dotnet/nuget/SEALNet.nuspec.in
    ${SEAL_SOURCE_DIR}/dotnet/nuget/SEALNet.nuspec
    @ONLY)

# Create SEALNet.targets from SEALNet.targets.in
configure_file(
    ${SEAL_SOURCE_DIR}/dotnet/nuget/SEALNet.targets.in
    ${SEAL_SOURCE_DIR}/dotnet/nuget/SEALNet.targets
    @ONLY)
