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

include(SEALMacros)

#########################
# External dependencies #
#########################

# [option] SEAL_BUILD_DEPS (default: ON)
# Download and build missing dependencies, throw error if disabled.
set(SEAL_BUILD_DEPS_OPTION_STR "Automatically downloand and build unmet dependencies")
option(SEAL_BUILD_DEPS ${SEAL_BUILD_DEPS_OPTION_STR} ON)

if(SEAL_BUILD_DEPS)
    include(FetchContent)
    set(FETCHCONTENT_BASE_DIR ${SEAL_THIRDPARTY_DIR} CACHE STRING "" FORCE)
    mark_as_advanced(FETCHCONTENT_BASE_DIR)
    mark_as_advanced(FETCHCONTENT_FULLY_DISCONNECTED)
    mark_as_advanced(FETCHCONTENT_QUIET)
endif()

# [option] SEAL_USE_MSGSL (default: ON)
set(SEAL_USE_MSGSL_OPTION_STR "Use Microsoft GSL")
option(SEAL_USE_MSGSL ${SEAL_USE_MSGSL_OPTION_STR} ON)
if(SEAL_USE_MSGSL)
    if(SEAL_BUILD_DEPS)
        message(STATUS "Download Microsoft.GSL ...")
        include(ExternalMSGSL)
    else()
        find_package(Microsoft.GSL CONFIG)
        if(NOT Microsoft.GSL_FOUND)
            message(FATAL_ERROR "Failed to find Microsoft.GSL.")
        endif()
    endif()
endif()

# [option] SEAL_USE_ZLIB (default: ON)
set(SEAL_USE_ZLIB_OPTION_STR "Use ZLIB for compressed serialization")
option(SEAL_USE_ZLIB ${SEAL_USE_ZLIB_OPTION_STR} ON)
if(SEAL_USE_ZLIB)
    if(SEAL_BUILD_DEPS)
        message(STATUS "Download ZLIB ...")
        include(ExternalZLIB)
        set(zlib "zlibstatic")
    else()
        find_package(ZLIB 1.2.11)
        if(NOT ZLIB_FOUND)
            message(FATAL_ERROR "Failed to find ZLIB")
        endif()
        set(zlib "ZLIB::ZLIB")
    endif()
endif()

# [option] SEAL_USE_ZSTD (default: ON)
set(SEAL_USE_ZSTD_OPTION_STR "Use Zstandard for compressed serialization")
option(SEAL_USE_ZSTD ${SEAL_USE_ZSTD_OPTION_STR} ON)
if(SEAL_USE_ZSTD)
    if(SEAL_BUILD_DEPS)
        message(STATUS "Download ZSTD ...")
        include(ExternalZSTD)
        set(zstd_static "libzstd_static")
    else()
        find_package(zstd CONFIG)
        if(NOT zstd_FOUND)
            message(FATAL_ERROR "Failed to find ZSTD")
        endif()
        if(TARGET zstd::libzstd_static)
            set(zstd_static "zstd::libzstd_static")
        elseif(TARGET libzstd)
            get_target_property(libzstd_type libzstd TYPE)
            if(libzstd_type STREQUAL "STATIC")
                set(zstd_static "libzstd")
            else()
                message(FATAL_ERROR "ZSTD must be static")
            endif()
        endif()
    endif()
endif()

# if SEAL_BUILD_TESTS is ON, use googletest
if(SEAL_BUILD_TESTS)
    if (SEAL_BUILD_DEPS)
        message(STATUS "Download GTest ...")
        include(ExternalGTest)
        add_library(GTest::gtest ALIAS gtest)
    else()
        find_package(GTest 1.10.0 CONFIG)
        if(NOT GTest_FOUND)
            message(FATAL_ERROR "Failed to find GTest")
        endif()
    endif()
endif()

####################
# SEAL C++ library #
####################

# [option] BUILD_SHARED_LIBS (default: OFF)
# Build a shared library if set to ON. Build a static library regardlessly.
set(BUILD_SHARED_LIBS_STR "Build shared library")
option(BUILD_SHARED_LIBS ${BUILD_SHARED_LIBS_STR} OFF)
if(MSVC AND BUILD_SHARED_LIBS)
    message(FATAL_ERROR "On Windows only static build is supported; set `BUILD_SHARED_LIBS=OFF`")
endif()

# [option] SEAL_THROW_ON_TRANSPARENT_CIPHERTEXT (default: ON)
set(SEAL_THROW_ON_TRANSPARENT_CIPHERTEXT_STR "Throw an exception when Evaluator outputs a transparent ciphertext")
option(SEAL_THROW_ON_TRANSPARENT_CIPHERTEXT ${SEAL_THROW_ON_TRANSPARENT_CIPHERTEXT_STR} ON)
mark_as_advanced(FORCE SEAL_THROW_ON_TRANSPARENT_CIPHERTEXT)

# [option] SEAL_USE_GAUSSIAN_NOISE (default: OFF)
# Use Gaussian distribution for noise sampling if set to ON, use centered binomial otherwise.
set(SEAL_USE_GAUSSIAN_NOISE_STR "Use a rounded Gaussian distribution for noise sampling instead of a Centered Binomial Distribution")
option(SEAL_USE_GAUSSIAN_NOISE ${SEAL_USE_GAUSSIAN_NOISE_STR} OFF)
mark_as_advanced(FORCE SEAL_USE_GAUSSIAN_NOISE)

# [option] SEAL_DEFAULT_PRNG (default: Blake2xb)
# Choose either Blake2xb or Shake256 to be the default PRNG.
set(SEAL_DEFAULT_PRNG_STR "Choose the default PRNG")
set(SEAL_DEFAULT_PRNG "Blake2xb" CACHE STRING ${SEAL_DEFAULT_PRNG_STR} FORCE)
set_property(CACHE SEAL_DEFAULT_PRNG PROPERTY
    STRINGS "Blake2xb" "Shake256")
mark_as_advanced(FORCE SEAL_DEFAULT_PRNG)

# [option] SEAL_USE_INTRIN (default: ON)
set(SEAL_USE_INTRIN_OPTION_STR "Use intrinsics")
option(SEAL_USE_INTRIN ${SEAL_USE_INTRIN_OPTION_STR} ON)
# Look for header files, use intrinsics if available, set to OFF otherwise.
include(CheckCXXIntrinsicsHeader)
if(NOT SEAL_INTRIN_HEADER_FOUND)
    set(SEAL_USE_INTRIN OFF CACHE BOOL ${SEAL_USE_INTRIN_OPTION_STR} FORCE)
endif()

# [option] SEAL_USE_${A_SPECIFIC_INTRIN} (default: ON, advanced)
# Not available if SEAL_USE_INTRIN is OFF.
# Use a specific intrinsic if available, set to OFF otherwise.
include(CheckCXXIntrinsicsSpecific)

if(MSVC)
    set(SEAL_USE__UMUL128_OPTION_STR "Use _umul128")
    cmake_dependent_option(SEAL_USE__UMUL128 ${SEAL_USE__UMUL128_OPTION_STR} ON "SEAL_USE_INTRIN" OFF)
    mark_as_advanced(FORCE SEAL_USE__UMUL128)
    if(NOT SEAL__UMUL128_FOUND)
        set(SEAL_USE__UMUL128 OFF CACHE BOOL ${SEAL_USE__UMUL128_OPTION_STR} FORCE)
    endif()

    set(SEAL_USE__BITSCANREVERSE64_OPTION_STR "Use _BitScanReverse64")
    cmake_dependent_option(SEAL_USE__BITSCANREVERSE64 ${SEAL_USE__BITSCANREVERSE64_OPTION_STR} ON "SEAL_USE_INTRIN" OFF)
    mark_as_advanced(FORCE SEAL_USE__BITSCANREVERSE64)
    if(NOT SEAL__BITSCANREVERSE64_FOUND)
        set(SEAL_USE__BITSCANREVERSE64 OFF CACHE BOOL ${SEAL_USE__BITSCANREVERSE64_OPTION_STR} FORCE)
    endif()
else()
    set(SEAL_USE___INT128_OPTION_STR "Use __int128")
    cmake_dependent_option(SEAL_USE___INT128 ${SEAL_USE___INT128_OPTION_STR} ON "SEAL_USE_INTRIN" OFF)
    mark_as_advanced(FORCE SEAL_USE___INT128)
    if(NOT SEAL___INT128_FOUND)
        set(SEAL_USE___INT128 OFF CACHE BOOL ${SEAL_USE___INT128_OPTION_STR} FORCE)
    endif()

    set(SEAL_USE___BUILTIN_CLZLL_OPTION_STR "Use __builtin_clzll")
    cmake_dependent_option(SEAL_USE___BUILTIN_CLZLL ${SEAL_USE___BUILTIN_CLZLL_OPTION_STR} ON "SEAL_USE_INTRIN" OFF)
    mark_as_advanced(FORCE SEAL_USE___BUILTIN_CLZLL)
    if(NOT SEAL___BUILTIN_CLZLL_FOUND)
        set(SEAL_USE___BUILTIN_CLZLL OFF CACHE BOOL ${SEAL_USE___BUILTIN_CLZLL_OPTION_STR} FORCE)
    endif()
endif()

set(SEAL_USE__ADDCARRY_U64_OPTION_STR "Use _addcarry_u64")
cmake_dependent_option(SEAL_USE__ADDCARRY_U64 ${SEAL_USE__ADDCARRY_U64_OPTION_STR} ON "SEAL_USE_INTRIN" OFF)
mark_as_advanced(FORCE SEAL_USE__ADDCARRY_U64)
if(NOT SEAL__ADDCARRY_U64_FOUND)
    set(SEAL_USE__ADDCARRY_U64 OFF CACHE BOOL ${SEAL_USE__ADDCARRY_U64_OPTION_STR} FORCE)
endif()

set(SEAL_USE__SUBBORROW_U64_OPTION_STR "Use _subborrow_u64")
cmake_dependent_option(SEAL_USE__SUBBORROW_U64 ${SEAL_USE__SUBBORROW_U64_OPTION_STR} ON "SEAL_USE_INTRIN" OFF)
mark_as_advanced(FORCE SEAL_USE__SUBBORROW_U64)
if(NOT SEAL__SUBBORROW_U64_FOUND)
    set(SEAL_USE__SUBBORROW_U64 OFF CACHE BOOL ${SEAL_USE__SUBBORROW_U64_OPTION_STR} FORCE)
endif()

# [option] SEAL_USE_${A_SPECIFIC_MEMSET_METHOD} (default: ON, advanced)
# Use a specific memset method if available, set to OFF otherwise.
include(CheckMemset)

set(SEAL_USE_MEMSET_S_OPTION_STR "Use memset_s")
option(SEAL_USE_MEMSET_S ${SEAL_USE_MEMSET_S_OPTION_STR} ON)
mark_as_advanced(FORCE SEAL_USE_MEMSET_S)
if(NOT SEAL_MEMSET_S_FOUND)
    set(SEAL_USE_MEMSET_S OFF CACHE BOOL ${SEAL_USE_MEMSET_S_OPTION_STR} FORCE)
endif()

set(SEAL_USE_EXPLICIT_BZERO_OPTION_STR "Use explicit_bzero")
option(SEAL_USE_EXPLICIT_BZERO ${SEAL_USE_EXPLICIT_BZERO_OPTION_STR} ON)
mark_as_advanced(FORCE SEAL_USE_EXPLICIT_BZERO)
if(NOT SEAL_EXPLICIT_BZERO_FOUND)
    set(SEAL_USE_EXPLICIT_BZERO OFF CACHE BOOL ${SEAL_USE_EXPLICIT_BZERO_OPTION_STR} FORCE)
endif()

set(SEAL_USE_EXPLICIT_MEMSET_OPTION_STR "Use explicit_memset")
option(SEAL_USE_EXPLICIT_MEMSET ${SEAL_USE_EXPLICIT_MEMSET_OPTION_STR} ON)
mark_as_advanced(FORCE SEAL_USE_EXPLICIT_MEMSET)
if(NOT SEAL_EXPLICIT_MEMSET_FOUND)
    set(SEAL_USE_EXPLICIT_MEMSET OFF CACHE BOOL ${SEAL_USE_EXPLICIT_MEMSET_OPTION_STR} FORCE)
endif()

# Add source files to library and header files to install
set(SEAL_SOURCE_FILES "")
add_subdirectory(native/src/seal)

# Build only a static library
if(NOT BUILD_SHARED_LIBS)
    add_library(seal STATIC ${SEAL_SOURCE_FILES})
    seal_set_version_filename(seal)
    seal_set_language(seal)
    seal_set_include_directories(seal)
    seal_set_version(seal)
    seal_link_threads(seal)
    seal_install_target(seal SEALTargets)

    if(SEAL_USE_MSGSL)
        if(SEAL_BUILD_DEPS)
            target_include_directories(seal PUBLIC $<BUILD_INTERFACE:${msgsl_SOURCE_DIR}/include>)
        else()
            target_link_libraries(seal PUBLIC Microsoft.GSL::GSL)
        endif()
    endif()

    if(SEAL_USE_ZLIB)
        if(SEAL_BUILD_DEPS)
            add_dependencies(seal ${zlib})
            target_include_directories(seal PRIVATE $<BUILD_INTERFACE:${zlib_SOURCE_DIR}>)
            target_include_directories(seal PRIVATE $<BUILD_INTERFACE:$<TARGET_PROPERTY:${zlib},BINARY_DIR>>)
            seal_combine_archives(seal ${zlib})
        else()
            target_link_libraries(seal PRIVATE ${zlib})
        endif()
    endif()

    if(SEAL_USE_ZSTD)
        if(SEAL_BUILD_DEPS)
            add_dependencies(seal ${zstd_static})
            target_include_directories(seal PRIVATE $<BUILD_INTERFACE:${zstd_SOURCE_DIR}/lib>)
            target_include_directories(seal PRIVATE $<BUILD_INTERFACE:${zstd_SOURCE_DIR}/lib/common>)
            seal_combine_archives(seal ${zstd_static})
        else()
            target_link_libraries(seal PRIVATE ${zstd_static})
        endif()
    endif()

# Build only a shared library
else()
    add_library(seal_shared SHARED ${SEAL_SOURCE_FILES})
    seal_set_soversion(seal_shared)
    set_target_properties(seal_shared PROPERTIES OUTPUT_NAME seal)
    seal_set_language(seal_shared)
    seal_set_include_directories(seal_shared)
    seal_set_version(seal_shared)
    seal_link_threads(seal_shared)
    seal_install_target(seal_shared SEALTargets)

    if(SEAL_USE_MSGSL)
        if(SEAL_BUILD_DEPS)
            target_include_directories(seal_shared PUBLIC $<BUILD_INTERFACE:${msgsl_SOURCE_DIR}/include>)
        else()
            target_link_libraries(seal_shared PUBLIC Microsoft.GSL::GSL)
        endif()
    endif()

    if(SEAL_USE_ZLIB)
        if(SEAL_BUILD_DEPS)
            target_link_libraries(seal_shared PRIVATE ${zlib})
        else()
            target_link_libraries(seal_shared PRIVATE ${zlib})
        endif()
    endif()

    if(SEAL_USE_ZSTD)
        if(SEAL_BUILD_DEPS)
            target_link_libraries(seal_shared PRIVATE ${zstd_static})
        else()
            target_link_libraries(seal_shared PRIVATE ${zstd_static})
        endif()
    endif()

    if(MSVC)
        target_link_libraries(seal_shared PRIVATE BCrypt::bcrypt)
    endif()
endif()

#########################
# SEAL C export library #
#########################

# Check that size_t is 8 bytes
include(CheckTypeSize)
check_type_size("size_t" SIZET LANGUAGE C)

set(SEAL_BUILD_SEAL_C_OPTION_STR "Build C export library for Microsoft SEAL")
cmake_dependent_option(SEAL_BUILD_SEAL_C ${SEAL_BUILD_SEAL_C_OPTION_STR} OFF "${SIZET} EQUAL 8" OFF)

set(BUILD_STATIC_SEALC_LIB_OPTION_STR "Build static C library for Microsoft SEAL")
cmake_dependent_option(BUILD_STATIC_SEALC_LIB ${BUILD_STATIC_SEALC_LIB_OPTION_STR} OFF "SEAL_BUILD_SEAL_C" OFF)

unset(SIZET CACHE)
unset(HAVE_SIZET CACHE)

# Create SEAL_C library but add no source files yet
if(SEAL_BUILD_SEAL_C)
    if(BUILD_STATIC_SEALC_LIB)
        add_library(sealc STATIC)
    else()
        add_library(sealc SHARED)
    endif()

    # Add source files to library and header files to install
    add_subdirectory(native/src/seal/c)
    seal_set_version(sealc)
    if(BUILD_STATIC_SEALC_LIB)
        seal_set_version_filename(sealc)
    else()
        seal_set_soversion(sealc)
    endif()
    seal_set_language(sealc)
    seal_set_include_directories(sealc)

    if(NOT BUILD_SHARED_LIBS)
        target_link_libraries(sealc PUBLIC seal)
    else()
        message(FATAL_ERROR "SEAL_C requires `BUILD_SHARED_LIBS=OFF`")
    endif()

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

# In UNIX-like platforms install MSGSL header files if SEAL_BUILD_DEPS is ON
if(SEAL_USE_MSGSL AND SEAL_BUILD_DEPS AND NOT MSVC)
    install(
        DIRECTORY
            ${msgsl_SOURCE_DIR}/include/gsl
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
    if(NOT BUILD_SHARED_LIBS)
        target_link_libraries(sealexamples PRIVATE seal)
    else()
        target_link_libraries(sealexamples PRIVATE seal_shared)
    endif()
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
    if(NOT BUILD_SHARED_LIBS)
        target_link_libraries(sealtest PRIVATE seal GTest::gtest)
    else()
        target_link_libraries(sealtest PRIVATE seal_shared GTest::gtest)
    endif()
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
    set(SEAL_WINDOWS_SEAL_C_PATH ${CMAKE_LIBRARY_RUNTIME_DIRECTORY}/sealc.dll)
elseif(UNIX)
    set(SEAL_LINUX_SEAL_C_PATH ${CMAKE_LIBRARY_OUTPUT_DIRECTORY}/libsealc.so)
elseif(APPLE)
    set(SEAL_MACOS_SEAL_C_PATH ${CMAKE_LIBRARY_OUTPUT_DIRECTORY}/libsealc.dylib)
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
