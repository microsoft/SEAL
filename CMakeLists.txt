# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT license.

cmake_minimum_required(VERSION 3.13)

###################################################
# Project SEAL includes the following components: #
#   1. SEAL C++ library                           #
#   2. SEAL C export library                      #
#   3. SEAL C++ examples                          #
#   4. SEAL C++ tests                             #
###################################################

# [option] CMAKE_BUILD_TYPE (default: "Release")
# Build in one of the following modes: Release, Debug, MiniSizeRel, or RelWithDebInfo.
# Most generators recognize these and can set the compiler flags accordingly. We set
# the build type here before creating the project to prevent the CMake generator from
# overriding our default of "Release".
if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE "Release" CACHE STRING "Build type" FORCE)
    set_property(CACHE CMAKE_BUILD_TYPE PROPERTY
        STRINGS "Release" "Debug" "MinSizeRel" "RelWithDebInfo")
endif()
message(STATUS "Build type (CMAKE_BUILD_TYPE): ${CMAKE_BUILD_TYPE}")

project(SEAL VERSION 4.1.2 LANGUAGES CXX C)

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
include(CheckSymbolExists)

# Extra modules
list(APPEND CMAKE_MODULE_PATH ${CMAKE_CURRENT_LIST_DIR}/cmake)
include(SEALMacros)

# Always build position-independent-code
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

# Make the install target depend on the all target (required by vcpkg)
set(CMAKE_SKIP_INSTALL_ALL_DEPENDENCY OFF)

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
message(STATUS "SEAL_USE_CXX17: ${SEAL_USE_CXX17}")

# Enable features from C++17 if available, disable features if set to OFF.
include(EnableCXX17)

# Enable security-related compile options (MSVC only)
set(SEAL_SECURE_COMPILE_OPTIONS_OPTIONS_STR "Enable Control Flow Guard and Spectre mitigations (MSVC only)")
option(SEAL_SECURE_COMPILE_OPTIONS ${SEAL_SECURE_COMPILE_OPTIONS_OPTIONS_STR} OFF)
mark_as_advanced(SEAL_SECURE_COMPILE_OPTIONS)

# Path for output
if(ANDROID_ABI)
    # Android compiles several targets at the same time. Need to specify
    # separate directories for separate ABIs.
    set(OUTLIB_PATH "lib/${ANDROID_ABI}")
else()
    set(OUTLIB_PATH "lib")
endif()

# Required files and directories
include(GNUInstallDirs)

# Runtime path setup
set(CMAKE_INSTALL_RPATH "${CMAKE_INSTALL_PREFIX}/${CMAKE_INSTALL_LIBDIR}")
set(CMAKE_INSTALL_RPATH_USE_LINK_PATH TRUE)

# Source Tree
set(SEAL_INCLUDES_DIR ${CMAKE_CURRENT_LIST_DIR}/native/src)
set(SEAL_CONFIG_IN_FILENAME ${CMAKE_CURRENT_LIST_DIR}/cmake/SEALConfig.cmake.in)
set(SEAL_CONFIG_H_IN_FILENAME ${SEAL_INCLUDES_DIR}/seal/util/config.h.in)

# Build tree
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/${OUTLIB_PATH})
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/${OUTLIB_PATH})
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/bin)
set(SEAL_TARGETS_FILENAME ${CMAKE_CURRENT_BINARY_DIR}/cmake/SEALTargets.cmake)
set(SEAL_CONFIG_FILENAME ${CMAKE_CURRENT_BINARY_DIR}/cmake/SEALConfig.cmake)
set(SEAL_CONFIG_VERSION_FILENAME ${CMAKE_CURRENT_BINARY_DIR}/cmake/SEALConfigVersion.cmake)
set(SEAL_CONFIG_H_FILENAME ${CMAKE_CURRENT_BINARY_DIR}/native/src/seal/util/config.h)
set(SEAL_THIRDPARTY_DIR ${CMAKE_CURRENT_BINARY_DIR}/thirdparty)

# Install
set(SEAL_CONFIG_INSTALL_DIR ${CMAKE_INSTALL_LIBDIR}/cmake/SEAL-${SEAL_VERSION_MAJOR}.${SEAL_VERSION_MINOR})
set(SEAL_INCLUDES_INSTALL_DIR ${CMAKE_INSTALL_INCLUDEDIR}/SEAL-${SEAL_VERSION_MAJOR}.${SEAL_VERSION_MINOR})

# pkg-config
set(SEAL_PKGCONFIG_IN_DIR ${CMAKE_CURRENT_LIST_DIR}/pkgconfig)
set(SEAL_PKGCONFIG_IN_FILENAME ${SEAL_PKGCONFIG_IN_DIR}/seal.pc.in)
set(SEAL_PKGCONFIG_SHARED_IN_FILENAME ${SEAL_PKGCONFIG_IN_DIR}/seal_shared.pc.in)
set(SEAL_PKGCONFIG_MSGSL_IN_FILENAME ${SEAL_PKGCONFIG_IN_DIR}/seal_msgsl.pc.in)
set(SEAL_PKGCONFIG_DIR ${CMAKE_CURRENT_BINARY_DIR}/pkgconfig)
set(SEAL_PKGCONFIG_FILENAME ${SEAL_PKGCONFIG_DIR}/seal.pc)
set(SEAL_PKGCONFIG_SHARED_FILENAME ${SEAL_PKGCONFIG_DIR}/seal_shared.pc)
set(SEAL_PKGCONFIG_MSGSL_FILENAME ${SEAL_PKGCONFIG_DIR}/seal_msgsl.pc)
set(SEAL_PKGCONFIG_INSTALL_DIR ${CMAKE_INSTALL_LIBDIR}/pkgconfig)

# Clean up artifacts from previous versions
include(CleanArtifacts)

#########################
# External dependencies #
#########################

# [option] SEAL_BUILD_DEPS (default: ON)
# Download and build missing dependencies, throw error if disabled.
set(SEAL_BUILD_DEPS_OPTION_STR "Automatically download and build unmet dependencies")
option(SEAL_BUILD_DEPS ${SEAL_BUILD_DEPS_OPTION_STR} ON)
message(STATUS "SEAL_BUILD_DEPS: ${SEAL_BUILD_DEPS}")

if(SEAL_BUILD_DEPS)
    include(FetchContent)
    mark_as_advanced(FETCHCONTENT_BASE_DIR)
    mark_as_advanced(FETCHCONTENT_FULLY_DISCONNECTED)
    mark_as_advanced(FETCHCONTENT_UPDATES_DISCONNECTED)
    mark_as_advanced(FETCHCONTENT_QUIET)
endif()

# [option] SEAL_USE_MSGSL (default: ON)
set(SEAL_USE_MSGSL_OPTION_STR "Use Microsoft GSL")
option(SEAL_USE_MSGSL ${SEAL_USE_MSGSL_OPTION_STR} ON)
message(STATUS "SEAL_USE_MSGSL: ${SEAL_USE_MSGSL}")

if(SEAL_USE_MSGSL)
    if(SEAL_BUILD_DEPS)
        message(STATUS "Microsoft GSL: download ...")
        seal_fetch_thirdparty_content(ExternalMSGSL)
    else()
        find_package(Microsoft.GSL 4 CONFIG)
        if(NOT Microsoft.GSL_FOUND)
            message(FATAL_ERROR "Microsoft GSL: not found")
        else()
            message(STATUS "Microsoft GSL: found")
        endif()
    endif()
endif()

# [option] SEAL_USE_ZLIB (default: ON)
set(SEAL_USE_ZLIB_OPTION_STR "Use ZLIB for compressed serialization")
option(SEAL_USE_ZLIB ${SEAL_USE_ZLIB_OPTION_STR} ON)
message(STATUS "SEAL_USE_ZLIB: ${SEAL_USE_ZLIB}")

if(SEAL_USE_ZLIB)
    if(SEAL_BUILD_DEPS)
        message(STATUS "ZLIB: download ...")
        seal_fetch_thirdparty_content(ExternalZLIB)
        set(zlib "zlibstatic")
    else()
        find_package(ZLIB 1)
        if(NOT ZLIB_FOUND)
            message(FATAL_ERROR "ZLIB: not found")
        else()
            message(STATUS "ZLIB: found")
        endif()
        set(zlib "ZLIB::ZLIB")
    endif()
endif()

# [option] SEAL_USE_ZSTD (default: ON)
set(SEAL_USE_ZSTD_OPTION_STR "Use Zstandard for compressed serialization")
option(SEAL_USE_ZSTD ${SEAL_USE_ZSTD_OPTION_STR} ON)
message(STATUS "SEAL_USE_ZSTD: ${SEAL_USE_ZSTD}")

if(SEAL_USE_ZSTD)
    if(SEAL_BUILD_DEPS)
        message(STATUS "Zstandard: download ...")
        seal_fetch_thirdparty_content(ExternalZSTD)
        set(zstd_static "libzstd_static")
    else()
        find_package(zstd CONFIG)
        if(NOT zstd_FOUND)
            message(FATAL_ERROR "Zstandard: not found")
        else()
            if(TARGET zstd::libzstd_static)
                set(zstd_static "zstd::libzstd_static")
            elseif(TARGET libzstd)
                get_target_property(libzstd_type libzstd TYPE)
                if(libzstd_type STREQUAL "STATIC_LIBRARY")
                    set(zstd_static "libzstd")
                    message(STATUS "Zstandard: found")
                else()
                    message(FATAL_ERROR "Zstandard: must be static")
                endif()
            elseif(TARGET zstd::libzstd_shared)
                message(FATAL_ERROR "Zstandard: must be static")
            else()
                message(FATAL_ERROR "Zstandard: not found")
            endif()
        endif()
    endif()
endif()

# [option] SEAL_USE_INTEL_HEXL (default: OFF)
set(SEAL_USE_INTEL_HEXL_OPTION_STR "Use Intel HEXL library")
option(SEAL_USE_INTEL_HEXL ${SEAL_USE_INTEL_HEXL_OPTION_STR} OFF)
message(STATUS "SEAL_USE_INTEL_HEXL: ${SEAL_USE_INTEL_HEXL}")

if(SEAL_USE_INTEL_HEXL)
    if(SEAL_BUILD_DEPS)
        message(STATUS "Intel HEXL: download ...")
        seal_fetch_thirdparty_content(ExternalIntelHEXL)
    else()
        find_package(HEXL 1.2.4)
        if (NOT TARGET HEXL::hexl)
            message(FATAL_ERROR "Intel HEXL: not found")
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
message(STATUS "BUILD_SHARED_LIBS: ${BUILD_SHARED_LIBS}")
if(WIN32 AND BUILD_SHARED_LIBS)
    message(FATAL_ERROR "On Windows only static build is supported; set `BUILD_SHARED_LIBS=OFF`")
endif()

# [option] SEAL_THROW_ON_TRANSPARENT_CIPHERTEXT (default: ON)
set(SEAL_THROW_ON_TRANSPARENT_CIPHERTEXT_STR "Throw an exception when Evaluator outputs a transparent ciphertext")
option(SEAL_THROW_ON_TRANSPARENT_CIPHERTEXT ${SEAL_THROW_ON_TRANSPARENT_CIPHERTEXT_STR} ON)
message(STATUS "SEAL_THROW_ON_TRANSPARENT_CIPHERTEXT: ${SEAL_THROW_ON_TRANSPARENT_CIPHERTEXT}")
mark_as_advanced(FORCE SEAL_THROW_ON_TRANSPARENT_CIPHERTEXT)

# [option] SEAL_USE_GAUSSIAN_NOISE (default: OFF)
# Use Gaussian distribution for noise sampling if set to ON, use centered binomial otherwise.
set(SEAL_USE_GAUSSIAN_NOISE_STR "Use a rounded Gaussian distribution for noise sampling instead of a Centered Binomial Distribution")
option(SEAL_USE_GAUSSIAN_NOISE ${SEAL_USE_GAUSSIAN_NOISE_STR} OFF)
message(STATUS "SEAL_USE_GAUSSIAN_NOISE: ${SEAL_USE_GAUSSIAN_NOISE}")
mark_as_advanced(FORCE SEAL_USE_GAUSSIAN_NOISE)

# [option] SEAL_DEFAULT_PRNG (default: Blake2xb)
# Choose either Blake2xb or Shake256 to be the default PRNG.
set(SEAL_DEFAULT_PRNG_STR "Choose the default PRNG")
set(SEAL_DEFAULT_PRNG "Blake2xb" CACHE STRING ${SEAL_DEFAULT_PRNG_STR} FORCE)
message(STATUS "SEAL_DEFAULT_PRNG: ${SEAL_DEFAULT_PRNG}")
set_property(CACHE SEAL_DEFAULT_PRNG PROPERTY
    STRINGS "Blake2xb" "Shake256")
mark_as_advanced(FORCE SEAL_DEFAULT_PRNG)

# [option] SEAL_AVOID_BRANCHING (default: OFF)
# Avoid branching in critical conditional move operations if set to ON, use faster method if set to OFF.
set(SEAL_AVOID_BRANCHING_STR "Use an always branching-free conditional move")
option(SEAL_AVOID_BRANCHING ${SEAL_AVOID_BRANCHING_STR} OFF)
message(STATUS "SEAL_AVOID_BRANCHING: ${SEAL_AVOID_BRANCHING}")
mark_as_advanced(FORCE SEAL_AVOID_BRANCHING)

# [option] SEAL_USE_INTRIN (default: ON)
set(SEAL_USE_INTRIN_OPTION_STR "Use intrinsics")
option(SEAL_USE_INTRIN ${SEAL_USE_INTRIN_OPTION_STR} ON)
# Look for header files, use intrinsics if available, set to OFF otherwise.
include(CheckCXXIntrinsicsHeader)
if(NOT SEAL_INTRIN_HEADER_FOUND)
    set(SEAL_USE_INTRIN OFF CACHE BOOL ${SEAL_USE_INTRIN_OPTION_STR} FORCE)
endif()
message(STATUS "SEAL_USE_INTRIN: ${SEAL_USE_INTRIN}")

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
message(STATUS "SEAL_USE_MEMSET_S: ${SEAL_USE_MEMSET_S}")

set(SEAL_USE_EXPLICIT_BZERO_OPTION_STR "Use explicit_bzero")
option(SEAL_USE_EXPLICIT_BZERO ${SEAL_USE_EXPLICIT_BZERO_OPTION_STR} ON)
mark_as_advanced(FORCE SEAL_USE_EXPLICIT_BZERO)
if(NOT SEAL_EXPLICIT_BZERO_FOUND)
    set(SEAL_USE_EXPLICIT_BZERO OFF CACHE BOOL ${SEAL_USE_EXPLICIT_BZERO_OPTION_STR} FORCE)
endif()
message(STATUS "SEAL_USE_EXPLICIT_BZERO: ${SEAL_USE_EXPLICIT_BZERO}")

set(SEAL_USE_EXPLICIT_MEMSET_OPTION_STR "Use explicit_memset")
option(SEAL_USE_EXPLICIT_MEMSET ${SEAL_USE_EXPLICIT_MEMSET_OPTION_STR} ON)
mark_as_advanced(FORCE SEAL_USE_EXPLICIT_MEMSET)
if(NOT SEAL_EXPLICIT_MEMSET_FOUND)
    set(SEAL_USE_EXPLICIT_MEMSET OFF CACHE BOOL ${SEAL_USE_EXPLICIT_MEMSET_OPTION_STR} FORCE)
endif()
message(STATUS "SEAL_USE_EXPLICIT_MEMSET: ${SEAL_USE_EXPLICIT_MEMSET}")

# [option] SEAL_USE_ALIGNED_ALLOC (default: ON, advanced)
# Not available if SEAL_USE_CXX17 is OFF or building for Android.
# Use 64-byte aligned malloc if available, set of OFF otherwise
if(MSVC)
    set(SEAL_USE_ALIGNED_ALLOC_OPTION_STR "Use _aligned_malloc")
else()
    set(SEAL_USE_ALIGNED_ALLOC_OPTION_STR "Use ::aligned_alloc")
endif()
cmake_dependent_option(SEAL_USE_ALIGNED_ALLOC ${SEAL_USE_ALIGNED_ALLOC_OPTION_STR} ON "SEAL_USE_CXX17;NOT ANDROID_ABI" OFF)
mark_as_advanced(FORCE SEAL_USE_ALIGNED_ALLOC)

# Add source files to library and header files to install
set(SEAL_SOURCE_FILES "")
add_subdirectory(native/src/seal)

# Create the config file
configure_file(${SEAL_CONFIG_H_IN_FILENAME} ${SEAL_CONFIG_H_FILENAME})
install(
    FILES ${SEAL_CONFIG_H_FILENAME}
    DESTINATION ${SEAL_INCLUDES_INSTALL_DIR}/seal/util)

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

    if(SEAL_USE_INTEL_HEXL)
        if(SEAL_BUILD_DEPS)
            add_dependencies(seal HEXL::hexl)
            target_include_directories(seal PRIVATE
                $<BUILD_INTERFACE:$<TARGET_PROPERTY:HEXL::hexl,INTERFACE_INCLUDE_DIRECTORIES>>)
            target_compile_options(seal PRIVATE $<TARGET_PROPERTY:HEXL::hexl,INTERFACE_COMPILE_OPTIONS>)
            get_target_property(HEXL_INTERFACE_LINK_OPTIONS HEXL::hexl INTERFACE_LINK_OPTIONS)
            if (NOT "${HEXL_INTERFACE_LINK_OPTIONS}" STREQUAL "HEXL_INTERFACE_LINK_OPTIONS-NOTFOUND")
                target_link_libraries(seal INTERFACE ${HEXL_INTERFACE_LINK_OPTIONS})
            endif()
            seal_combine_archives(seal HEXL::hexl)
        else()
            target_link_libraries(seal PUBLIC HEXL::hexl)
        endif()
    endif()

    # Set secure compile options if SEAL_SECURE_COMPILE_OPTIONS is ON; only supported on MSVC
    if(SEAL_SECURE_COMPILE_OPTIONS)
        seal_set_secure_compile_options(seal PUBLIC)
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
        target_link_libraries(seal_shared PRIVATE ${zlib})
        target_include_directories(seal_shared PRIVATE $<BUILD_INTERFACE:${zlib_SOURCE_DIR}>)
        target_include_directories(seal_shared PRIVATE $<BUILD_INTERFACE:$<TARGET_PROPERTY:${zlib},BINARY_DIR>>)
    endif()

    if(SEAL_USE_ZSTD)
        target_include_directories(seal_shared PRIVATE $<BUILD_INTERFACE:${zstd_SOURCE_DIR}/lib>)
        target_include_directories(seal_shared PRIVATE $<BUILD_INTERFACE:${zstd_SOURCE_DIR}/lib/common>)
        target_link_libraries(seal_shared PRIVATE ${zstd_static})
    endif()

    if(SEAL_USE_INTEL_HEXL)
        target_link_libraries(seal_shared PRIVATE HEXL::hexl)
        target_compile_options(seal_shared PRIVATE $<TARGET_PROPERTY:HEXL::hexl,INTERFACE_COMPILE_OPTIONS>)
        get_target_property(HEXL_INTERFACE_LINK_OPTIONS HEXL::hexl INTERFACE_LINK_OPTIONS)
        if (NOT "${HEXL_INTERFACE_LINK_OPTIONS}" STREQUAL "HEXL_INTERFACE_LINK_OPTIONS-NOTFOUND")
            target_link_libraries(seal_shared INTERFACE ${HEXL_INTERFACE_LINK_OPTIONS})
        endif()

        # Install shared HEXL library to installation directory
        install(DIRECTORY ${CMAKE_LIBRARY_OUTPUT_DIRECTORY}
            DESTINATION ${CMAKE_INSTALL_PREFIX}/${CMAKE_LIBRARY_PREFIX}
            FILES_MATCHING PATTERN "*hexl*"
            )
    endif()
endif()

# Add standard alias targets for SEAL::seal and SEAL::seal_shared
if(TARGET seal)
    add_library(SEAL::seal ALIAS seal)
endif()
if(TARGET seal_shared)
    add_library(SEAL::seal_shared ALIAS seal_shared)
endif()

#########################
# SEAL C export library #
#########################

# [option] SEAL_BUILD_SEAL_C (default: OFF)
set(SEAL_BUILD_SEAL_C_OPTION_STR "Build C export library for Microsoft SEAL")
option(SEAL_BUILD_SEAL_C ${SEAL_BUILD_SEAL_C_OPTION_STR} OFF)
message(STATUS "SEAL_BUILD_SEAL_C: ${SEAL_BUILD_SEAL_C}")

set(SEAL_BUILD_STATIC_SEAL_C_OPTION_STR "Build static C library for Microsoft SEAL")
cmake_dependent_option(SEAL_BUILD_STATIC_SEAL_C ${SEAL_BUILD_STATIC_SEAL_C_OPTION_STR} OFF "SEAL_BUILD_SEAL_C" OFF)
mark_as_advanced(SEAL_BUILD_STATIC_SEAL_C)

# Create SEAL_C library but add no source files yet
if(SEAL_BUILD_SEAL_C)
    # Check that size_t is 8 bytes
    include(CheckTypeSize)
    check_type_size("size_t" SIZET LANGUAGE C)
    if(NOT ${SIZET} EQUAL 8)
        unset(SIZET CACHE)
        unset(HAVE_SIZET CACHE)
        message(FATAL_ERROR "SEAL_C requires 64-bit platform")
    endif()
    unset(SIZET CACHE)
    unset(HAVE_SIZET CACHE)

    if(BUILD_SHARED_LIBS)
        message(FATAL_ERROR "SEAL_C (shared or static) requires a static SEAL; set `BUILD_SHARED_LIBS=OFF` and control "
                            "SEAL_C by setting `SEAL_BUILD_STATIC_SEAL_C` to `OFF` (default) or `ON`")
    endif()

    if(NOT SEAL_BUILD_DEPS)
        message(FATAL_ERROR "SEAL_C requires `SEAL_BUILD_DEPS=ON`")
    endif()

    if(NOT SEAL_BUILD_STATIC_SEAL_C AND SEAL_USE_INTEL_HEXL AND CMAKE_BUILD_TYPE STREQUAL "Debug" AND UNIX)
        message(WARNING "SEAL_C (shared) cannot find Address Sanitizer (libasan) enabled by Intel HEXL in Debug mode "
                        "on Unix-like systems. SEALNet does not work. Preload libasan for downstream applications.")
    endif()

    if(SEAL_BUILD_STATIC_SEAL_C)
        add_library(sealc STATIC)
    else()
        add_library(sealc SHARED)
    endif()

    # Add source files to library and header files to install
    add_subdirectory(${SEAL_INCLUDES_DIR}/seal/c)
    seal_set_version(sealc)
    if(SEAL_BUILD_STATIC_SEAL_C)
        seal_set_version_filename(sealc)
    else()
        seal_set_soversion(sealc)
    endif()
    seal_set_language(sealc)
    seal_set_include_directories(sealc)
    if (SEAL_USE_INTEL_HEXL)
        target_include_directories(sealc PRIVATE $<BUILD_INTERFACE:${hexl_SOURCE_DIR}/hexl/include>)
    endif()

    target_link_libraries(sealc PUBLIC seal)

    seal_install_target(sealc SEALTargets)
endif()

# Add standard alias target for SEAL::sealc
if(TARGET sealc)
    add_library(SEAL::sealc ALIAS sealc)
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

# Install header files of dependencies if SEAL_BUILD_DEPS is ON
if(SEAL_BUILD_DEPS)
    # MSGSL
    if(SEAL_USE_MSGSL)
        install(
            DIRECTORY ${msgsl_SOURCE_DIR}/include/gsl
            DESTINATION ${SEAL_INCLUDES_INSTALL_DIR})
    endif()
endif()

##############
# pkg-config #
##############

if(UNIX OR APPLE)
    # Set the requirements according to the current configuration if SEAL_BUILD_DEPS=OFF
    if(NOT SEAL_BUILD_DEPS)
        if(SEAL_USE_MSGSL)
            # Extract the include directories from Microsoft.GSL::GSL
            get_target_property(
                SEAL_PKGCONFIG_MSGSL_INCLUDE_DIR
                Microsoft.GSL::GSL
                INTERFACE_INCLUDE_DIRECTORIES)

            # Create the Microsoft GSL pkg-config file
            configure_file(${SEAL_PKGCONFIG_MSGSL_IN_FILENAME} ${SEAL_PKGCONFIG_MSGSL_FILENAME} @ONLY)

            set(SEAL_PKGCONFIG_MSGSL_REQUIRES_STRING "seal_msgsl >= ${Microsoft.GSL_VERSION_MAJOR}")
        endif()
        if(SEAL_USE_ZLIB)
            set(SEAL_PKGCONFIG_ZLIB_REQUIRES_STRING "zlib = ${ZLIB_VERSION_STRING}")
        endif()
        if(SEAL_USE_ZSTD)
            set(SEAL_PKGCONFIG_ZSTD_REQUIRES_STRING "libzstd >= ${zstd_VERSION_MAJOR}")
        endif()
        if(SEAL_USE_INTEL_HEXL)
            set(SEAL_PKGCONFIG_INTEL_HEXL_REQUIRES_STRING "hexl >= ${HEXL_VERSION_MAJOR}")
            message(STATUS "Intel HEXL does not have a pkg-config file")
        endif()
    endif()

    # Create the pkg-config file
    if(TARGET seal)
        configure_file(${SEAL_PKGCONFIG_IN_FILENAME} ${SEAL_PKGCONFIG_FILENAME} @ONLY)
    endif()
    if(TARGET seal_shared)
        configure_file(${SEAL_PKGCONFIG_SHARED_IN_FILENAME} ${SEAL_PKGCONFIG_SHARED_FILENAME} @ONLY)
    endif()

    # Install the pkg-config files
    if(EXISTS ${SEAL_PKGCONFIG_FILENAME})
        install(
            FILES ${SEAL_PKGCONFIG_FILENAME}
            DESTINATION ${SEAL_PKGCONFIG_INSTALL_DIR})
    endif()
    if(EXISTS ${SEAL_PKGCONFIG_SHARED_FILENAME})
        install(
            FILES ${SEAL_PKGCONFIG_SHARED_FILENAME}
            DESTINATION ${SEAL_PKGCONFIG_INSTALL_DIR})
    endif()
    if(EXISTS ${SEAL_PKGCONFIG_MSGSL_FILENAME})
        install(
            FILES ${SEAL_PKGCONFIG_MSGSL_FILENAME}
            DESTINATION ${SEAL_PKGCONFIG_INSTALL_DIR})
    endif()
endif()

#####################
# SEAL C++ examples #
#####################

# [option] SEAL_BUILD_EXAMPLES
set(SEAL_BUILD_EXAMPLES_OPTION_STR "Build C++ examples for Microsoft SEAL")
option(SEAL_BUILD_EXAMPLES ${SEAL_BUILD_EXAMPLES_OPTION_STR} OFF)
message(STATUS "SEAL_BUILD_EXAMPLES: ${SEAL_BUILD_EXAMPLES}")

if(SEAL_BUILD_EXAMPLES)
    add_subdirectory(native/examples)
endif()

##################
# SEAL C++ tests #
##################

# [option] SEAL_BUILD_TESTS
set(SEAL_BUILD_TESTS_OPTION_STR "Build C++ tests for Microsoft SEAL")
option(SEAL_BUILD_TESTS ${SEAL_BUILD_TESTS_OPTION_STR} OFF)
message(STATUS "SEAL_BUILD_TESTS: ${SEAL_BUILD_TESTS}")

if(SEAL_BUILD_TESTS)
    add_subdirectory(native/tests)
endif()

#######################
# SEAL C++ benchmarks #
#######################

# [option] SEAL_BUILD_BENCH
set(SEAL_BUILD_BENCH_OPTION_STR "Build C++ benchmarks for Microsoft SEAL")
option(SEAL_BUILD_BENCH ${SEAL_BUILD_BENCH_OPTION_STR} OFF)
message(STATUS "SEAL_BUILD_BENCH: ${SEAL_BUILD_BENCH}")

if(SEAL_BUILD_BENCH)
    add_subdirectory(native/bench)
endif()

#######################################
# Configure SEALNet and NuGet package #
#######################################

# In Windows we will set the SEAL_C library path according to the CMake generator
set(SEAL_WINDOWS_SEAL_C_DIRECTORY ${CMAKE_RUNTIME_OUTPUT_DIRECTORY})
get_property(SEAL_IS_MULTI_CONFIG_GENERATOR GLOBAL PROPERTY GENERATOR_IS_MULTI_CONFIG)
if(SEAL_IS_MULTI_CONFIG_GENERATOR)
    # Is this the Visual Studio generator? If so, the output path will contain the configuration.
    # We shall use CMAKE_BUILD_TYPE here, which by default will be "Release". The user has the
    # option of changing this by explicitly specifying CMAKE_BUILD_TYPE, which multi-config
    # generators otherwise ignore.
    set(SEAL_WINDOWS_SEAL_C_DIRECTORY ${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/${CMAKE_BUILD_TYPE})
endif()

# Create SEALNet.csproj, SEALNetExamples.csproj, and SEALNetTest.csproj
configure_file(
    ${CMAKE_CURRENT_LIST_DIR}/dotnet/src/SEALNet.csproj.in
    ${CMAKE_CURRENT_BINARY_DIR}/dotnet/src/SEALNet.csproj
    @ONLY)
configure_file(
    ${CMAKE_CURRENT_LIST_DIR}/dotnet/tests/SEALNetTest.csproj.in
    ${CMAKE_CURRENT_BINARY_DIR}/dotnet/tests/SEALNetTest.csproj
    @ONLY)
configure_file(
    ${CMAKE_CURRENT_LIST_DIR}/dotnet/examples/SEALNetExamples.csproj.in
    ${CMAKE_CURRENT_BINARY_DIR}/dotnet/examples/SEALNetExamples.csproj
    @ONLY)

# Create SEALNet.sln for Visual Studio to build all dotnet projects
configure_file(
    ${CMAKE_CURRENT_LIST_DIR}/dotnet/SEALNet.sln.in
    ${CMAKE_CURRENT_BINARY_DIR}/dotnet/SEALNet.sln
    @ONLY)

# Set the sealc dynamic library file names to be included in creating
# the NuGet package. When building a multi-platform NuGet package, the
# dynamic library paths need to be specified explicitly in the NuGet
# command. See dotnet/nuget/SEALNet.nuspec.in.

# Create SEALNet-multi.nuspec for a multi-platform NuGet package
configure_file(
    ${CMAKE_CURRENT_LIST_DIR}/dotnet/nuget/SEALNet-multi.nuspec.in
    ${CMAKE_CURRENT_BINARY_DIR}/dotnet/nuget/SEALNet-multi.nuspec
    @ONLY)

set(NUGET_WINDOWS_SEAL_C_PATH "")
set(NUGET_LINUX_SEAL_C_PATH "")
set(NUGET_MACOS_SEAL_C_PATH "")

# Supporting local building of NuGet package
if(WIN32)
    set(NUGET_WINDOWS_SEAL_C_PATH ${SEAL_WINDOWS_SEAL_C_DIRECTORY}/sealc.dll)
elseif(UNIX AND NOT APPLE)
    set(NUGET_LINUX_SEAL_C_PATH ${CMAKE_LIBRARY_OUTPUT_DIRECTORY}/libsealc.so)
elseif(APPLE)
    set(NUGET_MACOS_SEAL_C_PATH ${CMAKE_LIBRARY_OUTPUT_DIRECTORY}/libsealc.dylib)
endif()

# Create SEALNet.nuspec for a local NuGet pack from SEALNet.nuspec.in
configure_file(
    ${CMAKE_CURRENT_LIST_DIR}/dotnet/nuget/SEALNet.nuspec.in
    ${CMAKE_CURRENT_BINARY_DIR}/dotnet/nuget/SEALNet.nuspec
    @ONLY)
