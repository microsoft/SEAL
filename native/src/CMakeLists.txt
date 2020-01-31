# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT license.

cmake_minimum_required(VERSION 3.12)

project(SEAL VERSION 3.5.0 LANGUAGES CXX C)

if(MSVC)
    if(ALLOW_COMMAND_LINE_BUILD)
        message(STATUS "Configuring for Visual Studio")
    else()
        message(FATAL_ERROR "Please build Microsoft SEAL using the attached Visual Studio solution/project files")
    endif()
endif()

# Build in Release mode by default; otherwise use selected option
set(SEAL_DEFAULT_BUILD_TYPE "Release")
if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE ${SEAL_DEFAULT_BUILD_TYPE} CACHE
        STRING "Build type" FORCE)
    set_property(CACHE CMAKE_BUILD_TYPE PROPERTY
        STRINGS "Release" "Debug" "MinSizeRel" "RelWithDebInfo")
endif()
message(STATUS "Build type (CMAKE_BUILD_TYPE): ${CMAKE_BUILD_TYPE}")

# In Debug mode enable also SEAL_DEBUG by default
if(CMAKE_BUILD_TYPE STREQUAL "Debug")
    set(SEAL_DEBUG_DEFAULT ON)
else()
    set(SEAL_DEBUG_DEFAULT OFF)
endif()

# Required files and directories
include(GNUInstallDirs)
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${SEAL_SOURCE_DIR}/../lib)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${SEAL_SOURCE_DIR}/../lib)
set(CMAKE_LIBRARY_RUNTIME_DIRECTORY ${SEAL_SOURCE_DIR}/../bin)
set(SEAL_TARGETS_FILENAME ${SEAL_SOURCE_DIR}/cmake/SEALTargets.cmake)
set(SEAL_CONFIG_IN_FILENAME ${SEAL_SOURCE_DIR}/cmake/SEALConfig.cmake.in)
set(SEAL_CONFIG_FILENAME ${SEAL_SOURCE_DIR}/cmake/SEALConfig.cmake)
set(SEAL_CONFIG_VERSION_FILENAME ${SEAL_SOURCE_DIR}/cmake/SEALConfigVersion.cmake)
set(SEAL_CONFIG_INSTALL_DIR ${CMAKE_INSTALL_LIBDIR}/cmake/SEAL-${SEAL_VERSION_MAJOR}.${SEAL_VERSION_MINOR})
set(SEAL_INCLUDES_INSTALL_DIR ${CMAKE_INSTALL_INCLUDEDIR}/SEAL-${SEAL_VERSION_MAJOR}.${SEAL_VERSION_MINOR})
set(MSGSL_FIND_MODULE_PATH ${SEAL_SOURCE_DIR}/cmake/FindMSGSL.cmake)

# For extra modules we might have
list(APPEND CMAKE_MODULE_PATH ${SEAL_SOURCE_DIR}/cmake)

include(CMakePushCheckState)
include(CMakeDependentOption)
include(CheckIncludeFiles)
include(CheckCXXSourceRuns)
include(CheckTypeSize)

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

# Are we using SEAL_DEBUG?
set(SEAL_DEBUG ${SEAL_DEBUG_DEFAULT})
message(STATUS "Microsoft SEAL debug mode: ${SEAL_DEBUG}")

# Should we build also the shared library?
set(BUILD_SHARED_LIBS_STR "Build shared library")
option(BUILD_SHARED_LIBS ${BUILD_SHARED_LIBS_STR} OFF)
if(MSVC AND BUILD_SHARED_LIBS)
    message(WARNING "This build system only supports a static build; disabling `BUILD_SHARED_LIBS`")
    set(BUILD_SHARED_LIBS OFF CACHE)
endif()

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

# Always build position-independent-code
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

# Throw on multiply_plain by a zero plaintext
set(SEAL_THROW_ON_TRANSPARENT_CIPHERTEXT_STR "Throw an exception when a member of Evaluator outputs a transparent ciphertext")
option(SEAL_THROW_ON_TRANSPARENT_CIPHERTEXT ${SEAL_THROW_ON_TRANSPARENT_CIPHERTEXT_STR} ON)
mark_as_advanced(FORCE SEAL_THROW_ON_TRANSPARENT_CIPHERTEXT)

# Use intrinsics if available
set(SEAL_USE_INTRIN_OPTION_STR "Use intrinsics")
option(SEAL_USE_INTRIN ${SEAL_USE_INTRIN_OPTION_STR} ON)

# Use Microsoft GSL if available
set(SEAL_USE_MSGSL_OPTION_STR "Use Microsoft GSL")
option(SEAL_USE_MSGSL ${SEAL_USE_MSGSL_OPTION_STR} ON)

# Use zlib if available
set(SEAL_USE_ZLIB_OPTION_STR "Use zlib for compressed serialization")
option(SEAL_USE_ZLIB ${SEAL_USE_ZLIB_OPTION_STR} ON)

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

# Helper macro for clearing MSGSL cache
macro(clear_msgsl_cache)
    unset(MSGSL_INCLUDE_DIR CACHE)
endmacro()

# Try to find MSGSL if requested; first clear the cache if SEAL_USE_MSGSL
# is not set, or if SEAL_USE_MSGSL and MSGSL_ROOT are set (force search).
if(NOT SEAL_USE_MSGSL OR MSGSL_ROOT)
    clear_msgsl_cache()
endif()
if(SEAL_USE_MSGSL)
    find_package(MSGSL MODULE)
    if(NOT MSGSL_FOUND)
        set(SEAL_USE_MSGSL OFF CACHE BOOL ${SEAL_USE_MSGSL_OPTION_STR} FORCE)
        clear_msgsl_cache()
    endif()
endif()

# Specific options depending on SEAL_USE_MSGSL
set(SEAL_USE_MSGSL_SPAN_OPTION_STR "Use gsl::span")
cmake_dependent_option(SEAL_USE_MSGSL_SPAN ${SEAL_USE_MSGSL_SPAN_OPTION_STR} ON "SEAL_USE_MSGSL" OFF)
if(SEAL_USE_MSGSL_SPAN)
    # Detect gsl::span
    if(NOT HAVE_MSGSL_SPAN)
        set(SEAL_USE_MSGSL_SPAN OFF CACHE BOOL ${SEAL_USE_MSGSL_SPAN_OPTION_STR} FORCE)
    endif()
endif()

# Helper macro for clearing zlib cache
macro(clear_zlib_cache)
    unset(ZLIB_INCLUDE_DIR CACHE)
    unset(ZLIB_LIBRARY CACHE)
    unset(ZLIB_LIBRARY_DEBUG CACHE)
    unset(ZLIB_LIBRARY_RELEASE CACHE)
endmacro()

# Try to find zlib if requested; first clear the cache if SEAL_USE_ZLIB
# is not set, or if SEAL_USE_ZLIB and ZLIB_ROOT are set (force search).
if(NOT SEAL_USE_ZLIB OR ZLIB_ROOT)
    clear_zlib_cache()
endif()
if(SEAL_USE_ZLIB)
    find_package(ZLIB 1.2.11 EXACT)
    if(NOT ZLIB_FOUND)
        set(SEAL_USE_ZLIB OFF CACHE BOOL ${SEAL_USE_ZLIB_OPTION_STR} FORCE)
        clear_zlib_cache()
    endif()
endif()

# Set the sealc dynamic library file names to be included in creating
# the NuGet package. When building a multi-platform package, all three paths
# should be included.
if(SEAL_MULTIPLATFORM_NUGET_BUILD)
    set(SEAL_WINDOWS_SEAL_C_PATH ../../native/lib/x64/$Configuration$/sealc.dll)
    set(SEAL_LINUX_SEAL_C_PATH ../../native/lib/libsealc.so.${SEAL_VERSION})
    set(SEAL_MACOS_SEAL_C_PATH ../../native/lib/libsealc.${SEAL_VERSION}.dylib)
else()
    if(MSVC)
        set(SEAL_WINDOWS_SEAL_C_PATH ../../native/lib/x64/$Configuration$/sealc.dll)
    elseif(APPLE)
        set(SEAL_MACOS_SEAL_C_PATH ../../native/lib/libsealc.${SEAL_VERSION}.dylib)
    elseif(UNIX)
        set(SEAL_LINUX_SEAL_C_PATH ../../native/lib/libsealc.so.${SEAL_VERSION})
    endif()
endif()

# Create SEALNet.nuspec from SEALNet.nuspec.in
configure_file(
    ${SEAL_SOURCE_DIR}/../../dotnet/nuget/SEALNet.nuspec.in
    ${SEAL_SOURCE_DIR}/../../dotnet/nuget/SEALNet.nuspec
    @ONLY)

# Create SEALNet.targets from SEALNet.targets.in
configure_file(
    ${SEAL_SOURCE_DIR}/../../dotnet/nuget/SEALNet.targets.in
    ${SEAL_SOURCE_DIR}/../../dotnet/nuget/SEALNet.targets
    @ONLY)

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
    set_target_properties(seal PROPERTIES
        OUTPUT_NAME seal-${SEAL_VERSION_MAJOR}.${SEAL_VERSION_MINOR})
endmacro()

# Set the SOVERSION property
macro(set_soversion target)
    set_target_properties(${target} PROPERTIES
        SOVERSION ${SEAL_VERSION_MAJOR}.${SEAL_VERSION_MINOR})
endmacro()

# Set include directories for build and install interfaces
macro(set_include_directories target)
    target_include_directories(${target} PUBLIC
        $<BUILD_INTERFACE:${SEAL_SOURCE_DIR}>
        $<INSTALL_INTERFACE:${SEAL_INCLUDES_INSTALL_DIR}>)
endmacro()

# Link all dependencies
macro(link_dependencies target)
    # Require thread library
    if(NOT TARGET Threads::Threads)
        set(CMAKE_THREAD_PREFER_PTHREAD TRUE)
        set(THREADS_PREFER_PTHREAD_FLAG TRUE)
        find_package(Threads REQUIRED)
    endif()

    # Link Threads
    target_link_libraries(${target} PUBLIC Threads::Threads)

    if(SEAL_USE_MSGSL)
        # Link MSGSL
        target_link_libraries(${target} PUBLIC MSGSL::MSGSL)
    endif()

    if(SEAL_USE_ZLIB)
        # Link ZLIB
        target_link_libraries(${target} PUBLIC ZLIB::ZLIB)
    endif()
endmacro()

# Create an object library to compile sources only once
add_library(seal_obj OBJECT)

# Add source files to library and header files to install
add_subdirectory(seal)

# Set C++ language version and include directories for the object library
set_language(seal_obj)
set_include_directories(seal_obj)

# Always build the static library
add_library(seal STATIC $<TARGET_OBJECTS:seal_obj>)

set_version(seal)
set_version_filename(seal)
set_language(seal)
set_include_directories(seal)
link_dependencies(seal)

# Conditionally build the shared library
if(BUILD_SHARED_LIBS)
    add_library(seal_shared SHARED $<TARGET_OBJECTS:seal_obj>)

    set_version(seal_shared)
    set_soversion(seal_shared)
    set_language(seal_shared)
    set_include_directories(seal_shared)
    link_dependencies(seal_shared)
endif()

# For SEAL_C check that size_t is 8 bytes
include(CheckTypeSize)
check_type_size("size_t" SIZET LANGUAGE C)

set(SEAL_BUILD_SEAL_C_OPTION_STR "Build C export library for Microsoft SEAL")
cmake_dependent_option(SEAL_BUILD_SEAL_C ${SEAL_BUILD_SEAL_C_OPTION_STR}
    OFF "${SIZET} EQUAL 8" OFF)

# Create shared SEAL_C library but add no source files yet
if(SEAL_BUILD_SEAL_C)
    add_library(sealc SHARED)

    # Add source files to library and header files to install
    add_subdirectory(seal/c)

    set_version(sealc)
    set_soversion(sealc)
    set_language(sealc)
    set_include_directories(sealc)
    link_dependencies(sealc)
    target_link_libraries(sealc PUBLIC seal)
endif()

macro(install_target_if_exists target export)
    if(TARGET ${target})
        install(TARGETS ${target} EXPORT ${export}
            ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
            LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
            RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})
    endif()
endmacro()

# Associate seal and seal_shared to export SEALTargets
install_target_if_exists(seal SEALTargets)
install_target_if_exists(seal_shared SEALTargets)
install_target_if_exists(sealc SEALTargets)

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
        ${MSGSL_FIND_MODULE_PATH}
    DESTINATION ${SEAL_CONFIG_INSTALL_DIR})

# We export SEALTargets from the build tree so it can be used by other projects
# without requiring an install.
export(
    EXPORT SEALTargets
    NAMESPACE SEAL::
    FILE ${SEAL_TARGETS_FILENAME})
