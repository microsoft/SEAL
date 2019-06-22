# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT license.

cmake_minimum_required(VERSION 3.10)

project(SEAL VERSION 3.3.1 LANGUAGES CXX C)

if(DEFINED MSVC)
    if(DEFINED ALLOW_COMMAND_LINE_BUILD)
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
    set_property(CACHE CMAKE_BUILD_TYPE PROPERTY STRINGS
        "Release" "Debug" "MinSizeRel" "RelWithDebInfo")
endif()
message(STATUS "Build type (CMAKE_BUILD_TYPE): ${CMAKE_BUILD_TYPE}")

# In Debug mode enable also SEAL_DEBUG by default
if(CMAKE_BUILD_TYPE STREQUAL "Debug")
    set(SEAL_DEBUG_DEFAULT ON)
else()
    set(SEAL_DEBUG_DEFAULT OFF)
endif()

# Required files and directories
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${SEAL_SOURCE_DIR}/../lib)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${SEAL_SOURCE_DIR}/../lib)
set(CMAKE_LIBRARY_RUNTIME_DIRECTORY ${SEAL_SOURCE_DIR}/../bin)
set(SEAL_INCLUDES_INSTALL_DIR include)
set(SEAL_CONFIG_IN_FILENAME ${SEAL_SOURCE_DIR}/cmake/SEALConfig.cmake.in)
set(SEAL_CONFIG_FILENAME ${SEAL_SOURCE_DIR}/cmake/SEALConfig.cmake)
set(SEAL_TARGETS_FILENAME ${SEAL_SOURCE_DIR}/cmake/SEALTargets.cmake)
set(SEAL_CONFIG_VERSION_FILENAME ${SEAL_SOURCE_DIR}/cmake/SEALConfigVersion.cmake)
set(SEAL_CONFIG_INSTALL_DIR lib/cmake/SEAL)

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

# Should we use C++14 or C++17?
set(SEAL_USE_CXX17_OPTION_STR "Use C++17")
option(SEAL_USE_CXX17 ${SEAL_USE_CXX17_OPTION_STR} ON)

# Conditionally enable features from C++17
set(SEAL_USE_STD_BYTE OFF)
set(SEAL_USE_SHARED_MUTEX OFF)
set(SEAL_USE_IF_CONSTEXPR OFF)
set(SEAL_USE_MAYBE_UNUSED OFF)
set(SEAL_LANG_FLAG "-std=c++14")
if(SEAL_USE_CXX17)
    set(SEAL_USE_STD_BYTE ON)
    set(SEAL_USE_SHARED_MUTEX ON)
    set(SEAL_USE_IF_CONSTEXPR ON)
    set(SEAL_USE_MAYBE_UNUSED ON)
    set(SEAL_LANG_FLAG "-std=c++17")
endif()

# Should we build a shared library?
set(SEAL_DEFAULT_LIB_BUILD_TYPE "Static_PIC")
if(NOT SEAL_LIB_BUILD_TYPE)
    set(SEAL_LIB_BUILD_TYPE ${SEAL_DEFAULT_LIB_BUILD_TYPE} CACHE
        STRING "Library build type" FORCE)
    set_property(CACHE SEAL_LIB_BUILD_TYPE PROPERTY STRINGS
        "Static" "Static_PIC" "Shared")
endif()
message(STATUS "Library build type (SEAL_LIB_BUILD_TYPE): ${SEAL_LIB_BUILD_TYPE}")

# Optionally enable CMAKE_POSITION_INDEPENDENT_CODE
if(SEAL_LIB_BUILD_TYPE STREQUAL "Static")
  set(CMAKE_POSITION_INDEPENDENT_CODE OFF)
else()
  set(CMAKE_POSITION_INDEPENDENT_CODE ON)
endif()

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

# Check for intrin.h or x64intrin.h
if(SEAL_USE_INTRIN)
    if(DEFINED MSVC)
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
if(DEFINED MSVC)
    set(SEAL_USE__UMUL128_OPTION_STR "Use _umul128")
    cmake_dependent_option(SEAL_USE__UMUL128 SEAL_USE__UMUL128_OPTION_STR ON "SEAL_USE_INTRIN" OFF)

    set(SEAL_USE__BITSCANREVERSE64_OPTION_STR "Use _BitScanReverse64")
    cmake_dependent_option(SEAL_USE__BITSCANREVERSE64 SEAL_USE__BITSCANREVERSE64_OPTION_STR ON "SEAL_USE_INTRIN" OFF)
else()
    set(SEAL_USE___INT128_OPTION_STR "Use __int128")
    cmake_dependent_option(SEAL_USE___INT128 SEAL_USE___INT128_OPTION_STR ON "SEAL_USE_INTRIN" OFF)

    set(SEAL_USE___BUILTIN_CLZLL_OPTION_STR "Use __builtin_clzll")
    cmake_dependent_option(SEAL_USE___BUILTIN_CLZLL SEAL_USE___BUILTIN_CLZLL_OPTION_STR ON "SEAL_USE_INTRIN" OFF)
endif()

set(SEAL_USE__ADDCARRY_U64_OPTION_STR "Use _addcarry_u64")
cmake_dependent_option(SEAL_USE__ADDCARRY_U64 SEAL_USE__ADDCARRY_U64_OPTION_STR ON "SEAL_USE_INTRIN" OFF)

set(SEAL_USE__SUBBORROW_U64_OPTION_STR "Use _subborrow_u64")
cmake_dependent_option(SEAL_USE__SUBBORROW_U64 SEAL_USE__SUBBORROW_U64_OPTION_STR ON "SEAL_USE_INTRIN" OFF)

set(SEAL_USE_AES_NI_PRNG_OPTION_STR "Use fast AES-NI PRNG")
cmake_dependent_option(SEAL_USE_AES_NI_PRNG SEAL_USE_AES_NI_PRNG_OPTION_STR ON "SEAL_USE_INTRIN" OFF)

if(SEAL_USE_INTRIN)
    cmake_push_check_state(RESET)
    set(CMAKE_REQUIRED_QUIET TRUE)
    if(NOT DEFINED MSVC)
        set(CMAKE_REQUIRED_FLAGS "${CMAKE_REQUIRED_FLAGS} -O0 ${SEAL_LANG_FLAG}")
    endif()

    if(DEFINED MSVC)
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

    check_include_file_cxx("wmmintrin.h" HAVE_WMMINTRIN_HEADER)
    if(NOT HAVE_WMMINTRIN_HEADER)
        set(SEAL_USE_AES_NI_PRNG OFF CACHE BOOL ${SEAL_USE_AES_NI_PRNG_OPTION_STR} FORCE)
    endif()

    # Check that AES-NI runs
    if(SEAL_USE_AES_NI_PRNG)
        if(NOT DEFINED MSVC)
            set(CMAKE_REQUIRED_FLAGS "${CMAKE_REQUIRED_FLAGS} -maes")
        endif()
        check_cxx_source_runs("
            #include <wmmintrin.h>
            int main() {
                __m128i a{ 0 };
                volatile auto b = _mm_aeskeygenassist_si128(a, 0);
                return 0;
            }"
            USE_AES_KEYGEN_ASSIST
        )
        if(NOT USE_AES_KEYGEN_ASSIST EQUAL 1)
            set(SEAL_USE_AES_NI_PRNG OFF CACHE BOOL ${SEAL_USE_AES_NI_PRNG_OPTION_STR} FORCE)
        endif()
    endif()

    cmake_pop_check_state()
endif()

# Try to find MSGSL if requested
if(SEAL_USE_MSGSL)
    find_package(msgsl MODULE)
    if(NOT msgsl_FOUND)
        set(SEAL_USE_MSGSL OFF CACHE BOOL ${SEAL_USE_MSGSL_OPTION_STR} FORCE)
    endif()
endif()

# Specific options depending on SEAL_USE_MSGSL
set(SEAL_USE_MSGSL_SPAN_OPTION_STR "Use gsl::span")
cmake_dependent_option(SEAL_USE_MSGSL_SPAN ${SEAL_USE_MSGSL_SPAN_OPTION_STR} ON "SEAL_USE_MSGSL" OFF)

set(SEAL_USE_MSGSL_MULTISPAN_OPTION_STR "Use gsl::multi_span")
cmake_dependent_option(SEAL_USE_MSGSL_MULTISPAN ${SEAL_USE_MSGSL_MULTISPAN_OPTION_STR} ON "SEAL_USE_MSGSL" OFF)

if(SEAL_USE_MSGSL)
    # Now check for individual classes
    cmake_push_check_state(RESET)
    set(CMAKE_REQUIRED_INCLUDES ${MSGSL_INCLUDE_DIR})
    set(CMAKE_EXTRA_INCLUDE_FILES gsl/gsl)
    set(CMAKE_REQUIRED_FLAGS "${CMAKE_REQUIRED_FLAGS} -O0 ${SEAL_LANG_FLAG}")
    set(CMAKE_REQUIRED_QUIET TRUE)

    # Detect gsl::span
    if(SEAL_USE_MSGSL_SPAN)
        check_type_size("gsl::span<std::uint64_t>" MSGSL_SPAN LANGUAGE CXX)
        if(NOT MSGSL_SPAN GREATER 0)
            set(SEAL_USE_MSGSL_SPAN OFF CACHE BOOL ${SEAL_USE_MSGSL_SPAN_OPTION_STR} FORCE)
        endif()
    endif()

    # Detect gsl::multi_span
    if(SEAL_USE_MSGSL_MULTISPAN)
        check_type_size("gsl::multi_span<std::uint64_t, 1, gsl::dynamic_range>" MSGSL_MULTISPAN LANGUAGE CXX)
        if(NOT MSGSL_MULTISPAN GREATER 0)
            set(SEAL_USE_MSGSL_MULTISPAN OFF CACHE BOOL ${SEAL_USE_MSGSL_MULTISPAN_OPTION_STR} FORCE)
        endif()
    endif()

    cmake_pop_check_state()
endif()

# Create library but add no source files yet
if(SEAL_LIB_BUILD_TYPE STREQUAL "Shared")
    add_library(seal SHARED "")

    # Set SOVERSION for shared library
    set_target_properties(seal PROPERTIES
        SOVERSION ${SEAL_VERSION_MAJOR}.${SEAL_VERSION_MINOR})
else()
    add_library(seal STATIC "")
endif()

# Set VERSION for all library build types
set_target_properties(seal PROPERTIES VERSION ${SEAL_VERSION})

# Add source files to library and header files to install
add_subdirectory(seal)

# Add local include directories for build
target_include_directories(seal PUBLIC $<BUILD_INTERFACE:${SEAL_SOURCE_DIR}>)

# We require at least C++14
if(SEAL_USE_CXX17)
    target_compile_features(seal PUBLIC cxx_std_17)
else()
    target_compile_features(seal PUBLIC cxx_std_14)
endif()

# Add -maes flag if needed
if(SEAL_USE_AES_NI_PRNG)
    target_compile_options(seal PUBLIC "-maes")
endif()

# Require thread library
set(CMAKE_THREAD_PREFER_PTHREAD TRUE)
set(THREADS_PREFER_PTHREAD_FLAG TRUE)
find_package(Threads REQUIRED)

# Link Threads with seal
target_link_libraries(seal PUBLIC Threads::Threads)

# Create msgsl interface target
if(SEAL_USE_MSGSL)
    # Create interface target
    add_library(msgsl INTERFACE)
    set_target_properties(msgsl PROPERTIES
        INTERFACE_INCLUDE_DIRECTORIES ${MSGSL_INCLUDE_DIR})

    # Associate msgsl with export seal_export
    install(TARGETS msgsl EXPORT seal_export)

    # Link with seal
    target_link_libraries(seal PUBLIC msgsl)
endif()

# Associate seal to export seal_export
install(TARGETS seal EXPORT seal_export
    ARCHIVE DESTINATION lib
    LIBRARY DESTINATION lib
    RUNTIME DESTINATION bin
    INCLUDES DESTINATION ${SEAL_INCLUDES_INSTALL_DIR})

# Export the targets
export(EXPORT seal_export
    FILE ${SEAL_TARGETS_FILENAME}
    NAMESPACE SEAL::)

# Create the CMake config file
configure_file(${SEAL_CONFIG_IN_FILENAME} ${SEAL_CONFIG_FILENAME} @ONLY)

# Install the export
install(
    EXPORT seal_export
    FILE SEALTargets.cmake
    NAMESPACE SEAL::
    DESTINATION ${SEAL_CONFIG_INSTALL_DIR})

# Version file; we require exact version match for downstream
include(CMakePackageConfigHelpers)
write_basic_package_version_file(
    ${SEAL_CONFIG_VERSION_FILENAME}
    VERSION ${SEAL_VERSION}
    COMPATIBILITY ExactVersion)

# Install other files
install(
    FILES
        ${SEAL_CONFIG_FILENAME}
        ${SEAL_CONFIG_VERSION_FILENAME}
    DESTINATION ${SEAL_CONFIG_INSTALL_DIR})
