# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT license.

# Build XCFrameworks for iOS (device + simulator).
#
# Produces libseal.xcframework and libsealc.xcframework,
# each containing two arm64 slices: one for iOS device (iphoneos) and one for
# the iOS simulator on Apple Silicon (iphonesimulator).
#
# Design notes:
# - iOS-only by design (no macOS / Mac Catalyst / x86_64 simulator slices).
# - Static-archive XCFrameworks: the inner artifacts are .a files, not
#   .framework bundles. They carry no LC_RPATH / install-name / load
#   commands; the consumer's link step pulls our .o files into their final
#   binary. Required because iOS App Store policy disallows dlopen of
#   arbitrary user dynamic code.
# - zlib/zstd are merged into libseal.a via seal_combine_archives, so
#   consumers don't need to link them separately.
#
# Usage (from project root):
#   cmake -P cmake/ios_xcframework.cmake
#   cmake -DBUILD_TYPE=Debug -P cmake/ios_xcframework.cmake
#   cmake -DOUTPUT_DIR=./out -P cmake/ios_xcframework.cmake
#
# Options (pass with -D before -P):
#   BUILD_TYPE   Build configuration: Release (default) or Debug.
#   OUTPUT_DIR   Where to place the .xcframework bundles. Default: project root.
#   WORK_DIR     Directory for intermediate build/install files.
#                Default: <source>/out/ios-xcframework.

cmake_minimum_required(VERSION 3.22)

# Defaults and path setup

if(NOT DEFINED BUILD_TYPE)
    set(BUILD_TYPE Release)
endif()
if(NOT BUILD_TYPE STREQUAL "Release" AND NOT BUILD_TYPE STREQUAL "Debug")
    message(FATAL_ERROR "BUILD_TYPE must be 'Release' or 'Debug' (got '${BUILD_TYPE}').")
endif()

# Source directory is the parent of the cmake/ directory containing this script,
# which lets the script be invoked from any working directory.
get_filename_component(SOURCE_DIR "${CMAKE_CURRENT_LIST_DIR}/.." ABSOLUTE)

if(NOT DEFINED OUTPUT_DIR)
    set(OUTPUT_DIR "${SOURCE_DIR}")
endif()
get_filename_component(OUTPUT_DIR "${OUTPUT_DIR}" ABSOLUTE)

if(NOT DEFINED WORK_DIR)
    set(WORK_DIR "${SOURCE_DIR}/out/ios-xcframework")
endif()
get_filename_component(WORK_DIR "${WORK_DIR}" ABSOLUTE)

message(STATUS "Build type:   ${BUILD_TYPE}")
message(STATUS "Work dir:     ${WORK_DIR}")
message(STATUS "Output dir:   ${OUTPUT_DIR}")

# Derived paths

set(BUILD_DEVICE    "${WORK_DIR}/build-device")
set(BUILD_SIMULATOR "${WORK_DIR}/build-simulator")
set(INSTALL_DEVICE    "${WORK_DIR}/install-device")
set(INSTALL_SIMULATOR "${WORK_DIR}/install-simulator")
set(XCF_STAGING "${WORK_DIR}/staging")

set(LIBSEAL_NAME   "libseal.a")
set(LIBSEALC_NAME  "libsealc.a")

set(LIBSEAL_XCF  "${OUTPUT_DIR}/libseal.xcframework")
set(LIBSEALC_XCF "${OUTPUT_DIR}/libsealc.xcframework")

# Common CMake configure arguments

set(COMMON_ARGS
    -S "${SOURCE_DIR}"
    -GXcode
    -DSEAL_BUILD_SEAL_C=ON
    -DSEAL_BUILD_STATIC_SEAL_C=ON
    -DCMAKE_SYSTEM_NAME=iOS
    -DCMAKE_OSX_ARCHITECTURES=arm64
    -C "${SOURCE_DIR}/cmake/functions.ios.cmake"
)

# Configure

message(STATUS "Configuring for iOS device...")
execute_process(
    COMMAND ${CMAKE_COMMAND}
        ${COMMON_ARGS}
        -B "${BUILD_DEVICE}"
        -DCMAKE_OSX_SYSROOT=iphoneos
    RESULT_VARIABLE _result
)
if(NOT _result EQUAL 0)
    message(FATAL_ERROR "Failed to configure for iOS device.")
endif()

message(STATUS "Configuring for iOS simulator...")
execute_process(
    COMMAND ${CMAKE_COMMAND}
        ${COMMON_ARGS}
        -B "${BUILD_SIMULATOR}"
        -DCMAKE_OSX_SYSROOT=iphonesimulator
    RESULT_VARIABLE _result
)
if(NOT _result EQUAL 0)
    message(FATAL_ERROR "Failed to configure for iOS simulator.")
endif()

# Build

message(STATUS "Building for iOS device...")
execute_process(
    COMMAND ${CMAKE_COMMAND} --build "${BUILD_DEVICE}" --config ${BUILD_TYPE}
    RESULT_VARIABLE _result
)
if(NOT _result EQUAL 0)
    message(FATAL_ERROR "Failed to build for iOS device.")
endif()

message(STATUS "Building for iOS simulator...")
execute_process(
    COMMAND ${CMAKE_COMMAND} --build "${BUILD_SIMULATOR}" --config ${BUILD_TYPE}
    RESULT_VARIABLE _result
)
if(NOT _result EQUAL 0)
    message(FATAL_ERROR "Failed to build for iOS simulator.")
endif()

# Install

message(STATUS "Installing device build...")
execute_process(
    COMMAND ${CMAKE_COMMAND}
        --install "${BUILD_DEVICE}" --config ${BUILD_TYPE}
        --prefix "${INSTALL_DEVICE}"
    RESULT_VARIABLE _result
)
if(NOT _result EQUAL 0)
    message(FATAL_ERROR "Failed to install device build.")
endif()

message(STATUS "Installing simulator build...")
execute_process(
    COMMAND ${CMAKE_COMMAND}
        --install "${BUILD_SIMULATOR}" --config ${BUILD_TYPE}
        --prefix "${INSTALL_SIMULATOR}"
    RESULT_VARIABLE _result
)
if(NOT _result EQUAL 0)
    message(FATAL_ERROR "Failed to install simulator build.")
endif()

# Verify expected install artifacts
#
# Fail loudly with a clear message if something upstream (a renamed target, a
# changed install prefix layout, a disabled SEAL_C build) broke our assumptions,
# rather than letting xcodebuild emit a confusing "file not found" error later.

foreach(_slice IN ITEMS "${INSTALL_DEVICE}" "${INSTALL_SIMULATOR}")
    foreach(_libname IN ITEMS "${LIBSEAL_NAME}" "${LIBSEALC_NAME}")
        if(NOT EXISTS "${_slice}/lib/${_libname}")
            message(FATAL_ERROR
                "Expected install artifact not found: ${_slice}/lib/${_libname}")
        endif()
    endforeach()
    if(NOT IS_DIRECTORY "${_slice}/include/seal")
        message(FATAL_ERROR
            "Expected include directory not found: ${_slice}/include/seal")
    endif()
endforeach()

# Stage headers per slice
#
# xcodebuild -create-xcframework requires a separate -headers tree per slice
# because generated files (e.g. config.h) can differ between device and
# simulator. Each tree holds the SEAL headers and, at its top level, the
# Microsoft.GSL headers that SEAL's public API references, which SEAL installs
# in include/seal/thirdparty.

file(REMOVE_RECURSE "${XCF_STAGING}")
foreach(_slice IN ITEMS device simulator)
    if(_slice STREQUAL "device")
        set(_include "${INSTALL_DEVICE}/include")
    else()
        set(_include "${INSTALL_SIMULATOR}/include")
    endif()
    file(MAKE_DIRECTORY "${XCF_STAGING}/${_slice}")
    file(COPY "${_include}/seal" DESTINATION "${XCF_STAGING}/${_slice}"
        PATTERN "thirdparty" EXCLUDE)

    # file(COPY) copies each listed item as a subdirectory of DESTINATION, so
    # glob the entries of thirdparty to place them at the top level.
    file(GLOB _thirdparty_items "${_include}/seal/thirdparty/*")
    if(_thirdparty_items)
        file(COPY ${_thirdparty_items} DESTINATION "${XCF_STAGING}/${_slice}")
    endif()
endforeach()

# Create XCFrameworks
#
# xcodebuild refuses to overwrite an existing .xcframework output, so clear
# any prior bundles before re-creating them.

file(REMOVE_RECURSE "${LIBSEAL_XCF}")
file(REMOVE_RECURSE "${LIBSEALC_XCF}")

message(STATUS "Creating ${LIBSEAL_XCF}...")
execute_process(
    COMMAND xcodebuild -create-xcframework
        -library "${INSTALL_DEVICE}/lib/${LIBSEAL_NAME}"
        -headers "${XCF_STAGING}/device"
        -library "${INSTALL_SIMULATOR}/lib/${LIBSEAL_NAME}"
        -headers "${XCF_STAGING}/simulator"
        -output "${LIBSEAL_XCF}"
    RESULT_VARIABLE _result
)
if(NOT _result EQUAL 0)
    message(FATAL_ERROR "Failed to create libseal XCFramework.")
endif()

message(STATUS "Creating ${LIBSEALC_XCF}...")
execute_process(
    COMMAND xcodebuild -create-xcframework
        -library "${INSTALL_DEVICE}/lib/${LIBSEALC_NAME}"
        -headers "${XCF_STAGING}/device"
        -library "${INSTALL_SIMULATOR}/lib/${LIBSEALC_NAME}"
        -headers "${XCF_STAGING}/simulator"
        -output "${LIBSEALC_XCF}"
    RESULT_VARIABLE _result
)
if(NOT _result EQUAL 0)
    message(FATAL_ERROR "Failed to create libsealc XCFramework.")
endif()

# Cleanup

file(REMOVE_RECURSE "${XCF_STAGING}")

message(STATUS "Done.")
message(STATUS "  ${LIBSEAL_XCF}")
message(STATUS "  ${LIBSEALC_XCF}")
