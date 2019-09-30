# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT license.

# Simple attempt to locate Microsoft GSL
find_path(MSGSL_INCLUDE_DIR
    NAMES gsl/gsl gsl/span gsl/multi_span
    HINTS ${MSGSL_ROOT} ${CMAKE_INCLUDE_PATH})

find_package(PackageHandleStandardArgs)
find_package_handle_standard_args(msgsl
    REQUIRED_VARS MSGSL_INCLUDE_DIR)

if(msgsl_FOUND AND NOT TARGET msgsl::msgsl)
    # Now check for individual classes
    include(CMakePushCheckState)
    cmake_push_check_state(RESET)
    set(CMAKE_REQUIRED_INCLUDES ${MSGSL_INCLUDE_DIR})
    set(CMAKE_EXTRA_INCLUDE_FILES gsl/gsl)
    set(CMAKE_REQUIRED_FLAGS "${CMAKE_REQUIRED_FLAGS} -O0 -std=c++14")
    set(CMAKE_REQUIRED_QUIET TRUE)

    include(CheckTypeSize)

    # Detect gsl::span
    check_type_size("gsl::span<std::uint64_t>" msgsl_SPAN LANGUAGE CXX)

    # Detect gsl::multi_span
    check_type_size("gsl::multi_span<std::uint64_t, 1, gsl::dynamic_range>" msgsl_MULTISPAN LANGUAGE CXX)

    cmake_pop_check_state()

    # Create interface target for msgsl
    add_library(msgsl::msgsl IMPORTED INTERFACE)
    set_target_properties(msgsl::msgsl PROPERTIES
        INTERFACE_INCLUDE_DIRECTORIES ${MSGSL_INCLUDE_DIR})
endif()
