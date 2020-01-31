# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT license.

find_path(MSGSL_INCLUDE_DIR
    NAMES gsl/gsl gsl/span gsl/multi_span)

find_package(PackageHandleStandardArgs)
find_package_handle_standard_args(MSGSL
    REQUIRED_VARS MSGSL_INCLUDE_DIR)

if(MSGSL_FOUND AND NOT TARGET MSGSL::MSGSL)
    # Now check for individual classes
    include(CMakePushCheckState)
    cmake_push_check_state(RESET)
    set(CMAKE_REQUIRED_INCLUDES ${MSGSL_INCLUDE_DIR})
    set(CMAKE_EXTRA_INCLUDE_FILES gsl/gsl)
    set(CMAKE_REQUIRED_FLAGS "${CMAKE_REQUIRED_FLAGS} -O0 -std=c++14")
    set(CMAKE_REQUIRED_QUIET TRUE)

    include(CheckTypeSize)

    # Detect gsl::span
    check_type_size("gsl::span<std::uint64_t>" MSGSL_SPAN LANGUAGE CXX)

    cmake_pop_check_state()

    # Create interface target for MSGSL
    add_library(MSGSL::MSGSL IMPORTED INTERFACE)
    set_target_properties(MSGSL::MSGSL PROPERTIES
        INTERFACE_INCLUDE_DIRECTORIES ${MSGSL_INCLUDE_DIR})
endif()
