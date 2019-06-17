# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT license.

# Simple attempt to locate Microsoft GSL
set(CURRENT_MSGSL_INCLUDE_DIR ${MSGSL_INCLUDE_DIR})
unset(MSGSL_INCLUDE_DIR CACHE)
find_path(MSGSL_INCLUDE_DIR
    NAMES gsl/gsl gsl/span gsl/multi_span
    HINTS ${CMAKE_INCLUDE_PATH} ${CURRENT_MSGSL_INCLUDE_DIR})

# Determine whether found based on MSGSL_INCLUDE_DIR
find_package(PackageHandleStandardArgs)
find_package_handle_standard_args(msgsl
    REQUIRED_VARS MSGSL_INCLUDE_DIR)

if(msgsl_FOUND)
    # Now check for individual classes                                                                                              
    cmake_push_check_state(RESET)
    set(CMAKE_REQUIRED_INCLUDES ${MSGSL_INCLUDE_DIR})
    set(CMAKE_EXTRA_INCLUDE_FILES gsl/gsl)
    set(CMAKE_REQUIRED_FLAGS "${CMAKE_REQUIRED_FLAGS} -O0 -std=c++14")
    set(CMAKE_REQUIRED_QUIET TRUE)
       
    # Detect gsl::span
    check_type_size("gsl::span<std::uint64_t>" msgsl_SPAN LANGUAGE CXX)

    # Detect gsl::multi_span
    check_type_size("gsl::multi_span<std::uint64_t, 1, gsl::dynamic_range>" msgsl_MULTISPAN LANGUAGE CXX)
       
    cmake_pop_check_state()

    # Create interface target for msgsl
    add_library(msgsl INTERFACE)
    set_target_properties(msgsl PROPERTIES
        INTERFACE_INCLUDE_DIRECTORIES ${MSGSL_INCLUDE_DIR})
endif()
