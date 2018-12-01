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
