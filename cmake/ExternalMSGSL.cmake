# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT license.

set(GSL_CXX_STANDARD "14" CACHE STRING "" FORCE)
set(GSL_TEST OFF CACHE BOOL "" FORCE)
mark_as_advanced(GSL_CXX_STANDARD )
mark_as_advanced(GSL_TEST)
mark_as_advanced(FETCHCONTENT_SOURCE_DIR_MSGSL)
mark_as_advanced(FETCHCONTENT_UPDATES_DISCONNECTED_MSGSL)

add_subdirectory(
    ${CMAKE_SOURCE_DIR}/thirdparty/msgsl
    ${CMAKE_BINARY_DIR}/thirdparty/msgsl
    EXCLUDE_FROM_ALL)

include_directories(${CMAKE_SOURCE_DIR}/thirdparty/msgsl/include)

