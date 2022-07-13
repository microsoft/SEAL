# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT license.

set(BUILD_GMOCK OFF CACHE BOOL "" FORCE)
set(INSTALL_GTEST OFF CACHE BOOL "" FORCE)
set(gtest_force_shared_crt ON CACHE BOOL "" FORCE)
mark_as_advanced(BUILD_GMOCK)
mark_as_advanced(INSTALL_GTEST)
mark_as_advanced(FETCHCONTENT_SOURCE_DIR_GOOGLETEST)
mark_as_advanced(FETCHCONTENT_UPDATES_DISCONNECTED_GOOGLETEST)

add_subdirectory(
    ${CMAKE_SOURCE_DIR}/thirdparty/googletest
		${CMAKE_BINARY_DIR}/thirdparty/googletest
    EXCLUDE_FROM_ALL)
