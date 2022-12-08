# Copyright (c) Microsoft Corporation. All rights reserved.  Licensed under the MIT license.

set(SKIP_INSTALL_ALL ON CACHE BOOL "" FORCE)
mark_as_advanced(AMD64)
mark_as_advanced(ASM686)
mark_as_advanced(EXECUTABLE_OUTPUT_PATH)
mark_as_advanced(CMAKE_INSTALL_PREFIX)
mark_as_advanced(INSTALL_BIN_DIR)
mark_as_advanced(INSTALL_INC_DIR)
mark_as_advanced(INSTALL_LIB_DIR)
mark_as_advanced(INSTALL_MAN_DIR)
mark_as_advanced(INSTALL_PKGCONFIG_DIR)
mark_as_advanced(LIBRARY_OUTPUT_PATH)
mark_as_advanced(CMAKE_BACKWARDS_COMPATIBILITY)
mark_as_advanced(ZLIB_BUILD_STATIC)
mark_as_advanced(SKIP_INSTALL_ALL)

# ZLIB has no VERSION given to project(), needs to suppress CMP0048 warning
set(CMAKE_SUPPRESS_DEVELOPER_WARNINGS TRUE CACHE INTERNAL "Suppress CMP0048 warning" FORCE)

# ZLIB pollutes the source directory, so copy the source code under 
# {CMAKE_BINARY_DIR} and build it from there. This keeps *our* source
# directory clean.
file(
    COPY
    ${CMAKE_SOURCE_DIR}/thirdparty/zlib/
    DESTINATION
    ${CMAKE_BINARY_DIR}/thirdparty/zlib/)


add_subdirectory(
    ${CMAKE_BINARY_DIR}/thirdparty/zlib/
    ${CMAKE_BINARY_DIR}/thirdparty/zlib-build/
    EXCLUDE_FROM_ALL)
