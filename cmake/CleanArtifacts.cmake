# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT license.

# Remove native/src/gsl directory which is no longer used in version >= 3.5.0
if(NOT MSVC AND EXISTS ${SEAL_INCLUDES_BUILD_DIR}/gsl)
    message(STATUS "Removing ${SEAL_INCLUDES_BUILD_DIR}/gsl; this is no longer used by Microsoft SEAL >= 3.5.0")
    file(REMOVE_RECURSE ${SEAL_INCLUDES_BUILD_DIR}/gsl)
endif()

# Remove thirdparty/zlib/src/CMakeCache.txt: the location changed in SEAL >= 3.5.4
if(NOT MSVC AND EXISTS ${SEAL_THIRDPARTY_DIR}/zlib/src/CMakeCache.txt)
    message(STATUS "Removing old ${SEAL_THIRDPARTY_DIR}/zlib/src/CMakeCache.txt")
    file(REMOVE ${SEAL_THIRDPARTY_DIR}/zlib/src/CMakeCache.txt)
endif()