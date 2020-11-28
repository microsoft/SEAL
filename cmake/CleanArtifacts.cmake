# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT license.

# Remove native/src/gsl directory which is no longer used in version >= 3.5.0
if(EXISTS ${SEAL_INCLUDES_DIR}/gsl)
    message(STATUS "Removing ${SEAL_INCLUDES_DIR}/gsl; this is no longer used by Microsoft SEAL >= 3.5.0")
    file(REMOVE_RECURSE ${SEAL_INCLUDES_DIR}/gsl)
endif()

# Remove thirdparty/zlib/src/CMakeCache.txt: the location changed in SEAL >= 3.5.4
if(EXISTS ${SEAL_THIRDPARTY_DIR}/zlib/src/CMakeCache.txt)
    message(STATUS "Removing old ${SEAL_THIRDPARTY_DIR}/zlib/src/CMakeCache.txt")
    file(REMOVE ${SEAL_THIRDPARTY_DIR}/zlib/src/CMakeCache.txt)
endif()

# Remove config.h from source tree
if(EXISTS ${SEAL_INCLUDES_DIR}/seal/util/config.h)
    message(STATUS "Removing old ${SEAL_INCLUDES_DIR}/seal/util/config.h")
    file(REMOVE ${SEAL_INCLUDES_DIR}/seal/util/config.h)
endif()
