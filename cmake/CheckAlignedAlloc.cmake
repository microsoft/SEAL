# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT license.

# [option] SEAL_USE_ALIGNED_ALLOC (default: ON, advanced)
# Not available when no aligned allocation routine is found.
# Use 64-byte aligned allocation if available, set to OFF otherwise.
if(MSVC)
    set(SEAL_USE_ALIGNED_ALLOC_OPTION_STR "Use _aligned_malloc")
else()
    set(SEAL_USE_ALIGNED_ALLOC_OPTION_STR "Use std::aligned_alloc")
endif()

# Probe for the routine the headers will actually use: _aligned_malloc on Windows, where no
# CRT provides std::aligned_alloc, and std::aligned_alloc elsewhere. The probe compiles with
# SEAL_LANG_FLAG, so it also enforces the language standard each routine needs. On Android it
# likewise tracks the API level, as bionic introduced aligned_alloc in API 28.
# The cached result is discarded first, so that the probe re-runs whenever either of these changes
# in an existing build tree.
unset(SEAL_ALIGNED_ALLOC_FOUND CACHE)
cmake_push_check_state(RESET)
set(CMAKE_REQUIRED_QUIET TRUE)
if(NOT MSVC)
    set(CMAKE_REQUIRED_FLAGS "${CMAKE_REQUIRED_FLAGS} ${SEAL_LANG_FLAG}")
endif()
if(WIN32)
    check_cxx_source_compiles("
        #include <malloc.h>
        int main() {
            void *ptr = _aligned_malloc(64, 64);
            _aligned_free(ptr);
            return 0;
        }"
        SEAL_ALIGNED_ALLOC_FOUND
    )
else()
    check_cxx_source_compiles("
        #include <cstdlib>
        int main() {
            void *ptr = std::aligned_alloc(64, 64);
            std::free(ptr);
            return 0;
        }"
        SEAL_ALIGNED_ALLOC_FOUND
    )
endif()
cmake_pop_check_state()

cmake_dependent_option(SEAL_USE_ALIGNED_ALLOC ${SEAL_USE_ALIGNED_ALLOC_OPTION_STR} ON "SEAL_ALIGNED_ALLOC_FOUND" OFF)
mark_as_advanced(FORCE SEAL_USE_ALIGNED_ALLOC)
message(STATUS "SEAL_USE_ALIGNED_ALLOC: ${SEAL_USE_ALIGNED_ALLOC}")
