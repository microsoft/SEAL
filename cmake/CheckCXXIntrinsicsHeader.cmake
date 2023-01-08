# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT license.

# Check for intrin.h or x86intrin.h
if(SEAL_USE_INTRIN)
    set(CMAKE_REQUIRED_QUIET_OLD ${CMAKE_REQUIRED_QUIET})
    set(CMAKE_REQUIRED_QUIET ON)

    if(MSVC)
        set(SEAL_INTRIN_HEADER "intrin.h")
    else()
        if(CMAKE_SYSTEM_PROCESSOR STREQUAL "aarch64" OR CMAKE_SYSTEM_PROCESSOR STREQUAL "arm64")
            set(SEAL_ARM64 ON)
        else()
            set(SEAL_ARM64 OFF)
        endif()
        if(SEAL_ARM64)
            set(SEAL_INTRIN_HEADER "arm_neon.h")
        elseif(EMSCRIPTEN)
            set(SEAL_INTRIN_HEADER "wasm_simd128.h")
        else()
            set(SEAL_INTRIN_HEADER "x86intrin.h")
        endif()
    endif()

    check_include_file_cxx(${SEAL_INTRIN_HEADER} SEAL_INTRIN_HEADER_FOUND)
    set(CMAKE_REQUIRED_QUIET ${CMAKE_REQUIRED_QUIET_OLD})

    if(SEAL_INTRIN_HEADER_FOUND)
        message(STATUS "${SEAL_INTRIN_HEADER} - found")
    else()
        message(STATUS "${SEAL_INTRIN_HEADER} - not found")
    endif()
endif()
