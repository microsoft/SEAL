# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT license.

# Check for intrin.h or x86intrin.h
if(SEAL_USE_INTRIN)
    if(MSVC)
        set(SEAL_INTRIN_HEADER "intrin.h")
    else()
        check_cxx_source_runs("
            #if defined(__arm__) || defined(__aarch64__)
                int main() {
                    return 0;
                }
            #else
                #error
            #endif
            "
            SEAL_ARM64
        )
        if(SEAL_ARM64)
            set(SEAL_INTRIN_HEADER "arm_neon.h")
        elseif(EMSCRIPTEN)
            set(SEAL_INTRIN_HEADER "wasm_simd128.h")
        else()
            set(SEAL_INTRIN_HEADER "x86intrin.h")
        endif()
    endif()

    check_include_file_cxx(${SEAL_INTRIN_HEADER} SEAL_INTRIN_HEADER_FOUND)
endif()
