# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT license.

if(SEAL_USE_INTRIN)
    cmake_push_check_state(RESET)
    set(CMAKE_REQUIRED_QUIET TRUE)
    if(NOT MSVC)
        set(CMAKE_REQUIRED_FLAGS "${CMAKE_REQUIRED_FLAGS} -O0 ${SEAL_LANG_FLAG}")
    endif()

    if(MSVC)
        # Check for presence of _umul128
        check_cxx_source_runs("
            #include <${SEAL_INTRIN_HEADER}>
            int main() {
                unsigned long long a = 0, b = 0;
                unsigned long long c;
                volatile unsigned long long d;
                d = _umul128(a, b, &c);
                return 0;
            }"
            SEAL__UMUL128_FOUND
        )

        # Check for _BitScanReverse64
        check_cxx_source_runs("
            #include <${SEAL_INTRIN_HEADER}>
            int main() {
                unsigned long a = 0, b = 0;
                volatile unsigned char res = _BitScanReverse64(&a, b);
                return 0;
            }"
            SEAL__BITSCANREVERSE64_FOUND
        )
    else()
        # Check for presence of __int128
        set(CMAKE_EXTRA_INCLUDE_FILES ${SEAL_INTRIN_HEADER})
        check_type_size("__int128" INT128 LANGUAGE CXX)
        if(INT128 EQUAL 16)
            set(SEAL___INT128_FOUND ON)
        else()
            set(SEAL___INT128_FOUND OFF)
        endif()

        # Check for __builtin_clzll
        check_cxx_source_runs("
            int main() {
                volatile auto res = __builtin_clzll(0);
                return 0;
            }"
            SEAL___BUILTIN_CLZLL_FOUND
        )
    endif()

    # Check for _addcarry_u64
    check_cxx_source_runs("
        #include <${SEAL_INTRIN_HEADER}>
        int main() {
            unsigned long long a;
            volatile auto res = _addcarry_u64(0,0,0,&a);
            return 0;
        }"
        SEAL__ADDCARRY_U64_FOUND
    )

    # Check for _subborrow_u64
    check_cxx_source_runs("
        #include <${SEAL_INTRIN_HEADER}>
        int main() {
            unsigned long long a;
            volatile auto res = _subborrow_u64(0,0,0,&a);
            return 0;
        }"
        SEAL__SUBBORROW_U64_FOUND
    )

    cmake_pop_check_state()
endif()
