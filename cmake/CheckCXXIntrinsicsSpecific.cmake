# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT license.

macro(seal_start_detect_intrinsics)
    cmake_push_check_state(RESET)
    set(CMAKE_REQUIRED_QUIET TRUE)
    if(NOT MSVC)
        set(CMAKE_REQUIRED_FLAGS "${CMAKE_REQUIRED_FLAGS} -O0 ${SEAL_LANG_FLAG}")
    endif()
    if(SEAL_INTRIN_HEADER)
        set(CMAKE_EXTRA_INCLUDE_FILES ${SEAL_INTRIN_HEADER})
    endif()
endmacro()

macro(seal_end_detect_intrinsics)
    cmake_pop_check_state()
endmacro()

# Check for presence of _umul128
macro(seal_detect__umul128)
    seal_start_detect_intrinsics()

    seal_check_cxx_program("
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

    seal_end_detect_intrinsics()
endmacro()

# Check for presence of __umulh
macro(seal_detect___umulh)
    seal_start_detect_intrinsics()

    seal_check_cxx_program("
        #include <${SEAL_INTRIN_HEADER}>
        int main() {
            unsigned long long a = 0, b = 0;
            volatile unsigned long long c;
            c = __umulh(a, b);
            return 0;
        }"
        SEAL___UMULH_FOUND
    )

    seal_end_detect_intrinsics()
endmacro()

# Check for presence of __int128
macro(seal_detect___int128)
    seal_start_detect_intrinsics()

    check_type_size("__int128" INT128 LANGUAGE CXX)
    if(INT128 EQUAL 16)
        set(SEAL___INT128_FOUND ON)
    else()
        set(SEAL___INT128_FOUND OFF)
    endif()

    seal_end_detect_intrinsics()
endmacro()

# Check for presence of _BitScanReverse64
macro(seal_detect__BitScanReverse64)
    seal_start_detect_intrinsics()

    seal_check_cxx_program("
        #include <${SEAL_INTRIN_HEADER}>
        int main() {
            unsigned long a = 0, b = 0;
            volatile unsigned char res = _BitScanReverse64(&a, b);
            return 0;
        }"
        SEAL__BITSCANREVERSE64_FOUND
    )

    seal_end_detect_intrinsics()
endmacro()

# Check for presence of __builtin_clzll
macro(seal_detect___builtin_clzll)
    seal_start_detect_intrinsics()

    seal_check_cxx_program("
        int main() {
            volatile auto res = __builtin_clzll(1);
            return 0;
        }"
        SEAL___BUILTIN_CLZLL_FOUND
    )

    seal_end_detect_intrinsics()
endmacro()

# Check for presence of _addcarry_u64
macro(seal_detect__addcarry_u64)
    seal_start_detect_intrinsics()

    seal_check_cxx_program("
        #include <${SEAL_INTRIN_HEADER}>
        int main() {
            unsigned long long a;
            volatile auto res = _addcarry_u64(0,0,0,&a);
            return 0;
        }"
        SEAL__ADDCARRY_U64_FOUND
    )

    seal_end_detect_intrinsics()
endmacro()

# Check for presence of _subborrow_u64
macro(seal_detect__subborrow_u64)
    seal_start_detect_intrinsics()

    seal_check_cxx_program("
        #include <${SEAL_INTRIN_HEADER}>
        int main() {
            unsigned long long a;
            volatile auto res = _subborrow_u64(0,0,0,&a);
            return 0;
        }"
        SEAL__SUBBORROW_U64_FOUND
    )

    seal_end_detect_intrinsics()
endmacro()

# Check for presence of __builtin_addcll
macro(seal_detect___builtin_addcll)
    seal_start_detect_intrinsics()

    seal_check_cxx_program("
            int main() {
                unsigned long long a;
                volatile auto res = __builtin_addcll(0,0,0,&a);
                return 0;
            }"
            SEAL___BUILTIN_ADDCLL_FOUND
        )
    
    seal_end_detect_intrinsics()
endmacro()

# Check for presence of __builtin_subcll
macro(seal_detect___builtin_subcll)
    seal_start_detect_intrinsics()

    seal_check_cxx_program("
            int main() {
                unsigned long long a;
                volatile auto res = __builtin_subcll(0,0,0,&a);
                return 0;
            }"
            SEAL___BUILTIN_SUBCLL_FOUND
        )
    
    seal_end_detect_intrinsics()
endmacro()