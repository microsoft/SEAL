# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT license.

macro(seal_make_memfn_option id docstring)
    cmake_dependent_option(SEAL_USE_${id} "${docstring}" ON "SEAL_${id}_FOUND" OFF)
    mark_as_advanced(FORCE SEAL_USE_${id})
endmacro()

# Check for SecureZeroMemory
check_symbol_exists(SecureZeroMemory "Windows.h" SEAL_SECURE_ZERO_MEMORY_FOUND)
seal_make_memfn_option(SECURE_ZERO_MEMORY "Use SecureZeroMemory")
message(STATUS "Using SecureZeroMemory: ${SEAL_USE_SECURE_ZERO_MEMORY}")

# Check for memset_s
check_cxx_source_runs("
    #define __STDC_WANT_LIB_EXT1__ 1
    #include <string.h>
    int main(void)
    {
        char str[] = \"ghghghghghghghghghghgh\";
        int r = memset_s(str, sizeof(str), 'a', 5);
        return r;
    }"
    SEAL_MEMSET_S_FOUND)
seal_make_memfn_option(MEMSET_S "Use memset_s")
message(STATUS "Using memset_s: ${SEAL_USE_MEMSET_S}")

# Check for explicit_bzero
check_symbol_exists(explicit_bzero "string.h" SEAL_EXPLICIT_BZERO_FOUND)
seal_make_memfn_option(EXPLICIT_BZERO "Use explicit_bzero")
message(STATUS "Using explicit_bzero: ${SEAL_USE_EXPLICIT_BZERO}")

# Check for explicit_memset
check_symbol_exists(explicit_memset "string.h" SEAL_EXPLICIT_MEMSET_FOUND)
seal_make_memfn_option(EXPLICIT_MEMSET "Use explicit_memset")
message(STATUS "Using explicit_memset: ${SEAL_USE_EXPLICIT_MEMSET}")
