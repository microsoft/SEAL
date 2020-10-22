# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT license.

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

# Check for explicit_bzero
check_symbol_exists(explicit_bzero "string.h" SEAL_EXPLICIT_BZERO_FOUND)

# Check for explicit_memset
check_symbol_exists(explicit_memset "string.h" SEAL_EXPLICIT_MEMSET_FOUND)
