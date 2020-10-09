# Check for memset_s
if(SEAL_USE_MEMSET_S)
    check_cxx_source_runs("
        #define __STDC_WANT_LIB_EXT1__ 1
        #include <string.h>
        int main(void)
        {
            char str[] = \"ghghghghghghghghghghgh\";
            int r = memset_s(str, sizeof(str), 'a', 5);
            return r;
        }"
        USE_MEMSET_S)
    if(NOT USE_MEMSET_S)
        set(SEAL_USE_MEMSET_S OFF CACHE BOOL ${SEAL_USE_MEMSET_S_OPTION_STR} FORCE)
    endif()
    unset(USE_MEMSET_S CACHE)
endif()

# Check for explicit_bzero
if(SEAL_USE_EXPLICIT_BZERO)
    check_symbol_exists(explicit_bzero "string.h" USE_EXPLICIT_BZERO)
    if(NOT USE_EXPLICIT_BZERO)
        set(SEAL_USE_EXPLICIT_BZERO OFF CACHE BOOL ${SEAL_USE_EXPLICIT_BZERO_OPTION_STR} FORCE)
    endif()
    unset(USE_EXPLICIT_BZERO)
endif()

# Check for explicit_memset
if(SEAL_USE_EXPLICIT_MEMSET)
    check_symbol_exists(explicit_memset "string.h" USE_EXPLICIT_MEMSET)
    if(NOT USE_EXPLICIT_MEMSET)
        set(SEAL_USE_EXPLICIT_MEMSET OFF CACHE BOOL ${SEAL_USE_EXPLICIT_MEMSET_OPTION_STR} FORCE)
    endif()
    unset(USE_EXPLICIT_MEMSET)
endif()