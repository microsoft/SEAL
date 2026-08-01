# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT license.

include(CheckCXXCompilerFlag)

# For easier adding of CXX compiler flags.
function(seal_enable_cxx_compiler_flag_if_supported flag)
    string(FIND "${CMAKE_CXX_FLAGS}" "${flag}" flag_already_set)
    if(flag_already_set EQUAL -1)
        message(STATUS "Adding CXX compiler flag: ${flag} ...")
        check_cxx_compiler_flag("${flag}" flag_supported)
        if(flag_supported)
            set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} ${flag}" PARENT_SCOPE)
        endif()
        unset(flag_supported CACHE)
    endif()
endfunction()

if(NOT MSVC AND SEAL_DEBUG)
    # This only works with single-configuration generators.
    seal_enable_cxx_compiler_flag_if_supported("-Wall")
    seal_enable_cxx_compiler_flag_if_supported("-Wextra")
    seal_enable_cxx_compiler_flag_if_supported("-Wconversion")
    seal_enable_cxx_compiler_flag_if_supported("-Wshadow")
    seal_enable_cxx_compiler_flag_if_supported("-pedantic")
    if(CMAKE_CXX_COMPILER_ID MATCHES "Clang")
        # GCC accepts unknown -Wno-* flags without error, so the support probe above
        # cannot reject this Clang-only flag. Offer it only to compilers that implement
        # it, otherwise GCC reports it as unrecognized alongside every other diagnostic.
        seal_enable_cxx_compiler_flag_if_supported("-Wno-gnu-statement-expression-from-macro-expansion")
    endif()
endif()
