// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#pragma once

#if SEAL_COMPILER == SEAL_COMPILER_GCC

// We require GCC >= 6
#if (__GNUC__ < 6) || not defined(__cplusplus)
#pragma GCC error "SEAL requires __GNUC__ >= 6"
#endif

// Read in config.h
#include "seal/util/config.h"

#if (__GNUC__ == 6) && defined(SEAL_USE_IF_CONSTEXPR)
#pragma GCC error "g++-6 cannot compile Microsoft SEAL as C++17; set CMake build option `SEAL_USE_CXX17' to OFF"
#endif

// Are we using MSGSL?
#ifdef SEAL_USE_MSGSL
#include <gsl/gsl>
#endif

// Are intrinsics enabled?
#ifdef SEAL_USE_INTRIN
#include <x86intrin.h>

#ifdef SEAL_USE___BUILTIN_CLZLL
#define SEAL_MSB_INDEX_UINT64(result, value) {                                      \
    *result = 63UL - static_cast<unsigned long>(__builtin_clzll(value));            \
}
#endif

#ifdef SEAL_USE___INT128
#define SEAL_MULTIPLY_UINT64_HW64(operand1, operand2, hw64) {                       \
    *hw64 = static_cast<unsigned long long>(                                        \
            ((static_cast<unsigned __int128>(operand1)                              \
            * static_cast<unsigned __int128>(operand2)) >> 64));                    \
}

#define SEAL_MULTIPLY_UINT64(operand1, operand2, result128) {                       \
    unsigned __int128 product = static_cast<unsigned __int128>(operand1) * operand2;\
    result128[0] = static_cast<unsigned long long>(product);                        \
    result128[1] = static_cast<unsigned long long>(product >> 64);                  \
}

#define SEAL_DIVIDE_UINT128_UINT64(numerator, denominator, result) {                \
    unsigned __int128 n, q;                                                         \
    n = (static_cast<unsigned __int128>(numerator[1]) << 64) |                      \
        (static_cast<unsigned __int128>(numerator[0]));                             \
    q = n / denominator;                                                            \
    n -= q * denominator;                                                           \
    numerator[0] = static_cast<std::uint64_t>(n);                                   \
    numerator[1] = static_cast<std::uint64_t>(n >> 64);                             \
    quotient[0] = static_cast<std::uint64_t>(q);                                    \
    quotient[1] = static_cast<std::uint64_t>(q >> 64);                              \
}
#endif

#ifdef SEAL_USE__ADDCARRY_U64
#define SEAL_ADD_CARRY_UINT64(operand1, operand2, carry, result) _addcarry_u64(     \
    carry, operand1, operand2, result)
#endif

#ifdef SEAL_USE__SUBBORROW_U64
#if ((__GNUC__ == 7) && (__GNUC_MINOR__ >= 2)) || (__GNUC__  >= 8)
// The inverted arguments problem was fixed in GCC-7.2
// (https://patchwork.ozlabs.org/patch/784309/)
#define SEAL_SUB_BORROW_UINT64(operand1, operand2, borrow, result) _subborrow_u64(  \
    borrow, operand1, operand2, result)
#else
// Warning: Note the inverted order of operand1 and operand2
#define SEAL_SUB_BORROW_UINT64(operand1, operand2, borrow, result) _subborrow_u64(  \
    borrow, operand2, operand1, result)
#endif //(__GNUC__ == 7) && (__GNUC_MINOR__ >= 2)
#endif

#endif //SEAL_USE_INTRIN

#endif
