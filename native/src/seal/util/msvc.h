// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#pragma once

#if SEAL_COMPILER == SEAL_COMPILER_MSVC

// Require Visual Studio 2017 version 15.3 or newer
#if (_MSC_VER < 1911)
#error "Microsoft Visual Studio 2017 version 15.3 or newer required"
#endif

// Read in config.h
#include "seal/util/config.h"

// Do not throw when Evaluator produces transparent ciphertexts
//#undef SEAL_THROW_ON_TRANSPARENT_CIPHERTEXT

// Try to check presence of additional headers using __has_include
#ifdef __has_include

// Check for MSGSL
#if __has_include(<gsl/gsl>)
#include <gsl/gsl>
#define SEAL_USE_MSGSL
#else
#undef SEAL_USE_MSGSL
#endif //__has_include(<gsl/gsl>)

#endif

// In Visual Studio redefine std::byte (SEAL_BYTE)
#undef SEAL_USE_STD_BYTE

// In Visual Studio for now we disable the use of std::shared_mutex
#undef SEAL_USE_SHARED_MUTEX

// Are we compiling with C++17 or newer
#if (__cplusplus >= 201703L)

// Use `if constexpr'
#define SEAL_USE_IF_CONSTEXPR

// Use [[maybe_unused]]
#define SEAL_USE_MAYBE_UNUSED
#else
#undef SEAL_USE_IF_CONSTEXPR
#undef SEAL_USE_MAYBE_UNUSED
#endif

// X64
#ifdef _M_X64

#ifdef SEAL_USE_INTRIN
#include <intrin.h>

#ifdef SEAL_USE__UMUL128
#pragma intrinsic(_umul128)
#define SEAL_MULTIPLY_UINT64_HW64(operand1, operand2, hw64) {                       \
    _umul128(operand1, operand2, hw64);                                             \
}

#define SEAL_MULTIPLY_UINT64(operand1, operand2, result128) {                       \
    result128[0] = _umul128(operand1, operand2, result128 + 1);                     \
}
#endif

#ifdef SEAL_USE__BITSCANREVERSE64
#pragma intrinsic(_BitScanReverse64)
#define SEAL_MSB_INDEX_UINT64(result, value) _BitScanReverse64(result, value)
#endif

#ifdef SEAL_USE__ADDCARRY_U64
#pragma intrinsic(_addcarry_u64)
#define SEAL_ADD_CARRY_UINT64(operand1, operand2, carry, result) _addcarry_u64(     \
    carry, operand1, operand2, result)
#endif

#ifdef SEAL_USE__SUBBORROW_U64
#pragma intrinsic(_subborrow_u64)
#define SEAL_SUB_BORROW_UINT64(operand1, operand2, borrow, result) _subborrow_u64(  \
    borrow, operand1, operand2, result)
#endif

#endif
#else
#undef SEAL_USE_INTRIN

#endif //_M_X64

#endif
