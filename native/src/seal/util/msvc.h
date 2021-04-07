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

// In Visual Studio redefine std::byte (seal_byte)
#undef SEAL_USE_STD_BYTE

// In Visual Studio for now we disable the use of std::shared_mutex
#undef SEAL_USE_SHARED_MUTEX

// Are we compiling with C++17 or newer
#if (_MSVC_LANG >= 201703L)

// Use `if constexpr'
#define SEAL_USE_IF_CONSTEXPR

// Use [[maybe_unused]]
#define SEAL_USE_MAYBE_UNUSED

// Use [[nodiscard]]
#define SEAL_USE_NODISCARD

#else

#ifdef SEAL_USE_IF_CONSTEXPR
#pragma message("Disabling `if constexpr` based on _MSVC_LANG value " SEAL_STRINGIZE( \
    _MSVC_LANG) ": undefining SEAL_USE_IF_CONSTEXPR")
#undef SEAL_USE_IF_CONSTEXPR
#endif

#ifdef SEAL_USE_MAYBE_UNUSED
#pragma message("Disabling `[[maybe_unused]]` based on _MSVC_LANG value " SEAL_STRINGIZE( \
    _MSVC_LANG) ": undefining SEAL_USE_MAYBE_UNUSED")
#undef SEAL_USE_MAYBE_UNUSED
#endif

#ifdef SEAL_USE_NODISCARD
#pragma message("Disabling `[[nodiscard]]` based on _MSVC_LANG value " SEAL_STRINGIZE( \
    _MSVC_LANG) ": undefining SEAL_USE_NODISCARD")
#undef SEAL_USE_NODISCARD
#endif
#endif

#ifdef SEAL_USE_ALIGNED_ALLOC
#define SEAL_MALLOC(size) static_cast<seal_byte *>(_aligned_malloc((size), 64))
#define SEAL_FREE(ptr) _aligned_free(ptr)
#endif

// X64
#ifdef _M_X64

#ifdef SEAL_USE_INTRIN
#include <intrin.h>

#ifdef SEAL_USE__UMUL128
#pragma intrinsic(_umul128)
#define SEAL_MULTIPLY_UINT64_HW64(operand1, operand2, hw64) _umul128(operand1, operand2, hw64);

#define SEAL_MULTIPLY_UINT64(operand1, operand2, result128) result128[0] = _umul128(operand1, operand2, result128 + 1);
#endif

#ifdef SEAL_USE__BITSCANREVERSE64
#pragma intrinsic(_BitScanReverse64)
#define SEAL_MSB_INDEX_UINT64(result, value) _BitScanReverse64(result, value)
#endif

#ifdef SEAL_USE__ADDCARRY_U64
#pragma intrinsic(_addcarry_u64)
#define SEAL_ADD_CARRY_UINT64(operand1, operand2, carry, result) _addcarry_u64(carry, operand1, operand2, result)
#endif

#ifdef SEAL_USE__SUBBORROW_U64
#pragma intrinsic(_subborrow_u64)
#define SEAL_SUB_BORROW_UINT64(operand1, operand2, borrow, result) _subborrow_u64(borrow, operand1, operand2, result)
#endif

#endif
#else
#undef SEAL_USE_INTRIN

#endif //_M_X64

// Force inline
#define SEAL_FORCE_INLINE __forceinline

#endif
