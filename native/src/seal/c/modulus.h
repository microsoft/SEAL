// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#pragma once

///////////////////////////////////////////////////////////////////////////
//
// This API is provided as a simple interface for Microsoft SEAL library
// that can be PInvoked by .Net code.
//
///////////////////////////////////////////////////////////////////////////

#include "seal/c/defines.h"
#include <stdint.h>

SEAL_C_FUNC Modulus_Create1(uint64_t value, void **small_modulus);

SEAL_C_FUNC Modulus_Create2(void *copy, void **small_modulus);

SEAL_C_FUNC Modulus_Destroy(void *thisptr);

SEAL_C_FUNC Modulus_IsZero(void *thisptr, bool *is_zero);

SEAL_C_FUNC Modulus_IsPrime(void *thisptr, bool *is_prime);

SEAL_C_FUNC Modulus_Value(void *thisptr, uint64_t *value);

SEAL_C_FUNC Modulus_BitCount(void *thisptr, int *bit_count);

SEAL_C_FUNC Modulus_UInt64Count(void *thisptr, uint64_t *uint64_count);

SEAL_C_FUNC Modulus_Set1(void *thisptr, void *assign);

SEAL_C_FUNC Modulus_Set2(void *thisptr, uint64_t value);

SEAL_C_FUNC Modulus_ConstRatio(void *thisptr, uint64_t length, uint64_t ratio[]);

SEAL_C_FUNC Modulus_Equals1(void *thisptr, void *other, bool *result);

SEAL_C_FUNC Modulus_Equals2(void *thisptr, uint64_t other, bool *result);

SEAL_C_FUNC Modulus_SaveSize(void *thisptr, uint8_t compr_mode, int64_t *result);

SEAL_C_FUNC Modulus_Save(void *thisptr, uint8_t *outptr, uint64_t size, uint8_t compr_mode, int64_t *out_bytes);

SEAL_C_FUNC Modulus_Load(void *thisptr, uint8_t *inptr, uint64_t size, int64_t *in_bytes);

SEAL_C_FUNC CoeffModulus_MaxBitCount(uint64_t poly_modulus_degree, int sec_level, int *bit_count);

SEAL_C_FUNC CoeffModulus_BFVDefault(uint64_t poly_modulus_degree, int sec_level, uint64_t *length, void **coeffs);

SEAL_C_FUNC CoeffModulus_Create(uint64_t poly_modulus_degree, uint64_t length, int *bit_sizes, void **coeffs);
