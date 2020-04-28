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

SEAL_C_FUNC Plaintext_Create1(void *memoryPoolHandle, void **plaintext);

SEAL_C_FUNC Plaintext_Create2(uint64_t coeffCount, void *memoryPoolHandle, void **plaintext);

SEAL_C_FUNC Plaintext_Create3(uint64_t capacity, uint64_t coeffCount, void *memoryPoolHandle, void **plaintext);

SEAL_C_FUNC Plaintext_Create4(char *hex_poly, void *memoryPoolHandle, void **plaintext);

SEAL_C_FUNC Plaintext_Create5(void *copy, void **plaintext);

SEAL_C_FUNC Plaintext_Set1(void *thisptr, void *assign);

SEAL_C_FUNC Plaintext_Set2(void *thisptr, char *hex_poly);

SEAL_C_FUNC Plaintext_Set3(void *thisptr, uint64_t const_coeff);

SEAL_C_FUNC Plaintext_Destroy(void *thisptr);

SEAL_C_FUNC Plaintext_CoeffCount(void *thisptr, uint64_t *coeff_count);

SEAL_C_FUNC Plaintext_CoeffAt(void *thisptr, uint64_t index, uint64_t *coeff);

SEAL_C_FUNC Plaintext_SetCoeffAt(void *thisptr, uint64_t index, uint64_t value);

SEAL_C_FUNC Plaintext_ToString(void *thispt, char *outstr, uint64_t *length);

SEAL_C_FUNC Plaintext_IsNTTForm(void *thisptr, bool *is_ntt_form);

SEAL_C_FUNC Plaintext_IsZero(void *thisptr, bool *is_zero);

SEAL_C_FUNC Plaintext_SetZero1(void *thisptr);

SEAL_C_FUNC Plaintext_SetZero2(void *thisptr, uint64_t start_coeff);

SEAL_C_FUNC Plaintext_SetZero3(void *thisptr, uint64_t start_coeff, uint64_t length);

SEAL_C_FUNC Plaintext_GetParmsId(void *thisptr, uint64_t *parms_id);

SEAL_C_FUNC Plaintext_SetParmsId(void *thisptr, uint64_t *parms_id);

SEAL_C_FUNC Plaintext_Reserve(void *thisptr, uint64_t capacity);

SEAL_C_FUNC Plaintext_Resize(void *thisptr, uint64_t coeff_count);

SEAL_C_FUNC Plaintext_ShrinkToFit(void *thisptr);

SEAL_C_FUNC Plaintext_Release(void *thisptr);

SEAL_C_FUNC Plaintext_Capacity(void *thisptr, uint64_t *capacity);

SEAL_C_FUNC Plaintext_SignificantCoeffCount(void *thisptr, uint64_t *significant_coeff_count);

SEAL_C_FUNC Plaintext_NonZeroCoeffCount(void *thisptr, uint64_t *nonzero_coeff_count);

SEAL_C_FUNC Plaintext_Scale(void *thisptr, double *scale);

SEAL_C_FUNC Plaintext_SetScale(void *thisptr, double scale);

SEAL_C_FUNC Plaintext_Equals(void *thisptr, void *other, bool *result);

SEAL_C_FUNC Plaintext_SwapData(void *thisptr, uint64_t count, uint64_t *new_data);

SEAL_C_FUNC Plaintext_Pool(void *thisptr, void **pool);

SEAL_C_FUNC Plaintext_SaveSize(void *thisptr, uint8_t compr_mode, int64_t *result);

SEAL_C_FUNC Plaintext_Save(void *thisptr, uint8_t *outptr, uint64_t size, uint8_t compr_mode, int64_t *out_bytes);

SEAL_C_FUNC Plaintext_UnsafeLoad(void *thisptr, void *context, uint8_t *inptr, uint64_t size, int64_t *in_bytes);

SEAL_C_FUNC Plaintext_Load(void *thisptr, void *context, uint8_t *inptr, uint64_t size, int64_t *in_bytes);
