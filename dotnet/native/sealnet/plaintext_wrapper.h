// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#pragma once

///////////////////////////////////////////////////////////////////////////
//
// This API is provided as a simple interface for Microsoft SEAL library
// that can be PInvoked by .Net code.
//
///////////////////////////////////////////////////////////////////////////

#include "sealnet/defines.h"
#include <stdint.h>

SEALMETHOD Plaintext_Create1(void *memoryPoolHandle, void **plaintext);

SEALMETHOD Plaintext_Create2(uint64_t coeffCount, void *memoryPoolHandle, void **plaintext);

SEALMETHOD Plaintext_Create3(uint64_t capacity, uint64_t coeffCount, void *memoryPoolHandle, void **plaintext);

SEALMETHOD Plaintext_Create4(char *hexPoly, void *memoryPoolHandle, void **plaintext);

SEALMETHOD Plaintext_Create5(void *copy, void **plaintext);

SEALMETHOD Plaintext_Set1(void *thisptr, void *assign);

SEALMETHOD Plaintext_Set2(void *thisptr, char *hex_poly);

SEALMETHOD Plaintext_Set3(void *thisptr, uint64_t const_coeff);

SEALMETHOD Plaintext_Destroy(void *thisptr);

SEALMETHOD Plaintext_CoeffCount(void *thisptr, uint64_t *coeff_count);

SEALMETHOD Plaintext_CoeffAt(void *thisptr, uint64_t index, uint64_t *coeff);

SEALMETHOD Plaintext_SetCoeffAt(void *thisptr, uint64_t index, uint64_t value);

SEALMETHOD Plaintext_ToString(void *thispt, uint64_t *length, char *outstr);

SEALMETHOD Plaintext_IsNTTForm(void *thisptr, bool *is_ntt_form);

SEALMETHOD Plaintext_IsZero(void *thisptr, bool *is_zero);

SEALMETHOD Plaintext_SetZero1(void *thisptr);

SEALMETHOD Plaintext_SetZero2(void *thisptr, uint64_t start_coeff);

SEALMETHOD Plaintext_SetZero3(void *thisptr, uint64_t start_coeff, uint64_t length);

SEALMETHOD Plaintext_GetParmsId(void *thisptr, uint64_t *parms_id);

SEALMETHOD Plaintext_SetParmsId(void *thisptr, uint64_t *parms_id);

SEALMETHOD Plaintext_Reserve(void *thisptr, uint64_t capacity);

SEALMETHOD Plaintext_Resize(void *thisptr, uint64_t coeff_count);

SEALMETHOD Plaintext_ShrinkToFit(void *thisptr);

SEALMETHOD Plaintext_Release(void *thisptr);

SEALMETHOD Plaintext_Capacity(void *thisptr, uint64_t *capacity);

SEALMETHOD Plaintext_SignificantCoeffCount(void *thisptr, uint64_t *significant_coeff_count);

SEALMETHOD Plaintext_NonZeroCoeffCount(void *thisptr, uint64_t *nonzero_coeff_count);

SEALMETHOD Plaintext_Scale(void *thisptr, double *scale);

SEALMETHOD Plaintext_SetScale(void *thisptr, double scale);

SEALMETHOD Plaintext_Equals(void *thisptr, void *other, bool *result);

SEALMETHOD Plaintext_SwapData(void *thisptr, uint64_t count, uint64_t *new_data);

SEALMETHOD Plaintext_Pool(void *thisptr, void **pool);

SEALMETHOD Plaintext_SaveSize(void *thisptr, uint8_t compr_mode, int64_t *result);

SEALMETHOD Plaintext_Save(void *thisptr, uint8_t *outptr, uint64_t size, uint8_t compr_mode, int64_t *out_bytes);

SEALMETHOD Plaintext_UnsafeLoad(void *thisptr, void *context, uint8_t *inptr, uint64_t size, int64_t *in_bytes);

SEALMETHOD Plaintext_Load(void *thisptr, void *context, uint8_t *inptr, uint64_t size, int64_t *in_bytes);
