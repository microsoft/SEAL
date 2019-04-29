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

SEALNETNATIVE HRESULT SEALCALL Plaintext_Create1(void *memoryPoolHandle, void **plaintext);

SEALNETNATIVE HRESULT SEALCALL Plaintext_Create2(uint64_t coeffCount, void *memoryPoolHandle, void **plaintext);

SEALNETNATIVE HRESULT SEALCALL Plaintext_Create3(uint64_t capacity, uint64_t coeffCount, void *memoryPoolHandle, void **plaintext);

SEALNETNATIVE HRESULT SEALCALL Plaintext_Create4(char *hexPoly, void *memoryPoolHandle, void **plaintext);

SEALNETNATIVE HRESULT SEALCALL Plaintext_Create5(void *copy, void **plaintext);

SEALNETNATIVE HRESULT SEALCALL Plaintext_Set1(void *thisptr, void *assign);

SEALNETNATIVE HRESULT SEALCALL Plaintext_Set2(void *thisptr, char *hex_poly);

SEALNETNATIVE HRESULT SEALCALL Plaintext_Set3(void *thisptr, uint64_t const_coeff);

SEALNETNATIVE HRESULT SEALCALL Plaintext_Destroy(void *thisptr);

SEALNETNATIVE HRESULT SEALCALL Plaintext_CoeffCount(void *thisptr, uint64_t *coeff_count);

SEALNETNATIVE HRESULT SEALCALL Plaintext_CoeffAt(void *thisptr, uint64_t index, uint64_t *coeff);

SEALNETNATIVE HRESULT SEALCALL Plaintext_SetCoeffAt(void *thisptr, uint64_t index, uint64_t value);

SEALNETNATIVE HRESULT SEALCALL Plaintext_ToString(void *thispt, uint64_t *length, char *outstr);

SEALNETNATIVE HRESULT SEALCALL Plaintext_IsNTTForm(void *thisptr, bool *is_ntt_form);

SEALNETNATIVE HRESULT SEALCALL Plaintext_IsZero(void *thisptr, bool *is_zero);

SEALNETNATIVE HRESULT SEALCALL Plaintext_SetZero1(void *thisptr);

SEALNETNATIVE HRESULT SEALCALL Plaintext_SetZero2(void *thisptr, uint64_t start_coeff);

SEALNETNATIVE HRESULT SEALCALL Plaintext_SetZero3(void *thisptr, uint64_t start_coeff, uint64_t length);

SEALNETNATIVE HRESULT SEALCALL Plaintext_GetParmsId(void *thisptr, uint64_t *parms_id);

SEALNETNATIVE HRESULT SEALCALL Plaintext_SetParmsId(void *thisptr, uint64_t *parms_id);

SEALNETNATIVE HRESULT SEALCALL Plaintext_Reserve(void *thisptr, uint64_t capacity);

SEALNETNATIVE HRESULT SEALCALL Plaintext_Resize(void *thisptr, uint64_t coeff_count);

SEALNETNATIVE HRESULT SEALCALL Plaintext_ShrinkToFit(void *thisptr);

SEALNETNATIVE HRESULT SEALCALL Plaintext_Release(void *thisptr);

SEALNETNATIVE HRESULT SEALCALL Plaintext_Capacity(void *thisptr, uint64_t *capacity);

SEALNETNATIVE HRESULT SEALCALL Plaintext_SignificantCoeffCount(void *thisptr, uint64_t *significant_coeff_count);

SEALNETNATIVE HRESULT SEALCALL Plaintext_NonZeroCoeffCount(void *thisptr, uint64_t *nonzero_coeff_count);

SEALNETNATIVE HRESULT SEALCALL Plaintext_Scale(void *thisptr, double *scale);

SEALNETNATIVE HRESULT SEALCALL Plaintext_SetScale(void *thisptr, double scale);

SEALNETNATIVE HRESULT SEALCALL Plaintext_Equals(void *thisptr, void *other, bool *result);

SEALNETNATIVE HRESULT SEALCALL Plaintext_SwapData(void *thisptr, uint64_t count, uint64_t *new_data);

SEALNETNATIVE HRESULT SEALCALL Plaintext_Pool(void *thisptr, void **pool);