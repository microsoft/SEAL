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

SEALNETNATIVE HRESULT SEALCALL Ciphertext_Create1(void *pool, void **cipher);

SEALNETNATIVE HRESULT SEALCALL Ciphertext_Create2(void *copy, void **cipher);

SEALNETNATIVE HRESULT SEALCALL Ciphertext_Create3(void *context, void *pool, void **cipher);

SEALNETNATIVE HRESULT SEALCALL Ciphertext_Create4(void *context, uint64_t *parms_id, void *pool, void **cipher);

SEALNETNATIVE HRESULT SEALCALL Ciphertext_Create5(void *context, uint64_t *parms_id, uint64_t capacity, void *pool, void **ciphertext);

SEALNETNATIVE HRESULT SEALCALL Ciphertext_Reserve1(void *thisptr, void *context, uint64_t *parms_id, uint64_t size_capacity);

SEALNETNATIVE HRESULT SEALCALL Ciphertext_Reserve2(void *thisptr, void *context, uint64_t size_capacity);

SEALNETNATIVE HRESULT SEALCALL Ciphertext_Reserve3(void *thisptr, uint64_t size_capacity);

SEALNETNATIVE HRESULT SEALCALL Ciphertext_Set(void *thisptr, void *assign);

SEALNETNATIVE HRESULT SEALCALL Ciphertext_Destroy(void *thisptr);

SEALNETNATIVE HRESULT SEALCALL Ciphertext_UInt64Count(void *thisptr, uint64_t *uint64_count);

SEALNETNATIVE HRESULT SEALCALL Ciphertext_UInt64CountCapacity(void *thisptr, uint64_t *uint64_count_capacity);

SEALNETNATIVE HRESULT SEALCALL Ciphertext_Size(void *thisptr, uint64_t *size);

SEALNETNATIVE HRESULT SEALCALL Ciphertext_SizeCapacity(void *thisptr, uint64_t *size_capacity);

SEALNETNATIVE HRESULT SEALCALL Ciphertext_PolyModulusDegree(void *thisptr, uint64_t *poly_modulus_degree);

SEALNETNATIVE HRESULT SEALCALL Ciphertext_CoeffModCount(void *thisptr, uint64_t *coeff_mod_count);

SEALNETNATIVE HRESULT SEALCALL Ciphertext_ParmsId(void *thisptr, uint64_t *parms_id);

SEALNETNATIVE HRESULT SEALCALL Ciphertext_SetParmsId(void *thisptr, uint64_t *parms_id);

SEALNETNATIVE HRESULT SEALCALL Ciphertext_Resize1(void *thisptr, void *context, uint64_t *parms_id, uint64_t size);

SEALNETNATIVE HRESULT SEALCALL Ciphertext_Resize2(void *thisptr, void *context, uint64_t size);

SEALNETNATIVE HRESULT SEALCALL Ciphertext_Resize3(void *thisptr, uint64_t size);

SEALNETNATIVE HRESULT SEALCALL Ciphertext_Resize4(void *thisptr, uint64_t size, uint64_t polyModulusDegree, uint64_t coeffModCount);

SEALNETNATIVE HRESULT SEALCALL Ciphertext_GetDataAt1(void *thisptr, uint64_t index, uint64_t *data);

SEALNETNATIVE HRESULT SEALCALL Ciphertext_GetDataAt2(void *thisptr, uint64_t poly_index, uint64_t coeff_index, uint64_t *data);

SEALNETNATIVE HRESULT SEALCALL Ciphertext_SetDataAt(void *thisptr, uint64_t index, uint64_t value);

SEALNETNATIVE HRESULT SEALCALL Ciphertext_IsNTTForm(void *thisptr, bool *is_ntt_form);

SEALNETNATIVE HRESULT SEALCALL Ciphertext_SetIsNTTForm(void *thisptr, bool is_ntt_form);

SEALNETNATIVE HRESULT SEALCALL Ciphertext_Scale(void *thisptr, double *scale);

SEALNETNATIVE HRESULT SEALCALL Ciphertext_SetScale(void *thisptr, double scale);

SEALNETNATIVE HRESULT SEALCALL Ciphertext_Release(void *thisptr);

SEALNETNATIVE HRESULT SEALCALL Ciphertext_IsTransparent(void *thisptr, bool *result);

SEALNETNATIVE HRESULT SEALCALL Ciphertext_Pool(void *thisptr, void **pool);