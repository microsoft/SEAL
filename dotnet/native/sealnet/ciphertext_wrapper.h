// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#pragma once

///////////////////////////////////////////////////////////////////////////
//
// This API is provided as a simple interface for the SEAL library
// that can be PInvoked by .Net code.
// 
///////////////////////////////////////////////////////////////////////////

#include "sealnet/defines.h"
#include <stdint.h>

SEALDLL HRESULT SEALCALL Ciphertext_Create1(void *pool, void **cipher);

SEALDLL HRESULT SEALCALL Ciphertext_Create2(void *copy, void **cipher);

SEALDLL HRESULT SEALCALL Ciphertext_Create3(void *context, void *pool, void **cipher);
 
SEALDLL HRESULT SEALCALL Ciphertext_Create4(void *context, uint64_t *parms_id, void *pool, void **cipher);

SEALDLL HRESULT SEALCALL Ciphertext_Create5(void *context, uint64_t *parms_id, uint64_t capacity, void *pool, void **ciphertext);

SEALDLL HRESULT SEALCALL Ciphertext_Reserve1(void *thisptr, void *context, uint64_t *parms_id, uint64_t size_capacity);

SEALDLL HRESULT SEALCALL Ciphertext_Reserve2(void *thisptr, void *context, uint64_t size_capacity);

SEALDLL HRESULT SEALCALL Ciphertext_Reserve3(void *thisptr, uint64_t size_capacity);

SEALDLL HRESULT SEALCALL Ciphertext_Set(void *thisptr, void *assign);

SEALDLL HRESULT SEALCALL Ciphertext_Destroy(void *thisptr);

SEALDLL HRESULT SEALCALL Ciphertext_UInt64Count(void *thisptr, uint64_t *uint64_count);

SEALDLL HRESULT SEALCALL Ciphertext_UInt64CountCapacity(void *thisptr, uint64_t *uint64_count_capacity);

SEALDLL HRESULT SEALCALL Ciphertext_Size(void *thisptr, uint64_t *size);

SEALDLL HRESULT SEALCALL Ciphertext_SizeCapacity(void *thisptr, uint64_t *size_capacity);

SEALDLL HRESULT SEALCALL Ciphertext_PolyModulusDegree(void *thisptr, uint64_t *poly_modulus_degree);

SEALDLL HRESULT SEALCALL Ciphertext_CoeffModCount(void *thisptr, uint64_t *coeff_mod_count);

SEALDLL HRESULT SEALCALL Ciphertext_ParmsId(void *thisptr, uint64_t *parms_id);

SEALDLL HRESULT SEALCALL Ciphertext_SetParmsId(void *thisptr, uint64_t *parms_id);

SEALDLL HRESULT SEALCALL Ciphertext_Resize1(void *thisptr, void *context, uint64_t *parms_id, uint64_t size);

SEALDLL HRESULT SEALCALL Ciphertext_Resize2(void *thisptr, void *context, uint64_t size);

SEALDLL HRESULT SEALCALL Ciphertext_Resize3(void *thisptr, uint64_t size);

SEALDLL HRESULT SEALCALL Ciphertext_Resize4(void *thisptr, uint64_t size, uint64_t polyModulusDegree, uint64_t coeffModCount);

SEALDLL HRESULT SEALCALL Ciphertext_GetDataAt1(void *thisptr, uint64_t index, uint64_t *data);

SEALDLL HRESULT SEALCALL Ciphertext_GetDataAt2(void *thisptr, uint64_t poly_index, uint64_t coeff_index, uint64_t *data);

SEALDLL HRESULT SEALCALL Ciphertext_SetDataAt(void *thisptr, uint64_t index, uint64_t value);

SEALDLL HRESULT SEALCALL Ciphertext_IsNTTForm(void *thisptr, bool *is_ntt_form);

SEALDLL HRESULT SEALCALL Ciphertext_SetIsNTTForm(void *thisptr, bool is_ntt_form);

SEALDLL HRESULT SEALCALL Ciphertext_Scale(void *thisptr, double *scale);

SEALDLL HRESULT SEALCALL Ciphertext_SetScale(void *thisptr, double scale);

SEALDLL HRESULT SEALCALL Ciphertext_Release(void *thisptr);

SEALDLL HRESULT SEALCALL Ciphertext_IsValidFor(void *thisptr, void *context, bool *result);

SEALDLL HRESULT SEALCALL Ciphertext_IsMetadataValidFor(void *thisptr, void *context, bool *result);

SEALDLL HRESULT SEALCALL Ciphertext_IsTransparent(void *thisptr, bool *result);

SEALDLL HRESULT SEALCALL Ciphertext_Pool(void *thisptr, void **pool);
