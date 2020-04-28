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

SEAL_C_FUNC Ciphertext_Create1(void *pool, void **cipher);

SEAL_C_FUNC Ciphertext_Create2(void *copy, void **cipher);

SEAL_C_FUNC Ciphertext_Create3(void *context, void *pool, void **cipher);

SEAL_C_FUNC Ciphertext_Create4(void *context, uint64_t *parms_id, void *pool, void **cipher);

SEAL_C_FUNC Ciphertext_Create5(void *context, uint64_t *parms_id, uint64_t capacity, void *pool, void **ciphertext);

SEAL_C_FUNC Ciphertext_Reserve1(void *thisptr, void *context, uint64_t *parms_id, uint64_t size_capacity);

SEAL_C_FUNC Ciphertext_Reserve2(void *thisptr, void *context, uint64_t size_capacity);

SEAL_C_FUNC Ciphertext_Reserve3(void *thisptr, uint64_t size_capacity);

SEAL_C_FUNC Ciphertext_Set(void *thisptr, void *assign);

SEAL_C_FUNC Ciphertext_Destroy(void *thisptr);

SEAL_C_FUNC Ciphertext_Size(void *thisptr, uint64_t *size);

SEAL_C_FUNC Ciphertext_SizeCapacity(void *thisptr, uint64_t *size_capacity);

SEAL_C_FUNC Ciphertext_PolyModulusDegree(void *thisptr, uint64_t *poly_modulus_degree);

SEAL_C_FUNC Ciphertext_CoeffModulusSize(void *thisptr, uint64_t *coeff_modulus_size);

SEAL_C_FUNC Ciphertext_ParmsId(void *thisptr, uint64_t *parms_id);

SEAL_C_FUNC Ciphertext_SetParmsId(void *thisptr, uint64_t *parms_id);

SEAL_C_FUNC Ciphertext_Resize1(void *thisptr, void *context, uint64_t *parms_id, uint64_t size);

SEAL_C_FUNC Ciphertext_Resize2(void *thisptr, void *context, uint64_t size);

SEAL_C_FUNC Ciphertext_Resize3(void *thisptr, uint64_t size);

SEAL_C_FUNC Ciphertext_Resize4(void *thisptr, uint64_t size, uint64_t polyModulusDegree, uint64_t coeffModCount);

SEAL_C_FUNC Ciphertext_GetDataAt1(void *thisptr, uint64_t index, uint64_t *data);

SEAL_C_FUNC Ciphertext_GetDataAt2(void *thisptr, uint64_t poly_index, uint64_t coeff_index, uint64_t *data);

SEAL_C_FUNC Ciphertext_SetDataAt(void *thisptr, uint64_t index, uint64_t value);

SEAL_C_FUNC Ciphertext_IsNTTForm(void *thisptr, bool *is_ntt_form);

SEAL_C_FUNC Ciphertext_SetIsNTTForm(void *thisptr, bool is_ntt_form);

SEAL_C_FUNC Ciphertext_Scale(void *thisptr, double *scale);

SEAL_C_FUNC Ciphertext_SetScale(void *thisptr, double scale);

SEAL_C_FUNC Ciphertext_Release(void *thisptr);

SEAL_C_FUNC Ciphertext_IsTransparent(void *thisptr, bool *result);

SEAL_C_FUNC Ciphertext_Pool(void *thisptr, void **pool);

SEAL_C_FUNC Ciphertext_SaveSize(void *thisptr, uint8_t compr_mode, int64_t *result);

SEAL_C_FUNC Ciphertext_Save(void *thisptr, uint8_t *outptr, uint64_t size, uint8_t compr_mode, int64_t *out_bytes);

SEAL_C_FUNC Ciphertext_UnsafeLoad(void *thisptr, void *context, uint8_t *inptr, uint64_t size, int64_t *in_bytes);

SEAL_C_FUNC Ciphertext_Load(void *thisptr, void *context, uint8_t *inptr, uint64_t size, int64_t *in_bytes);
