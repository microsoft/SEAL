// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#pragma once

///////////////////////////////////////////////////////////////////////////
//
// This API is provided as a simple interface for Microsoft SEAL library
// that can be PInvoked by .Net code.
//
///////////////////////////////////////////////////////////////////////////

#include <stdint.h>
#include "sealnet/defines.h"

SEALMETHOD Ciphertext_Create1(void *pool, void **cipher);

SEALMETHOD Ciphertext_Create2(void *copy, void **cipher);

SEALMETHOD Ciphertext_Create3(void *context, void *pool, void **cipher);

SEALMETHOD Ciphertext_Create4(void *context, uint64_t *parms_id, void *pool, void **cipher);

SEALMETHOD Ciphertext_Create5(void *context, uint64_t *parms_id, uint64_t capacity, void *pool, void **ciphertext);

SEALMETHOD Ciphertext_Reserve1(void *thisptr, void *context, uint64_t *parms_id, uint64_t size_capacity);

SEALMETHOD Ciphertext_Reserve2(void *thisptr, void *context, uint64_t size_capacity);

SEALMETHOD Ciphertext_Reserve3(void *thisptr, uint64_t size_capacity);

SEALMETHOD Ciphertext_Set(void *thisptr, void *assign);

SEALMETHOD Ciphertext_Destroy(void *thisptr);

SEALMETHOD Ciphertext_Size(void *thisptr, uint64_t *size);

SEALMETHOD Ciphertext_SizeCapacity(void *thisptr, uint64_t *size_capacity);

SEALMETHOD Ciphertext_PolyModulusDegree(void *thisptr, uint64_t *poly_modulus_degree);

SEALMETHOD Ciphertext_CoeffModCount(void *thisptr, uint64_t *coeff_mod_count);

SEALMETHOD Ciphertext_ParmsId(void *thisptr, uint64_t *parms_id);

SEALMETHOD Ciphertext_SetParmsId(void *thisptr, uint64_t *parms_id);

SEALMETHOD Ciphertext_Resize1(void *thisptr, void *context, uint64_t *parms_id, uint64_t size);

SEALMETHOD Ciphertext_Resize2(void *thisptr, void *context, uint64_t size);

SEALMETHOD Ciphertext_Resize3(void *thisptr, uint64_t size);

SEALMETHOD Ciphertext_Resize4(void *thisptr, uint64_t size, uint64_t polyModulusDegree, uint64_t coeffModCount);

SEALMETHOD Ciphertext_GetDataAt1(void *thisptr, uint64_t index, uint64_t *data);

SEALMETHOD Ciphertext_GetDataAt2(void *thisptr, uint64_t poly_index, uint64_t coeff_index, uint64_t *data);

SEALMETHOD Ciphertext_SetDataAt(void *thisptr, uint64_t index, uint64_t value);

SEALMETHOD Ciphertext_IsNTTForm(void *thisptr, bool *is_ntt_form);

SEALMETHOD Ciphertext_SetIsNTTForm(void *thisptr, bool is_ntt_form);

SEALMETHOD Ciphertext_Scale(void *thisptr, double *scale);

SEALMETHOD Ciphertext_SetScale(void *thisptr, double scale);

SEALMETHOD Ciphertext_Release(void *thisptr);

SEALMETHOD Ciphertext_IsTransparent(void *thisptr, bool *result);

SEALMETHOD Ciphertext_Pool(void *thisptr, void **pool);

SEALMETHOD Ciphertext_SaveSize(void *thisptr, uint8_t compr_mode, int64_t *result);

SEALMETHOD Ciphertext_Save(void *thisptr, uint8_t *outptr, uint64_t size, uint8_t compr_mode, int64_t *out_bytes);

SEALMETHOD Ciphertext_UnsafeLoad(void *thisptr, void *context, uint8_t *inptr, uint64_t size, int64_t *in_bytes);

SEALMETHOD Ciphertext_Load(void *thisptr, void *context, uint8_t *inptr, uint64_t size, int64_t *in_bytes);
