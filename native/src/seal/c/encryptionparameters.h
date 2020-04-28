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

SEAL_C_FUNC EncParams_Create1(uint8_t scheme, void **enc_params);

SEAL_C_FUNC EncParams_Create2(void *copy, void **enc_params);

SEAL_C_FUNC EncParams_Destroy(void *thisptr);

SEAL_C_FUNC EncParams_Set(void *thisptr, void *assign);

SEAL_C_FUNC EncParams_GetPolyModulusDegree(void *thisptr, uint64_t *degree);

SEAL_C_FUNC EncParams_SetPolyModulusDegree(void *thisptr, uint64_t degree);

SEAL_C_FUNC EncParams_GetCoeffModulus(void *thisptr, uint64_t *length, void **coeffs);

SEAL_C_FUNC EncParams_SetCoeffModulus(void *thisptr, uint64_t length, void **coeffs);

SEAL_C_FUNC EncParams_GetScheme(void *thisptr, uint8_t *scheme);

SEAL_C_FUNC EncParams_GetParmsId(void *thisptr, uint64_t *parms_id);

SEAL_C_FUNC EncParams_GetPlainModulus(void *thisptr, void **plain_modulus);

SEAL_C_FUNC EncParams_SetPlainModulus1(void *thisptr, void *modulus);

SEAL_C_FUNC EncParams_SetPlainModulus2(void *thisptr, uint64_t plain_modulus);

SEAL_C_FUNC EncParams_Equals(void *thisptr, void *otherptr, bool *result);

SEAL_C_FUNC EncParams_SaveSize(void *thisptr, uint8_t compr_mode, int64_t *result);

SEAL_C_FUNC EncParams_Save(void *thisptr, uint8_t *outptr, uint64_t size, uint8_t compr_mode, int64_t *out_bytes);

SEAL_C_FUNC EncParams_Load(void *thisptr, uint8_t *inptr, uint64_t size, int64_t *in_bytes);
