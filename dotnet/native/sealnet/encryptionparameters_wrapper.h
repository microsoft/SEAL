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

SEALMETHOD EncParams_Create1(uint8_t scheme, void **enc_params);

SEALMETHOD EncParams_Create2(void *copy, void **enc_params);

SEALMETHOD EncParams_Destroy(void *thisptr);

SEALMETHOD EncParams_Set(void *thisptr, void *assign);

SEALMETHOD EncParams_GetPolyModulusDegree(void *thisptr, uint64_t *degree);

SEALMETHOD EncParams_SetPolyModulusDegree(void *thisptr, uint64_t degree);

SEALMETHOD EncParams_GetCoeffModulus(void *thisptr, uint64_t *length, void **coeffs);

SEALMETHOD EncParams_SetCoeffModulus(void *thisptr, uint64_t length, void **coeffs);

SEALMETHOD EncParams_GetScheme(void *thisptr, uint8_t *scheme);

SEALMETHOD EncParams_GetParmsId(void *thisptr, uint64_t *parms_id);

SEALMETHOD EncParams_GetPlainModulus(void *thisptr, void **plain_modulus);

SEALMETHOD EncParams_SetPlainModulus1(void *thisptr, void *modulus);

SEALMETHOD EncParams_SetPlainModulus2(void *thisptr, uint64_t plain_modulus);

SEALMETHOD EncParams_Equals(void *thisptr, void *otherptr, bool *result);

SEALMETHOD EncParams_SaveSize(void *thisptr, uint8_t compr_mode, int64_t *result);

SEALMETHOD EncParams_Save(void *thisptr, uint8_t *outptr, uint64_t size, uint8_t compr_mode, int64_t *out_bytes);

SEALMETHOD EncParams_Load(void *thisptr, uint8_t *inptr, uint64_t size, int64_t *in_bytes);
