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

SEALMETHOD SecretKey_Create1(void **secret_key);

SEALMETHOD SecretKey_Create2(void *copy, void **secret_key);

SEALMETHOD SecretKey_Set(void *thisptr, void *assign);

SEALMETHOD SecretKey_Data(void *thisptr, void **data);

SEALMETHOD SecretKey_Destroy(void *thisptr);

SEALMETHOD SecretKey_ParmsId(void *thisptr, uint64_t *parms_id);

SEALMETHOD SecretKey_Pool(void *thisptr, void **pool);

SEALMETHOD SecretKey_SaveSize(void *thisptr, uint8_t compr_mode, int64_t *result);

SEALMETHOD SecretKey_Save(void *thisptr, uint8_t *outptr, uint64_t size, uint8_t compr_mode, int64_t *out_bytes);

SEALMETHOD SecretKey_UnsafeLoad(void *thisptr, void *context, uint8_t *inptr, uint64_t size, int64_t *in_bytes);

SEALMETHOD SecretKey_Load(void *thisptr, void *context, uint8_t *inptr, uint64_t size, int64_t *in_bytes);
