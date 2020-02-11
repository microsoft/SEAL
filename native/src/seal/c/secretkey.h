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

SEAL_C_FUNC SecretKey_Create1(void **secret_key);

SEAL_C_FUNC SecretKey_Create2(void *copy, void **secret_key);

SEAL_C_FUNC SecretKey_Set(void *thisptr, void *assign);

SEAL_C_FUNC SecretKey_Data(void *thisptr, void **data);

SEAL_C_FUNC SecretKey_Destroy(void *thisptr);

SEAL_C_FUNC SecretKey_ParmsId(void *thisptr, uint64_t *parms_id);

SEAL_C_FUNC SecretKey_Pool(void *thisptr, void **pool);

SEAL_C_FUNC SecretKey_SaveSize(void *thisptr, uint8_t compr_mode, int64_t *result);

SEAL_C_FUNC SecretKey_Save(void *thisptr, uint8_t *outptr, uint64_t size, uint8_t compr_mode, int64_t *out_bytes);

SEAL_C_FUNC SecretKey_UnsafeLoad(void *thisptr, void *context, uint8_t *inptr, uint64_t size, int64_t *in_bytes);

SEAL_C_FUNC SecretKey_Load(void *thisptr, void *context, uint8_t *inptr, uint64_t size, int64_t *in_bytes);
