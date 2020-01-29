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

SEALMETHOD PublicKey_Create1(void **public_key);

SEALMETHOD PublicKey_Create2(void *copy, void **public_key);

SEALMETHOD PublicKey_Set(void *thisptr, void *assign);

SEALMETHOD PublicKey_Data(void *thisptr, void **data);

SEALMETHOD PublicKey_ParmsId(void *thisptr, uint64_t *parms_id);

SEALMETHOD PublicKey_Pool(void *thisptr, void **pool);

SEALMETHOD PublicKey_Destroy(void *thisptr);

SEALMETHOD PublicKey_SaveSize(void *thisptr, uint8_t compr_mode, int64_t *result);

SEALMETHOD PublicKey_Save(void *thisptr, uint8_t *outptr, uint64_t size, uint8_t compr_mode, int64_t *out_bytes);

SEALMETHOD PublicKey_UnsafeLoad(void *thisptr, void *context, uint8_t *inptr, uint64_t size, int64_t *in_bytes);

SEALMETHOD PublicKey_Load(void *thisptr, void *context, uint8_t *inptr, uint64_t size, int64_t *in_bytes);
