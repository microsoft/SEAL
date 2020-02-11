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

SEAL_C_FUNC BatchEncoder_Create(void *context, void **batch_encoder);

SEAL_C_FUNC BatchEncoder_Destroy(void *thisptr);

SEAL_C_FUNC BatchEncoder_Encode1(void *thisptr, uint64_t count, uint64_t *values, void *destination);

SEAL_C_FUNC BatchEncoder_Encode2(void *thisptr, uint64_t count, int64_t *values, void *destination);

SEAL_C_FUNC BatchEncoder_Encode3(void *thisptr, void *plain, void *pool);

SEAL_C_FUNC BatchEncoder_Decode1(void *thisptr, void *plain, uint64_t *count, uint64_t *destination, void *pool);

SEAL_C_FUNC BatchEncoder_Decode2(void *thisptr, void *plain, uint64_t *count, int64_t *destination, void *pool);

SEAL_C_FUNC BatchEncoder_Decode3(void *thisptr, void *plain, void *pool);

SEAL_C_FUNC BatchEncoder_GetSlotCount(void *thisptr, uint64_t *slot_count);
