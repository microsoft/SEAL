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

SEALMETHOD BatchEncoder_Create(void *context, void **batch_encoder);

SEALMETHOD BatchEncoder_Destroy(void *thisptr);

SEALMETHOD BatchEncoder_Encode1(void *thisptr, uint64_t count, uint64_t *values, void *destination);

SEALMETHOD BatchEncoder_Encode2(void *thisptr, uint64_t count, int64_t *values, void *destination);

SEALMETHOD BatchEncoder_Encode3(void *thisptr, void *plain, void *pool);

SEALMETHOD BatchEncoder_Decode1(void *thisptr, void *plain, uint64_t *count, uint64_t *destination, void *pool);

SEALMETHOD BatchEncoder_Decode2(void *thisptr, void *plain, uint64_t *count, int64_t *destination, void *pool);

SEALMETHOD BatchEncoder_Decode3(void *thisptr, void *plain, void *pool);

SEALMETHOD BatchEncoder_GetSlotCount(void *thisptr, uint64_t *slot_count);
