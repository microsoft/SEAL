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

SEALNETNATIVE HRESULT SEALCALL BatchEncoder_Create(void *context, void **batch_encoder);

SEALNETNATIVE HRESULT SEALCALL BatchEncoder_Destroy(void *thisptr);

SEALNETNATIVE HRESULT SEALCALL BatchEncoder_Encode1(void *thisptr, uint64_t count, uint64_t *values, void *destination);

SEALNETNATIVE HRESULT SEALCALL BatchEncoder_Encode2(void *thisptr, uint64_t count, int64_t *values, void *destination);

SEALNETNATIVE HRESULT SEALCALL BatchEncoder_Encode3(void *thisptr, void *plain, void *pool);

SEALNETNATIVE HRESULT SEALCALL BatchEncoder_Decode1(void *thisptr, void *plain, uint64_t *count, uint64_t *destination, void *pool);

SEALNETNATIVE HRESULT SEALCALL BatchEncoder_Decode2(void *thisptr, void *plain, uint64_t *count, int64_t *destination, void *pool);

SEALNETNATIVE HRESULT SEALCALL BatchEncoder_Decode3(void *thisptr, void *plain, void *pool);

SEALNETNATIVE HRESULT SEALCALL BatchEncoder_GetSlotCount(void *thisptr, uint64_t *slot_count);
