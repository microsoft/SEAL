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

SEALMETHOD MemoryPoolHandle_Create1(void **handle);

SEALMETHOD MemoryPoolHandle_Create2(void *otherptr, void **handle);

SEALMETHOD MemoryPoolHandle_Destroy(void *thisptr);

SEALMETHOD MemoryPoolHandle_Set(void *thisptr, void *assignptr);

SEALMETHOD MemoryPoolHandle_Global(void **handle);

SEALMETHOD MemoryPoolHandle_ThreadLocal(void **handle);

SEALMETHOD MemoryPoolHandle_New(bool clear_on_destruction, void **handle);

SEALMETHOD MemoryPoolHandle_PoolCount(void *thisptr, uint64_t *count);

SEALMETHOD MemoryPoolHandle_AllocByteCount(void *thisptr, uint64_t *count);

SEALMETHOD MemoryPoolHandle_UseCount(void *thisptr, long *count);

SEALMETHOD MemoryPoolHandle_IsInitialized(void *thisptr, bool *result);

SEALMETHOD MemoryPoolHandle_Equals(void *thisptr, void *otherptr, bool *result);
