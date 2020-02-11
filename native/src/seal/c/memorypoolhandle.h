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

SEAL_C_FUNC MemoryPoolHandle_Create1(void **handle);

SEAL_C_FUNC MemoryPoolHandle_Create2(void *otherptr, void **handle);

SEAL_C_FUNC MemoryPoolHandle_Destroy(void *thisptr);

SEAL_C_FUNC MemoryPoolHandle_Set(void *thisptr, void *assignptr);

SEAL_C_FUNC MemoryPoolHandle_Global(void **handle);

SEAL_C_FUNC MemoryPoolHandle_ThreadLocal(void **handle);

SEAL_C_FUNC MemoryPoolHandle_New(bool clear_on_destruction, void **handle);

SEAL_C_FUNC MemoryPoolHandle_PoolCount(void *thisptr, uint64_t *count);

SEAL_C_FUNC MemoryPoolHandle_AllocByteCount(void *thisptr, uint64_t *count);

SEAL_C_FUNC MemoryPoolHandle_UseCount(void *thisptr, long *count);

SEAL_C_FUNC MemoryPoolHandle_IsInitialized(void *thisptr, bool *result);

SEAL_C_FUNC MemoryPoolHandle_Equals(void *thisptr, void *otherptr, bool *result);
