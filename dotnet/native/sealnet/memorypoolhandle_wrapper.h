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

SEALNETNATIVE HRESULT SEALCALL MemoryPoolHandle_Create1(void **handle);

SEALNETNATIVE HRESULT SEALCALL MemoryPoolHandle_Create2(void *otherptr, void **handle);

SEALNETNATIVE HRESULT SEALCALL MemoryPoolHandle_Destroy(void *thisptr);

SEALNETNATIVE HRESULT SEALCALL MemoryPoolHandle_Set(void *thisptr, void *assignptr);

SEALNETNATIVE HRESULT SEALCALL MemoryPoolHandle_Global(void **handle);

SEALNETNATIVE HRESULT SEALCALL MemoryPoolHandle_ThreadLocal(void **handle);

SEALNETNATIVE HRESULT SEALCALL MemoryPoolHandle_New(bool clear_on_destruction, void **handle);

SEALNETNATIVE HRESULT SEALCALL MemoryPoolHandle_PoolCount(void *thisptr, uint64_t *count);

SEALNETNATIVE HRESULT SEALCALL MemoryPoolHandle_AllocByteCount(void *thisptr, uint64_t *count);

SEALNETNATIVE HRESULT SEALCALL MemoryPoolHandle_UseCount(void *thisptr, long *count);

SEALNETNATIVE HRESULT SEALCALL MemoryPoolHandle_IsInitialized(void *thisptr, bool *result);

SEALNETNATIVE HRESULT SEALCALL MemoryPoolHandle_Equals(void *thisptr, void *otherptr, bool *result);
