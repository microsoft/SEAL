// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#pragma once

///////////////////////////////////////////////////////////////////////////
//
// This API is provided as a simple interface for the SEAL library
// that can be PInvoked by .Net code.
// 
///////////////////////////////////////////////////////////////////////////

#include "defines.h"
#include <stdint.h>

SEALDLL HRESULT SEALCALL MemoryPoolHandle_Create1(void** handle);

SEALDLL HRESULT SEALCALL MemoryPoolHandle_Create2(void* otherptr, void** handle);

SEALDLL HRESULT SEALCALL MemoryPoolHandle_Destroy(void* thisptr);

SEALDLL HRESULT SEALCALL MemoryPoolHandle_Set(void* thisptr, void* assignptr);

SEALDLL HRESULT SEALCALL MemoryPoolHandle_Global(void** handle);

SEALDLL HRESULT SEALCALL MemoryPoolHandle_ThreadLocal(void** handle);

SEALDLL HRESULT SEALCALL MemoryPoolHandle_New(bool clear_on_destruction, void** handle);

SEALDLL HRESULT SEALCALL MemoryPoolHandle_PoolCount(void* thisptr, uint64_t* count);

SEALDLL HRESULT SEALCALL MemoryPoolHandle_AllocByteCount(void* thisptr, uint64_t* count);

SEALDLL HRESULT SEALCALL MemoryPoolHandle_IsInitialized(void* thisptr, bool* result);

SEALDLL HRESULT SEALCALL MemoryPoolHandle_Equals(void* thisptr, void* otherptr, bool* result);
