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

SEALNETNATIVE HRESULT SEALCALL MemoryManager_GetPool1(int prof_opt, bool clear_on_destruction, void **pool_handle);

SEALNETNATIVE HRESULT SEALCALL MemoryManager_GetPool2(void **pool_handle);

SEALNETNATIVE HRESULT SEALCALL MemoryManager_SwitchProfile(void *new_profile);

SEALNETNATIVE HRESULT SEALCALL MMProf_CreateGlobal(void **profile);

SEALNETNATIVE HRESULT SEALCALL MMProf_CreateFixed(void *pool, void **profile);

SEALNETNATIVE HRESULT SEALCALL MMProf_CreateNew(void **profile);

SEALNETNATIVE HRESULT SEALCALL MMProf_CreateThreadLocal(void **profile);

SEALNETNATIVE HRESULT SEALCALL MMProf_GetPool(void *thisptr, void **pool_handle);

SEALNETNATIVE HRESULT SEALCALL MMProf_Destroy(void *thisptr);
