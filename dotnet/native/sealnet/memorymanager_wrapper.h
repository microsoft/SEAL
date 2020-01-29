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

SEALMETHOD MemoryManager_GetPool1(int prof_opt, bool clear_on_destruction, void **pool_handle);

SEALMETHOD MemoryManager_GetPool2(void **pool_handle);

SEALMETHOD MemoryManager_SwitchProfile(void *new_profile);

SEALMETHOD MMProf_CreateGlobal(void **profile);

SEALMETHOD MMProf_CreateFixed(void *pool, void **profile);

SEALMETHOD MMProf_CreateNew(void **profile);

SEALMETHOD MMProf_CreateThreadLocal(void **profile);

SEALMETHOD MMProf_GetPool(void *thisptr, void **pool_handle);

SEALMETHOD MMProf_Destroy(void *thisptr);
