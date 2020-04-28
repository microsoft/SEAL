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

SEAL_C_FUNC KSwitchKeys_Create1(void **kswitch_keys);

SEAL_C_FUNC KSwitchKeys_Create2(void *copy, void **kswitch_keys);

SEAL_C_FUNC KSwitchKeys_Destroy(void *thisptr);

SEAL_C_FUNC KSwitchKeys_Set(void *thisptr, void *assign);

SEAL_C_FUNC KSwitchKeys_Size(void *thisptr, uint64_t *size);

SEAL_C_FUNC KSwitchKeys_RawSize(void *thisptr, uint64_t *key_count);

SEAL_C_FUNC KSwitchKeys_GetKeyList(void *thisptr, uint64_t index, uint64_t *count, void **key_list);

SEAL_C_FUNC KSwitchKeys_ClearDataAndReserve(void *thisptr, uint64_t size);

SEAL_C_FUNC KSwitchKeys_AddKeyList(void *thisptr, uint64_t count, void **key_list);

SEAL_C_FUNC KSwitchKeys_GetParmsId(void *thisptr, uint64_t *parms_id);

SEAL_C_FUNC KSwitchKeys_SetParmsId(void *thisptr, uint64_t *parms_id);

SEAL_C_FUNC KSwitchKeys_Pool(void *thisptr, void **pool);

SEAL_C_FUNC KSwitchKeys_SaveSize(void *thisptr, uint8_t compr_mode, int64_t *result);

SEAL_C_FUNC KSwitchKeys_Save(void *thisptr, uint8_t *outptr, uint64_t size, uint8_t compr_mode, int64_t *out_bytes);

SEAL_C_FUNC KSwitchKeys_UnsafeLoad(void *thisptr, void *context, uint8_t *inptr, uint64_t size, int64_t *in_bytes);

SEAL_C_FUNC KSwitchKeys_Load(void *thisptr, void *context, uint8_t *inptr, uint64_t size, int64_t *in_bytes);
