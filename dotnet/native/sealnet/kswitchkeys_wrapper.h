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

SEALMETHOD KSwitchKeys_Create1(void **kswitch_keys);

SEALMETHOD KSwitchKeys_Create2(void *copy, void **kswitch_keys);

SEALMETHOD KSwitchKeys_Destroy(void *thisptr);

SEALMETHOD KSwitchKeys_Set(void *thisptr, void *assign);

SEALMETHOD KSwitchKeys_Size(void *thisptr, uint64_t *size);

SEALMETHOD KSwitchKeys_RawSize(void *thisptr, uint64_t *key_count);

SEALMETHOD KSwitchKeys_GetKeyList(void *thisptr, uint64_t index, uint64_t *count, void **key_list);

SEALMETHOD KSwitchKeys_ClearDataAndReserve(void *thisptr, uint64_t size);

SEALMETHOD KSwitchKeys_AddKeyList(void *thisptr, uint64_t count, void **key_list);

SEALMETHOD KSwitchKeys_GetParmsId(void *thisptr, uint64_t *parms_id);

SEALMETHOD KSwitchKeys_SetParmsId(void *thisptr, uint64_t *parms_id);

SEALMETHOD KSwitchKeys_Pool(void *thisptr, void **pool);

SEALMETHOD KSwitchKeys_SaveSize(void *thisptr, uint8_t compr_mode, int64_t *result);

SEALMETHOD KSwitchKeys_Save(void *thisptr, uint8_t *outptr, uint64_t size, uint8_t compr_mode, int64_t *out_bytes);

SEALMETHOD KSwitchKeys_UnsafeLoad(void *thisptr, void *context, uint8_t *inptr, uint64_t size, int64_t *in_bytes);

SEALMETHOD KSwitchKeys_Load(void *thisptr, void *context, uint8_t *inptr, uint64_t size, int64_t *in_bytes);
