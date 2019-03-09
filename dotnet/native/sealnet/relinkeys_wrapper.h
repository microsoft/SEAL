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

SEALNETNATIVE HRESULT SEALCALL RelinKeys_Create1(void **relin_keys);

SEALNETNATIVE HRESULT SEALCALL RelinKeys_Create2(void *copy, void **relin_keys);

SEALNETNATIVE HRESULT SEALCALL RelinKeys_Destroy(void *thisptr);

SEALNETNATIVE HRESULT SEALCALL RelinKeys_Set(void *thisptr, void *copy);

SEALNETNATIVE HRESULT SEALCALL RelinKeys_Size(void *thisptr, uint64_t *size);

SEALNETNATIVE HRESULT SEALCALL RelinKeys_DBC(void *thisptr, int *dbc);

SEALNETNATIVE HRESULT SEALCALL RelinKeys_SetDBC(void *thisptr, int dbc);

SEALNETNATIVE HRESULT SEALCALL RelinKeys_GetKeyList(void *thisptr, uint64_t index, uint64_t *count, void **ciphers);

SEALNETNATIVE HRESULT SEALCALL RelinKeys_HasKey(void *thisptr, uint64_t key_power, bool *has_key);

SEALNETNATIVE HRESULT SEALCALL RelinKeys_GetKey(void *thisptr, uint64_t key_power, uint64_t *count, void **ciphers);

SEALNETNATIVE HRESULT SEALCALL RelinKeys_ClearDataAndReserve(void *thisptr, uint64_t size);

SEALNETNATIVE HRESULT SEALCALL RelinKeys_AddKeyList(void *thisptr, uint64_t count, void **ciphers);

SEALNETNATIVE HRESULT SEALCALL RelinKeys_GetParmsId(void *thisptr, uint64_t *parms_id);

SEALNETNATIVE HRESULT SEALCALL RelinKeys_SetParmsId(void *thisptr, uint64_t *parms_id);

SEALNETNATIVE HRESULT SEALCALL RelinKeys_IsValidFor(void *thisptr, void *context, bool *result);

SEALNETNATIVE HRESULT SEALCALL RelinKeys_IsMetadataValidFor(void *thisptr, void *context, bool *result);

SEALNETNATIVE HRESULT SEALCALL RelinKeys_Pool(void *thisptr, void **pool);
