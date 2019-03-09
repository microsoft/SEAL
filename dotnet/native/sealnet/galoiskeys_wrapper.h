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

SEALNETNATIVE HRESULT SEALCALL GaloisKeys_Create1(void **galois_keys);

SEALNETNATIVE HRESULT SEALCALL GaloisKeys_Create2(void *copy, void **galois_keys);

SEALNETNATIVE HRESULT SEALCALL GaloisKeys_Destroy(void *thisptr);

SEALNETNATIVE HRESULT SEALCALL GaloisKeys_Set(void *thisptr, void *assign);

SEALNETNATIVE HRESULT SEALCALL GaloisKeys_Size(void *thisptr, uint64_t *size);

SEALNETNATIVE HRESULT SEALCALL GaloisKeys_DBC(void *thisptr, int *dbc);

SEALNETNATIVE HRESULT SEALCALL GaloisKeys_SetDBC(void *thisptr, int dbc);

SEALNETNATIVE HRESULT SEALCALL GaloisKeys_GetKeyCount(void *thisptr, uint64_t *key_count);

SEALNETNATIVE HRESULT SEALCALL GaloisKeys_GetKeyList(void *thisptr, uint64_t index, uint64_t *count, void **ciphers);

SEALNETNATIVE HRESULT SEALCALL GaloisKeys_GetKey(void *thisptr, uint64_t galois_elt, uint64_t *count, void **ciphers);

SEALNETNATIVE HRESULT SEALCALL GaloisKeys_ClearDataAndReserve(void *thisptr, uint64_t size);

SEALNETNATIVE HRESULT SEALCALL GaloisKeys_AddKeyList(void *thisptr, uint64_t count, void **ciphers);

SEALNETNATIVE HRESULT SEALCALL GaloisKeys_HasKey(void *thisptr, uint64_t galois_elt, bool *has_key);

SEALNETNATIVE HRESULT SEALCALL GaloisKeys_GetParmsId(void *thisptr, uint64_t *parms_id);

SEALNETNATIVE HRESULT SEALCALL GaloisKeys_SetParmsId(void *thisptr, uint64_t *parms_id);

SEALNETNATIVE HRESULT SEALCALL GaloisKeys_IsValidFor(void *thisptr, void *contextptr, bool *result);

SEALNETNATIVE HRESULT SEALCALL GaloisKeys_IsMetadataValidFor(void *thisptr, void *contextptr, bool *result);

SEALNETNATIVE HRESULT SEALCALL GaloisKeys_Pool(void *thisptr, void **pool);
