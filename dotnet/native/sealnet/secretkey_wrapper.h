// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#pragma once

///////////////////////////////////////////////////////////////////////////
//
// This API is provided as a simple interface for the SEAL library
// that can be PInvoked by .Net code.
// 
///////////////////////////////////////////////////////////////////////////

#include "sealnet/defines.h"
#include <stdint.h>

SEALDLL HRESULT SEALCALL SecretKey_Create1(void **secret_key);

SEALDLL HRESULT SEALCALL SecretKey_Create2(void *copy, void **secret_key);

SEALDLL HRESULT SEALCALL SecretKey_Set(void *thisptr, void *assign);

SEALDLL HRESULT SEALCALL SecretKey_Data(void *thisptr, void **data);

SEALDLL HRESULT SEALCALL SecretKey_Destroy(void *thisptr);

SEALDLL HRESULT SEALCALL SecretKey_IsValidFor(void *thisptr, void *contextptr, bool *result);

SEALDLL HRESULT SEALCALL SecretKey_IsMetadataValidFor(void *thisptr, void *contextptr, bool *result);

SEALDLL HRESULT SEALCALL SecretKey_ParmsId(void *thisptr, uint64_t *parms_id);

SEALDLL HRESULT SEALCALL SecretKey_Pool(void *thisptr, void **pool);
