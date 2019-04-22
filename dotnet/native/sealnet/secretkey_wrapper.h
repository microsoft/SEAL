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

SEALNETNATIVE HRESULT SEALCALL SecretKey_Create1(void **secret_key);

SEALNETNATIVE HRESULT SEALCALL SecretKey_Create2(void *copy, void **secret_key);

SEALNETNATIVE HRESULT SEALCALL SecretKey_Set(void *thisptr, void *assign);

SEALNETNATIVE HRESULT SEALCALL SecretKey_Data(void *thisptr, void **data);

SEALNETNATIVE HRESULT SEALCALL SecretKey_Destroy(void *thisptr);

SEALNETNATIVE HRESULT SEALCALL SecretKey_ParmsId(void *thisptr, uint64_t *parms_id);

SEALNETNATIVE HRESULT SEALCALL SecretKey_Pool(void *thisptr, void **pool);