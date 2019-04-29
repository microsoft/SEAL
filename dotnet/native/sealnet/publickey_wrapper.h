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

SEALNETNATIVE HRESULT SEALCALL PublicKey_Create1(void **public_key);

SEALNETNATIVE HRESULT SEALCALL PublicKey_Create2(void *copy, void **public_key);

SEALNETNATIVE HRESULT SEALCALL PublicKey_Set(void *thisptr, void *assign);

SEALNETNATIVE HRESULT SEALCALL PublicKey_Data(void *thisptr, void **data);

SEALNETNATIVE HRESULT SEALCALL PublicKey_ParmsId(void *thisptr, uint64_t *parms_id);

SEALNETNATIVE HRESULT SEALCALL PublicKey_Pool(void *thisptr, void **pool);

SEALNETNATIVE HRESULT SEALCALL PublicKey_Destroy(void *thisptr);