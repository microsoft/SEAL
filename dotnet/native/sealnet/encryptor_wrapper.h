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

SEALNETNATIVE HRESULT SEALCALL Encryptor_Create(void *context, void *public_key, void **encryptor);

SEALNETNATIVE HRESULT SEALCALL Encryptor_Encrypt(void *thisptr, void *plaintext, void *destination, void *pool_handle);

SEALNETNATIVE HRESULT SEALCALL Encryptor_EncryptZero1(void *thisptr, uint64_t *parms_id, void *destination, void *pool_handle);

SEALNETNATIVE HRESULT SEALCALL Encryptor_EncryptZero2(void *thisptr, void *destination, void *pool_handle);

SEALNETNATIVE HRESULT SEALCALL Encryptor_Destroy(void *thisptr);
