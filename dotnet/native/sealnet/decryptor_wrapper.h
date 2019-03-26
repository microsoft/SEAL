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

SEALNETNATIVE HRESULT SEALCALL Decryptor_Create(void *context, void *secret_key, void **decryptor);

SEALNETNATIVE HRESULT SEALCALL Decryptor_Destroy(void *thisptr);

SEALNETNATIVE HRESULT SEALCALL Decryptor_Decrypt(void *thisptr, void *encrypted, void *destination);

SEALNETNATIVE HRESULT SEALCALL Decryptor_InvariantNoiseBudget(void *thisptr, void *encrypted, int *invariant_noise_budget);
