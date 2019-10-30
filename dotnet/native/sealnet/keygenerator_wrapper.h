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

SEALNETNATIVE HRESULT SEALCALL KeyGenerator_Create1(void *sealContext, void **key_generator);

SEALNETNATIVE HRESULT SEALCALL KeyGenerator_Create2(void *sealContext, void *secret_key, void **key_generator);

SEALNETNATIVE HRESULT SEALCALL KeyGenerator_Create3(void *sealContext, void *secret_key, void *public_key, void **key_generator);

SEALNETNATIVE HRESULT SEALCALL KeyGenerator_Destroy(void *thisptr);

SEALNETNATIVE HRESULT SEALCALL KeyGenerator_RelinKeys(void *thisptr, bool save_seed, void **relin_keys);

SEALNETNATIVE HRESULT SEALCALL KeyGenerator_GaloisKeysFromElts(void *thisptr, uint64_t count, uint64_t *galois_elts, bool save_seed, void **galois_keys);

SEALNETNATIVE HRESULT SEALCALL KeyGenerator_GaloisKeysFromSteps(void *thisptr, uint64_t count, int *steps, bool save_seed, void **galois_keys);

SEALNETNATIVE HRESULT SEALCALL KeyGenerator_GaloisKeysAll(void *thisptr, bool save_seed, void **galois_keys);

SEALNETNATIVE HRESULT SEALCALL KeyGenerator_PublicKey(void *thisptr, void **public_key);

SEALNETNATIVE HRESULT SEALCALL KeyGenerator_SecretKey(void *thisptr, void **secret_key);

SEALNETNATIVE HRESULT SEALCALL KeyGenerator_ContextUsingKeyswitching(void *thisptr, bool *using_keyswitching);