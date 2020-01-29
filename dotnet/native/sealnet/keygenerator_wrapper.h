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

SEALMETHOD KeyGenerator_Create1(void *sealContext, void **key_generator);

SEALMETHOD KeyGenerator_Create2(void *sealContext, void *secret_key, void **key_generator);

SEALMETHOD KeyGenerator_Destroy(void *thisptr);

SEALMETHOD KeyGenerator_RelinKeys(void *thisptr, bool save_seed, void **relin_keys);

SEALMETHOD KeyGenerator_GaloisKeysFromElts(
    void *thisptr, uint64_t count, uint64_t *galois_elts, bool save_seed, void **galois_keys);

SEALMETHOD KeyGenerator_GaloisKeysFromSteps(
    void *thisptr, uint64_t count, int *steps, bool save_seed, void **galois_keys);

SEALMETHOD KeyGenerator_GaloisKeysAll(void *thisptr, bool save_seed, void **galois_keys);

SEALMETHOD KeyGenerator_PublicKey(void *thisptr, void **public_key);

SEALMETHOD KeyGenerator_SecretKey(void *thisptr, void **secret_key);

SEALMETHOD KeyGenerator_ContextUsingKeyswitching(void *thisptr, bool *using_keyswitching);
