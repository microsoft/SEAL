// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#pragma once

///////////////////////////////////////////////////////////////////////////
//
// This API is provided as a simple interface for Microsoft SEAL library
// that can be PInvoked by .Net code.
//
///////////////////////////////////////////////////////////////////////////

#include "seal/c/defines.h"
#include <stdint.h>

SEAL_C_FUNC KeyGenerator_Create1(void *context, void **key_generator);

SEAL_C_FUNC KeyGenerator_Create2(void *context, void *secret_key, void **key_generator);

SEAL_C_FUNC KeyGenerator_Destroy(void *thisptr);

SEAL_C_FUNC KeyGenerator_CreateRelinKeys(void *thisptr, bool save_seed, void **relin_keys);

SEAL_C_FUNC KeyGenerator_CreateGaloisKeysFromElts(
    void *thisptr, uint64_t count, uint32_t *galois_elts, bool save_seed, void **galois_keys);

SEAL_C_FUNC KeyGenerator_CreateGaloisKeysFromSteps(
    void *thisptr, uint64_t count, int *steps, bool save_seed, void **galois_keys);

SEAL_C_FUNC KeyGenerator_CreateGaloisKeysAll(void *thisptr, bool save_seed, void **galois_keys);

SEAL_C_FUNC KeyGenerator_CreatePublicKey(void *thisptr, bool save_seed, void **public_key);

SEAL_C_FUNC KeyGenerator_SecretKey(void *thisptr, void **secret_key);

SEAL_C_FUNC KeyGenerator_ContextUsingKeyswitching(void *thisptr, bool *using_keyswitching);
