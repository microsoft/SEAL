// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#pragma once

///////////////////////////////////////////////////////////////////////////
//
// This API is provided as a simple interface for the SEAL library
// that can be PInvoked by .Net code.
// 
///////////////////////////////////////////////////////////////////////////

#include "defines.h"
#include <stdint.h>

SEALDLL HRESULT SEALCALL KeyGenerator_Create1(void *sealContext, void **key_generator);

SEALDLL HRESULT SEALCALL KeyGenerator_Create2(void *sealContext, void *secret_key, void **key_generator);

SEALDLL HRESULT SEALCALL KeyGenerator_Create3(void *sealContext, void *secret_key, void *public_key, void **key_generator);

SEALDLL HRESULT SEALCALL KeyGenerator_Destroy(void *thisptr);

SEALDLL HRESULT SEALCALL KeyGenerator_RelinKeys(void *thisptr, int decompositionBitCount, int count, void **relin_keys);

SEALDLL HRESULT SEALCALL KeyGenerator_GaloisKeys1(void *thisptr, int decompositionBitCount, void **galois_keys);

SEALDLL HRESULT SEALCALL KeyGenerator_GaloisKeys2(void *thisptr, int decomposition_bit_count, int count, uint64_t *galois_elts, void **galois_keys);

SEALDLL HRESULT SEALCALL KeyGenerator_GaloisKeys3(void *thisptr, int decomposition_bit_count, int count, int *steps, void **galois_keys);

SEALDLL HRESULT SEALCALL KeyGenerator_PublicKey(void *thisptr, void **public_key);

SEALDLL HRESULT SEALCALL KeyGenerator_SecretKey(void *thisptr, void **secret_key);
