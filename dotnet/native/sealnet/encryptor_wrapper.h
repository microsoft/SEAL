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

SEALMETHOD Encryptor_Create(void *context, void *public_key, void *secret_key, void **encryptor);

SEALMETHOD Encryptor_SetPublicKey(void *thisptr, void *public_key);

SEALMETHOD Encryptor_SetSecretKey(void *thisptr, void *secret_key);

SEALMETHOD Encryptor_Encrypt(void *thisptr, void *plaintext, void *destination, void *pool_handle);

SEALMETHOD Encryptor_EncryptZero1(void *thisptr, uint64_t *parms_id, void *destination, void *pool_handle);

SEALMETHOD Encryptor_EncryptZero2(void *thisptr, void *destination, void *pool_handle);

SEALMETHOD Encryptor_EncryptSymmetric(
    void *thisptr, void *plaintext, bool save_seed, void *destination, void *pool_handle);

SEALMETHOD Encryptor_EncryptZeroSymmetric1(
    void *thisptr, uint64_t *parms_id, bool save_seed, void *destination, void *pool_handle);

SEALMETHOD Encryptor_EncryptZeroSymmetric2(void *thisptr, bool save_seed, void *destination, void *pool_handle);

SEALMETHOD Encryptor_Destroy(void *thisptr);
