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

SEAL_C_FUNC Decryptor_Create(void *context, void *secret_key, void **decryptor);

SEAL_C_FUNC Decryptor_Destroy(void *thisptr);

SEAL_C_FUNC Decryptor_Decrypt(void *thisptr, void *encrypted, void *destination);

SEAL_C_FUNC Decryptor_InvariantNoiseBudget(void *thisptr, void *encrypted, int *invariant_noise_budget);
