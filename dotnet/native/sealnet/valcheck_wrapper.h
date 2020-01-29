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

SEALMETHOD ValCheck_Plaintext_IsValidFor(void *plaintext, void *context, bool *result);

SEALMETHOD ValCheck_Ciphertext_IsValidFor(void *ciphertext, void *context, bool *result);

SEALMETHOD ValCheck_SecretKey_IsValidFor(void *secret_key, void *context, bool *result);

SEALMETHOD ValCheck_PublicKey_IsValidFor(void *public_key, void *context, bool *result);

SEALMETHOD ValCheck_KSwitchKeys_IsValidFor(void *kswitch_keys, void *context, bool *result);

SEALMETHOD ValCheck_RelinKeys_IsValidFor(void *relin_keys, void *context, bool *result);

SEALMETHOD ValCheck_GaloisKeys_IsValidFor(void *galois_keys, void *context, bool *result);