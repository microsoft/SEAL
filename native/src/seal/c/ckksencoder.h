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

SEAL_C_FUNC CKKSEncoder_Create(void *context, void **ckks_encoder);

SEAL_C_FUNC CKKSEncoder_Destroy(void *thisptr);

// Array of doubles
SEAL_C_FUNC CKKSEncoder_Encode1(
    void *thisptr, uint64_t value_count, double *values, uint64_t *parms_id, double scale, void *destination,
    void *pool);

// Array of complex numbers (two doubles per value)
SEAL_C_FUNC CKKSEncoder_Encode2(
    void *thisptr, uint64_t value_count, double *complex_values, uint64_t *parms_id, double scale, void *destination,
    void *pool);

// Single double value
SEAL_C_FUNC CKKSEncoder_Encode3(
    void *thisptr, double value, uint64_t *parms_id, double scale, void *destination, void *pool);

// Single complex value
SEAL_C_FUNC CKKSEncoder_Encode4(
    void *thisptr, double value_re, double value_im, uint64_t *parms_id, double scale, void *destination, void *pool);

// Single Int64 value
SEAL_C_FUNC CKKSEncoder_Encode5(void *thisptr, int64_t value, uint64_t *parms_id, void *destination);

// Array of doubles
SEAL_C_FUNC CKKSEncoder_Decode1(void *thisptr, void *plain, uint64_t *value_count, double *values, void *pool);

// Array of complex numbers
SEAL_C_FUNC CKKSEncoder_Decode2(void *thisptr, void *plain, uint64_t *value_count, double *values, void *pool);

SEAL_C_FUNC CKKSEncoder_SlotCount(void *thisptr, uint64_t *slot_count);
