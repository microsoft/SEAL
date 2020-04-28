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

SEAL_C_FUNC IntegerEncoder_Create(void *context, void **encoder);

SEAL_C_FUNC IntegerEncoder_Destroy(void *thisptr);

SEAL_C_FUNC IntegerEncoder_Encode1(void *thisptr, int32_t value, void *plain);

SEAL_C_FUNC IntegerEncoder_Encode2(void *thisptr, uint32_t value, void *plain);

SEAL_C_FUNC IntegerEncoder_Encode3(void *thisptr, uint64_t value, void *plain);

SEAL_C_FUNC IntegerEncoder_Encode4(void *thisptr, int64_t value, void *plain);

SEAL_C_FUNC IntegerEncoder_Encode5(void *thisptr, void *biguint, void *plain);

SEAL_C_FUNC IntegerEncoder_DecodeUInt32(void *thisptr, void *plain, uint32_t *result);

SEAL_C_FUNC IntegerEncoder_DecodeUInt64(void *thisptr, void *plain, uint64_t *result);

SEAL_C_FUNC IntegerEncoder_DecodeInt32(void *thisptr, void *plain, int32_t *result);

SEAL_C_FUNC IntegerEncoder_DecodeInt64(void *thisptr, void *plain, int64_t *result);

SEAL_C_FUNC IntegerEncoder_DecodeBigUInt(void *thisptr, void *plain, void **biguint);

SEAL_C_FUNC IntegerEncoder_PlainModulus(void *thisptr, void **smallModulus);
