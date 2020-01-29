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

SEALMETHOD IntegerEncoder_Create(void *context, void **encoder);

SEALMETHOD IntegerEncoder_Destroy(void *thisptr);

SEALMETHOD IntegerEncoder_Encode1(void *thisptr, int32_t value, void *plain);

SEALMETHOD IntegerEncoder_Encode2(void *thisptr, uint32_t value, void *plain);

SEALMETHOD IntegerEncoder_Encode3(void *thisptr, uint64_t value, void *plain);

SEALMETHOD IntegerEncoder_Encode4(void *thisptr, int64_t value, void *plain);

SEALMETHOD IntegerEncoder_Encode5(void *thisptr, void *biguint, void *plain);

SEALMETHOD IntegerEncoder_DecodeUInt32(void *thisptr, void *plain, uint32_t *result);

SEALMETHOD IntegerEncoder_DecodeUInt64(void *thisptr, void *plain, uint64_t *result);

SEALMETHOD IntegerEncoder_DecodeInt32(void *thisptr, void *plain, int32_t *result);

SEALMETHOD IntegerEncoder_DecodeInt64(void *thisptr, void *plain, int64_t *result);

SEALMETHOD IntegerEncoder_DecodeBigUInt(void *thisptr, void *plain, void **biguint);

SEALMETHOD IntegerEncoder_PlainModulus(void *thisptr, void **smallModulus);
