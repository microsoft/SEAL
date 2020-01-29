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

SEALMETHOD Serialization_SEALMagic(uint16_t *result);

SEALMETHOD Serialization_IsSupportedComprMode(uint8_t compr_mode, bool *result);

SEALMETHOD Serialization_ComprModeDefault(uint8_t *result);

SEALMETHOD Serialization_IsValidHeader(uint8_t *headerptr, uint64_t size, bool *result);