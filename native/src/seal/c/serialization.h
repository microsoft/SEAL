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

SEAL_C_FUNC Serialization_SEALMagic(uint16_t *result);

SEAL_C_FUNC Serialization_SEALHeaderSize(uint8_t *result);

SEAL_C_FUNC Serialization_IsSupportedComprMode(uint8_t compr_mode, bool *result);

SEAL_C_FUNC Serialization_ComprModeDefault(uint8_t *result);

SEAL_C_FUNC Serialization_IsCompatibleVersion(uint8_t *headerptr, uint64_t size, bool *result);

SEAL_C_FUNC Serialization_IsValidHeader(uint8_t *headerptr, uint64_t size, bool *result);
