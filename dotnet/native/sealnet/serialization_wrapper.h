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

SEALNETNATIVE HRESULT SEALCALL Serialization_SEALMagic(uint16_t *result);

SEALNETNATIVE HRESULT SEALCALL Serialization_IsSupportedComprMode(uint8_t compr_mode, bool *result);

SEALNETNATIVE HRESULT SEALCALL Serialization_ComprModeDefault(uint8_t *result);

SEALNETNATIVE HRESULT SEALCALL Serialization_IsValidHeader(uint8_t *headerptr, uint64_t size, bool *result);