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

SEALMETHOD RelinKeys_GetIndex(uint64_t key_power, uint64_t *index);