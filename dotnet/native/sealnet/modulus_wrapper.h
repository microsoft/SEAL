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

SEALMETHOD CoeffModulus_MaxBitCount(uint64_t poly_modulus_degree, int sec_level, int *bit_count);

SEALMETHOD CoeffModulus_BFVDefault(uint64_t poly_modulus_degree, int sec_level, uint64_t *length, void **coeffs);

SEALMETHOD CoeffModulus_Create(uint64_t poly_modulus_degree, uint64_t length, int *bit_sizes, void **coeffs);
