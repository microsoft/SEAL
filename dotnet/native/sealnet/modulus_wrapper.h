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

SEALNETNATIVE HRESULT SEALCALL CoeffModulus_MaxBitCount(uint64_t poly_modulus_degree, int sec_level, int *bit_count);

SEALNETNATIVE HRESULT SEALCALL CoeffModulus_BFVDefault(uint64_t poly_modulus_degree, int sec_level, uint64_t *length, void **coeffs);

SEALNETNATIVE HRESULT SEALCALL CoeffModulus_Create(uint64_t poly_modulus_degree, uint64_t length, int *bit_sizes, void **coeffs);
