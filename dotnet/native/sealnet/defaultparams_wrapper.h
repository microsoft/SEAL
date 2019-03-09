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

SEALNETNATIVE HRESULT SEALCALL DefParams_CoeffModulus128(uint64_t polyModulusDegree, uint64_t *length, void **coeffs);

SEALNETNATIVE HRESULT SEALCALL DefParams_CoeffModulus192(uint64_t polyModulusDegree, uint64_t *length, void **coeffs);

SEALNETNATIVE HRESULT SEALCALL DefParams_CoeffModulus256(uint64_t polyModulusDegree, uint64_t *length, void **coeffs);

SEALNETNATIVE HRESULT SEALCALL DefParams_SmallMods60Bit(uint64_t index, void **small_modulus);

SEALNETNATIVE HRESULT SEALCALL DefParams_SmallMods50Bit(uint64_t index, void **small_modulus);

SEALNETNATIVE HRESULT SEALCALL DefParams_SmallMods40Bit(uint64_t index, void **small_modulus);

SEALNETNATIVE HRESULT SEALCALL DefParams_SmallMods30Bit(uint64_t index, void **small_modulus);

SEALNETNATIVE HRESULT SEALCALL DefParams_DBCMax(int *dbc_max_value);

SEALNETNATIVE HRESULT SEALCALL DefParams_DBCMin(int *dbc_min_value);
