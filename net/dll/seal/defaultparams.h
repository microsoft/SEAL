#pragma once

///////////////////////////////////////////////////////////////////////////
//
// This API is provided as a simple interface for the SEAL library
// that can be PInvoked by .Net code.
// 
///////////////////////////////////////////////////////////////////////////

#include "defines.h"
#include <stdint.h>

SEALDLL HRESULT SEALCALL DefParams_CoeffModulus128(int polyModulusDegree, int* length, void** coeffs);

SEALDLL HRESULT SEALCALL DefParams_CoeffModulus192(int polyModulusDegree, int* length, void** coeffs);

SEALDLL HRESULT SEALCALL DefParams_CoeffModulus256(int polyModulusDegree, int* length, void** coeffs);

SEALDLL HRESULT SEALCALL DefParams_SmallMods60Bit(int index, void** small_modulus);

SEALDLL HRESULT SEALCALL DefParams_SmallMods50Bit(int index, void** small_modulus);

SEALDLL HRESULT SEALCALL DefParams_SmallMods40Bit(int index, void** small_modulus);

SEALDLL HRESULT SEALCALL DefParams_SmallMods30Bit(int index, void** small_modulus);

SEALDLL HRESULT SEALCALL DefParams_DBCMax(int* dbc_max_value);

SEALDLL HRESULT SEALCALL DefParams_DBCMin(int* dbc_min_value);
