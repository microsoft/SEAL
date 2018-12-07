// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#pragma once

///////////////////////////////////////////////////////////////////////////
//
// This API is provided as a simple interface for the SEAL library
// that can be PInvoked by .Net code.
// 
///////////////////////////////////////////////////////////////////////////

#include "defines.h"
#include <stdint.h>

SEALDLL HRESULT SEALCALL EncParams_Create1(int scheme, void** enc_params);

SEALDLL HRESULT SEALCALL EncParams_Create2(void* copy, void** enc_params);

SEALDLL HRESULT SEALCALL EncParams_Destroy(void* thisptr);

SEALDLL HRESULT SEALCALL EncParams_Set(void* thisptr, void* assign);

SEALDLL HRESULT SEALCALL EncParams_GetPolyModulusDegree(void* thisptr, uint64_t* degree);

SEALDLL HRESULT SEALCALL EncParams_SetPolyModulusDegree(void* thisptr, uint64_t degree);

SEALDLL HRESULT SEALCALL EncParams_GetCoeffModulus(void* thisptr, uint64_t* length, void** coeffs);

SEALDLL HRESULT SEALCALL EncParams_SetCoeffModulus(void* thisptr, uint64_t length, void** coeffs);

SEALDLL HRESULT SEALCALL EncParams_GetScheme(void* thisptr, int* scheme);

SEALDLL HRESULT SEALCALL EncParams_GetParmsId(void* thisptr, uint64_t* parms_id);

SEALDLL HRESULT SEALCALL EncParams_GetPlainModulus(void* thisptr, void** plain_modulus);

SEALDLL HRESULT SEALCALL EncParams_SetPlainModulus1(void* thisptr, void* modulus);

SEALDLL HRESULT SEALCALL EncParams_SetPlainModulus2(void* thisptr, uint64_t plainModulus);

SEALDLL HRESULT SEALCALL EncParams_NoiseStandardDeviation(void* thisptr, double* nsd);

SEALDLL HRESULT SEALCALL EncParams_SetNoiseStandardDeviation(void* thisptr, double nsd);

SEALDLL HRESULT SEALCALL EncParams_NoiseMaxDeviation(void* thisptr, double* nmd);

SEALDLL HRESULT SEALCALL EncParams_Equals(void* thisptr, void* otherptr, bool* result);
