// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#pragma once

///////////////////////////////////////////////////////////////////////////
//
// This API is provided as a simple interface for the SEAL library
// that can be PInvoked by .Net code.
// 
///////////////////////////////////////////////////////////////////////////

#include "sealnet/defines.h"
#include <stdint.h>


SEALDLL HRESULT SEALCALL ContextData_Destroy(void *thisptr);

SEALDLL HRESULT SEALCALL ContextData_TotalCoeffModulus(void *thisptr, uint64_t *count, uint64_t *total_coeff_modulus);

SEALDLL HRESULT SEALCALL ContextData_TotalCoeffModulusBitCount(void *thisptr, int *bit_count);

SEALDLL HRESULT SEALCALL ContextData_Parms(void *thisptr, void **parms);

SEALDLL HRESULT SEALCALL ContextData_Qualifiers(void *thisptr, void **epq);

SEALDLL HRESULT SEALCALL ContextData_CoeffDivPlainModulus(void *thisptr, uint64_t *count, uint64_t *coeff_div);

SEALDLL HRESULT SEALCALL ContextData_PlainUpperHalfThreshold(void *thisptr, uint64_t *puht);

SEALDLL HRESULT SEALCALL ContextData_PlainUpperHalfIncrement(void *thisptr, uint64_t *count, uint64_t *puhi);

SEALDLL HRESULT SEALCALL ContextData_UpperHalfThreshold(void *thisptr, uint64_t *count, uint64_t *uht);

SEALDLL HRESULT SEALCALL ContextData_UpperHalfIncrement(void *thisptr, uint64_t *count, uint64_t *uhi);

SEALDLL HRESULT SEALCALL ContextData_NextContextData(void *thisptr, void **next_data);

SEALDLL HRESULT SEALCALL ContextData_ChainIndex(void *thisptr, uint64_t *index);
