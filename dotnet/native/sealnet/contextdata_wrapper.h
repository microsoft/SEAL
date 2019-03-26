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


SEALNETNATIVE HRESULT SEALCALL ContextData_Destroy(void *thisptr);

SEALNETNATIVE HRESULT SEALCALL ContextData_TotalCoeffModulus(void *thisptr, uint64_t *count, uint64_t *total_coeff_modulus);

SEALNETNATIVE HRESULT SEALCALL ContextData_TotalCoeffModulusBitCount(void *thisptr, int *bit_count);

SEALNETNATIVE HRESULT SEALCALL ContextData_Parms(void *thisptr, void **parms);

SEALNETNATIVE HRESULT SEALCALL ContextData_Qualifiers(void *thisptr, void **epq);

SEALNETNATIVE HRESULT SEALCALL ContextData_CoeffDivPlainModulus(void *thisptr, uint64_t *count, uint64_t *coeff_div);

SEALNETNATIVE HRESULT SEALCALL ContextData_PlainUpperHalfThreshold(void *thisptr, uint64_t *puht);

SEALNETNATIVE HRESULT SEALCALL ContextData_PlainUpperHalfIncrement(void *thisptr, uint64_t *count, uint64_t *puhi);

SEALNETNATIVE HRESULT SEALCALL ContextData_UpperHalfThreshold(void *thisptr, uint64_t *count, uint64_t *uht);

SEALNETNATIVE HRESULT SEALCALL ContextData_UpperHalfIncrement(void *thisptr, uint64_t *count, uint64_t *uhi);

SEALNETNATIVE HRESULT SEALCALL ContextData_PrevContextData(void *thisptr, void **prev_data);

SEALNETNATIVE HRESULT SEALCALL ContextData_NextContextData(void *thisptr, void **next_data);

SEALNETNATIVE HRESULT SEALCALL ContextData_ChainIndex(void *thisptr, uint64_t *index);
