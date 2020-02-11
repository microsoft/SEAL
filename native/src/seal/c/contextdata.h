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

SEAL_C_FUNC ContextData_Destroy(void *thisptr);

SEAL_C_FUNC ContextData_TotalCoeffModulus(void *thisptr, uint64_t *count, uint64_t *total_coeff_modulus);

SEAL_C_FUNC ContextData_TotalCoeffModulusBitCount(void *thisptr, int *bit_count);

SEAL_C_FUNC ContextData_Parms(void *thisptr, void **parms);

SEAL_C_FUNC ContextData_Qualifiers(void *thisptr, void **epq);

SEAL_C_FUNC ContextData_CoeffDivPlainModulus(void *thisptr, uint64_t *count, uint64_t *coeff_div);

SEAL_C_FUNC ContextData_PlainUpperHalfThreshold(void *thisptr, uint64_t *puht);

SEAL_C_FUNC ContextData_PlainUpperHalfIncrement(void *thisptr, uint64_t *count, uint64_t *puhi);

SEAL_C_FUNC ContextData_UpperHalfThreshold(void *thisptr, uint64_t *count, uint64_t *uht);

SEAL_C_FUNC ContextData_UpperHalfIncrement(void *thisptr, uint64_t *count, uint64_t *uhi);

SEAL_C_FUNC ContextData_PrevContextData(void *thisptr, void **prev_data);

SEAL_C_FUNC ContextData_NextContextData(void *thisptr, void **next_data);

SEAL_C_FUNC ContextData_ChainIndex(void *thisptr, uint64_t *index);
