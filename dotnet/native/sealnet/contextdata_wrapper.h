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

SEALMETHOD ContextData_Destroy(void *thisptr);

SEALMETHOD ContextData_TotalCoeffModulus(void *thisptr, uint64_t *count, uint64_t *total_coeff_modulus);

SEALMETHOD ContextData_TotalCoeffModulusBitCount(void *thisptr, int *bit_count);

SEALMETHOD ContextData_Parms(void *thisptr, void **parms);

SEALMETHOD ContextData_Qualifiers(void *thisptr, void **epq);

SEALMETHOD ContextData_CoeffDivPlainModulus(void *thisptr, uint64_t *count, uint64_t *coeff_div);

SEALMETHOD ContextData_PlainUpperHalfThreshold(void *thisptr, uint64_t *puht);

SEALMETHOD ContextData_PlainUpperHalfIncrement(void *thisptr, uint64_t *count, uint64_t *puhi);

SEALMETHOD ContextData_UpperHalfThreshold(void *thisptr, uint64_t *count, uint64_t *uht);

SEALMETHOD ContextData_UpperHalfIncrement(void *thisptr, uint64_t *count, uint64_t *uhi);

SEALMETHOD ContextData_PrevContextData(void *thisptr, void **prev_data);

SEALMETHOD ContextData_NextContextData(void *thisptr, void **next_data);

SEALMETHOD ContextData_ChainIndex(void *thisptr, uint64_t *index);
