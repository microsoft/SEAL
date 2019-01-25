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

SEALDLL HRESULT SEALCALL SmallModulus_Create1(uint64_t value, void **small_modulus);

SEALDLL HRESULT SEALCALL SmallModulus_Create2(void *copy, void **small_modulus);

SEALDLL HRESULT SEALCALL SmallModulus_Destroy(void *thisptr);

SEALDLL HRESULT SEALCALL SmallModulus_IsZero(void *thisptr, bool *is_zero);

SEALDLL HRESULT SEALCALL SmallModulus_Value(void *thisptr, uint64_t *value);

SEALDLL HRESULT SEALCALL SmallModulus_BitCount(void *thisptr, int *bit_count);

SEALDLL HRESULT SEALCALL SmallModulus_UInt64Count(void *thisptr, uint64_t *uint64_count);

SEALDLL HRESULT SEALCALL SmallModulus_Set1(void *thisptr, void *assign);

SEALDLL HRESULT SEALCALL SmallModulus_Set2(void *thisptr, uint64_t value);

SEALDLL HRESULT SEALCALL SmallModulus_ConstRatio(void *thisptr, int length, uint64_t ratio[]);

SEALDLL HRESULT SEALCALL SmallModulus_Equals1(void *thisptr, void *other, bool *result);

SEALDLL HRESULT SEALCALL SmallModulus_Equals2(void *thisptr, uint64_t other, bool *result);
