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

SEALNETNATIVE HRESULT SEALCALL SmallModulus_Create1(uint64_t value, void **small_modulus);

SEALNETNATIVE HRESULT SEALCALL SmallModulus_Create2(void *copy, void **small_modulus);

SEALNETNATIVE HRESULT SEALCALL SmallModulus_Destroy(void *thisptr);

SEALNETNATIVE HRESULT SEALCALL SmallModulus_IsZero(void *thisptr, bool *is_zero);

SEALNETNATIVE HRESULT SEALCALL SmallModulus_IsPrime(void *thisptr, bool *is_prime);

SEALNETNATIVE HRESULT SEALCALL SmallModulus_Value(void *thisptr, uint64_t *value);

SEALNETNATIVE HRESULT SEALCALL SmallModulus_BitCount(void *thisptr, int *bit_count);

SEALNETNATIVE HRESULT SEALCALL SmallModulus_UInt64Count(void *thisptr, uint64_t *uint64_count);

SEALNETNATIVE HRESULT SEALCALL SmallModulus_Set1(void *thisptr, void *assign);

SEALNETNATIVE HRESULT SEALCALL SmallModulus_Set2(void *thisptr, uint64_t value);

SEALNETNATIVE HRESULT SEALCALL SmallModulus_ConstRatio(void *thisptr, uint64_t length, uint64_t ratio[]);

SEALNETNATIVE HRESULT SEALCALL SmallModulus_Equals1(void *thisptr, void *other, bool *result);

SEALNETNATIVE HRESULT SEALCALL SmallModulus_Equals2(void *thisptr, uint64_t other, bool *result);