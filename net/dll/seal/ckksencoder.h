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

SEALDLL HRESULT SEALCALL CKKSEncoder_Create(void* context, void** ckks_encoder);

SEALDLL HRESULT SEALCALL CKKSEncoder_Destroy(void* thisptr);

// Array of doubles
SEALDLL HRESULT SEALCALL CKKSEncoder_Encode1(void* thisptr, uint64_t value_count, double* values, uint64_t* parms_id, double scale, void* destination, void* pool);

// Array of complex numbers (two doubles per value)
SEALDLL HRESULT SEALCALL CKKSEncoder_Encode2(void* thisptr, uint64_t value_count, double* complex_values, uint64_t* parms_id, double scale, void* destination, void* pool);

// Single double value
SEALDLL HRESULT SEALCALL CKKSEncoder_Encode3(void* thisptr, double value, uint64_t* parms_id, double scale, void* destination, void* pool);

// Single complex value
SEALDLL HRESULT SEALCALL CKKSEncoder_Encode4(void* thisptr, double real, double imaginary, uint64_t* parms_id, double scale, void* destination, void* pool);

// Single UInt64 value
SEALDLL HRESULT SEALCALL CKKSEncoder_Encode5(void* thisptr, uint64_t value, uint64_t* parms_id, void* destination);

// Array of doubles
SEALDLL HRESULT SEALCALL CKKSEncoder_Decode1(void* thisptr, void* plain, uint64_t* value_count, double* values, void* pool);

// Array of complex numbers
SEALDLL HRESULT SEALCALL CKKSEncoder_Decode2(void* thisptr, void* plain, uint64_t* value_count, double* values, void* pool);

SEALDLL HRESULT SEALCALL CKKSEncoder_SlotCount(void* thisptr, uint64_t* slot_count);
