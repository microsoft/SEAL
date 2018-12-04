#pragma once

///////////////////////////////////////////////////////////////////////////
//
// This API is provided as a simple interface for the SEAL library
// that can be PInvoked by .Net code.
// 
///////////////////////////////////////////////////////////////////////////

#include "defines.h"
#include <stdint.h>

SEALDLL HRESULT SEALCALL Plaintext_Create1(void* memoryPoolHandle, void** plaintext);

SEALDLL HRESULT SEALCALL Plaintext_Create2(int coeffCount, void* memoryPoolHandle, void** plaintext);

SEALDLL HRESULT SEALCALL Plaintext_Create3(int capacity, int coeffCount, void* memoryPoolHandle, void** plaintext);

SEALDLL HRESULT SEALCALL Plaintext_Create4(char* hexPoly, void* memoryPoolHandle, void** plaintext);

SEALDLL HRESULT SEALCALL Plaintext_Set1(void* thisptr, void* assign);

SEALDLL HRESULT SEALCALL Plaintext_Set2(void *thisptr, char* hex_poly);

SEALDLL HRESULT SEALCALL Plaintext_Set3(void *thisptr, uint64_t const_coeff);

SEALDLL HRESULT SEALCALL Plaintext_Destroy(void* thisptr);

SEALDLL HRESULT SEALCALL Plaintext_CoeffCount(void* thisptr, int* coeff_count);

SEALDLL HRESULT SEALCALL Plaintext_CoeffAt(void* thisptr, int index, uint64_t* coeff);

SEALDLL HRESULT SEALCALL Plaintext_SetCoeffAt(void* thisptr, int index, uint64_t value);

SEALDLL HRESULT SEALCALL Plaintext_ToString(void* thispt, int* length, char* outstr);

SEALDLL HRESULT SEALCALL Plaintext_IsNTTForm(void* thisptr, bool* is_ntt_form);

SEALDLL HRESULT SEALCALL Plaintext_IsZero(void* thisptr, bool* is_zero);

SEALDLL HRESULT SEALCALL Plaintext_SetZero1(void *thisptr);

SEALDLL HRESULT SEALCALL Plaintext_SetZero2(void *thisptr, int start_coeff);

SEALDLL HRESULT SEALCALL Plaintext_SetZero3(void *thisptr, int start_coeff, int length);

SEALDLL HRESULT SEALCALL Plaintext_GetParmsId(void* thisptr, uint64_t* parms_id);

SEALDLL HRESULT SEALCALL Plaintext_SetParmsId(void* thisptr, uint64_t* parms_id);

SEALDLL HRESULT SEALCALL Plaintext_Reserve(void* thisptr, int capacity);

SEALDLL HRESULT SEALCALL Plaintext_Resize(void* thisptr, int coeff_count);

SEALDLL HRESULT SEALCALL Plaintext_ShrinkToFit(void* thisptr);

SEALDLL HRESULT SEALCALL Plaintext_Release(void* thisptr);

SEALDLL HRESULT SEALCALL Plaintext_Capacity(void* thisptr, int* capacity);

SEALDLL HRESULT SEALCALL Plaintext_SignificantCoeffCount(void* thisptr, int* significant_coeff_count);

SEALDLL HRESULT SEALCALL Plaintext_Scale(void* thisptr, double* scale);

SEALDLL HRESULT SEALCALL Plaintext_SetScale(void* thisptr, double scale);

SEALDLL HRESULT SEALCALL Plaintext_Equals(void *thisptr, void* other, bool* result);

SEALDLL HRESULT SEALCALL Plaintext_IsValidFor(void *thisptr, void* contextpr, bool* result);

SEALDLL HRESULT SEALCALL Plaintext_SwapData(void* thisptr, int count, uint64_t* new_data);
