#pragma once

///////////////////////////////////////////////////////////////////////////
//
// This API is provided as a simple interface for the SEAL library
// that can be PInvoked by .Net code.
// 
///////////////////////////////////////////////////////////////////////////

#include "defines.h"
#include <stdint.h>

SEALDLL HRESULT SEALCALL PublicKey_Create1(void** public_key);

SEALDLL HRESULT SEALCALL PublicKey_Create2(void* copy, void** public_key);

SEALDLL HRESULT SEALCALL PublicKey_Set(void* thisptr, void* assign);

SEALDLL HRESULT SEALCALL PublicKey_Data(void* thisptr, void** data);

SEALDLL HRESULT SEALCALL PublicKey_ParmsId(void* thisptr, uint64_t* parms_id);

SEALDLL HRESULT SEALCALL PublicKey_IsValidFor(void* thisptr, void* context, bool* result);

SEALDLL HRESULT SEALCALL PublicKey_Pool(void* thisptr, void** pool);

SEALDLL HRESULT SEALCALL PublicKey_Destroy(void* thisptr);
