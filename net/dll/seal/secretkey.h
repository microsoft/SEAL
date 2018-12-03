#pragma once

///////////////////////////////////////////////////////////////////////////
//
// This API is provided as a simple interface for the SEAL library
// that can be PInvoked by .Net code.
// 
///////////////////////////////////////////////////////////////////////////

#include "defines.h"
#include <stdint.h>

SEALDLL HRESULT SEALCALL SecretKey_Create1(void** secret_key);

SEALDLL HRESULT SEALCALL SecretKey_Create2(void* copy, void** secret_key);

SEALDLL HRESULT SEALCALL SecretKey_Set(void* thisptr, void* assign);

SEALDLL HRESULT SEALCALL SecretKey_Data(void* thisptr, void** data);

SEALDLL HRESULT SEALCALL SecretKey_Destroy(void* thisptr);
