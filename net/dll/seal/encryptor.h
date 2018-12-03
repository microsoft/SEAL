#pragma once

///////////////////////////////////////////////////////////////////////////
//
// This API is provided as a simple interface for the SEAL library
// that can be PInvoked by .Net code.
// 
///////////////////////////////////////////////////////////////////////////

#include "defines.h"
#include <stdint.h>

SEALDLL HRESULT SEALCALL Encryptor_Create(void* context, void* public_key, void** encryptor);

SEALDLL HRESULT SEALCALL Encryptor_Encrypt(void* thisptr, void* plaintext, void* destination, void* pool_handle);

SEALDLL HRESULT SEALCALL Encryptor_Destroy(void* thisptr);
