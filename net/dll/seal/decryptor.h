#pragma once

///////////////////////////////////////////////////////////////////////////
//
// This API is provided as a simple interface for the SEAL library
// that can be PInvoked by .Net code.
// 
///////////////////////////////////////////////////////////////////////////

#include "defines.h"
#include <stdint.h>

SEALDLL HRESULT SEALCALL Decryptor_Create(void* context, void* secret_key, void** decryptor);

SEALDLL HRESULT SEALCALL Decryptor_Destroy(void* thisptr);

SEALDLL HRESULT SEALCALL Decryptor_Decrypt(void* thisptr, void* encrypted, void* destination, void* pool_handle);

SEALDLL HRESULT SEALCALL Decryptor_InvariantNoiseBudget(void* thisptr, void* encrypted, void* pool_handle, int* invariant_noise_budget);
