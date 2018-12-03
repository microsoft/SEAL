#pragma once

///////////////////////////////////////////////////////////////////////////
//
// This API is provided as a simple interface for the SEAL library
// that can be PInvoked by .Net code.
// 
///////////////////////////////////////////////////////////////////////////

#include "defines.h"
#include <stdint.h>

SEALDLL HRESULT SEALCALL RelinKeys_Create1(void** relin_keys);

SEALDLL HRESULT SEALCALL RelinKeys_Create2(void* copy, void** relin_keys);

SEALDLL HRESULT SEALCALL RelinKeys_Destroy(void* thisptr);

SEALDLL HRESULT SEALCALL RelinKeys_Set(void* thisptr, void* copy);

SEALDLL HRESULT SEALCALL RelinKeys_Size(void* thisptr, int* size);

SEALDLL HRESULT SEALCALL RelinKeys_DBC(void* thisptr, int* dbc);

SEALDLL HRESULT SEALCALL RelinKeys_SetDBC(void* thisptr, int dbc);

SEALDLL HRESULT SEALCALL RelinKeys_GetKeyList(void* thisptr, int index, int* count, void** ciphers);

SEALDLL HRESULT SEALCALL RelinKeys_HasKey(void* thisptr, int key_power, bool* has_key);

SEALDLL HRESULT SEALCALL RelinKeys_GetKey(void* thisptr, int key_power, int* count, void** ciphers);

SEALDLL HRESULT SEALCALL RelinKeys_ClearDataAndReserve(void* thisptr, int size);

SEALDLL HRESULT SEALCALL RelinKeys_AddKeyList(void* thisptr, int count, void** ciphers);

SEALDLL HRESULT SEALCALL RelinKeys_GetParmsId(void* thisptr, uint64_t* parms_id);

SEALDLL HRESULT SEALCALL RelinKeys_SetParmsId(void* thisptr, uint64_t* parms_id);
