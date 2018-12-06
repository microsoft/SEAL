#pragma once

///////////////////////////////////////////////////////////////////////////
//
// This API is provided as a simple interface for the SEAL library
// that can be PInvoked by .Net code.
// 
///////////////////////////////////////////////////////////////////////////

#include "defines.h"
#include <stdint.h>

SEALDLL HRESULT SEALCALL MemoryManager_GetPool1(int prof_opt, bool clear_on_destruction, void** pool_handle);

SEALDLL HRESULT SEALCALL MemoryManager_GetPool2(void** pool_handle);

SEALDLL HRESULT SEALCALL MemoryManager_SwitchProfile(void* new_profile, void** old_profile);

SEALDLL HRESULT SEALCALL MMProf_CreateGlobal(void** profile);

SEALDLL HRESULT SEALCALL MMProf_CreateFixed(void* pool, void** profile);

SEALDLL HRESULT SEALCALL MMProf_CreateNew(void** profile);

SEALDLL HRESULT SEALCALL MMProf_CreateThreadLocal(void** profile);

SEALDLL HRESULT SEALCALL MMProf_CreateCopy(void* profile, void** copy);

SEALDLL HRESULT SEALCALL MMProf_GetPool(void* thisptr, void** pool_handle);

SEALDLL HRESULT SEALCALL MMProf_Destroy(void* thisptr);

SEALDLL HRESULT SEALCALL MMProf_DestroyGlobal(void* thisptr);

SEALDLL HRESULT SEALCALL MMProf_DestroyFixed(void* thisptr);

SEALDLL HRESULT SEALCALL MMProf_DestroyNew(void* thisptr);

SEALDLL HRESULT SEALCALL MMProf_DestroyThreadLocal(void* thisptr);
