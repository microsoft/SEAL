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
