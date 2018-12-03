#pragma once

///////////////////////////////////////////////////////////////////////////
//
// This API is provided as a simple interface for the SEAL library
// that can be PInvoked by .Net code.
// 
///////////////////////////////////////////////////////////////////////////

#include "defines.h"
#include <stdint.h>

SEALDLL HRESULT SEALCALL BatchEncoder_Create(void* context, void** batch_encoder);

SEALDLL HRESULT SEALCALL BatchEncoder_Destroy(void* thisptr);

SEALDLL HRESULT SEALCALL BatchEncoder_Encode1(void* thisptr, int count, uint64_t* values, void* destination);

SEALDLL HRESULT SEALCALL BatchEncoder_Encode2(void* thisptr, int count, int64_t* values, void* destination);

SEALDLL HRESULT SEALCALL BatchEncoder_Encode3(void* thisptr, void* plain, void* pool);

SEALDLL HRESULT SEALCALL BatchEncoder_Decode1(void* thisptr, void* plain, int* count, uint64_t* destination, void* pool);

SEALDLL HRESULT SEALCALL BatchEncoder_Decode2(void* thisptr, void* plain, int* count, int64_t* destination, void* pool);

SEALDLL HRESULT SEALCALL BatchEncoder_Decode3(void* thisptr, void* plain, void* pool);

SEALDLL HRESULT SEALCALL BatchEncoder_GetSlotCount(void* thisptr, int* slot_count);
