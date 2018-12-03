#pragma once

///////////////////////////////////////////////////////////////////////////
//
// This API is provided as a simple interface for the SEAL library
// that can be PInvoked by .Net code.
// 
///////////////////////////////////////////////////////////////////////////

#include "defines.h"
#include <stdint.h>

SEALDLL HRESULT SEALCALL EPQ_Create(void* copy, void** epq);

SEALDLL HRESULT SEALCALL EPQ_Destroy(void* thisptr);

SEALDLL HRESULT SEALCALL EPQ_ParametersSet(void* thisptr, bool* parameters_set);

SEALDLL HRESULT SEALCALL EPQ_EnableFFT(void* thisptr, bool* enable_fft);

SEALDLL HRESULT SEALCALL EPQ_EnableNTT(void* thisptr, bool* enable_ntt);

SEALDLL HRESULT SEALCALL EPQ_EnableBatching(void* thisptr, bool* enable_batching);

SEALDLL HRESULT SEALCALL EPQ_EnableFastPlainLift(void* thisptr, bool* enable_fast_plain_lift);
