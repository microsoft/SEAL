// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#pragma once

///////////////////////////////////////////////////////////////////////////
//
// This API is provided as a simple interface for the SEAL library
// that can be PInvoked by .Net code.
// 
///////////////////////////////////////////////////////////////////////////

#include "defines.h"
#include <stdint.h>

SEALDLL HRESULT SEALCALL EPQ_Create(void *copy, void **epq);

SEALDLL HRESULT SEALCALL EPQ_Destroy(void *thisptr);

SEALDLL HRESULT SEALCALL EPQ_ParametersSet(void *thisptr, bool *parameters_set);

SEALDLL HRESULT SEALCALL EPQ_UsingFFT(void *thisptr, bool *using_fft);

SEALDLL HRESULT SEALCALL EPQ_UsingNTT(void *thisptr, bool *using_ntt);

SEALDLL HRESULT SEALCALL EPQ_UsingBatching(void *thisptr, bool *using_batching);

SEALDLL HRESULT SEALCALL EPQ_UsingFastPlainLift(void *thisptr, bool *using_fast_plain_lift);

SEALDLL HRESULT SEALCALL EPQ_UsingHEStdSecurity(void *thisptr, bool *using_HE_std_security);
