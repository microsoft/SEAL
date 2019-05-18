// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#pragma once

///////////////////////////////////////////////////////////////////////////
//
// This API is provided as a simple interface for Microsoft SEAL library
// that can be PInvoked by .Net code.
//
///////////////////////////////////////////////////////////////////////////

#include "sealnet/defines.h"
#include <stdint.h>

SEALNETNATIVE HRESULT SEALCALL EPQ_Create(void *copy, void **epq);

SEALNETNATIVE HRESULT SEALCALL EPQ_Destroy(void *thisptr);

SEALNETNATIVE HRESULT SEALCALL EPQ_ParametersSet(void *thisptr, bool *parameters_set);

SEALNETNATIVE HRESULT SEALCALL EPQ_UsingFFT(void *thisptr, bool *using_fft);

SEALNETNATIVE HRESULT SEALCALL EPQ_UsingNTT(void *thisptr, bool *using_ntt);

SEALNETNATIVE HRESULT SEALCALL EPQ_UsingBatching(void *thisptr, bool *using_batching);

SEALNETNATIVE HRESULT SEALCALL EPQ_UsingFastPlainLift(void *thisptr, bool *using_fast_plain_lift);

SEALNETNATIVE HRESULT SEALCALL EPQ_UsingDescendingModulusChain(void *thisptr, bool *using_descending_modulus_chain);

SEALNETNATIVE HRESULT SEALCALL EPQ_SecLevel(void *thisptr, int *sec_level);
