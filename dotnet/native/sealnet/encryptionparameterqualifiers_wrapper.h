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

SEALMETHOD EPQ_Create(void *copy, void **epq);

SEALMETHOD EPQ_Destroy(void *thisptr);

SEALMETHOD EPQ_ParametersSet(void *thisptr, bool *parameters_set);

SEALMETHOD EPQ_UsingFFT(void *thisptr, bool *using_fft);

SEALMETHOD EPQ_UsingNTT(void *thisptr, bool *using_ntt);

SEALMETHOD EPQ_UsingBatching(void *thisptr, bool *using_batching);

SEALMETHOD EPQ_UsingFastPlainLift(void *thisptr, bool *using_fast_plain_lift);

SEALMETHOD EPQ_UsingDescendingModulusChain(void *thisptr, bool *using_descending_modulus_chain);

SEALMETHOD EPQ_SecLevel(void *thisptr, int *sec_level);
