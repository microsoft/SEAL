// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#pragma once

///////////////////////////////////////////////////////////////////////////
//
// This API is provided as a simple interface for Microsoft SEAL library
// that can be PInvoked by .Net code.
//
///////////////////////////////////////////////////////////////////////////

#include "seal/c/defines.h"
#include <stdint.h>

SEAL_C_FUNC EPQ_Create(void *copy, void **epq);

SEAL_C_FUNC EPQ_Destroy(void *thisptr);

SEAL_C_FUNC EPQ_ParametersSet(void *thisptr, bool *parameters_set);

SEAL_C_FUNC EPQ_UsingFFT(void *thisptr, bool *using_fft);

SEAL_C_FUNC EPQ_UsingNTT(void *thisptr, bool *using_ntt);

SEAL_C_FUNC EPQ_UsingBatching(void *thisptr, bool *using_batching);

SEAL_C_FUNC EPQ_UsingFastPlainLift(void *thisptr, bool *using_fast_plain_lift);

SEAL_C_FUNC EPQ_UsingDescendingModulusChain(void *thisptr, bool *using_descending_modulus_chain);

SEAL_C_FUNC EPQ_SecLevel(void *thisptr, int *sec_level);

SEAL_C_FUNC EPQ_ParameterErrorName(void *thisptr, char *outstr, uint64_t *length);

SEAL_C_FUNC EPQ_ParameterErrorMessage(void *thisptr, char *outstr, uint64_t *length);