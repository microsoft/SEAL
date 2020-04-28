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

SEAL_C_FUNC SEALContext_Create(void *encryptionParams, bool expand_mod_chain, int sec_level, void **context);

SEAL_C_FUNC SEALContext_Destroy(void *thisptr);

SEAL_C_FUNC SEALContext_KeyParmsId(void *thisptr, uint64_t *parms_id);

SEAL_C_FUNC SEALContext_FirstParmsId(void *thisptr, uint64_t *parms_id);

SEAL_C_FUNC SEALContext_LastParmsId(void *thisptr, uint64_t *parms_id);

SEAL_C_FUNC SEALContext_ParametersSet(void *thisptr, bool *params_set);

SEAL_C_FUNC SEALContext_KeyContextData(void *thisptr, void **context_data);

SEAL_C_FUNC SEALContext_FirstContextData(void *thisptr, void **context_data);

SEAL_C_FUNC SEALContext_LastContextData(void *thisptr, void **context_data);

SEAL_C_FUNC SEALContext_GetContextData(void *thisptr, uint64_t *parms_id, void **context_data);

SEAL_C_FUNC SEALContext_UsingKeyswitching(void *thisptr, bool *using_keyswitching);

SEAL_C_FUNC SEALContext_ParameterErrorName(void *thisptr, char *outstr, uint64_t *length);

SEAL_C_FUNC SEALContext_ParameterErrorMessage(void *thisptr, char *outstr, uint64_t *length);