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

SEALNETNATIVE HRESULT SEALCALL SEALContext_Create(void *encryptionParams,
    bool expand_mod_chain, int sec_level, void **context);

SEALNETNATIVE HRESULT SEALCALL SEALContext_Destroy(void *thisptr);

SEALNETNATIVE HRESULT SEALCALL SEALContext_KeyParmsId(void *thisptr, uint64_t *parms_id);

SEALNETNATIVE HRESULT SEALCALL SEALContext_FirstParmsId(void *thisptr, uint64_t *parms_id);

SEALNETNATIVE HRESULT SEALCALL SEALContext_LastParmsId(void *thisptr, uint64_t *parms_id);

SEALNETNATIVE HRESULT SEALCALL SEALContext_ParametersSet(void *thisptr, bool *params_set);

SEALNETNATIVE HRESULT SEALCALL SEALContext_KeyContextData(void *thisptr, void **context_data);

SEALNETNATIVE HRESULT SEALCALL SEALContext_FirstContextData(void *thisptr, void **context_data);

SEALNETNATIVE HRESULT SEALCALL SEALContext_LastContextData(void *thisptr, void **context_data);

SEALNETNATIVE HRESULT SEALCALL SEALContext_GetContextData(void *thisptr, uint64_t *parms_id, void **context_data);

SEALNETNATIVE HRESULT SEALCALL SEALContext_UsingKeyswitching(void *thisptr, bool *using_keyswitching);
