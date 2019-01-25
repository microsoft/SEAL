// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#pragma once

///////////////////////////////////////////////////////////////////////////
//
// This API is provided as a simple interface for the SEAL library
// that can be PInvoked by .Net code.
// 
///////////////////////////////////////////////////////////////////////////

#include "sealnet/defines.h"
#include <stdint.h>

SEALDLL HRESULT SEALCALL SEALContext_Create(void *encryptionParams, bool expand_mod_chain, void **context);

SEALDLL HRESULT SEALCALL SEALContext_Destroy(void *thisptr);

SEALDLL HRESULT SEALCALL SEALContext_FirstParmsId(void *thisptr, uint64_t *parms_id);

SEALDLL HRESULT SEALCALL SEALContext_LastParmsId(void *thisptr, uint64_t *parms_id);

SEALDLL HRESULT SEALCALL SEALContext_ParametersSet(void *thisptr, bool *params_set);

SEALDLL HRESULT SEALCALL SEALContext_FirstContextData(void *thisptr, void **first_context_data);

SEALDLL HRESULT SEALCALL SEALContext_GetContextData(void *thisptr, uint64_t *parms_id, void **context_data);
