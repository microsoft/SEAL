// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

// STD
#include <unordered_map>

// SEALNet
#include "sealnet/stdafx.h"
#include "sealnet/sealcontext_wrapper.h"
#include "sealnet/utilities.h"

// SEAL
#include "seal/context.h"

using namespace std;
using namespace seal;
using namespace sealnet;

namespace sealnet
{
    /**
    The purpose of this map is to keep SEALContext shared pointers alive
    while they are being used as regular pointers in the managed world.
    */
    unordered_map<SEALContext*, shared_ptr<SEALContext>> pointer_store_;
}

SEALNETNATIVE HRESULT SEALCALL SEALContext_Create(void *encryptionParams,
    bool expand_mod_chain, int sec_level, void **context)
{
    EncryptionParameters *encParams = FromVoid<EncryptionParameters>(encryptionParams);
    IfNullRet(encParams, E_POINTER);
    IfNullRet(context, E_POINTER);

    sec_level_type security_level = static_cast<sec_level_type>(sec_level);
    auto result = SEALContext::Create(*encParams, expand_mod_chain, security_level);
    pointer_store_[result.get()] = result;

    *context = result.get();
    return S_OK;
}

SEALNETNATIVE HRESULT SEALCALL SEALContext_Destroy(void *thisptr)
{
    SEALContext *context = FromVoid<SEALContext>(thisptr);
    IfNullRet(context, E_POINTER);

    pointer_store_.erase(context);
    return S_OK;
}

SEALNETNATIVE HRESULT SEALCALL SEALContext_KeyParmsId(void *thisptr, uint64_t *parms_id)
{
    SEALContext *context = FromVoid<SEALContext>(thisptr);
    IfNullRet(context, E_POINTER);
    IfNullRet(parms_id, E_POINTER);

    CopyParmsId(context->key_parms_id(), parms_id);
    return S_OK;
}

SEALNETNATIVE HRESULT SEALCALL SEALContext_FirstParmsId(void *thisptr, uint64_t *parms_id)
{
    SEALContext *context = FromVoid<SEALContext>(thisptr);
    IfNullRet(context, E_POINTER);
    IfNullRet(parms_id, E_POINTER);

    CopyParmsId(context->first_parms_id(), parms_id);
    return S_OK;
}

SEALNETNATIVE HRESULT SEALCALL SEALContext_LastParmsId(void *thisptr, uint64_t *parms_id)
{
    SEALContext *context = FromVoid<SEALContext>(thisptr);
    IfNullRet(context, E_POINTER);
    IfNullRet(parms_id, E_POINTER);

    CopyParmsId(context->last_parms_id(), parms_id);
    return S_OK;
}

SEALNETNATIVE HRESULT SEALCALL SEALContext_ParametersSet(void *thisptr, bool *params_set)
{
    SEALContext *context = FromVoid<SEALContext>(thisptr);
    IfNullRet(context, E_POINTER);
    IfNullRet(params_set, E_POINTER);

    *params_set = context->parameters_set();
    return S_OK;
}

SEALNETNATIVE HRESULT SEALCALL SEALContext_KeyContextData(void *thisptr, void **context_data)
{
    SEALContext *context = FromVoid<SEALContext>(thisptr);
    IfNullRet(context, E_POINTER);
    IfNullRet(context_data, E_POINTER);

    // The pointer that is returned should not be deleted.
    auto data = context->key_context_data();
    *context_data = const_cast<SEALContext::ContextData*>(data.get());
    return S_OK;
}

SEALNETNATIVE HRESULT SEALCALL SEALContext_FirstContextData(void *thisptr, void **context_data)
{
    SEALContext *context = FromVoid<SEALContext>(thisptr);
    IfNullRet(context, E_POINTER);
    IfNullRet(context_data, E_POINTER);

    // The pointer that is returned should not be deleted.
    auto data = context->first_context_data();
    *context_data = const_cast<SEALContext::ContextData*>(data.get());
    return S_OK;
}

SEALNETNATIVE HRESULT SEALCALL SEALContext_LastContextData(void *thisptr, void **context_data)
{
    SEALContext *context = FromVoid<SEALContext>(thisptr);
    IfNullRet(context, E_POINTER);
    IfNullRet(context_data, E_POINTER);

    // The pointer that is returned should not be deleted.
    auto data = context->last_context_data();
    *context_data = const_cast<SEALContext::ContextData*>(data.get());
    return S_OK;
}

SEALNETNATIVE HRESULT SEALCALL SEALContext_GetContextData(void *thisptr, uint64_t *parms_id, void **context_data)
{
    SEALContext *context = FromVoid<SEALContext>(thisptr);
    IfNullRet(context, E_POINTER);
    IfNullRet(parms_id, E_POINTER);
    IfNullRet(context_data, E_POINTER);

    // The pointer that is returned should not be deleted.
    parms_id_type parms;
    CopyParmsId(parms_id, parms);
    auto data = context->get_context_data(parms);
    *context_data = const_cast<SEALContext::ContextData*>(data.get());
    return S_OK;
}

SEALNETNATIVE HRESULT SEALCALL SEALContext_UsingKeyswitching(void *thisptr, bool *using_keyswitching)
{
    SEALContext *context = FromVoid<SEALContext>(thisptr);
    IfNullRet(context, E_POINTER);
    IfNullRet(using_keyswitching, E_POINTER);

    *using_keyswitching = context->using_keyswitching();
    return S_OK;
}