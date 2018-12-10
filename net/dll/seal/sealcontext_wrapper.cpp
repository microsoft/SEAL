// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

// STD
#include <unordered_map>

// SEALDll
#include "stdafx.h"
#include "sealcontext_wrapper.h"
#include "utilities.h"

// SEAL
#include "seal/context.h"

using namespace std;
using namespace seal;
using namespace seal::dll;


namespace seal
{
    namespace dll
    {
        /**
        The purpose of this map is to keep SEALContext shared pointers alive
        while they are being used as regular pointers in the managed world.
        */
        unordered_map<SEALContext*, shared_ptr<SEALContext>> pointer_store_;
    }
}


SEALDLL HRESULT SEALCALL SEALContext_Create(void* encryptionParams, void** context)
{
    EncryptionParameters* encParams = FromVoid<EncryptionParameters>(encryptionParams);
    IfNullRet(encParams, E_POINTER);
    IfNullRet(context, E_POINTER);

    auto result = SEALContext::Create(*encParams);
    pointer_store_.insert_or_assign(result.get(), result);

    *context = result.get();
    return S_OK;
}

SEALDLL HRESULT SEALCALL SEALContext_Destroy(void* thisptr)
{
    SEALContext* context = FromVoid<SEALContext>(thisptr);
    IfNullRet(context, E_POINTER);

    pointer_store_.erase(context);
    return S_OK;
}

SEALDLL HRESULT SEALCALL SEALContext_FirstParmsId(void* thisptr, uint64_t* parms_id)
{
    SEALContext* context = FromVoid<SEALContext>(thisptr);
    IfNullRet(context, E_POINTER);
    IfNullRet(parms_id, E_POINTER);

    CopyParmsId(context->first_parms_id(), parms_id);
    return S_OK;
}

SEALDLL HRESULT SEALCALL SEALContext_LastParmsId(void* thisptr, uint64_t* parms_id)
{
    SEALContext* context = FromVoid<SEALContext>(thisptr);
    IfNullRet(context, E_POINTER);
    IfNullRet(parms_id, E_POINTER);

    CopyParmsId(context->last_parms_id(), parms_id);
    return S_OK;
}

SEALDLL HRESULT SEALCALL SEALContext_ParametersSet(void* thisptr, bool* params_set)
{
    SEALContext* context = FromVoid<SEALContext>(thisptr);
    IfNullRet(context, E_POINTER);
    IfNullRet(params_set, E_POINTER);

    *params_set = context->parameters_set();
    return S_OK;
}

SEALDLL HRESULT SEALCALL SEALContext_FirstContextData(void* thisptr, void** first_context_data)
{
    SEALContext* context = FromVoid<SEALContext>(thisptr);
    IfNullRet(context, E_POINTER);
    IfNullRet(first_context_data, E_POINTER);

    // The pointer that is returned should not be deleted.
    auto context_data = context->context_data();
    *first_context_data = const_cast<SEALContext::ContextData*>(context_data.get());
    return S_OK;
}

SEALDLL HRESULT SEALCALL SEALContext_GetContextData(void* thisptr, uint64_t* parms_id, void** context_data)
{
    SEALContext* context = FromVoid<SEALContext>(thisptr);
    IfNullRet(context, E_POINTER);
    IfNullRet(parms_id, E_POINTER);
    IfNullRet(context_data, E_POINTER);

    // The pointer that is returned should not be deleted.
    parms_id_type parms;
    CopyParmsId(parms_id, parms);
    auto data = context->context_data(parms);
    *context_data = const_cast<SEALContext::ContextData*>(data.get());
    return S_OK;
}

