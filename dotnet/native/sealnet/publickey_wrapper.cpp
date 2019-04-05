// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

// SEALNet
#include "sealnet/stdafx.h"
#include "sealnet/publickey_wrapper.h"
#include "sealnet/utilities.h"

// SEAL
#include "seal/publickey.h"

using namespace std;
using namespace seal;
using namespace sealnet;

SEALNETNATIVE HRESULT SEALCALL PublicKey_Create1(void **public_key)
{
    IfNullRet(public_key, E_POINTER);

    PublicKey *pkey = new PublicKey();
    *public_key = pkey;
    return S_OK;
}

SEALNETNATIVE HRESULT SEALCALL PublicKey_Create2(void *copy, void **public_key)
{
    PublicKey *copyptr = FromVoid<PublicKey>(copy);
    IfNullRet(copyptr, E_POINTER);
    IfNullRet(public_key, E_POINTER);

    PublicKey *pkey = new PublicKey(*copyptr);
    *public_key = pkey;
    return S_OK;
}

SEALNETNATIVE HRESULT SEALCALL PublicKey_Set(void *thisptr, void *assign)
{
    PublicKey *pkey = FromVoid<PublicKey>(thisptr);
    IfNullRet(pkey, E_POINTER);
    PublicKey *assignptr = FromVoid<PublicKey>(assign);
    IfNullRet(assignptr, E_POINTER);

    *pkey = *assignptr;
    return S_OK;
}

SEALNETNATIVE HRESULT SEALCALL PublicKey_Data(void *thisptr, void **data)
{
    PublicKey *pkey = FromVoid<PublicKey>(thisptr);
    IfNullRet(pkey, E_POINTER);
    IfNullRet(data, E_POINTER);

    // This returns a pointer to an existing object, not a new object.
    // Make sure the managed side does not try to delete it.
    Ciphertext *cipher = &pkey->data();
    *data = cipher;
    return S_OK;
}

SEALNETNATIVE HRESULT SEALCALL PublicKey_ParmsId(void *thisptr, uint64_t *parms_id)
{
    PublicKey *pkey = FromVoid<PublicKey>(thisptr);
    IfNullRet(pkey, E_POINTER);
    IfNullRet(parms_id, E_POINTER);

    CopyParmsId(pkey->parms_id(), parms_id);
    return S_OK;
}

SEALNETNATIVE HRESULT SEALCALL PublicKey_Pool(void *thisptr, void **pool)
{
    PublicKey *pkey = FromVoid<PublicKey>(thisptr);
    IfNullRet(pkey, E_POINTER);
    IfNullRet(pool, E_POINTER);

    MemoryPoolHandle *handleptr = new MemoryPoolHandle(pkey->pool());
    *pool = handleptr;
    return S_OK;
}

SEALNETNATIVE HRESULT SEALCALL PublicKey_Destroy(void *thisptr)
{
    PublicKey *pkey = FromVoid<PublicKey>(thisptr);
    IfNullRet(pkey, E_POINTER);

    delete pkey;
    return S_OK;
}

