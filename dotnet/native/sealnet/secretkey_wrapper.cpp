// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

// SEALNet
#include "sealnet/stdafx.h"
#include "sealnet/secretkey_wrapper.h"
#include "sealnet/utilities.h"

// SEAL
#include "seal/secretkey.h"

using namespace std;
using namespace seal;
using namespace sealnet;

SEALNETNATIVE HRESULT SEALCALL SecretKey_Create1(void **secret_key)
{
    IfNullRet(secret_key, E_POINTER);

    SecretKey *skey = new SecretKey();
    *secret_key = skey;
    return S_OK;
}

SEALNETNATIVE HRESULT SEALCALL SecretKey_Create2(void *copy, void **secret_key)
{
    SecretKey *copyptr = FromVoid<SecretKey>(copy);
    IfNullRet(copyptr, E_POINTER);
    IfNullRet(secret_key, E_POINTER);

    SecretKey *skey = new SecretKey(*copyptr);
    *secret_key = skey;
    return S_OK;
}

SEALNETNATIVE HRESULT SEALCALL SecretKey_Set(void *thisptr, void *assign)
{
    SecretKey *skey = FromVoid<SecretKey>(thisptr);
    IfNullRet(skey, E_POINTER);
    SecretKey *assignptr = FromVoid<SecretKey>(assign);
    IfNullRet(assignptr, E_POINTER);

    *skey = *assignptr;
    return S_OK;
}

SEALNETNATIVE HRESULT SEALCALL SecretKey_Data(void *thisptr, void **data)
{
    SecretKey *skey = FromVoid<SecretKey>(thisptr);
    IfNullRet(skey, E_POINTER);
    IfNullRet(data, E_POINTER);

    // This returns a pointer to an existing object, not a new object.
    // Make sure the managed side does not try to delete it.
    const Plaintext *plaintext = &skey->data();
    *data = const_cast<Plaintext*>(plaintext);
    return S_OK;
}

SEALNETNATIVE HRESULT SEALCALL SecretKey_Destroy(void *thisptr)
{
    SecretKey *skey = FromVoid<SecretKey>(thisptr);
    IfNullRet(skey, E_POINTER);

    delete skey;
    return S_OK;
}

SEALNETNATIVE HRESULT SEALCALL SecretKey_ParmsId(void *thisptr, uint64_t *parms_id)
{
    SecretKey *skey = FromVoid<SecretKey>(thisptr);
    IfNullRet(skey, E_POINTER);
    IfNullRet(parms_id, E_POINTER);

    CopyParmsId(skey->parms_id(), parms_id);
    return S_OK;
}

SEALNETNATIVE HRESULT SEALCALL SecretKey_Pool(void *thisptr, void **pool)
{
    SecretKey *skey = FromVoid<SecretKey>(thisptr);
    IfNullRet(skey, E_POINTER);
    IfNullRet(pool, E_POINTER);

    MemoryPoolHandle *handleptr = new MemoryPoolHandle(skey->pool());
    *pool = handleptr;
    return S_OK;
}
