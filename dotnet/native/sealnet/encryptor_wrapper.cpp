// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

// SEALNet
#include "sealnet/stdafx.h"
#include "sealnet/encryptor_wrapper.h"
#include "sealnet/utilities.h"

// SEAL
#include "seal/encryptor.h"

using namespace std;
using namespace seal;
using namespace sealnet;

SEALNETNATIVE HRESULT SEALCALL Encryptor_Create(void *context, void *public_key, void **encryptor)
{
    SEALContext *contextptr = FromVoid<SEALContext>(context);
    IfNullRet(contextptr, E_POINTER);
    PublicKey *pkey = FromVoid<PublicKey>(public_key);
    IfNullRet(pkey, E_POINTER);
    const auto &sharedctx = SharedContextFromVoid(context);
    IfNullRet(sharedctx.get(), E_POINTER);

    try
    {
        Encryptor *enc = new Encryptor(sharedctx, *pkey);
        *encryptor = enc;
        return S_OK;
    }
    catch (const invalid_argument&)
    {
        return E_INVALIDARG;
    }
}

SEALNETNATIVE HRESULT SEALCALL Encryptor_Encrypt(void *thisptr, void *plaintext, void *destination, void *pool_handle)
{
    Encryptor *encryptor = FromVoid<Encryptor>(thisptr);
    IfNullRet(encryptor, E_POINTER);
    Plaintext *plain = FromVoid<Plaintext>(plaintext);
    IfNullRet(plain, E_POINTER);
    Ciphertext *cipher = FromVoid<Ciphertext>(destination);
    IfNullRet(cipher, E_POINTER);
    unique_ptr<MemoryPoolHandle> pool = MemHandleFromVoid(pool_handle);

    try
    {
        encryptor->encrypt(*plain, *cipher, *pool);
        return S_OK;
    }
    catch (const invalid_argument&)
    {
        return E_INVALIDARG;
    }
}

SEALNETNATIVE HRESULT SEALCALL Encryptor_Destroy(void *thisptr)
{
    Encryptor *encryptor = FromVoid<Encryptor>(thisptr);
    IfNullRet(encryptor, E_POINTER);

    delete encryptor;
    return S_OK;
}
