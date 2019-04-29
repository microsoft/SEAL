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

SEALNETNATIVE HRESULT SEALCALL Encryptor_EncryptZero1(void *thisptr, uint64_t *parms_id, void *destination, void *pool_handle)
{
    Encryptor *encryptor = FromVoid<Encryptor>(thisptr);
    IfNullRet(encryptor, E_POINTER);
    IfNullRet(parms_id, E_POINTER);
    Ciphertext *cipher = FromVoid<Ciphertext>(destination);
    IfNullRet(cipher, E_POINTER);
    unique_ptr<MemoryPoolHandle> pool = MemHandleFromVoid(pool_handle);

    parms_id_type parms;
    CopyParmsId(parms_id, parms);

    try
    {
        encryptor->encrypt_zero(parms, *cipher, *pool);
        return S_OK;
    }
    catch (const invalid_argument&)
    {
        return E_INVALIDARG;
    }
}

SEALNETNATIVE HRESULT SEALCALL Encryptor_EncryptZero2(void *thisptr, void *destination, void *pool_handle)
{
    Encryptor *encryptor = FromVoid<Encryptor>(thisptr);
    IfNullRet(encryptor, E_POINTER);
    Ciphertext *cipher = FromVoid<Ciphertext>(destination);
    IfNullRet(cipher, E_POINTER);
    unique_ptr<MemoryPoolHandle> pool = MemHandleFromVoid(pool_handle);

    try
    {
        encryptor->encrypt_zero(*cipher, *pool);
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
