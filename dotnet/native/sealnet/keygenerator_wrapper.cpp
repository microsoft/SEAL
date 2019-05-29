// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

// STD
#include <algorithm>
#include <iterator>

// SEALNet
#include "sealnet/stdafx.h"
#include "sealnet/keygenerator_wrapper.h"
#include "sealnet/utilities.h"

// SEAL
#include "seal/keygenerator.h"
#include "seal/util/common.h"

using namespace std;
using namespace seal;
using namespace sealnet;
using namespace seal::util;

SEALNETNATIVE HRESULT SEALCALL KeyGenerator_Create1(void *sealContext, void **key_generator)
{
    const auto &sharedctx = SharedContextFromVoid(sealContext);
    IfNullRet(sharedctx.get(), E_POINTER);
    IfNullRet(key_generator, E_POINTER);

    try
    {
        KeyGenerator *keygen = new KeyGenerator(sharedctx);
        *key_generator = keygen;
        return S_OK;
    }
    catch (const invalid_argument&)
    {
        return E_INVALIDARG;
    }
}

SEALNETNATIVE HRESULT SEALCALL KeyGenerator_Create2(void *sealContext, void *secret_key, void **key_generator)
{
    const auto &sharedctx = SharedContextFromVoid(sealContext);
    IfNullRet(sharedctx.get(), E_POINTER);
    SecretKey *secret_key_ptr = FromVoid<SecretKey>(secret_key);
    IfNullRet(secret_key_ptr, E_POINTER);
    IfNullRet(key_generator, E_POINTER);

    try
    {
        KeyGenerator *keygen = new KeyGenerator(sharedctx, *secret_key_ptr);
        *key_generator = keygen;
        return S_OK;
    }
    catch (const invalid_argument&)
    {
        return E_INVALIDARG;
    }
}

SEALNETNATIVE HRESULT SEALCALL KeyGenerator_Create3(void *sealContext, void *secret_key, void *public_key, void **key_generator)
{
    const auto &sharedctx = SharedContextFromVoid(sealContext);
    IfNullRet(sharedctx.get(), E_POINTER);
    SecretKey *secret_key_ptr = FromVoid<SecretKey>(secret_key);
    IfNullRet(secret_key_ptr, E_POINTER);
    PublicKey *public_key_ptr = FromVoid<PublicKey>(public_key);
    IfNullRet(public_key_ptr, E_POINTER);
    IfNullRet(key_generator, E_POINTER);

    try
    {
        KeyGenerator *keygen = new KeyGenerator(sharedctx, *secret_key_ptr, *public_key_ptr);
        *key_generator = keygen;
        return S_OK;
    }
    catch (const invalid_argument&)
    {
        return E_INVALIDARG;
    }
}

SEALNETNATIVE HRESULT SEALCALL KeyGenerator_Destroy(void *thisptr)
{
    KeyGenerator *keygen = FromVoid<KeyGenerator>(thisptr);
    IfNullRet(keygen, E_POINTER);

    delete keygen;
    return S_OK;
}

SEALNETNATIVE HRESULT SEALCALL KeyGenerator_RelinKeys(void *thisptr, void **relin_keys)
{
    KeyGenerator *keygen = FromVoid<KeyGenerator>(thisptr);
    IfNullRet(keygen, E_POINTER);
    IfNullRet(relin_keys, E_POINTER);

    try
    {
        RelinKeys *relinKeys = new RelinKeys(keygen->relin_keys());
        *relin_keys = relinKeys;
        return S_OK;
    }
    catch (const invalid_argument&)
    {
        return E_INVALIDARG;
    }
}

SEALNETNATIVE HRESULT SEALCALL KeyGenerator_GaloisKeys1(void *thisptr, void **galois_keys)
{
    KeyGenerator *keygen = FromVoid<KeyGenerator>(thisptr);
    IfNullRet(keygen, E_POINTER);
    IfNullRet(galois_keys, E_POINTER);

    try
    {
        GaloisKeys *keys = new GaloisKeys(keygen->galois_keys());
        *galois_keys = keys;
        return S_OK;
    }
    catch (const invalid_argument&)
    {
        return E_INVALIDARG;
    }
}

SEALNETNATIVE HRESULT SEALCALL KeyGenerator_GaloisKeys2(void *thisptr, uint64_t count, uint64_t *galois_elts, void **galois_keys)
{
    KeyGenerator *keygen = FromVoid<KeyGenerator>(thisptr);
    IfNullRet(keygen, E_POINTER);
    IfNullRet(galois_elts, E_POINTER);
    IfNullRet(galois_keys, E_POINTER);

    vector<uint64_t> galois_elts_vec;
    copy_n(galois_elts, count, back_inserter(galois_elts_vec));

    try
    {
        GaloisKeys *keys = new GaloisKeys(keygen->galois_keys(galois_elts_vec));
        *galois_keys = keys;
        return S_OK;
    }
    catch (const invalid_argument&)
    {
        return E_INVALIDARG;
    }
}

SEALNETNATIVE HRESULT SEALCALL KeyGenerator_GaloisKeys3(void *thisptr, uint64_t count, int *steps, void **galois_keys)
{
    KeyGenerator *keygen = FromVoid<KeyGenerator>(thisptr);
    IfNullRet(keygen, E_POINTER);
    IfNullRet(steps, E_POINTER);
    IfNullRet(galois_keys, E_POINTER);

    vector<int> steps_vec;
    copy_n(steps, count, back_inserter(steps_vec));

    try
    {
        GaloisKeys *keys = new GaloisKeys(keygen->galois_keys(steps_vec));
        *galois_keys = keys;
        return S_OK;
    }
    catch (const invalid_argument&)
    {
        return E_INVALIDARG;
    }
    catch (const logic_error&)
    {
        return HRESULT_FROM_WIN32(ERROR_INVALID_OPERATION);
    }
}

SEALNETNATIVE HRESULT SEALCALL KeyGenerator_PublicKey(void *thisptr, void **public_key)
{
    KeyGenerator *keygen = FromVoid<KeyGenerator>(thisptr);
    IfNullRet(keygen, E_POINTER);
    IfNullRet(public_key, E_POINTER);

    PublicKey *key = new PublicKey(keygen->public_key());
    *public_key = key;
    return S_OK;
}

SEALNETNATIVE HRESULT SEALCALL KeyGenerator_SecretKey(void *thisptr, void **secret_key)
{
    KeyGenerator *keygen = FromVoid<KeyGenerator>(thisptr);
    IfNullRet(keygen, E_POINTER);
    IfNullRet(secret_key, E_POINTER);

    SecretKey *key = new SecretKey(keygen->secret_key());
    *secret_key = key;
    return S_OK;
}