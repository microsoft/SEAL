// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

// SEALDll
#include "stdafx.h"
#include "keygenerator.h"
#include "utilities.h"

// SEAL
#include "seal/keygenerator.h"

using namespace std;
using namespace seal;
using namespace seal::dll;


SEALDLL HRESULT SEALCALL KeyGenerator_Create1(void* sealContext, void** key_generator)
{
    const auto& sharedctx = SharedContextFromVoid(sealContext);
    IfNullRet(sharedctx.get(), E_POINTER);
    IfNullRet(key_generator, E_POINTER);

    try
    {
        KeyGenerator* keygen = new KeyGenerator(sharedctx);
        *key_generator = keygen;
        return S_OK;
    }
    catch (const invalid_argument&)
    {
        return E_INVALIDARG;
    }
}

SEALDLL HRESULT SEALCALL KeyGenerator_Create2(void* sealContext, void* secret_key, void** key_generator)
{
    const auto& sharedctx = SharedContextFromVoid(sealContext);
    IfNullRet(sharedctx.get(), E_POINTER);
    SecretKey* secret_key_ptr = FromVoid<SecretKey>(secret_key);
    IfNullRet(secret_key_ptr, E_POINTER);
    IfNullRet(key_generator, E_POINTER);

    try
    {
        KeyGenerator* keygen = new KeyGenerator(sharedctx, *secret_key_ptr);
        *key_generator = keygen;
        return S_OK;
    }
    catch (const invalid_argument&)
    {
        return E_INVALIDARG;
    }
}

SEALDLL HRESULT SEALCALL KeyGenerator_Create3(void* sealContext, void* secret_key, void* public_key, void** key_generator)
{
    const auto& sharedctx = SharedContextFromVoid(sealContext);
    IfNullRet(sharedctx.get(), E_POINTER);
    SecretKey* secret_key_ptr = FromVoid<SecretKey>(secret_key);
    IfNullRet(secret_key_ptr, E_POINTER);
    PublicKey* public_key_ptr = FromVoid<PublicKey>(public_key);
    IfNullRet(public_key_ptr, E_POINTER);
    IfNullRet(key_generator, E_POINTER);

    try
    {
        KeyGenerator* keygen = new KeyGenerator(sharedctx, *secret_key_ptr, *public_key_ptr);
        *key_generator = keygen;
        return S_OK;
    }
    catch (const invalid_argument&)
    {
        return E_INVALIDARG;
    }
}


SEALDLL HRESULT SEALCALL KeyGenerator_Destroy(void* thisptr)
{
    KeyGenerator* keygen = FromVoid<KeyGenerator>(thisptr);
    IfNullRet(keygen, E_POINTER);

    delete keygen;
    return S_OK;
}

SEALDLL HRESULT SEALCALL KeyGenerator_RelinKeys(void* thisptr, int decompositionBitCount, int count, void** relin_keys)
{
    KeyGenerator* keygen = FromVoid<KeyGenerator>(thisptr);
    IfNullRet(keygen, E_POINTER);
    IfNullRet(relin_keys, E_POINTER);

    try
    {
        RelinKeys* relinKeys = new RelinKeys(keygen->relin_keys(decompositionBitCount, count));
        *relin_keys = relinKeys;
        return S_OK;
    }
    catch (const invalid_argument&)
    {
        return E_INVALIDARG;
    }
}

SEALDLL HRESULT SEALCALL KeyGenerator_GaloisKeys1(void* thisptr, int decompositionBitCount, void** galois_keys)
{
    KeyGenerator* keygen = FromVoid<KeyGenerator>(thisptr);
    IfNullRet(keygen, E_POINTER);
    IfNullRet(galois_keys, E_POINTER);

    try
    {
        GaloisKeys* keys = new GaloisKeys(keygen->galois_keys(decompositionBitCount));
        *galois_keys = keys;
        return S_OK;
    }
    catch (const invalid_argument&)
    {
        return E_INVALIDARG;
    }
}

SEALDLL HRESULT SEALCALL KeyGenerator_GaloisKeys2(void* thisptr, int decomposition_bit_count, int count, uint64_t* galois_elts, void** galois_keys)
{
    KeyGenerator* keygen = FromVoid<KeyGenerator>(thisptr);
    IfNullRet(keygen, E_POINTER);
    IfNullRet(galois_elts, E_POINTER);
    IfNullRet(galois_keys, E_POINTER);

    vector<uint64_t> galois_elts_vec(count);
    for (int i = 0; i < count; i++)
    {
        galois_elts_vec[i] = galois_elts[i];
    }

    try
    {
        GaloisKeys* keys = new GaloisKeys(keygen->galois_keys(decomposition_bit_count, galois_elts_vec));
        *galois_keys = keys;
        return S_OK;
    }
    catch (const invalid_argument&)
    {
        return E_INVALIDARG;
    }
}

SEALDLL HRESULT SEALCALL KeyGenerator_PublicKey(void* thisptr, void** public_key)
{
    KeyGenerator* keygen = FromVoid<KeyGenerator>(thisptr);
    IfNullRet(keygen, E_POINTER);
    IfNullRet(public_key, E_POINTER);

    // This returns an existing object, not a new object.
    // Make sure the managed side does not try to delete it.
    const PublicKey* pubKey = &keygen->public_key();
    *public_key = const_cast<PublicKey*>(pubKey);
    return S_OK;
}

SEALDLL HRESULT SEALCALL KeyGenerator_SecretKey(void* thisptr, void** secret_key)
{
    KeyGenerator* keygen = FromVoid<KeyGenerator>(thisptr);
    IfNullRet(keygen, E_POINTER);
    IfNullRet(secret_key, E_POINTER);

    // This returns an existing object, not a new object.
    // Make sure the managed side does not try to delete it.
    const SecretKey* secretKey = &keygen->secret_key();
    *secret_key = const_cast<SecretKey*>(secretKey);
    return S_OK;
}
