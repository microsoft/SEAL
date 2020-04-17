// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

// STD
#include <algorithm>
#include <iterator>

// SEALNet
#include "seal/c/keygenerator.h"
#include "seal/c/stdafx.h"
#include "seal/c/utilities.h"

// SEAL
#include "seal/keygenerator.h"
#include "seal/util/common.h"

using namespace std;
using namespace seal;
using namespace seal::c;
using namespace seal::util;

struct seal::KeyGenerator::KeyGeneratorPrivateHelper
{
    static RelinKeys relin_keys(KeyGenerator *keygen, bool save_seed)
    {
        return keygen->relin_keys(size_t(1), save_seed);
    }

    static GaloisKeys galois_keys(KeyGenerator *keygen, const vector<uint32_t> &galois_elts, bool save_seed)
    {
        return keygen->galois_keys(galois_elts, save_seed);
    }

    static const GaloisTool *galois_tool(KeyGenerator *keygen)
    {
        return keygen->context_->key_context_data()->galois_tool();
    }

    static bool using_keyswitching(const KeyGenerator &keygen)
    {
        return keygen.context_->using_keyswitching();
    }
};

SEAL_C_FUNC KeyGenerator_Create1(void *sealContext, void **key_generator)
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
    catch (const invalid_argument &)
    {
        return E_INVALIDARG;
    }
}

SEAL_C_FUNC KeyGenerator_Create2(void *sealContext, void *secret_key, void **key_generator)
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
    catch (const invalid_argument &)
    {
        return E_INVALIDARG;
    }
}

SEAL_C_FUNC KeyGenerator_Destroy(void *thisptr)
{
    KeyGenerator *keygen = FromVoid<KeyGenerator>(thisptr);
    IfNullRet(keygen, E_POINTER);

    delete keygen;
    return S_OK;
}

SEAL_C_FUNC KeyGenerator_RelinKeys(void *thisptr, bool save_seed, void **relin_keys)
{
    KeyGenerator *keygen = FromVoid<KeyGenerator>(thisptr);
    IfNullRet(keygen, E_POINTER);
    IfNullRet(relin_keys, E_POINTER);

    try
    {
        RelinKeys *relinKeys = new RelinKeys(KeyGenerator::KeyGeneratorPrivateHelper::relin_keys(keygen, save_seed));
        *relin_keys = relinKeys;
        return S_OK;
    }
    catch (const invalid_argument &)
    {
        return E_INVALIDARG;
    }
    catch (const logic_error &)
    {
        return COR_E_INVALIDOPERATION;
    }
}

SEAL_C_FUNC KeyGenerator_GaloisKeysFromElts(
    void *thisptr, uint64_t count, uint32_t *galois_elts, bool save_seed, void **galois_keys)
{
    KeyGenerator *keygen = FromVoid<KeyGenerator>(thisptr);
    IfNullRet(keygen, E_POINTER);
    IfNullRet(galois_elts, E_POINTER);
    IfNullRet(galois_keys, E_POINTER);

    vector<uint32_t> galois_elts_vec;
    copy_n(galois_elts, count, back_inserter(galois_elts_vec));

    try
    {
        GaloisKeys *keys =
            new GaloisKeys(KeyGenerator::KeyGeneratorPrivateHelper::galois_keys(keygen, galois_elts_vec, save_seed));
        *galois_keys = keys;
        return S_OK;
    }
    catch (const invalid_argument &)
    {
        return E_INVALIDARG;
    }
    catch (const logic_error &)
    {
        return COR_E_INVALIDOPERATION;
    }
}

SEAL_C_FUNC KeyGenerator_GaloisKeysFromSteps(
    void *thisptr, uint64_t count, int *steps, bool save_seed, void **galois_keys)
{
    KeyGenerator *keygen = FromVoid<KeyGenerator>(thisptr);
    IfNullRet(keygen, E_POINTER);
    IfNullRet(steps, E_POINTER);
    IfNullRet(galois_keys, E_POINTER);

    vector<int> steps_vec;
    copy_n(steps, count, back_inserter(steps_vec));
    vector<uint32_t> galois_elts_vec;

    try
    {
        galois_elts_vec = KeyGenerator::KeyGeneratorPrivateHelper::galois_tool(keygen)->get_elts_from_steps(steps_vec);
        GaloisKeys *keys =
            new GaloisKeys(KeyGenerator::KeyGeneratorPrivateHelper::galois_keys(keygen, galois_elts_vec, save_seed));
        *galois_keys = keys;
        return S_OK;
    }
    catch (const invalid_argument &)
    {
        return E_INVALIDARG;
    }
    catch (const logic_error &)
    {
        return COR_E_INVALIDOPERATION;
    }
}

SEAL_C_FUNC KeyGenerator_GaloisKeysAll(void *thisptr, bool save_seed, void **galois_keys)
{
    KeyGenerator *keygen = FromVoid<KeyGenerator>(thisptr);
    IfNullRet(keygen, E_POINTER);
    IfNullRet(galois_keys, E_POINTER);

    vector<uint32_t> galois_elts_vec = KeyGenerator::KeyGeneratorPrivateHelper::galois_tool(keygen)->get_elts_all();

    try
    {
        GaloisKeys *keys =
            new GaloisKeys(KeyGenerator::KeyGeneratorPrivateHelper::galois_keys(keygen, galois_elts_vec, save_seed));
        *galois_keys = keys;
        return S_OK;
    }
    catch (const invalid_argument &)
    {
        return E_INVALIDARG;
    }
    catch (const logic_error &)
    {
        return COR_E_INVALIDOPERATION;
    }
}

SEAL_C_FUNC KeyGenerator_PublicKey(void *thisptr, void **public_key)
{
    KeyGenerator *keygen = FromVoid<KeyGenerator>(thisptr);
    IfNullRet(keygen, E_POINTER);
    IfNullRet(public_key, E_POINTER);

    PublicKey *key = new PublicKey(keygen->public_key());
    *public_key = key;
    return S_OK;
}

SEAL_C_FUNC KeyGenerator_SecretKey(void *thisptr, void **secret_key)
{
    KeyGenerator *keygen = FromVoid<KeyGenerator>(thisptr);
    IfNullRet(keygen, E_POINTER);
    IfNullRet(secret_key, E_POINTER);

    SecretKey *key = new SecretKey(keygen->secret_key());
    *secret_key = key;
    return S_OK;
}

SEAL_C_FUNC KeyGenerator_ContextUsingKeyswitching(void *thisptr, bool *using_keyswitching)
{
    KeyGenerator *keygen = FromVoid<KeyGenerator>(thisptr);
    IfNullRet(keygen, E_POINTER);
    IfNullRet(using_keyswitching, E_POINTER);

    *using_keyswitching = KeyGenerator::KeyGeneratorPrivateHelper::using_keyswitching(*keygen);
    return S_OK;
}
