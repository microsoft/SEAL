// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

// SEALNet
#include "sealnet/stdafx.h"
#include "sealnet/galoiskeys_wrapper.h"
#include "sealnet/utilities.h"

// SEAL
#include "seal/galoiskeys.h"

using namespace std;
using namespace seal;
using namespace sealnet;

namespace seal
{
    struct GaloisKeys::GaloisKeysPrivateHelper
    {
        static void set_decomposition_bit_count(GaloisKeys &keys, int value)
        {
            keys.decomposition_bit_count_ = value;
        }
    };
}

namespace {
    HRESULT GetKeyFromVector(const vector<Ciphertext> &key, uint64_t *count, void **ciphers)
    {
        *count = key.size();

        if (nullptr == ciphers)
        {
            // We only wanted the count
            return S_OK;
        }

        auto ciphertexts = reinterpret_cast<Ciphertext**>(ciphers);
        for (size_t i = 0; i < key.size(); i++)
        {
            ciphertexts[i] = new Ciphertext(key[i]);
        }

        return S_OK;
    }
}

SEALNETNATIVE HRESULT SEALCALL GaloisKeys_Create1(void **galois_keys)
{
    IfNullRet(galois_keys, E_POINTER);
    GaloisKeys *keys = new GaloisKeys();
    *galois_keys = keys;
    return S_OK;
}

SEALNETNATIVE HRESULT SEALCALL GaloisKeys_Create2(void *copy, void **galois_keys)
{
    GaloisKeys *copyptr = FromVoid<GaloisKeys>(copy);
    IfNullRet(copyptr, E_POINTER);
    IfNullRet(galois_keys, E_POINTER);

    GaloisKeys *keys = new GaloisKeys(*copyptr);
    *galois_keys = keys;
    return S_OK;
}

SEALNETNATIVE HRESULT SEALCALL GaloisKeys_Destroy(void *thisptr)
{
    GaloisKeys *keys = FromVoid<GaloisKeys>(thisptr);
    IfNullRet(keys, E_POINTER);

    delete keys;
    return S_OK;
}

SEALNETNATIVE HRESULT SEALCALL GaloisKeys_Set(void *thisptr, void *assign)
{
    GaloisKeys *keys = FromVoid<GaloisKeys>(thisptr);
    IfNullRet(keys, E_POINTER);
    GaloisKeys *assignptr = FromVoid<GaloisKeys>(assign);
    IfNullRet(assignptr, E_POINTER);

    *keys = *assignptr;
    return S_OK;
}

SEALNETNATIVE HRESULT SEALCALL GaloisKeys_Size(void *thisptr, uint64_t *size)
{
    GaloisKeys *keys = FromVoid<GaloisKeys>(thisptr);
    IfNullRet(keys, E_POINTER);
    IfNullRet(size, E_POINTER);

    *size = keys->size();
    return S_OK;
}

SEALNETNATIVE HRESULT SEALCALL GaloisKeys_DBC(void *thisptr, int *dbc)
{
    GaloisKeys *keys = FromVoid<GaloisKeys>(thisptr);
    IfNullRet(keys, E_POINTER);
    IfNullRet(dbc, E_POINTER);

    *dbc = keys->decomposition_bit_count();
    return S_OK;
}

SEALNETNATIVE HRESULT SEALCALL GaloisKeys_SetDBC(void *thisptr, int dbc)
{
    GaloisKeys *keys = FromVoid<GaloisKeys>(thisptr);
    IfNullRet(keys, E_POINTER);

    GaloisKeys::GaloisKeysPrivateHelper::set_decomposition_bit_count(*keys, dbc);
    return S_OK;
}

SEALNETNATIVE HRESULT SEALCALL GaloisKeys_GetKeyCount(void *thisptr, uint64_t *key_count)
{
    GaloisKeys *keys = FromVoid<GaloisKeys>(thisptr);
    IfNullRet(keys, E_POINTER);
    IfNullRet(key_count, E_POINTER);

    *key_count = keys->data().size();
    return S_OK;
}

SEALNETNATIVE HRESULT SEALCALL GaloisKeys_GetKeyList(void *thisptr, uint64_t index, uint64_t *count, void **ciphers)
{
    GaloisKeys *keys = FromVoid<GaloisKeys>(thisptr);
    IfNullRet(keys, E_POINTER);
    IfNullRet(count, E_POINTER);

    auto list = keys->data()[index];
    return GetKeyFromVector(list, count, ciphers);
}

SEALNETNATIVE HRESULT SEALCALL GaloisKeys_GetKey(void *thisptr, uint64_t galois_elt, uint64_t *count, void **ciphers)
{
    GaloisKeys *keys = FromVoid<GaloisKeys>(thisptr);
    IfNullRet(keys, E_POINTER);
    IfNullRet(count, E_POINTER);

    if (!keys->has_key(galois_elt))
    {
        return E_INVALIDARG;
    }

    const auto &key = keys->key(galois_elt);
    return GetKeyFromVector(key, count, ciphers);
}

SEALNETNATIVE HRESULT SEALCALL GaloisKeys_ClearDataAndReserve(void *thisptr, uint64_t size)
{
    GaloisKeys *keys = FromVoid<GaloisKeys>(thisptr);
    IfNullRet(keys, E_POINTER);

    keys->data().clear();
    keys->data().reserve(size);
    return S_OK;
}

SEALNETNATIVE HRESULT SEALCALL GaloisKeys_AddKeyList(void *thisptr, uint64_t count, void **ciphers)
{
    GaloisKeys *keys = FromVoid<GaloisKeys>(thisptr);
    IfNullRet(keys, E_POINTER);
    IfNullRet(ciphers, E_POINTER);

    Ciphertext **ciphertexts = reinterpret_cast<Ciphertext**>(ciphers);

    // Don't resize, only reserve
    keys->data().emplace_back();
    keys->data().back().reserve(count);

    for (uint64_t i = 0; i < count; i++)
    {
        Ciphertext *cipher = ciphertexts[i];
        Ciphertext new_key(keys->pool());
        new_key = *cipher;

        keys->data().back().emplace_back(move(new_key));
    }

    return S_OK;
}

SEALNETNATIVE HRESULT SEALCALL GaloisKeys_HasKey(void *thisptr, uint64_t galois_elt, bool *has_key)
{
    GaloisKeys *keys = FromVoid<GaloisKeys>(thisptr);
    IfNullRet(keys, E_POINTER);
    IfNullRet(has_key, E_POINTER);

    try
    {
        *has_key = keys->has_key(galois_elt);
        return S_OK;
    }
    catch (const invalid_argument&)
    {
        return E_INVALIDARG;
    }
}

SEALNETNATIVE HRESULT SEALCALL GaloisKeys_GetParmsId(void *thisptr, uint64_t *parms_id)
{
    GaloisKeys *keys = FromVoid<GaloisKeys>(thisptr);
    IfNullRet(keys, E_POINTER);
    IfNullRet(parms_id, E_POINTER);

    for (size_t i = 0; i < keys->parms_id().size(); i++)
    {
        parms_id[i] = keys->parms_id()[i];
    }

    return S_OK;
}

SEALNETNATIVE HRESULT SEALCALL GaloisKeys_SetParmsId(void *thisptr, uint64_t *parms_id)
{
    GaloisKeys *keys = FromVoid<GaloisKeys>(thisptr);
    IfNullRet(keys, E_POINTER);
    IfNullRet(parms_id, E_POINTER);

    CopyParmsId(parms_id, keys->parms_id());
    return S_OK;
}

SEALNETNATIVE HRESULT SEALCALL GaloisKeys_IsValidFor(void *thisptr, void *contextptr, bool *result)
{
    GaloisKeys *keys = FromVoid<GaloisKeys>(thisptr);
    IfNullRet(keys, E_POINTER);
    const auto &sharedctx = SharedContextFromVoid(contextptr);
    IfNullRet(sharedctx.get(), E_POINTER);
    IfNullRet(result, E_POINTER);

    *result = keys->is_valid_for(sharedctx);
    return S_OK;
}

SEALNETNATIVE HRESULT SEALCALL GaloisKeys_IsMetadataValidFor(void *thisptr, void *contextptr, bool *result)
{
    GaloisKeys *keys = FromVoid<GaloisKeys>(thisptr);
    IfNullRet(keys, E_POINTER);
    const auto &sharedctx = SharedContextFromVoid(contextptr);
    IfNullRet(sharedctx.get(), E_POINTER);
    IfNullRet(result, E_POINTER);

    *result = keys->is_metadata_valid_for(sharedctx);
    return S_OK;
}

SEALNETNATIVE HRESULT SEALCALL GaloisKeys_Pool(void *thisptr, void **pool)
{
    GaloisKeys *keys = FromVoid<GaloisKeys>(thisptr);
    IfNullRet(keys, E_POINTER);
    IfNullRet(pool, E_POINTER);

    MemoryPoolHandle *handleptr = new MemoryPoolHandle(keys->pool());
    *pool = handleptr;
    return S_OK;
}
