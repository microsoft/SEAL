// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

// SEALNet
#include "seal/c/kswitchkeys.h"
#include "seal/c/utilities.h"

// SEAL
#include "seal/kswitchkeys.h"

using namespace std;
using namespace seal;
using namespace seal::c;

namespace
{
    HRESULT GetKeyFromVector(const vector<PublicKey> &keys, uint64_t *count, void **key_list)
    {
        uint64_t required = static_cast<uint64_t>(keys.size());
        HRESULT result = PrepareOutputBuffer(required, count, key_list);
        if (result != S_OK || nullptr == key_list)
        {
            return result;
        }

        vector<unique_ptr<PublicKey>> key_copies;
        key_copies.reserve(keys.size());
        transform(keys.cbegin(), keys.cend(), back_inserter(key_copies), [](const auto &key) {
            return make_unique<PublicKey>(key);
        });

        auto pkeys = reinterpret_cast<PublicKey **>(key_list);
        transform(key_copies.begin(), key_copies.end(), pkeys, [](auto &key) { return key.release(); });
        return S_OK;
    }
} // namespace

// Enables access to private members of seal::PublicKey.
using ph = struct PublicKey::PublicKeyPrivateHelper
{
    inline static PublicKey Create(MemoryPoolHandle pool)
    {
        return PublicKey(pool);
    }
};

SEAL_C_FUNC KSwitchKeys_Create1(void **kswitch_keys)
{
    IfNullRet(kswitch_keys, E_POINTER);

    try
    {
        KSwitchKeys *keys = new KSwitchKeys();
        *kswitch_keys = keys;
        return S_OK;
    }
    SEAL_C_CATCH_ALL
}

SEAL_C_FUNC KSwitchKeys_Create2(void *copy, void **kswitch_keys)
{
    KSwitchKeys *copyptr = FromVoid<KSwitchKeys>(copy);
    IfNullRet(copyptr, E_POINTER);
    IfNullRet(kswitch_keys, E_POINTER);

    try
    {
        KSwitchKeys *keys = new KSwitchKeys(*copyptr);
        *kswitch_keys = keys;
        return S_OK;
    }
    SEAL_C_CATCH_ALL
}

SEAL_C_FUNC KSwitchKeys_Destroy(void *thisptr)
{
    KSwitchKeys *keys = FromVoid<KSwitchKeys>(thisptr);
    IfNullRet(keys, E_POINTER);

    delete keys;
    return S_OK;
}

SEAL_C_FUNC KSwitchKeys_Set(void *thisptr, void *assign)
{
    KSwitchKeys *keys = FromVoid<KSwitchKeys>(thisptr);
    IfNullRet(keys, E_POINTER);
    KSwitchKeys *assignptr = FromVoid<KSwitchKeys>(assign);
    IfNullRet(assignptr, E_POINTER);

    try
    {
        *keys = *assignptr;
        return S_OK;
    }
    SEAL_C_CATCH_ALL
}

SEAL_C_FUNC KSwitchKeys_Size(void *thisptr, uint64_t *size)
{
    KSwitchKeys *keys = FromVoid<KSwitchKeys>(thisptr);
    IfNullRet(keys, E_POINTER);
    IfNullRet(size, E_POINTER);

    *size = keys->size();
    return S_OK;
}

SEAL_C_FUNC KSwitchKeys_RawSize(void *thisptr, uint64_t *size)
{
    KSwitchKeys *keys = FromVoid<KSwitchKeys>(thisptr);
    IfNullRet(keys, E_POINTER);
    IfNullRet(size, E_POINTER);

    *size = keys->data().size();
    return S_OK;
}

SEAL_C_FUNC KSwitchKeys_GetKeyList(void *thisptr, uint64_t index, uint64_t *count, void **key_list)
{
    KSwitchKeys *keys = FromVoid<KSwitchKeys>(thisptr);
    IfNullRet(keys, E_POINTER);
    IfNullRet(count, E_POINTER);

    try
    {
        if (index >= keys->data().size())
        {
            return HRESULT_FROM_WIN32(ERROR_INVALID_INDEX);
        }

        const auto &key = keys->data()[static_cast<size_t>(index)];
        return GetKeyFromVector(key, count, key_list);
    }
    SEAL_C_CATCH_ALL
}

SEAL_C_FUNC KSwitchKeys_ClearDataAndReserve(void *thisptr, uint64_t size)
{
    KSwitchKeys *keys = FromVoid<KSwitchKeys>(thisptr);
    IfNullRet(keys, E_POINTER);

    try
    {
        keys->data().clear();
        keys->data().reserve(size);
        return S_OK;
    }
    SEAL_C_CATCH_ALL
}

SEAL_C_FUNC KSwitchKeys_AddKeyList(void *thisptr, uint64_t count, void **key_list)
{
    KSwitchKeys *keys = FromVoid<KSwitchKeys>(thisptr);
    IfNullRet(keys, E_POINTER);
    IfNullRet(key_list, E_POINTER);

    try
    {
        PublicKey **key = reinterpret_cast<PublicKey **>(key_list);

        // Don't resize, only reserve
        keys->data().emplace_back();
        keys->data().back().reserve(count);

        for (uint64_t i = 0; i < count; i++)
        {
            PublicKey *pkey = key[i];
            PublicKey new_pkey(ph::Create(keys->pool()));
            new_pkey = *pkey;

            keys->data().back().emplace_back(std::move(new_pkey));
        }

        return S_OK;
    }
    SEAL_C_CATCH_ALL
}

SEAL_C_FUNC KSwitchKeys_GetParmsId(void *thisptr, uint64_t *parms_id)
{
    KSwitchKeys *keys = FromVoid<KSwitchKeys>(thisptr);
    IfNullRet(keys, E_POINTER);
    IfNullRet(parms_id, E_POINTER);

    for (size_t i = 0; i < keys->parms_id().size(); i++)
    {
        parms_id[i] = keys->parms_id()[i];
    }

    return S_OK;
}

SEAL_C_FUNC KSwitchKeys_SetParmsId(void *thisptr, uint64_t *parms_id)
{
    KSwitchKeys *keys = FromVoid<KSwitchKeys>(thisptr);
    IfNullRet(keys, E_POINTER);
    IfNullRet(parms_id, E_POINTER);

    CopyParmsId(parms_id, keys->parms_id());
    return S_OK;
}

SEAL_C_FUNC KSwitchKeys_Pool(void *thisptr, void **pool)
{
    KSwitchKeys *keys = FromVoid<KSwitchKeys>(thisptr);
    IfNullRet(keys, E_POINTER);
    IfNullRet(pool, E_POINTER);

    try
    {
        MemoryPoolHandle *handleptr = new MemoryPoolHandle(keys->pool());
        *pool = handleptr;
        return S_OK;
    }
    SEAL_C_CATCH_ALL
}

SEAL_C_FUNC KSwitchKeys_SaveSize(void *thisptr, uint8_t compr_mode, int64_t *result)
{
    KSwitchKeys *keys = FromVoid<KSwitchKeys>(thisptr);
    IfNullRet(keys, E_POINTER);
    IfNullRet(result, E_POINTER);

    try
    {
        *result = static_cast<int64_t>(keys->save_size(static_cast<compr_mode_type>(compr_mode)));
        return S_OK;
    }
    SEAL_C_CATCH_ALL
}

SEAL_C_FUNC KSwitchKeys_Save(void *thisptr, uint8_t *outptr, uint64_t size, uint8_t compr_mode, int64_t *out_bytes)
{
    KSwitchKeys *keys = FromVoid<KSwitchKeys>(thisptr);
    IfNullRet(keys, E_POINTER);
    IfNullRet(outptr, E_POINTER);
    IfNullRet(out_bytes, E_POINTER);

    try
    {
        *out_bytes = util::safe_cast<int64_t>(keys->save(
            reinterpret_cast<seal_byte *>(outptr), util::safe_cast<size_t>(size),
            static_cast<compr_mode_type>(compr_mode)));
        return S_OK;
    }
    SEAL_C_CATCH_ALL
}

SEAL_C_FUNC KSwitchKeys_UnsafeLoad(void *thisptr, void *context, uint8_t *inptr, uint64_t size, int64_t *in_bytes)
{
    const SEALContext *ctx = FromVoid<SEALContext>(context);
    IfNullRet(ctx, E_POINTER);
    KSwitchKeys *keys = FromVoid<KSwitchKeys>(thisptr);
    IfNullRet(keys, E_POINTER);
    IfNullRet(inptr, E_POINTER);
    IfNullRet(in_bytes, E_POINTER);

    try
    {
        *in_bytes = util::safe_cast<int64_t>(
            keys->unsafe_load(*ctx, reinterpret_cast<seal_byte *>(inptr), util::safe_cast<size_t>(size)));
        return S_OK;
    }
    SEAL_C_CATCH_ALL
}

SEAL_C_FUNC KSwitchKeys_Load(void *thisptr, void *context, uint8_t *inptr, uint64_t size, int64_t *in_bytes)
{
    const SEALContext *ctx = FromVoid<SEALContext>(context);
    IfNullRet(ctx, E_POINTER);
    KSwitchKeys *keys = FromVoid<KSwitchKeys>(thisptr);
    IfNullRet(keys, E_POINTER);
    IfNullRet(inptr, E_POINTER);
    IfNullRet(in_bytes, E_POINTER);

    try
    {
        *in_bytes = util::safe_cast<int64_t>(
            keys->load(*ctx, reinterpret_cast<seal_byte *>(inptr), util::safe_cast<size_t>(size)));
        return S_OK;
    }
    SEAL_C_CATCH_ALL
}
