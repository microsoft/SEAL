// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

// SEALNet
#include "seal/c/kswitchkeys.h"
#include "seal/c/stdafx.h"
#include "seal/c/utilities.h"

// SEAL
#include "seal/kswitchkeys.h"

using namespace std;
using namespace seal;
using namespace seal::c;

namespace
{
    HRESULT GetKeyFromVector(const vector<PublicKey> &key, uint64_t *count, void **key_list)
    {
        *count = key.size();

        if (nullptr == key_list)
        {
            // We only wanted the count
            return S_OK;
        }

        auto pkeys = reinterpret_cast<PublicKey **>(key_list);
        for (size_t i = 0; i < key.size(); i++)
        {
            pkeys[i] = new PublicKey(key[i]);
        }

        return S_OK;
    }
} // namespace

namespace seal
{
    struct PublicKey::PublicKeyPrivateHelper
    {
        inline static PublicKey Create(MemoryPoolHandle pool)
        {
            return PublicKey(pool);
        }
    };
} // namespace seal

SEAL_C_FUNC KSwitchKeys_Create1(void **kswitch_keys)
{
    IfNullRet(kswitch_keys, E_POINTER);
    KSwitchKeys *keys = new KSwitchKeys();
    *kswitch_keys = keys;
    return S_OK;
}

SEAL_C_FUNC KSwitchKeys_Create2(void *copy, void **kswitch_keys)
{
    KSwitchKeys *copyptr = FromVoid<KSwitchKeys>(copy);
    IfNullRet(copyptr, E_POINTER);
    IfNullRet(kswitch_keys, E_POINTER);

    KSwitchKeys *keys = new KSwitchKeys(*copyptr);
    *kswitch_keys = keys;
    return S_OK;
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

    *keys = *assignptr;
    return S_OK;
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

    auto key = keys->data()[index];
    return GetKeyFromVector(key, count, key_list);
}

SEAL_C_FUNC KSwitchKeys_ClearDataAndReserve(void *thisptr, uint64_t size)
{
    KSwitchKeys *keys = FromVoid<KSwitchKeys>(thisptr);
    IfNullRet(keys, E_POINTER);

    keys->data().clear();
    keys->data().reserve(size);
    return S_OK;
}

SEAL_C_FUNC KSwitchKeys_AddKeyList(void *thisptr, uint64_t count, void **key_list)
{
    KSwitchKeys *keys = FromVoid<KSwitchKeys>(thisptr);
    IfNullRet(keys, E_POINTER);
    IfNullRet(key_list, E_POINTER);

    PublicKey **key = reinterpret_cast<PublicKey **>(key_list);

    // Don't resize, only reserve
    keys->data().emplace_back();
    keys->data().back().reserve(count);

    for (uint64_t i = 0; i < count; i++)
    {
        PublicKey *pkey = key[i];
        PublicKey new_pkey(PublicKey::PublicKeyPrivateHelper::Create(keys->pool()));
        new_pkey = *pkey;

        keys->data().back().emplace_back(move(new_pkey));
    }

    return S_OK;
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

    MemoryPoolHandle *handleptr = new MemoryPoolHandle(keys->pool());
    *pool = handleptr;
    return S_OK;
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
    catch (const invalid_argument &)
    {
        return E_INVALIDARG;
    }
    catch (const logic_error &)
    {
        return COR_E_INVALIDOPERATION;
    }
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
            reinterpret_cast<SEAL_BYTE *>(outptr), util::safe_cast<size_t>(size),
            static_cast<compr_mode_type>(compr_mode)));
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
    catch (const runtime_error &)
    {
        return COR_E_IO;
    }
}

SEAL_C_FUNC KSwitchKeys_UnsafeLoad(void *thisptr, void *context, uint8_t *inptr, uint64_t size, int64_t *in_bytes)
{
    KSwitchKeys *keys = FromVoid<KSwitchKeys>(thisptr);
    IfNullRet(keys, E_POINTER);
    const auto &sharedctx = SharedContextFromVoid(context);
    IfNullRet(sharedctx.get(), E_POINTER);
    IfNullRet(inptr, E_POINTER);
    IfNullRet(in_bytes, E_POINTER);

    try
    {
        *in_bytes = util::safe_cast<int64_t>(
            keys->unsafe_load(sharedctx, reinterpret_cast<SEAL_BYTE *>(inptr), util::safe_cast<size_t>(size)));
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
    catch (const runtime_error &)
    {
        return COR_E_IO;
    }
}

SEAL_C_FUNC KSwitchKeys_Load(void *thisptr, void *context, uint8_t *inptr, uint64_t size, int64_t *in_bytes)
{
    KSwitchKeys *keys = FromVoid<KSwitchKeys>(thisptr);
    IfNullRet(keys, E_POINTER);
    const auto &sharedctx = SharedContextFromVoid(context);
    IfNullRet(sharedctx.get(), E_POINTER);
    IfNullRet(inptr, E_POINTER);
    IfNullRet(in_bytes, E_POINTER);

    try
    {
        *in_bytes = util::safe_cast<int64_t>(
            keys->load(sharedctx, reinterpret_cast<SEAL_BYTE *>(inptr), util::safe_cast<size_t>(size)));
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
    catch (const runtime_error &)
    {
        return COR_E_IO;
    }
}
