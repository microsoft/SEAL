// SEALDll
#include "stdafx.h"
#include "relinkeys.h"
#include "utilities.h"

// SEAL
#include "seal/relinkeys.h"

using namespace std;
using namespace seal;
using namespace seal::dll;


namespace seal
{
    struct RelinKeys::RelinKeysPrivateHelper
    {
        static void set_decomposition_bit_count(RelinKeys& keys, int value)
        {
            keys.decomposition_bit_count_ = value;
        }
    };
}


SEALDLL HRESULT SEALCALL RelinKeys_Create1(void** relin_keys)
{
    IfNullRet(relin_keys, E_POINTER);

    RelinKeys* keys = new RelinKeys();
    *relin_keys = keys;
    return S_OK;
}

SEALDLL HRESULT SEALCALL RelinKeys_Create2(void* copy, void** relin_keys)
{
    RelinKeys* copyptr = FromVoid<RelinKeys>(copy);
    IfNullRet(copyptr, E_POINTER);
    IfNullRet(relin_keys, E_POINTER);

    RelinKeys* keys = new RelinKeys(*copyptr);
    *relin_keys = keys;
    return S_OK;
}

SEALDLL HRESULT SEALCALL RelinKeys_Set(void* thisptr, void* copy)
{
    RelinKeys* keys = FromVoid<RelinKeys>(thisptr);
    IfNullRet(keys, E_POINTER);
    RelinKeys* copyptr = FromVoid<RelinKeys>(copy);
    IfNullRet(copyptr, E_POINTER);

    *keys = *copyptr;
    return S_OK;
}

SEALDLL HRESULT SEALCALL RelinKeys_Destroy(void* thisptr)
{
    RelinKeys* keys = FromVoid<RelinKeys>(thisptr);
    IfNullRet(keys, E_POINTER);

    delete keys;
    return S_OK;
}

SEALDLL HRESULT SEALCALL RelinKeys_Size(void* thisptr, int* size)
{
    RelinKeys* keys = FromVoid<RelinKeys>(thisptr);
    IfNullRet(keys, E_POINTER);
    IfNullRet(size, E_POINTER);

    *size = static_cast<int>(keys->size());
    return S_OK;
}

SEALDLL HRESULT SEALCALL RelinKeys_DBC(void* thisptr, int* dbc)
{
    RelinKeys* keys = FromVoid<RelinKeys>(thisptr);
    IfNullRet(keys, E_POINTER);
    IfNullRet(dbc, E_POINTER);

    *dbc = keys->decomposition_bit_count();
    return S_OK;
}

SEALDLL HRESULT SEALCALL RelinKeys_SetDBC(void* thisptr, int dbc)
{
    RelinKeys* keys = FromVoid<RelinKeys>(thisptr);
    IfNullRet(keys, E_POINTER);

    RelinKeys::RelinKeysPrivateHelper::set_decomposition_bit_count(*keys, dbc);
    return S_OK;
}

SEALDLL HRESULT SEALCALL RelinKeys_GetKeyList(void* thisptr, int index, int* count, void** ciphers)
{
    RelinKeys* keys = FromVoid<RelinKeys>(thisptr);
    IfNullRet(keys, E_POINTER);
    IfNullRet(count, E_POINTER);

    if (index < 0 || index >= keys->data().size())
    {
        return HRESULT_FROM_WIN32(ERROR_INVALID_INDEX);
    }

    auto list = keys->data()[index];

    *count = static_cast<int>(list.size());

    if (nullptr == ciphers)
    {
        // We only wanted the count.
        return S_OK;
    }

    auto ciphertexts = reinterpret_cast<Ciphertext**>(ciphers);
    for (int i = 0; i < list.size(); i++)
    {
        ciphertexts[i] = new Ciphertext(list[i]);
    }

    return S_OK;
}

SEALDLL HRESULT SEALCALL RelinKeys_HasKey(void* thisptr, int key_power, bool* has_key)
{
    RelinKeys* keys = FromVoid<RelinKeys>(thisptr);
    IfNullRet(keys, E_POINTER);
    IfNullRet(has_key, E_POINTER);

    *has_key = keys->has_key(key_power);
    return S_OK;
}

SEALDLL HRESULT SEALCALL RelinKeys_GetKey(void* thisptr, int key_power, int* count, void** ciphers)
{
    RelinKeys* keys = FromVoid<RelinKeys>(thisptr);
    IfNullRet(keys, E_POINTER);
    IfNullRet(count, E_POINTER);

    return RelinKeys_GetKeyList(thisptr, key_power - 2, count, ciphers);
}


SEALDLL HRESULT SEALCALL RelinKeys_ClearDataAndReserve(void* thisptr, int size)
{
    RelinKeys* keys = FromVoid<RelinKeys>(thisptr);
    IfNullRet(keys, E_POINTER);

    keys->data().clear();
    keys->data().reserve(size);
    return S_OK;
}

SEALDLL HRESULT SEALCALL RelinKeys_AddKeyList(void* thisptr, int count, void** ciphers)
{
    RelinKeys* keys = FromVoid<RelinKeys>(thisptr);
    IfNullRet(keys, E_POINTER);
    IfNullRet(ciphers, E_POINTER);

    Ciphertext** ciphertexts = reinterpret_cast<Ciphertext**>(ciphers);

    // Don't resize, only reserve
    keys->data().emplace_back();
    keys->data().back().reserve(count);

    for (int i = 0; i < count; i++)
    {
        Ciphertext* cipher = ciphertexts[i];
        Ciphertext new_key(keys->pool());
        new_key = *cipher;

        keys->data().back().emplace_back(move(new_key));
    }

    return S_OK;
}

SEALDLL HRESULT SEALCALL RelinKeys_GetParmsId(void* thisptr, uint64_t* parms_id)
{
    RelinKeys* keys = FromVoid<RelinKeys>(thisptr);
    IfNullRet(keys, E_POINTER);
    IfNullRet(parms_id, E_POINTER);

    for (int i = 0; i < keys->parms_id().size(); i++)
    {
        parms_id[i] = keys->parms_id()[i];
    }

    return S_OK;
}

SEALDLL HRESULT SEALCALL RelinKeys_SetParmsId(void* thisptr, uint64_t* parms_id)
{
    RelinKeys* keys = FromVoid<RelinKeys>(thisptr);
    IfNullRet(keys, E_POINTER);
    IfNullRet(parms_id, E_POINTER);

    CopyParmsId(parms_id, keys->parms_id());
    return S_OK;
}
