// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

// SEALNet
#include "seal/c/publickey.h"
#include "seal/c/stdafx.h"
#include "seal/c/utilities.h"

// SEAL
#include "seal/publickey.h"

using namespace std;
using namespace seal;
using namespace seal::c;

SEAL_C_FUNC PublicKey_Create1(void **public_key)
{
    IfNullRet(public_key, E_POINTER);

    PublicKey *pkey = new PublicKey();
    *public_key = pkey;
    return S_OK;
}

SEAL_C_FUNC PublicKey_Create2(void *copy, void **public_key)
{
    PublicKey *copyptr = FromVoid<PublicKey>(copy);
    IfNullRet(copyptr, E_POINTER);
    IfNullRet(public_key, E_POINTER);

    PublicKey *pkey = new PublicKey(*copyptr);
    *public_key = pkey;
    return S_OK;
}

SEAL_C_FUNC PublicKey_Set(void *thisptr, void *assign)
{
    PublicKey *pkey = FromVoid<PublicKey>(thisptr);
    IfNullRet(pkey, E_POINTER);
    PublicKey *assignptr = FromVoid<PublicKey>(assign);
    IfNullRet(assignptr, E_POINTER);

    *pkey = *assignptr;
    return S_OK;
}

SEAL_C_FUNC PublicKey_Data(void *thisptr, void **data)
{
    PublicKey *pkey = FromVoid<PublicKey>(thisptr);
    IfNullRet(pkey, E_POINTER);
    IfNullRet(data, E_POINTER);

    // This returns a pointer to an existing object, not a new object.
    // Make sure the managed side does not try to delete it.
    Ciphertext *cipher = &pkey->data();
    *data = cipher;
    return S_OK;
}

SEAL_C_FUNC PublicKey_ParmsId(void *thisptr, uint64_t *parms_id)
{
    PublicKey *pkey = FromVoid<PublicKey>(thisptr);
    IfNullRet(pkey, E_POINTER);
    IfNullRet(parms_id, E_POINTER);

    CopyParmsId(pkey->parms_id(), parms_id);
    return S_OK;
}

SEAL_C_FUNC PublicKey_Pool(void *thisptr, void **pool)
{
    PublicKey *pkey = FromVoid<PublicKey>(thisptr);
    IfNullRet(pkey, E_POINTER);
    IfNullRet(pool, E_POINTER);

    MemoryPoolHandle *handleptr = new MemoryPoolHandle(pkey->pool());
    *pool = handleptr;
    return S_OK;
}

SEAL_C_FUNC PublicKey_Destroy(void *thisptr)
{
    PublicKey *pkey = FromVoid<PublicKey>(thisptr);
    IfNullRet(pkey, E_POINTER);

    delete pkey;
    return S_OK;
}

SEAL_C_FUNC PublicKey_SaveSize(void *thisptr, uint8_t compr_mode, int64_t *result)
{
    PublicKey *pkey = FromVoid<PublicKey>(thisptr);
    IfNullRet(pkey, E_POINTER);
    IfNullRet(result, E_POINTER);

    try
    {
        *result = static_cast<int64_t>(pkey->save_size(static_cast<compr_mode_type>(compr_mode)));
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

SEAL_C_FUNC PublicKey_Save(void *thisptr, uint8_t *outptr, uint64_t size, uint8_t compr_mode, int64_t *out_bytes)
{
    PublicKey *pkey = FromVoid<PublicKey>(thisptr);
    IfNullRet(pkey, E_POINTER);
    IfNullRet(outptr, E_POINTER);
    IfNullRet(out_bytes, E_POINTER);

    try
    {
        *out_bytes = util::safe_cast<int64_t>(pkey->save(
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

SEAL_C_FUNC PublicKey_UnsafeLoad(void *thisptr, void *context, uint8_t *inptr, uint64_t size, int64_t *in_bytes)
{
    PublicKey *pkey = FromVoid<PublicKey>(thisptr);
    IfNullRet(pkey, E_POINTER);
    const auto &sharedctx = SharedContextFromVoid(context);
    IfNullRet(sharedctx.get(), E_POINTER);
    IfNullRet(inptr, E_POINTER);
    IfNullRet(in_bytes, E_POINTER);

    try
    {
        *in_bytes = util::safe_cast<int64_t>(
            pkey->unsafe_load(sharedctx, reinterpret_cast<SEAL_BYTE *>(inptr), util::safe_cast<size_t>(size)));
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

SEAL_C_FUNC PublicKey_Load(void *thisptr, void *context, uint8_t *inptr, uint64_t size, int64_t *in_bytes)
{
    PublicKey *pkey = FromVoid<PublicKey>(thisptr);
    IfNullRet(pkey, E_POINTER);
    const auto &sharedctx = SharedContextFromVoid(context);
    IfNullRet(sharedctx.get(), E_POINTER);
    IfNullRet(inptr, E_POINTER);
    IfNullRet(in_bytes, E_POINTER);

    try
    {
        *in_bytes = util::safe_cast<int64_t>(
            pkey->load(sharedctx, reinterpret_cast<SEAL_BYTE *>(inptr), util::safe_cast<size_t>(size)));
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
