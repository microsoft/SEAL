// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

// STD
#include <vector>

// SEALNet
#include "seal/c/batchencoder.h"
#include "seal/c/stdafx.h"
#include "seal/c/utilities.h"

// SEAL
#include "seal/batchencoder.h"

using namespace std;
using namespace seal;
using namespace seal::c;

SEAL_C_FUNC BatchEncoder_Create(void *context, void **batch_encoder)
{
    const auto &sharedctx = SharedContextFromVoid(context);
    IfNullRet(sharedctx, E_POINTER);
    IfNullRet(batch_encoder, E_POINTER);

    try
    {
        BatchEncoder *encoder = new BatchEncoder(sharedctx);
        *batch_encoder = encoder;
        return S_OK;
    }
    catch (const invalid_argument &)
    {
        return E_INVALIDARG;
    }
}

SEAL_C_FUNC BatchEncoder_Destroy(void *thisptr)
{
    BatchEncoder *encoder = FromVoid<BatchEncoder>(thisptr);
    IfNullRet(encoder, E_POINTER);

    delete encoder;
    return S_OK;
}

SEAL_C_FUNC BatchEncoder_Encode1(void *thisptr, uint64_t count, uint64_t *values, void *destination)
{
    BatchEncoder *encoder = FromVoid<BatchEncoder>(thisptr);
    IfNullRet(encoder, E_POINTER);
    IfNullRet(values, E_POINTER);
    Plaintext *plain = FromVoid<Plaintext>(destination);
    IfNullRet(plain, E_POINTER);

    vector<uint64_t> valvec(count);
    for (uint64_t i = 0; i < count; i++)
    {
        valvec[i] = values[i];
    }

    try
    {
        encoder->encode(valvec, *plain);
        return S_OK;
    }
    catch (const invalid_argument &)
    {
        return E_INVALIDARG;
    }
}

SEAL_C_FUNC BatchEncoder_Encode2(void *thisptr, uint64_t count, int64_t *values, void *destination)
{
    BatchEncoder *encoder = FromVoid<BatchEncoder>(thisptr);
    IfNullRet(encoder, E_POINTER);
    IfNullRet(values, E_POINTER);
    Plaintext *plain = FromVoid<Plaintext>(destination);
    IfNullRet(plain, E_POINTER);

    vector<int64_t> valvec(count);
    for (uint64_t i = 0; i < count; i++)
    {
        valvec[i] = values[i];
    }

    try
    {
        encoder->encode(valvec, *plain);
        return S_OK;
    }
    catch (const invalid_argument &)
    {
        return E_INVALIDARG;
    }
}

SEAL_C_FUNC BatchEncoder_Encode3(void *thisptr, void *plain, void *pool)
{
    BatchEncoder *encoder = FromVoid<BatchEncoder>(thisptr);
    IfNullRet(encoder, E_POINTER);
    Plaintext *plainptr = FromVoid<Plaintext>(plain);
    IfNullRet(plainptr, E_POINTER);
    unique_ptr<MemoryPoolHandle> handle = MemHandleFromVoid(pool);

    try
    {
        encoder->encode(*plainptr, *handle);
        return S_OK;
    }
    catch (const invalid_argument &)
    {
        return E_INVALIDARG;
    }
}

SEAL_C_FUNC BatchEncoder_Decode1(void *thisptr, void *plain, uint64_t *count, uint64_t *destination, void *pool)
{
    BatchEncoder *encoder = FromVoid<BatchEncoder>(thisptr);
    IfNullRet(encoder, E_POINTER);
    IfNullRet(count, E_POINTER);
    IfNullRet(destination, E_POINTER);
    Plaintext *plainptr = FromVoid<Plaintext>(plain);
    IfNullRet(plainptr, E_POINTER);
    unique_ptr<MemoryPoolHandle> handle = MemHandleFromVoid(pool);

    vector<uint64_t> result;
    try
    {
        encoder->decode(*plainptr, result, *handle);
    }
    catch (const invalid_argument &)
    {
        return E_INVALIDARG;
    }

    // Copy to actual destination
    *count = result.size();

    for (uint64_t i = 0; i < *count; i++)
    {
        destination[i] = result[i];
    }

    return S_OK;
}

SEAL_C_FUNC BatchEncoder_Decode2(void *thisptr, void *plain, uint64_t *count, int64_t *destination, void *pool)
{
    BatchEncoder *encoder = FromVoid<BatchEncoder>(thisptr);
    IfNullRet(encoder, E_POINTER);
    IfNullRet(count, E_POINTER);
    IfNullRet(destination, E_POINTER);
    Plaintext *plainptr = FromVoid<Plaintext>(plain);
    IfNullRet(plainptr, E_POINTER);
    unique_ptr<MemoryPoolHandle> handle = MemHandleFromVoid(pool);

    vector<int64_t> result;
    try
    {
        encoder->decode(*plainptr, result, *handle);
    }
    catch (const invalid_argument &)
    {
        return E_INVALIDARG;
    }

    *count = result.size();

    // Copy to actual destination
    for (uint64_t i = 0; i < *count; i++)
    {
        destination[i] = result[i];
    }

    return S_OK;
}

SEAL_C_FUNC BatchEncoder_Decode3(void *thisptr, void *plain, void *pool)
{
    BatchEncoder *encoder = FromVoid<BatchEncoder>(thisptr);
    IfNullRet(encoder, E_POINTER);
    Plaintext *plainptr = FromVoid<Plaintext>(plain);
    IfNullRet(plainptr, E_POINTER);
    unique_ptr<MemoryPoolHandle> handle = MemHandleFromVoid(pool);

    try
    {
        encoder->decode(*plainptr, *handle);
        return S_OK;
    }
    catch (const invalid_argument &)
    {
        return E_INVALIDARG;
    }
}

SEAL_C_FUNC BatchEncoder_GetSlotCount(void *thisptr, uint64_t *slot_count)
{
    BatchEncoder *encoder = FromVoid<BatchEncoder>(thisptr);
    IfNullRet(encoder, E_POINTER);
    IfNullRet(slot_count, E_POINTER);

    *slot_count = encoder->slot_count();
    return S_OK;
}
