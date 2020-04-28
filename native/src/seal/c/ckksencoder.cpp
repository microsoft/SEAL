// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

// STD
#include <vector>

// SEALNet
#include "seal/c/ckksencoder.h"
#include "seal/c/stdafx.h"
#include "seal/c/utilities.h"

// SEAL
#include "seal/ckks.h"

using namespace std;
using namespace seal;
using namespace seal::c;

SEAL_C_FUNC CKKSEncoder_Create(void *context, void **ckks_encoder)
{
    const auto &sharedctx = SharedContextFromVoid(context);
    IfNullRet(sharedctx.get(), E_POINTER);
    IfNullRet(ckks_encoder, E_POINTER);

    try
    {
        CKKSEncoder *encoder = new CKKSEncoder(sharedctx);
        *ckks_encoder = encoder;
        return S_OK;
    }
    catch (const invalid_argument &)
    {
        return E_INVALIDARG;
    }
}

SEAL_C_FUNC CKKSEncoder_Destroy(void *thisptr)
{
    CKKSEncoder *encoder = FromVoid<CKKSEncoder>(thisptr);
    IfNullRet(encoder, E_POINTER);

    delete encoder;
    return S_OK;
}

// Array of doubles
SEAL_C_FUNC CKKSEncoder_Encode1(
    void *thisptr, uint64_t value_count, double *values, uint64_t *parms_id, double scale, void *destination,
    void *pool)
{
    CKKSEncoder *encoder = FromVoid<CKKSEncoder>(thisptr);
    IfNullRet(encoder, E_POINTER);
    Plaintext *destinationptr = FromVoid<Plaintext>(destination);
    IfNullRet(destinationptr, E_POINTER);
    IfNullRet(parms_id, E_POINTER);
    unique_ptr<MemoryPoolHandle> handle = MemHandleFromVoid(pool);

    parms_id_type parms;
    CopyParmsId(parms_id, parms);

    vector<double> input(value_count);
    for (uint64_t i = 0; i < value_count; i++)
    {
        input[i] = values[i];
    }

    try
    {
        encoder->encode(input, parms, scale, *destinationptr, *handle);
        return S_OK;
    }
    catch (const invalid_argument &)
    {
        return E_INVALIDARG;
    }
}

// Array of complex numbers (two doubles per value)
SEAL_C_FUNC CKKSEncoder_Encode2(
    void *thisptr, uint64_t value_count, double *complex_values, uint64_t *parms_id, double scale, void *destination,
    void *pool)
{
    CKKSEncoder *encoder = FromVoid<CKKSEncoder>(thisptr);
    IfNullRet(encoder, E_POINTER);
    Plaintext *destinationptr = FromVoid<Plaintext>(destination);
    IfNullRet(destinationptr, E_POINTER);
    IfNullRet(parms_id, E_POINTER);
    unique_ptr<MemoryPoolHandle> handle = MemHandleFromVoid(pool);

    parms_id_type parms;
    CopyParmsId(parms_id, parms);

    vector<complex<double>> input(value_count);
    for (uint64_t i = 0; i < value_count; i++)
    {
        input[i] = complex<double>(complex_values[i * 2], complex_values[i * 2 + 1]);
    }

    try
    {
        encoder->encode(input, parms, scale, *destinationptr, *handle);
        return S_OK;
    }
    catch (const invalid_argument &)
    {
        return E_INVALIDARG;
    }
}

// Single double value
SEAL_C_FUNC CKKSEncoder_Encode3(
    void *thisptr, double value, uint64_t *parms_id, double scale, void *destination, void *pool)
{
    CKKSEncoder *encoder = FromVoid<CKKSEncoder>(thisptr);
    IfNullRet(encoder, E_POINTER);
    Plaintext *destinationptr = FromVoid<Plaintext>(destination);
    IfNullRet(destinationptr, E_POINTER);
    IfNullRet(parms_id, E_POINTER);
    unique_ptr<MemoryPoolHandle> handle = MemHandleFromVoid(pool);

    parms_id_type parms;
    CopyParmsId(parms_id, parms);

    try
    {
        encoder->encode(value, parms, scale, *destinationptr, *handle);
        return S_OK;
    }
    catch (const invalid_argument &)
    {
        return E_INVALIDARG;
    }
}

// Single complex value
SEAL_C_FUNC CKKSEncoder_Encode4(
    void *thisptr, double value_re, double value_im, uint64_t *parms_id, double scale, void *destination, void *pool)
{
    CKKSEncoder *encoder = FromVoid<CKKSEncoder>(thisptr);
    IfNullRet(encoder, E_POINTER);
    Plaintext *destinationptr = FromVoid<Plaintext>(destination);
    IfNullRet(destinationptr, E_POINTER);
    IfNullRet(parms_id, E_POINTER);
    unique_ptr<MemoryPoolHandle> handle = MemHandleFromVoid(pool);

    parms_id_type parms;
    CopyParmsId(parms_id, parms);

    complex<double> input(value_re, value_im);

    try
    {
        encoder->encode(input, parms, scale, *destinationptr, *handle);
        return S_OK;
    }
    catch (const invalid_argument &)
    {
        return E_INVALIDARG;
    }
}

// Single Int64 value
SEAL_C_FUNC CKKSEncoder_Encode5(void *thisptr, int64_t value, uint64_t *parms_id, void *destination)
{
    CKKSEncoder *encoder = FromVoid<CKKSEncoder>(thisptr);
    IfNullRet(encoder, E_POINTER);
    Plaintext *destinationptr = FromVoid<Plaintext>(destination);
    IfNullRet(destinationptr, E_POINTER);
    IfNullRet(parms_id, E_POINTER);

    parms_id_type parms;
    CopyParmsId(parms_id, parms);

    try
    {
        encoder->encode(value, parms, *destinationptr);
        return S_OK;
    }
    catch (const invalid_argument &)
    {
        return E_INVALIDARG;
    }
}

// Array of doubles
SEAL_C_FUNC CKKSEncoder_Decode1(void *thisptr, void *plain, uint64_t *value_count, double *values, void *pool)
{
    CKKSEncoder *encoder = FromVoid<CKKSEncoder>(thisptr);
    IfNullRet(encoder, E_POINTER);
    IfNullRet(value_count, E_POINTER);
    IfNullRet(values, E_POINTER);
    Plaintext *plainptr = FromVoid<Plaintext>(plain);
    IfNullRet(plainptr, E_POINTER);
    unique_ptr<MemoryPoolHandle> handle = MemHandleFromVoid(pool);

    vector<double> destination;

    try
    {
        encoder->decode(*plainptr, destination, *handle);
    }
    catch (const invalid_argument &)
    {
        return E_INVALIDARG;
    }

    *value_count = destination.size();

    // Copy to actual destination
    for (uint64_t i = 0; i < destination.size(); i++)
    {
        values[i] = destination[i];
    }

    return S_OK;
}

// Array of complex numbers
SEAL_C_FUNC CKKSEncoder_Decode2(void *thisptr, void *plain, uint64_t *value_count, double *values, void *pool)
{
    CKKSEncoder *encoder = FromVoid<CKKSEncoder>(thisptr);
    IfNullRet(encoder, E_POINTER);
    IfNullRet(value_count, E_POINTER);
    IfNullRet(values, E_POINTER);
    Plaintext *plainptr = FromVoid<Plaintext>(plain);
    IfNullRet(plainptr, E_POINTER);
    unique_ptr<MemoryPoolHandle> handle = MemHandleFromVoid(pool);

    vector<complex<double>> destination;

    try
    {
        encoder->decode(*plainptr, destination, *handle);
    }
    catch (const invalid_argument &)
    {
        return E_INVALIDARG;
    }

    *value_count = destination.size();

    // Copy to actual destination
    for (uint64_t i = 0; i < destination.size(); i++)
    {
        values[i * 2] = destination[i].real();
        values[i * 2 + 1] = destination[i].imag();
    }

    return S_OK;
}

SEAL_C_FUNC CKKSEncoder_SlotCount(void *thisptr, uint64_t *slot_count)
{
    CKKSEncoder *encoder = FromVoid<CKKSEncoder>(thisptr);
    IfNullRet(encoder, E_POINTER);
    IfNullRet(slot_count, E_POINTER);

    *slot_count = encoder->slot_count();
    return S_OK;
}
