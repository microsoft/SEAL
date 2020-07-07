// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

// SEALNet
#include "seal/c/intencoder.h"
#include "seal/c/stdafx.h"
#include "seal/c/utilities.h"

// SEAL
#include "seal/intencoder.h"

using namespace std;
using namespace seal;
using namespace seal::c;

SEAL_C_FUNC IntegerEncoder_Create(void *context, void **encoder)
{
    const auto &sharedctx = SharedContextFromVoid(context);
    IfNullRet(sharedctx.get(), E_POINTER);
    IfNullRet(encoder, E_POINTER);

    try
    {
        IntegerEncoder *intEncoder = new IntegerEncoder(sharedctx);
        *encoder = intEncoder;
        return S_OK;
    }
    catch (const invalid_argument &)
    {
        return E_INVALIDARG;
    }
}

SEAL_C_FUNC IntegerEncoder_Destroy(void *thisptr)
{
    IntegerEncoder *intenc = FromVoid<IntegerEncoder>(thisptr);
    IfNullRet(intenc, E_POINTER);

    delete intenc;
    return S_OK;
}

SEAL_C_FUNC IntegerEncoder_Encode1(void *thisptr, int32_t value, void *plain)
{
    IntegerEncoder *intenc = FromVoid<IntegerEncoder>(thisptr);
    IfNullRet(intenc, E_POINTER);
    Plaintext *dest = FromVoid<Plaintext>(plain);
    IfNullRet(dest, E_POINTER);

    intenc->encode(value, *dest);
    return S_OK;
}

SEAL_C_FUNC IntegerEncoder_Encode2(void *thisptr, uint32_t value, void *plain)
{
    IntegerEncoder *intenc = FromVoid<IntegerEncoder>(thisptr);
    IfNullRet(intenc, E_POINTER);
    Plaintext *dest = FromVoid<Plaintext>(plain);
    IfNullRet(dest, E_POINTER);

    intenc->encode(value, *dest);
    return S_OK;
}

SEAL_C_FUNC IntegerEncoder_Encode3(void *thisptr, uint64_t value, void *plain)
{
    IntegerEncoder *intenc = FromVoid<IntegerEncoder>(thisptr);
    IfNullRet(intenc, E_POINTER);
    Plaintext *dest = FromVoid<Plaintext>(plain);
    IfNullRet(dest, E_POINTER);

    intenc->encode(value, *dest);
    return S_OK;
}

SEAL_C_FUNC IntegerEncoder_Encode4(void *thisptr, int64_t value, void *plain)
{
    IntegerEncoder *intenc = FromVoid<IntegerEncoder>(thisptr);
    IfNullRet(intenc, E_POINTER);
    Plaintext *dest = FromVoid<Plaintext>(plain);
    IfNullRet(dest, E_POINTER);

    intenc->encode(value, *dest);
    return S_OK;
}

SEAL_C_FUNC IntegerEncoder_Encode5(void *thisptr, void *biguint, void *plain)
{
    IntegerEncoder *intenc = FromVoid<IntegerEncoder>(thisptr);
    IfNullRet(intenc, E_POINTER);
    BigUInt *bui = FromVoid<BigUInt>(biguint);
    IfNullRet(bui, E_POINTER);
    Plaintext *dest = FromVoid<Plaintext>(plain);
    IfNullRet(dest, E_POINTER);

    intenc->encode(*bui, *dest);
    return S_OK;
}

SEAL_C_FUNC IntegerEncoder_DecodeUInt32(void *thisptr, void *plainptr, uint32_t *result)
{
    IntegerEncoder *intenc = FromVoid<IntegerEncoder>(thisptr);
    IfNullRet(intenc, E_POINTER);
    Plaintext *plain = FromVoid<Plaintext>(plainptr);
    IfNullRet(plain, E_POINTER);
    IfNullRet(result, E_POINTER);

    try
    {
        *result = intenc->decode_uint32(*plain);
        return S_OK;
    }
    catch (const invalid_argument &)
    {
        return E_INVALIDARG;
    }
}

SEAL_C_FUNC IntegerEncoder_DecodeUInt64(void *thisptr, void *plainptr, uint64_t *result)
{
    IntegerEncoder *intenc = FromVoid<IntegerEncoder>(thisptr);
    IfNullRet(intenc, E_POINTER);
    Plaintext *plain = FromVoid<Plaintext>(plainptr);
    IfNullRet(plain, E_POINTER);
    IfNullRet(result, E_POINTER);

    try
    {
        *result = intenc->decode_uint64(*plain);
        return S_OK;
    }
    catch (const invalid_argument &)
    {
        return E_INVALIDARG;
    }
}

SEAL_C_FUNC IntegerEncoder_DecodeInt32(void *thisptr, void *plainptr, int32_t *result)
{
    IntegerEncoder *intenc = FromVoid<IntegerEncoder>(thisptr);
    IfNullRet(intenc, E_POINTER);
    Plaintext *plain = FromVoid<Plaintext>(plainptr);
    IfNullRet(plain, E_POINTER);
    IfNullRet(result, E_POINTER);

    try
    {
        *result = intenc->decode_int32(*plain);
        return S_OK;
    }
    catch (const invalid_argument &)
    {
        return E_INVALIDARG;
    }
}

SEAL_C_FUNC IntegerEncoder_DecodeInt64(void *thisptr, void *plainptr, int64_t *result)
{
    IntegerEncoder *intenc = FromVoid<IntegerEncoder>(thisptr);
    IfNullRet(intenc, E_POINTER);
    Plaintext *plain = FromVoid<Plaintext>(plainptr);
    IfNullRet(plain, E_POINTER);
    IfNullRet(result, E_POINTER);

    try
    {
        *result = intenc->decode_int64(*plain);
        return S_OK;
    }
    catch (invalid_argument &)
    {
        return E_INVALIDARG;
    }
}

SEAL_C_FUNC IntegerEncoder_DecodeBigUInt(void *thisptr, void *plainptr, void **biguint)
{
    IntegerEncoder *intenc = FromVoid<IntegerEncoder>(thisptr);
    IfNullRet(intenc, E_POINTER);
    Plaintext *plain = FromVoid<Plaintext>(plainptr);
    IfNullRet(plain, E_POINTER);
    IfNullRet(biguint, E_POINTER);

    try
    {
        BigUInt result = intenc->decode_biguint(*plain);
        BigUInt *resultPtr = new BigUInt(result);
        *biguint = resultPtr;
        return S_OK;
    }
    catch (const invalid_argument &)
    {
        return E_INVALIDARG;
    }
}

SEAL_C_FUNC IntegerEncoder_PlainModulus(void *thisptr, void **smallModPtr)
{
    IntegerEncoder *intenc = FromVoid<IntegerEncoder>(thisptr);
    IfNullRet(intenc, E_POINTER);
    IfNullRet(smallModPtr, E_POINTER);

    Modulus *sm = new Modulus(intenc->plain_modulus());
    *smallModPtr = sm;
    return S_OK;
}
