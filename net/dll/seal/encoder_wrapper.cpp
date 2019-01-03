// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

// SEALDLL
#include "stdafx.h"
#include "encoder_wrapper.h"
#include "utilities.h"

// SEAL
#include "seal/encoder.h"

using namespace seal;
using namespace seal::dll;


SEALDLL HRESULT SEALCALL IntegerEncoder_Create1(void* plain_modulus, uint64_t base, void** encoder)
{
    SmallModulus* pm = FromVoid<SmallModulus>(plain_modulus);
    IfNullRet(pm, E_POINTER);
    IfNullRet(encoder, E_POINTER);

    try
    {
        IntegerEncoder* intEncoder = new IntegerEncoder(*pm, base);
        *encoder = intEncoder;
        return S_OK;
    }
    catch (const std::invalid_argument&)
    {
        return E_INVALIDARG;
    }
}

SEALDLL HRESULT SEALCALL IntegerEncoder_Create2(void* copy, void** encoder)
{
    IntegerEncoder* intenc = FromVoid<IntegerEncoder>(copy);
    IfNullRet(intenc, E_POINTER);
    IfNullRet(encoder, E_POINTER);

    IntegerEncoder* newEnc = new IntegerEncoder(*intenc);
    *encoder = newEnc;
    return S_OK;
}

SEALDLL HRESULT SEALCALL IntegerEncoder_Destroy(void* thisptr)
{
    IntegerEncoder* intenc = FromVoid<IntegerEncoder>(thisptr);
    IfNullRet(intenc, E_POINTER);

    delete intenc;
    return S_OK;
}

SEALDLL HRESULT SEALCALL IntegerEncoder_Encode1(void* thisptr, int32_t value, void* plain)
{
    IntegerEncoder* intenc = FromVoid<IntegerEncoder>(thisptr);
    IfNullRet(intenc, E_POINTER);
    Plaintext* dest = FromVoid<Plaintext>(plain);
    IfNullRet(dest, E_POINTER);

    intenc->encode(value, *dest);
    return S_OK;
}

SEALDLL HRESULT SEALCALL IntegerEncoder_Encode2(void* thisptr, uint32_t value, void* plain)
{
    IntegerEncoder* intenc = FromVoid<IntegerEncoder>(thisptr);
    IfNullRet(intenc, E_POINTER);
    Plaintext* dest = FromVoid<Plaintext>(plain);
    IfNullRet(dest, E_POINTER);

    intenc->encode(value, *dest);
    return S_OK;
}

SEALDLL HRESULT SEALCALL IntegerEncoder_Encode3(void* thisptr, uint64_t value, void* plain)
{
    IntegerEncoder* intenc = FromVoid<IntegerEncoder>(thisptr);
    IfNullRet(intenc, E_POINTER);
    Plaintext* dest = FromVoid<Plaintext>(plain);
    IfNullRet(dest, E_POINTER);

    intenc->encode(value, *dest);
    return S_OK;
}

SEALDLL HRESULT SEALCALL IntegerEncoder_Encode4(void* thisptr, int64_t value, void* plain)
{
    IntegerEncoder* intenc = FromVoid<IntegerEncoder>(thisptr);
    IfNullRet(intenc, E_POINTER);
    Plaintext* dest = FromVoid<Plaintext>(plain);
    IfNullRet(dest, E_POINTER);

    intenc->encode(value, *dest);
    return S_OK;
}

SEALDLL HRESULT SEALCALL IntegerEncoder_Encode5(void* thisptr, void* biguint, void* plain)
{
    IntegerEncoder* intenc = FromVoid<IntegerEncoder>(thisptr);
    IfNullRet(intenc, E_POINTER);
    BigUInt* bui = FromVoid<BigUInt>(biguint);
    IfNullRet(bui, E_POINTER);
    Plaintext* dest = FromVoid<Plaintext>(plain);
    IfNullRet(dest, E_POINTER);

    intenc->encode(*bui, *dest);
    return S_OK;
}

SEALDLL HRESULT SEALCALL IntegerEncoder_DecodeUint32(void* thisptr, void* plainptr, uint32_t* result)
{
    IntegerEncoder* intenc = FromVoid<IntegerEncoder>(thisptr);
    IfNullRet(intenc, E_POINTER);
    Plaintext* plain = FromVoid<Plaintext>(plainptr);
    IfNullRet(plain, E_POINTER);
    IfNullRet(result, E_POINTER);

    try
    {
        *result = intenc->decode_uint32(*plain);
        return S_OK;
    }
    catch (const std::invalid_argument&)
    {
        return E_INVALIDARG;
    }
}

SEALDLL HRESULT SEALCALL IntegerEncoder_DecodeUint64(void* thisptr, void* plainptr, uint64_t* result)
{
    IntegerEncoder* intenc = FromVoid<IntegerEncoder>(thisptr);
    IfNullRet(intenc, E_POINTER);
    Plaintext* plain = FromVoid<Plaintext>(plainptr);
    IfNullRet(plain, E_POINTER);
    IfNullRet(result, E_POINTER);

    try
    {
        *result = intenc->decode_uint64(*plain);
        return S_OK;
    }
    catch (const std::invalid_argument&)
    {
        return E_INVALIDARG;
    }
}

SEALDLL HRESULT SEALCALL IntegerEncoder_DecodeInt32(void* thisptr, void* plainptr, int32_t* result)
{
    IntegerEncoder* intenc = FromVoid<IntegerEncoder>(thisptr);
    IfNullRet(intenc, E_POINTER);
    Plaintext* plain = FromVoid<Plaintext>(plainptr);
    IfNullRet(plain, E_POINTER);
    IfNullRet(result, E_POINTER);

    try
    {
        *result = intenc->decode_int32(*plain);
        return S_OK;
    }
    catch (const std::invalid_argument&)
    {
        return E_INVALIDARG;
    }
}

SEALDLL HRESULT SEALCALL IntegerEncoder_DecodeInt64(void* thisptr, void* plainptr, int64_t* result)
{
    IntegerEncoder* intenc = FromVoid<IntegerEncoder>(thisptr);
    IfNullRet(intenc, E_POINTER);
    Plaintext* plain = FromVoid<Plaintext>(plainptr);
    IfNullRet(plain, E_POINTER);
    IfNullRet(result, E_POINTER);

    try
    {
        *result = intenc->decode_int64(*plain);
        return S_OK;
    }
    catch (std::invalid_argument&)
    {
        return E_INVALIDARG;
    }
}

SEALDLL HRESULT SEALCALL IntegerEncoder_DecodeBigUInt(void* thisptr, void* plainptr, void* biguint)
{
    IntegerEncoder* intenc = FromVoid<IntegerEncoder>(thisptr);
    IfNullRet(intenc, E_POINTER);
    Plaintext* plain = FromVoid<Plaintext>(plainptr);
    IfNullRet(plain, E_POINTER);
    BigUInt* bui = FromVoid<BigUInt>(biguint);
    IfNullRet(bui, E_POINTER);

    try
    {
        intenc->decode_biguint(*plain, *bui);
        return S_OK;
    }
    catch (const std::invalid_argument&)
    {
        return E_INVALIDARG;
    }
}

SEALDLL HRESULT SEALCALL IntegerEncoder_PlainModulus(void* thisptr, void** smallModPtr)
{
    IntegerEncoder* intenc = FromVoid<IntegerEncoder>(thisptr);
    IfNullRet(intenc, E_POINTER);
    IfNullRet(smallModPtr, E_POINTER);

    SmallModulus* sm = new SmallModulus(intenc->plain_modulus());
    *smallModPtr = sm;
    return S_OK;
}

SEALDLL HRESULT SEALCALL IntegerEncoder_Base(void* thisptr, uint64_t* result)
{
    IntegerEncoder* intenc = FromVoid<IntegerEncoder>(thisptr);
    IfNullRet(intenc, E_POINTER);
    IfNullRet(result, E_POINTER);

    *result = intenc->base();
    return S_OK;
}
