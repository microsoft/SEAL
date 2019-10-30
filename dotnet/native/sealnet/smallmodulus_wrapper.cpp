// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

// STD
#include <algorithm>

// SEALNet
#include "sealnet/stdafx.h"
#include "sealnet/smallmodulus_wrapper.h"
#include "sealnet/utilities.h"

// SEAL
#include "seal/smallmodulus.h"

using namespace std;
using namespace seal;
using namespace sealnet;

SEALNETNATIVE HRESULT SEALCALL SmallModulus_Create1(uint64_t value, void **small_modulus)
{
    IfNullRet(small_modulus, E_POINTER);

    try
    {
        SmallModulus *sm = new SmallModulus(value);
        *small_modulus = sm;
        return S_OK;
    }
    catch (const invalid_argument&)
    {
        return E_INVALIDARG;
    }
}

SEALNETNATIVE HRESULT SEALCALL SmallModulus_Create2(void *copy, void **small_modulus)
{
    SmallModulus *copypt = FromVoid<SmallModulus>(copy);
    IfNullRet(copypt, E_POINTER);

    SmallModulus *sm = new SmallModulus(*copypt);
    *small_modulus = sm;
    return S_OK;
}

SEALNETNATIVE HRESULT SEALCALL SmallModulus_Destroy(void *thisptr)
{
    SmallModulus *sm = FromVoid<SmallModulus>(thisptr);
    IfNullRet(sm, E_POINTER);

    delete sm;
    return S_OK;
}

SEALNETNATIVE HRESULT SEALCALL SmallModulus_IsZero(void *thisptr, bool *is_zero)
{
    SmallModulus *sm = FromVoid<SmallModulus>(thisptr);
    IfNullRet(sm, E_POINTER);
    IfNullRet(is_zero, E_POINTER);

    *is_zero = sm->is_zero();
    return S_OK;
}

SEALNETNATIVE HRESULT SEALCALL SmallModulus_IsPrime(void *thisptr, bool *is_prime)
{
    SmallModulus *sm = FromVoid<SmallModulus>(thisptr);
    IfNullRet(sm, E_POINTER);
    IfNullRet(is_prime, E_POINTER);

    *is_prime = sm->is_prime();
    return S_OK;
}

SEALNETNATIVE HRESULT SEALCALL SmallModulus_Value(void *thisptr, uint64_t *value)
{
    SmallModulus *sm = FromVoid<SmallModulus>(thisptr);
    IfNullRet(sm, E_POINTER);
    IfNullRet(value, E_POINTER);

    *value = sm->value();
    return S_OK;
}

SEALNETNATIVE HRESULT SEALCALL SmallModulus_BitCount(void *thisptr, int *bit_count)
{
    SmallModulus *sm = FromVoid<SmallModulus>(thisptr);
    IfNullRet(sm, E_POINTER);
    IfNullRet(bit_count, E_POINTER);

    *bit_count = sm->bit_count();
    return S_OK;
}

SEALNETNATIVE HRESULT SEALCALL SmallModulus_UInt64Count(void *thisptr, uint64_t *uint64_count)
{
    SmallModulus *sm = FromVoid<SmallModulus>(thisptr);
    IfNullRet(sm, E_POINTER);
    IfNullRet(uint64_count, E_POINTER);

    *uint64_count = sm->uint64_count();
    return S_OK;
}

SEALNETNATIVE HRESULT SEALCALL SmallModulus_Set1(void *thisptr, void *assign)
{
    SmallModulus *sm = FromVoid<SmallModulus>(thisptr);
    IfNullRet(sm, E_POINTER);
    SmallModulus *assignpt = FromVoid<SmallModulus>(assign);
    IfNullRet(assignpt, E_POINTER);

    *sm = *assignpt;
    return S_OK;
}

SEALNETNATIVE HRESULT SEALCALL SmallModulus_Set2(void *thisptr, uint64_t value)
{
    SmallModulus *sm = FromVoid<SmallModulus>(thisptr);
    IfNullRet(sm, E_POINTER);

    try
    {
        *sm = value;
    }
    catch (const invalid_argument&)
    {
        return E_INVALIDARG;
    }

    return S_OK;
}

SEALNETNATIVE HRESULT SEALCALL SmallModulus_ConstRatio(void *thisptr, uint64_t length, uint64_t ratio[])
{
    SmallModulus *sm = FromVoid<SmallModulus>(thisptr);
    IfNullRet(sm, E_POINTER);

    if (length != 3)
    {
        return E_INVALIDARG;
    }

    auto ratio_array = sm->const_ratio();
    copy(ratio_array.begin(), ratio_array.end(), ratio);

    return S_OK;
}

SEALNETNATIVE HRESULT SEALCALL SmallModulus_Equals1(void *thisptr, void *other, bool *result)
{
    SmallModulus *sm = FromVoid<SmallModulus>(thisptr);
    IfNullRet(sm, E_POINTER);
    SmallModulus *otherpt = FromVoid<SmallModulus>(other);
    IfNullRet(otherpt, E_POINTER);
    IfNullRet(result, E_POINTER);

    *result = (*sm == *otherpt);
    return S_OK;
}

SEALNETNATIVE HRESULT SEALCALL SmallModulus_Equals2(void *thisptr, uint64_t other, bool *result)
{
    SmallModulus *sm = FromVoid<SmallModulus>(thisptr);
    IfNullRet(sm, E_POINTER);
    IfNullRet(result, E_POINTER);

    *result = (*sm == other);
    return S_OK;
}

SEALNETNATIVE HRESULT SEALCALL SmallModulus_SaveSize(void *thisptr, uint8_t compr_mode, int64_t *result)
{
    SmallModulus *sm = FromVoid<SmallModulus>(thisptr);
    IfNullRet(sm, E_POINTER);
    IfNullRet(result, E_POINTER);

    try
    {
        *result = static_cast<int64_t>(
            sm->save_size(static_cast<compr_mode_type>(compr_mode)));
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

SEALNETNATIVE HRESULT SEALCALL SmallModulus_Save(void *thisptr, uint8_t *outptr, uint64_t size, uint8_t compr_mode, int64_t *out_bytes)
{
    SmallModulus *sm = FromVoid<SmallModulus>(thisptr);
    IfNullRet(sm, E_POINTER);
    IfNullRet(outptr, E_POINTER);
    IfNullRet(out_bytes, E_POINTER);

    try
    {
        *out_bytes = util::safe_cast<int64_t>(sm->save(
            reinterpret_cast<SEAL_BYTE *>(outptr),
            util::safe_cast<size_t>(size),
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

SEALNETNATIVE HRESULT SEALCALL SmallModulus_Load(void *thisptr, uint8_t *inptr, uint64_t size, int64_t *in_bytes)
{
    SmallModulus *sm = FromVoid<SmallModulus>(thisptr);
    IfNullRet(sm, E_POINTER);
    IfNullRet(inptr, E_POINTER);
    IfNullRet(in_bytes, E_POINTER);

    try
    {
        *in_bytes = util::safe_cast<int64_t>(sm->load(
            reinterpret_cast<SEAL_BYTE *>(inptr),
            util::safe_cast<size_t>(size)));
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
