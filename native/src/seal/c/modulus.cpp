// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

// STD
#include <algorithm>
#include <iterator>

// SEALNet
#include "seal/c/modulus.h"
#include "seal/c/stdafx.h"
#include "seal/c/utilities.h"

// SEAL
#include "seal/modulus.h"

using namespace std;
using namespace seal;
using namespace seal::c;

SEAL_C_FUNC Modulus_Create1(uint64_t value, void **small_modulus)
{
    IfNullRet(small_modulus, E_POINTER);

    try
    {
        Modulus *sm = new Modulus(value);
        *small_modulus = sm;
        return S_OK;
    }
    catch (const invalid_argument &)
    {
        return E_INVALIDARG;
    }
}

SEAL_C_FUNC Modulus_Create2(void *copy, void **small_modulus)
{
    Modulus *copypt = FromVoid<Modulus>(copy);
    IfNullRet(copypt, E_POINTER);

    Modulus *sm = new Modulus(*copypt);
    *small_modulus = sm;
    return S_OK;
}

SEAL_C_FUNC Modulus_Destroy(void *thisptr)
{
    Modulus *sm = FromVoid<Modulus>(thisptr);
    IfNullRet(sm, E_POINTER);

    delete sm;
    return S_OK;
}

SEAL_C_FUNC Modulus_IsZero(void *thisptr, bool *is_zero)
{
    Modulus *sm = FromVoid<Modulus>(thisptr);
    IfNullRet(sm, E_POINTER);
    IfNullRet(is_zero, E_POINTER);

    *is_zero = sm->is_zero();
    return S_OK;
}

SEAL_C_FUNC Modulus_IsPrime(void *thisptr, bool *is_prime)
{
    Modulus *sm = FromVoid<Modulus>(thisptr);
    IfNullRet(sm, E_POINTER);
    IfNullRet(is_prime, E_POINTER);

    *is_prime = sm->is_prime();
    return S_OK;
}

SEAL_C_FUNC Modulus_Value(void *thisptr, uint64_t *value)
{
    Modulus *sm = FromVoid<Modulus>(thisptr);
    IfNullRet(sm, E_POINTER);
    IfNullRet(value, E_POINTER);

    *value = sm->value();
    return S_OK;
}

SEAL_C_FUNC Modulus_BitCount(void *thisptr, int *bit_count)
{
    Modulus *sm = FromVoid<Modulus>(thisptr);
    IfNullRet(sm, E_POINTER);
    IfNullRet(bit_count, E_POINTER);

    *bit_count = sm->bit_count();
    return S_OK;
}

SEAL_C_FUNC Modulus_UInt64Count(void *thisptr, uint64_t *uint64_count)
{
    Modulus *sm = FromVoid<Modulus>(thisptr);
    IfNullRet(sm, E_POINTER);
    IfNullRet(uint64_count, E_POINTER);

    *uint64_count = sm->uint64_count();
    return S_OK;
}

SEAL_C_FUNC Modulus_Set1(void *thisptr, void *assign)
{
    Modulus *sm = FromVoid<Modulus>(thisptr);
    IfNullRet(sm, E_POINTER);
    Modulus *assignpt = FromVoid<Modulus>(assign);
    IfNullRet(assignpt, E_POINTER);

    *sm = *assignpt;
    return S_OK;
}

SEAL_C_FUNC Modulus_Set2(void *thisptr, uint64_t value)
{
    Modulus *sm = FromVoid<Modulus>(thisptr);
    IfNullRet(sm, E_POINTER);

    try
    {
        *sm = value;
    }
    catch (const invalid_argument &)
    {
        return E_INVALIDARG;
    }

    return S_OK;
}

SEAL_C_FUNC Modulus_ConstRatio(void *thisptr, uint64_t length, uint64_t ratio[])
{
    Modulus *sm = FromVoid<Modulus>(thisptr);
    IfNullRet(sm, E_POINTER);

    if (length != 3)
    {
        return E_INVALIDARG;
    }

    auto ratio_array = sm->const_ratio();
    copy(ratio_array.begin(), ratio_array.end(), ratio);

    return S_OK;
}

SEAL_C_FUNC Modulus_Equals1(void *thisptr, void *other, bool *result)
{
    Modulus *sm = FromVoid<Modulus>(thisptr);
    IfNullRet(sm, E_POINTER);
    Modulus *otherpt = FromVoid<Modulus>(other);
    IfNullRet(otherpt, E_POINTER);
    IfNullRet(result, E_POINTER);

    *result = (*sm == *otherpt);
    return S_OK;
}

SEAL_C_FUNC Modulus_Equals2(void *thisptr, uint64_t other, bool *result)
{
    Modulus *sm = FromVoid<Modulus>(thisptr);
    IfNullRet(sm, E_POINTER);
    IfNullRet(result, E_POINTER);

    *result = (*sm == other);
    return S_OK;
}

SEAL_C_FUNC Modulus_SaveSize(void *thisptr, uint8_t compr_mode, int64_t *result)
{
    Modulus *sm = FromVoid<Modulus>(thisptr);
    IfNullRet(sm, E_POINTER);
    IfNullRet(result, E_POINTER);

    try
    {
        *result = static_cast<int64_t>(sm->save_size(static_cast<compr_mode_type>(compr_mode)));
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

SEAL_C_FUNC Modulus_Save(void *thisptr, uint8_t *outptr, uint64_t size, uint8_t compr_mode, int64_t *out_bytes)
{
    Modulus *sm = FromVoid<Modulus>(thisptr);
    IfNullRet(sm, E_POINTER);
    IfNullRet(outptr, E_POINTER);
    IfNullRet(out_bytes, E_POINTER);

    try
    {
        *out_bytes = util::safe_cast<int64_t>(sm->save(
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

SEAL_C_FUNC Modulus_Load(void *thisptr, uint8_t *inptr, uint64_t size, int64_t *in_bytes)
{
    Modulus *sm = FromVoid<Modulus>(thisptr);
    IfNullRet(sm, E_POINTER);
    IfNullRet(inptr, E_POINTER);
    IfNullRet(in_bytes, E_POINTER);

    try
    {
        *in_bytes =
            util::safe_cast<int64_t>(sm->load(reinterpret_cast<SEAL_BYTE *>(inptr), util::safe_cast<size_t>(size)));
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

SEAL_C_FUNC CoeffModulus_MaxBitCount(uint64_t poly_modulus_degree, int sec_level, int *bit_count)
{
    IfNullRet(bit_count, E_POINTER);

    sec_level_type security_level = static_cast<sec_level_type>(sec_level);
    *bit_count = CoeffModulus::MaxBitCount(poly_modulus_degree, security_level);
    return S_OK;
}

SEAL_C_FUNC CoeffModulus_BFVDefault(uint64_t poly_modulus_degree, int sec_level, uint64_t *length, void **coeffs)
{
    IfNullRet(length, E_POINTER);

    sec_level_type security_level = static_cast<sec_level_type>(sec_level);
    vector<Modulus> result;

    try
    {
        result = CoeffModulus::BFVDefault(poly_modulus_degree, security_level);
    }
    catch (const invalid_argument &)
    {
        return E_INVALIDARG;
    }

    BuildModulusPointers(result, length, coeffs);
    return S_OK;
}

SEAL_C_FUNC CoeffModulus_Create(uint64_t poly_modulus_degree, uint64_t length, int *bit_sizes, void **coeffs)
{
    IfNullRet(bit_sizes, E_POINTER);
    IfNullRet(coeffs, E_POINTER);

    vector<int> bit_sizes_vec;
    copy_n(bit_sizes, length, back_inserter(bit_sizes_vec));
    vector<Modulus> result;

    try
    {
        result = CoeffModulus::Create(poly_modulus_degree, bit_sizes_vec);
    }
    catch (const invalid_argument &)
    {
        return E_INVALIDARG;
    }
    catch (const logic_error &)
    {
        return COR_E_INVALIDOPERATION;
    }

    BuildModulusPointers(result, &length, coeffs);
    return S_OK;
}
