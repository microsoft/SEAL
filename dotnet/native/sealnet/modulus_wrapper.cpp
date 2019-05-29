// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

// STD
#include <algorithm>
#include <iterator>

// SEALNet
#include "sealnet/stdafx.h"
#include "sealnet/modulus_wrapper.h"
#include "sealnet/utilities.h"

// SEAL
#include "seal/modulus.h"

using namespace std;
using namespace seal;
using namespace sealnet;

SEALNETNATIVE HRESULT SEALCALL CoeffModulus_MaxBitCount(uint64_t poly_modulus_degree, int sec_level, int *bit_count)
{
    IfNullRet(bit_count, E_POINTER);

    sec_level_type security_level = static_cast<sec_level_type>(sec_level);
    *bit_count = CoeffModulus::MaxBitCount(poly_modulus_degree, security_level);
    return S_OK;
}

SEALNETNATIVE HRESULT SEALCALL CoeffModulus_BFVDefault(uint64_t poly_modulus_degree, int sec_level, uint64_t *length, void **coeffs)
{
    IfNullRet(length, E_POINTER);

    sec_level_type security_level = static_cast<sec_level_type>(sec_level);
    vector<SmallModulus> result;

    try
    {
        result = CoeffModulus::BFVDefault(poly_modulus_degree, security_level);
    }
    catch (const invalid_argument&)
    {
        return E_INVALIDARG;
    }

    BuildSmallModulusPointers(result, length, coeffs);
    return S_OK;
}

SEALNETNATIVE HRESULT SEALCALL CoeffModulus_Create(uint64_t poly_modulus_degree, uint64_t length, int *bit_sizes, void **coeffs)
{
    IfNullRet(bit_sizes, E_POINTER);
    IfNullRet(coeffs, E_POINTER);

    vector<int> bit_sizes_vec;
    copy_n(bit_sizes, length, back_inserter(bit_sizes_vec));
    vector<SmallModulus> result;

    try
    {
        result = CoeffModulus::Create(poly_modulus_degree, bit_sizes_vec);
    }
    catch (const invalid_argument&)
    {
        return E_INVALIDARG;
    }
    catch (const logic_error&)
    {
        return HRESULT_FROM_WIN32(ERROR_INVALID_OPERATION);
    }

    BuildSmallModulusPointers(result, &length, coeffs);
    return S_OK;
}
