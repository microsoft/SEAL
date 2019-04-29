// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

// STD
#include <string>
#include <algorithm>

// SEALNet
#include "sealnet/stdafx.h"
#include "sealnet/plaintext_wrapper.h"
#include "sealnet/utilities.h"

// SEAL
#include "seal/plaintext.h"
#include "seal/util/common.h"

using namespace std;
using namespace seal;
using namespace sealnet;
using namespace seal::util;

namespace seal
{
    /**
    Enables access to private members of seal::Plaintext.
    */
    struct Plaintext::PlaintextPrivateHelper
    {
        static void set_scale(seal::Plaintext *plain, double new_scale)
        {
            plain->scale_ = new_scale;
        }

        static void swap_data(seal::Plaintext *plain, seal::IntArray<uint64_t> &new_data)
        {
            swap(plain->data_, new_data);
        }
    };
}

SEALNETNATIVE HRESULT SEALCALL Plaintext_Create1(void *memoryPoolHandle, void **plaintext)
{
    IfNullRet(plaintext, E_POINTER);
    unique_ptr<MemoryPoolHandle> handle = MemHandleFromVoid(memoryPoolHandle);
    Plaintext *plain = nullptr;

    try
    {
        plain = new Plaintext(*handle);
        *plaintext = plain;
        return S_OK;
    }
    catch (const invalid_argument&)
    {
        return E_INVALIDARG;
    }

    return E_UNEXPECTED;
}

SEALNETNATIVE HRESULT SEALCALL Plaintext_Create2(uint64_t coeffCount, void *memoryPoolHandle, void **plaintext)
{
    IfNullRet(plaintext, E_POINTER);
    unique_ptr<MemoryPoolHandle> handle = MemHandleFromVoid(memoryPoolHandle);
    Plaintext *plain = nullptr;

    try
    {
        plain = new Plaintext(coeffCount, *handle);
        *plaintext = plain;
        return S_OK;
    }
    catch (const invalid_argument&)
    {
        return E_INVALIDARG;
    }

    return E_UNEXPECTED;
}

SEALNETNATIVE HRESULT SEALCALL Plaintext_Create3(uint64_t capacity, uint64_t coeffCount, void *memoryPoolHandle, void **plaintext)
{
    IfNullRet(plaintext, E_POINTER);
    unique_ptr<MemoryPoolHandle> handle = MemHandleFromVoid(memoryPoolHandle);
    Plaintext *plain = nullptr;

    try
    {
        plain = new Plaintext(capacity, coeffCount, *handle);
        *plaintext = plain;
        return S_OK;
    }
    catch (const invalid_argument&)
    {
        return E_INVALIDARG;
    }

    return E_UNEXPECTED;
}

SEALNETNATIVE HRESULT SEALCALL Plaintext_Create4(char *hexPoly, void *memoryPoolHandle, void **plaintext)
{
    IfNullRet(plaintext, E_POINTER);
    IfNullRet(hexPoly, E_POINTER);
    unique_ptr<MemoryPoolHandle> handle = MemHandleFromVoid(memoryPoolHandle);
    string hexPolyStr(hexPoly);

    try
    {
        Plaintext *plain = new Plaintext(hexPolyStr, *handle);
        *plaintext = plain;
        return S_OK;
    }
    catch (const invalid_argument&)
    {
        return E_INVALIDARG;
    }

    return E_UNEXPECTED;
}

SEALNETNATIVE HRESULT SEALCALL Plaintext_Create5(void *copy, void **plaintext)
{
    Plaintext *copyptr = FromVoid<Plaintext>(copy);
    IfNullRet(copyptr, E_POINTER);
    IfNullRet(plaintext, E_POINTER);

    Plaintext *plain = new Plaintext(*copyptr);
    *plaintext = plain;
    return S_OK;
}

SEALNETNATIVE HRESULT SEALCALL Plaintext_Set1(void *thisptr, void *assign)
{
    Plaintext *plain = FromVoid<Plaintext>(thisptr);
    IfNullRet(plain, E_POINTER);
    Plaintext *assignptr = FromVoid<Plaintext>(assign);
    IfNullRet(assignptr, E_POINTER);

    *plain = *assignptr;
    return S_OK;
}

SEALNETNATIVE HRESULT SEALCALL Plaintext_Set2(void *thisptr, char *hex_poly)
{
    Plaintext *plain = FromVoid<Plaintext>(thisptr);
    IfNullRet(plain, E_POINTER);
    IfNullRet(hex_poly, E_POINTER);

    try
    {
        string hex_poly_str(hex_poly);
        *plain = hex_poly_str;
        return S_OK;
    }
    catch (const invalid_argument&)
    {
        return E_INVALIDARG;
    }

    return E_UNEXPECTED;
}

SEALNETNATIVE HRESULT SEALCALL Plaintext_Set3(void *thisptr, uint64_t const_coeff)
{
    Plaintext *plain = FromVoid<Plaintext>(thisptr);
    IfNullRet(plain, E_POINTER);

    try
    {
        *plain = const_coeff;
        return S_OK;
    }
    catch (const logic_error&)
    {
        return E_INVALIDARG;
    }
}

SEALNETNATIVE HRESULT SEALCALL Plaintext_Destroy(void *thisptr)
{
    Plaintext *plain = FromVoid<Plaintext>(thisptr);
    IfNullRet(plain, E_POINTER);

    delete plain;
    return S_OK;
}

SEALNETNATIVE HRESULT SEALCALL Plaintext_CoeffCount(void *thisptr, uint64_t *coeff_count)
{
    Plaintext *plain = FromVoid<Plaintext>(thisptr);
    IfNullRet(plain, E_POINTER);
    IfNullRet(coeff_count, E_POINTER);

    *coeff_count = plain->coeff_count();
    return S_OK;
}

SEALNETNATIVE HRESULT SEALCALL Plaintext_CoeffAt(void *thisptr, uint64_t index, uint64_t *coeff)
{
    Plaintext *plain = FromVoid<Plaintext>(thisptr);
    IfNullRet(plain, E_POINTER);
    IfNullRet(coeff, E_POINTER);

    try
    {
        *coeff = (*plain)[index];
        return S_OK;
    }
    catch (const invalid_argument&)
    {
        return E_INVALIDARG;
    }
    catch (const out_of_range&)
    {
        return HRESULT_FROM_WIN32(ERROR_INVALID_INDEX);
    }
}

SEALNETNATIVE HRESULT SEALCALL Plaintext_SetCoeffAt(void *thisptr, uint64_t index, uint64_t value)
{
    Plaintext *plain = FromVoid<Plaintext>(thisptr);
    IfNullRet(plain, E_POINTER);

    try
    {
        (*plain)[index] = value;
        return S_OK;
    }
    catch (const out_of_range&)
    {
        return HRESULT_FROM_WIN32(ERROR_INVALID_INDEX);
    }
}

SEALNETNATIVE HRESULT SEALCALL Plaintext_ToString(void *thispt, uint64_t *length, char *outstr)
{
    Plaintext *plain = FromVoid<Plaintext>(thispt);
    IfNullRet(plain, E_POINTER);
    IfNullRet(length, E_POINTER);

    try
    {
        string str = plain->to_string();
        return ToStringHelper(str, outstr, length);
    }
    catch (const invalid_argument&)
    {
        return E_INVALIDARG;
    }

    return E_UNEXPECTED;
}

SEALNETNATIVE HRESULT SEALCALL Plaintext_IsNTTForm(void *thisptr, bool *is_ntt_form)
{
    Plaintext *plain = FromVoid<Plaintext>(thisptr);
    IfNullRet(plain, E_POINTER);
    IfNullRet(is_ntt_form, E_POINTER);

    *is_ntt_form = plain->is_ntt_form();
    return S_OK;
}

SEALNETNATIVE HRESULT SEALCALL Plaintext_IsZero(void *thisptr, bool *is_zero)
{
    Plaintext *plain = FromVoid<Plaintext>(thisptr);
    IfNullRet(plain, E_POINTER);
    IfNullRet(is_zero, E_POINTER);

    *is_zero = plain->is_zero();
    return S_OK;
}

SEALNETNATIVE HRESULT SEALCALL Plaintext_GetParmsId(void *thisptr, uint64_t *parms_id)
{
    Plaintext *plain = FromVoid<Plaintext>(thisptr);
    IfNullRet(plain, E_POINTER);
    IfNullRet(parms_id, E_POINTER);

    for (size_t i = 0; i < plain->parms_id().size(); i++)
    {
        parms_id[i] = plain->parms_id()[i];
    }

    return S_OK;
}

SEALNETNATIVE HRESULT SEALCALL Plaintext_SetParmsId(void *thisptr, uint64_t *parms_id)
{
    Plaintext *plain = FromVoid<Plaintext>(thisptr);
    IfNullRet(plain, E_POINTER);
    IfNullRet(parms_id, E_POINTER);

    CopyParmsId(parms_id, plain->parms_id());
    return S_OK;
}

SEALNETNATIVE HRESULT SEALCALL Plaintext_SetZero1(void *thisptr)
{
    Plaintext *plain = FromVoid<Plaintext>(thisptr);
    IfNullRet(plain, E_POINTER);

    plain->set_zero();
    return S_OK;
}

SEALNETNATIVE HRESULT SEALCALL Plaintext_SetZero2(void *thisptr, uint64_t start_coeff)
{
    Plaintext *plain = FromVoid<Plaintext>(thisptr);
    IfNullRet(plain, E_POINTER);

    try
    {
        using size_type = Plaintext::size_type;
        plain->set_zero(safe_cast<size_type>(start_coeff));
        return S_OK;
    }
    catch (const out_of_range&)
    {
        return HRESULT_FROM_WIN32(ERROR_INVALID_INDEX);
    }
}

SEALNETNATIVE HRESULT SEALCALL Plaintext_SetZero3(void *thisptr, uint64_t start_coeff, uint64_t length)
{
    Plaintext *plain = FromVoid<Plaintext>(thisptr);
    IfNullRet(plain, E_POINTER);

    try
    {
        using size_type = Plaintext::size_type;
        plain->set_zero(safe_cast<size_type>(start_coeff), safe_cast<size_type>(length));
        return S_OK;
    }
    catch (const out_of_range&)
    {
        return HRESULT_FROM_WIN32(ERROR_INVALID_INDEX);
    }
}

SEALNETNATIVE HRESULT SEALCALL Plaintext_Reserve(void *thisptr, uint64_t capacity)
{
    Plaintext *plain = FromVoid<Plaintext>(thisptr);
    IfNullRet(plain, E_POINTER);

    try
    {
        plain->reserve(capacity);
        return S_OK;
    }
    catch (const invalid_argument&)
    {
        return E_INVALIDARG;
    }
    catch (const logic_error&)
    {
        return HRESULT_FROM_WIN32(ERROR_INVALID_OPERATION);
    }
}

SEALNETNATIVE HRESULT SEALCALL Plaintext_Resize(void *thisptr, uint64_t coeff_count)
{
    Plaintext *plain = FromVoid<Plaintext>(thisptr);
    IfNullRet(plain, E_POINTER);

    try
    {
        plain->resize(coeff_count);
        return S_OK;
    }
    catch (const invalid_argument&)
    {
        return E_INVALIDARG;
    }
    catch (const logic_error&)
    {
        return HRESULT_FROM_WIN32(ERROR_INVALID_OPERATION);
    }
}

SEALNETNATIVE HRESULT SEALCALL Plaintext_ShrinkToFit(void *thisptr)
{
    Plaintext *plain = FromVoid<Plaintext>(thisptr);
    IfNullRet(plain, E_POINTER);

    plain->shrink_to_fit();
    return S_OK;
}

SEALNETNATIVE HRESULT SEALCALL Plaintext_Release(void *thisptr)
{
    Plaintext *plain = FromVoid<Plaintext>(thisptr);
    IfNullRet(plain, E_POINTER);

    plain->release();
    return S_OK;
}

SEALNETNATIVE HRESULT SEALCALL Plaintext_Capacity(void *thisptr, uint64_t *capacity)
{
    Plaintext *plain = FromVoid<Plaintext>(thisptr);
    IfNullRet(plain, E_POINTER);
    IfNullRet(capacity, E_POINTER);

    *capacity = plain->capacity();
    return S_OK;
}

SEALNETNATIVE HRESULT SEALCALL Plaintext_SignificantCoeffCount(void *thisptr, uint64_t *significant_coeff_count)
{
    Plaintext *plain = FromVoid<Plaintext>(thisptr);
    IfNullRet(plain, E_POINTER);
    IfNullRet(significant_coeff_count, E_POINTER);

    *significant_coeff_count = plain->significant_coeff_count();
    return S_OK;
}

SEALNETNATIVE HRESULT SEALCALL Plaintext_NonZeroCoeffCount(void *thisptr, uint64_t *nonzero_coeff_count)
{
    Plaintext *plain = FromVoid<Plaintext>(thisptr);
    IfNullRet(plain, E_POINTER);
    IfNullRet(nonzero_coeff_count, E_POINTER);

    *nonzero_coeff_count = plain->nonzero_coeff_count();
    return S_OK;
}

SEALNETNATIVE HRESULT SEALCALL Plaintext_Scale(void *thisptr, double *scale)
{
    Plaintext *plain = FromVoid<Plaintext>(thisptr);
    IfNullRet(plain, E_POINTER);
    IfNullRet(scale, E_POINTER);

    *scale = plain->scale();
    return S_OK;
}

SEALNETNATIVE HRESULT SEALCALL Plaintext_SetScale(void *thisptr, double scale)
{
    Plaintext *plain = FromVoid<Plaintext>(thisptr);
    IfNullRet(plain, E_POINTER);

    Plaintext::PlaintextPrivateHelper::set_scale(plain, scale);
    return S_OK;
}

SEALNETNATIVE HRESULT SEALCALL Plaintext_Equals(void *thisptr, void *other, bool *result)
{
    Plaintext *plain = FromVoid<Plaintext>(thisptr);
    IfNullRet(plain, E_POINTER);
    Plaintext *otherptr = FromVoid<Plaintext>(other);
    IfNullRet(otherptr, E_POINTER);
    IfNullRet(result, E_POINTER);

    *result = (*plain == *otherptr);
    return S_OK;
}

SEALNETNATIVE HRESULT SEALCALL Plaintext_SwapData(void *thisptr, uint64_t count, uint64_t *new_data)
{
    Plaintext *plain = FromVoid<Plaintext>(thisptr);
    IfNullRet(plain, E_POINTER);
    IfNullRet(new_data, E_POINTER);

    IntArray<uint64_t> new_array(plain->pool());
    new_array.resize(count);
    copy_n(new_data, count, new_array.begin());

    Plaintext::PlaintextPrivateHelper::swap_data(plain, new_array);
    return S_OK;
}

SEALNETNATIVE HRESULT SEALCALL Plaintext_Pool(void *thisptr, void **pool)
{
    Plaintext *plain = FromVoid<Plaintext>(thisptr);
    IfNullRet(plain, E_POINTER);
    IfNullRet(pool, E_POINTER);

    MemoryPoolHandle *handleptr = new MemoryPoolHandle(plain->pool());
    *pool = handleptr;
    return S_OK;
}
