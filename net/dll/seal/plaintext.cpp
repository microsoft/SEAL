// STD
#include <string>

// SEALDll
#include "stdafx.h"
#include "plaintext.h"
#include "utilities.h"

// SEAL
#include "seal/plaintext.h"

using namespace std;
using namespace seal;
using namespace seal::dll;


namespace seal
{
    /**
    Enables access to private members of seal::Plaintext.
    */
    struct Plaintext::PlaintextPrivateHelper
    {
        static void set_scale(seal::Plaintext* plain, double new_scale)
        {
            plain->scale_ = new_scale;
        }
    };
}


SEALDLL HRESULT SEALCALL Plaintext_Create1(void* memoryPoolHandle, void** plaintext)
{
    IfNullRet(plaintext, E_POINTER);
    MemoryPoolHandle* handle = FromVoid<MemoryPoolHandle>(memoryPoolHandle);
    if (nullptr == handle)
        handle = &MemoryManager::GetPool();
    Plaintext* plain = nullptr;

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

SEALDLL HRESULT SEALCALL Plaintext_Create2(int coeffCount, void* memoryPoolHandle, void** plaintext)
{
    IfNullRet(plaintext, E_POINTER);
    MemoryPoolHandle* handle = FromVoid<MemoryPoolHandle>(memoryPoolHandle);
    if (nullptr == handle)
        handle = &MemoryManager::GetPool();
    Plaintext* plain = nullptr;

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

SEALDLL HRESULT SEALCALL Plaintext_Create3(int capacity, int coeffCount, void* memoryPoolHandle, void** plaintext)
{
    IfNullRet(plaintext, E_POINTER);
    MemoryPoolHandle* handle = FromVoid<MemoryPoolHandle>(memoryPoolHandle);
    if (nullptr == handle)
        handle = &MemoryManager::GetPool();
    Plaintext* plain = nullptr;

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

SEALDLL HRESULT SEALCALL Plaintext_Create4(char* hexPoly, void* memoryPoolHandle, void** plaintext)
{
    IfNullRet(plaintext, E_POINTER);
    IfNullRet(hexPoly, E_POINTER);
    MemoryPoolHandle* handle = FromVoid<MemoryPoolHandle>(memoryPoolHandle);
    if (nullptr == handle)
        handle = &MemoryManager::GetPool();
    string hexPolyStr(hexPoly);

    try
    {
        Plaintext* plain = new Plaintext(hexPolyStr, *handle);
        *plaintext = plain;
        return S_OK;
    }
    catch (const invalid_argument&)
    {
        return E_INVALIDARG;
    }

    return E_UNEXPECTED;
}

SEALDLL HRESULT SEALCALL Plaintext_Set1(void* thisptr, void* assign)
{
    Plaintext* plain = FromVoid<Plaintext>(thisptr);
    IfNullRet(plain, E_POINTER);
    Plaintext* assignptr = FromVoid<Plaintext>(assign);
    IfNullRet(assignptr, E_POINTER);

    *plain = *assignptr;
    return S_OK;
}

SEALDLL HRESULT SEALCALL Plaintext_Set2(void *thisptr, char* hex_poly)
{
    Plaintext* plain = FromVoid<Plaintext>(thisptr);
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

SEALDLL HRESULT SEALCALL Plaintext_Set3(void *thisptr, uint64_t const_coeff)
{
    Plaintext* plain = FromVoid<Plaintext>(thisptr);
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

SEALDLL HRESULT SEALCALL Plaintext_Destroy(void* thisptr)
{
    Plaintext* plain = FromVoid<Plaintext>(thisptr);
    IfNullRet(plain, E_POINTER);

    delete plain;
    return S_OK;
}

SEALDLL HRESULT SEALCALL Plaintext_CoeffCount(void* thisptr, int* coeff_count)
{
    Plaintext* plain = FromVoid<Plaintext>(thisptr);
    IfNullRet(plain, E_POINTER);
    IfNullRet(coeff_count, E_POINTER);

    *coeff_count = static_cast<int>(plain->coeff_count());
    return S_OK;
}

SEALDLL HRESULT SEALCALL Plaintext_CoeffAt(void* thisptr, int index, uint64_t* coeff)
{
    Plaintext* plain = FromVoid<Plaintext>(thisptr);
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

SEALDLL HRESULT SEALCALL Plaintext_SetCoeffAt(void* thisptr, int index, uint64_t value)
{
    Plaintext* plain = FromVoid<Plaintext>(thisptr);
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

SEALDLL HRESULT SEALCALL Plaintext_ToString(void* thispt, int* length, char* outstr)
{
    Plaintext* plain = FromVoid<Plaintext>(thispt);
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

SEALDLL HRESULT SEALCALL Plaintext_IsNTTForm(void* thisptr, bool* is_ntt_form)
{
    Plaintext* plain = FromVoid<Plaintext>(thisptr);
    IfNullRet(plain, E_POINTER);
    IfNullRet(is_ntt_form, E_POINTER);

    *is_ntt_form = plain->is_ntt_form();
    return S_OK;
}

SEALDLL HRESULT SEALCALL Plaintext_IsZero(void* thisptr, bool* is_zero)
{
    Plaintext* plain = FromVoid<Plaintext>(thisptr);
    IfNullRet(plain, E_POINTER);
    IfNullRet(is_zero, E_POINTER);

    *is_zero = plain->is_zero();
    return S_OK;
}

SEALDLL HRESULT SEALCALL Plaintext_GetParmsId(void* thisptr, uint64_t* parms_id)
{
    Plaintext* plain = FromVoid<Plaintext>(thisptr);
    IfNullRet(plain, E_POINTER);
    IfNullRet(parms_id, E_POINTER);

    for (int i = 0; i < plain->parms_id().size(); i++)
    {
        parms_id[i] = plain->parms_id()[i];
    }

    return S_OK;
}

SEALDLL HRESULT SEALCALL Plaintext_SetParmsId(void* thisptr, uint64_t* parms_id)
{
    Plaintext* plain = FromVoid<Plaintext>(thisptr);
    IfNullRet(plain, E_POINTER);
    IfNullRet(parms_id, E_POINTER);

    memcpy(plain->parms_id().data(), parms_id, sizeof(uint64_t) * plain->parms_id().size());
    return S_OK;
}

SEALDLL HRESULT SEALCALL Plaintext_SetZero1(void *thisptr)
{
    Plaintext* plain = FromVoid<Plaintext>(thisptr);
    IfNullRet(plain, E_POINTER);

    plain->set_zero();
    return S_OK;
}

SEALDLL HRESULT SEALCALL Plaintext_SetZero2(void *thisptr, int start_coeff)
{
    Plaintext* plain = FromVoid<Plaintext>(thisptr);
    IfNullRet(plain, E_POINTER);

    try
    {
        plain->set_zero(start_coeff);
        return S_OK;
    }
    catch (const out_of_range&)
    {
        return HRESULT_FROM_WIN32(ERROR_INVALID_INDEX);
    }
}

SEALDLL HRESULT SEALCALL Plaintext_SetZero3(void *thisptr, int start_coeff, int length)
{
    Plaintext* plain = FromVoid<Plaintext>(thisptr);
    IfNullRet(plain, E_POINTER);

    try
    {
        plain->set_zero(start_coeff, length);
        return S_OK;
    }
    catch (const out_of_range&)
    {
        return HRESULT_FROM_WIN32(ERROR_INVALID_INDEX);
    }
}

SEALDLL HRESULT SEALCALL Plaintext_Reserve(void* thisptr, int capacity)
{
    Plaintext* plain = FromVoid<Plaintext>(thisptr);
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

SEALDLL HRESULT SEALCALL Plaintext_Resize(void* thisptr, int coeff_count)
{
    Plaintext* plain = FromVoid<Plaintext>(thisptr);
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

SEALDLL HRESULT SEALCALL Plaintext_ShrinkToFit(void* thisptr)
{
    Plaintext* plain = FromVoid<Plaintext>(thisptr);
    IfNullRet(plain, E_POINTER);

    plain->shrink_to_fit();
    return S_OK;
}

SEALDLL HRESULT SEALCALL Plaintext_Release(void* thisptr)
{
    Plaintext* plain = FromVoid<Plaintext>(thisptr);
    IfNullRet(plain, E_POINTER);

    plain->release();
    return S_OK;
}

SEALDLL HRESULT SEALCALL Plaintext_Capacity(void* thisptr, int* capacity)
{
    Plaintext* plain = FromVoid<Plaintext>(thisptr);
    IfNullRet(plain, E_POINTER);
    IfNullRet(capacity, E_POINTER);

    *capacity = static_cast<int>(plain->capacity());
    return S_OK;
}

SEALDLL HRESULT SEALCALL Plaintext_SignificantCoeffCount(void* thisptr, int* significant_coeff_count)
{
    Plaintext* plain = FromVoid<Plaintext>(thisptr);
    IfNullRet(plain, E_POINTER);
    IfNullRet(significant_coeff_count, E_POINTER);

    *significant_coeff_count = static_cast<int>(plain->significant_coeff_count());
    return S_OK;
}

SEALDLL HRESULT SEALCALL Plaintext_Scale(void* thisptr, double* scale)
{
    Plaintext* plain = FromVoid<Plaintext>(thisptr);
    IfNullRet(plain, E_POINTER);
    IfNullRet(scale, E_POINTER);

    *scale = plain->scale();
    return S_OK;
}

SEALDLL HRESULT SEALCALL Plaintext_SetScale(void* thisptr, double scale)
{
    Plaintext* plain = FromVoid<Plaintext>(thisptr);
    IfNullRet(plain, E_POINTER);

    Plaintext::PlaintextPrivateHelper::set_scale(plain, scale);
    return S_OK;
}

SEALDLL HRESULT SEALCALL Plaintext_Equals(void *thisptr, void* other, bool* result)
{
    Plaintext* plain = FromVoid<Plaintext>(thisptr);
    IfNullRet(plain, E_POINTER);
    Plaintext* otherptr = FromVoid<Plaintext>(other);
    IfNullRet(otherptr, E_POINTER);
    IfNullRet(result, E_POINTER);

    *result = (*plain == *otherptr);
    return S_OK;
}
