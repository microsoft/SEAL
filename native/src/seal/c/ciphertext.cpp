// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

// SEALNet
#include "seal/c/ciphertext.h"
#include "seal/c/stdafx.h"
#include "seal/c/utilities.h"

// SEAL
#include "seal/ciphertext.h"

using namespace std;
using namespace seal;
using namespace seal::c;

namespace seal
{
    /**
    Enables access to private members of seal::Ciphertext.
    */
    struct Ciphertext::CiphertextPrivateHelper
    {
        static void resize(Ciphertext *ciphertext, size_t size, size_t poly_modulus_degree, size_t coeff_modulus_size)
        {
            ciphertext->resize_internal(size, poly_modulus_degree, coeff_modulus_size);
        }

        static void set_ntt_form(Ciphertext *ciphertext, bool is_ntt_form)
        {
            ciphertext->is_ntt_form_ = is_ntt_form;
        }
    };
} // namespace seal

SEAL_C_FUNC Ciphertext_Create1(void *memoryPoolHandle, void **ciphertext)
{
    IfNullRet(ciphertext, E_POINTER);
    unique_ptr<MemoryPoolHandle> handle = MemHandleFromVoid(memoryPoolHandle);

    try
    {
        Ciphertext *cipher = new Ciphertext(*handle);
        *ciphertext = cipher;
        return S_OK;
    }
    catch (const invalid_argument &)
    {
        return E_INVALIDARG;
    }
}

SEAL_C_FUNC Ciphertext_Create2(void *copy, void **ciphertext)
{
    Ciphertext *copyptr = FromVoid<Ciphertext>(copy);
    IfNullRet(copyptr, E_POINTER);
    IfNullRet(ciphertext, E_POINTER);

    Ciphertext *cipher = new Ciphertext(*copyptr);
    *ciphertext = cipher;
    return S_OK;
}

SEAL_C_FUNC Ciphertext_Create3(void *context, void *pool, void **ciphertext)
{
    const auto &sharedctx = SharedContextFromVoid(context);
    IfNullRet(sharedctx.get(), E_POINTER);
    IfNullRet(ciphertext, E_POINTER);
    unique_ptr<MemoryPoolHandle> pool_ptr = MemHandleFromVoid(pool);

    try
    {
        Ciphertext *cipher = new Ciphertext(sharedctx, *pool_ptr);
        *ciphertext = cipher;
        return S_OK;
    }
    catch (const invalid_argument &)
    {
        return E_INVALIDARG;
    }
}

SEAL_C_FUNC Ciphertext_Create4(void *context, uint64_t *parms_id, void *pool, void **ciphertext)
{
    const auto &sharedctx = SharedContextFromVoid(context);
    IfNullRet(sharedctx.get(), E_POINTER);
    IfNullRet(parms_id, E_POINTER);
    IfNullRet(ciphertext, E_POINTER);
    unique_ptr<MemoryPoolHandle> pool_ptr = MemHandleFromVoid(pool);

    try
    {
        parms_id_type parmsid;
        CopyParmsId(parms_id, parmsid);

        Ciphertext *cipher = new Ciphertext(sharedctx, parmsid, *pool_ptr);
        *ciphertext = cipher;
        return S_OK;
    }
    catch (const invalid_argument &)
    {
        return E_INVALIDARG;
    }
}

SEAL_C_FUNC Ciphertext_Create5(void *context, uint64_t *parms_id, uint64_t capacity, void *pool, void **ciphertext)
{
    const auto &sharedctx = SharedContextFromVoid(context);
    IfNullRet(sharedctx.get(), E_POINTER);
    IfNullRet(parms_id, E_POINTER);
    IfNullRet(ciphertext, E_POINTER);
    unique_ptr<MemoryPoolHandle> pool_ptr = MemHandleFromVoid(pool);

    try
    {
        parms_id_type parmsid;
        CopyParmsId(parms_id, parmsid);

        Ciphertext *cipher = new Ciphertext(sharedctx, parmsid, capacity, *pool_ptr);
        *ciphertext = cipher;
        return S_OK;
    }
    catch (const invalid_argument &)
    {
        return E_INVALIDARG;
    }
}

SEAL_C_FUNC Ciphertext_Reserve1(void *thisptr, void *context, uint64_t *parms_id, uint64_t size_capacity)
{
    const auto &sharedctx = SharedContextFromVoid(context);
    IfNullRet(sharedctx.get(), E_POINTER);
    Ciphertext *cipher = FromVoid<Ciphertext>(thisptr);
    IfNullRet(cipher, E_POINTER);
    IfNullRet(parms_id, E_POINTER);

    parms_id_type parms;
    CopyParmsId(parms_id, parms);

    try
    {
        cipher->reserve(sharedctx, parms, size_capacity);
        return S_OK;
    }
    catch (const invalid_argument &)
    {
        return E_INVALIDARG;
    }
}

SEAL_C_FUNC Ciphertext_Reserve2(void *thisptr, void *context, uint64_t size_capacity)
{
    Ciphertext *cipher = FromVoid<Ciphertext>(thisptr);
    IfNullRet(cipher, E_POINTER);
    const auto &sharedctx = SharedContextFromVoid(context);
    IfNullRet(sharedctx.get(), E_POINTER);

    try
    {
        cipher->reserve(sharedctx, size_capacity);
        return S_OK;
    }
    catch (const invalid_argument &)
    {
        return E_INVALIDARG;
    }
}

SEAL_C_FUNC Ciphertext_Reserve3(void *thisptr, uint64_t size_capacity)
{
    Ciphertext *cipher = FromVoid<Ciphertext>(thisptr);
    IfNullRet(cipher, E_POINTER);

    try
    {
        cipher->reserve(size_capacity);
        return S_OK;
    }
    catch (const invalid_argument &)
    {
        return E_INVALIDARG;
    }
}

SEAL_C_FUNC Ciphertext_Set(void *thisptr, void *assign)
{
    Ciphertext *cipher = FromVoid<Ciphertext>(thisptr);
    IfNullRet(cipher, E_POINTER);
    Ciphertext *assignptr = FromVoid<Ciphertext>(assign);
    IfNullRet(assignptr, E_POINTER);

    *cipher = *assignptr;
    return S_OK;
}

SEAL_C_FUNC Ciphertext_Destroy(void *thisptr)
{
    Ciphertext *cipher = FromVoid<Ciphertext>(thisptr);
    IfNullRet(cipher, E_POINTER);

    delete cipher;
    return S_OK;
}

SEAL_C_FUNC Ciphertext_Size(void *thisptr, uint64_t *size)
{
    Ciphertext *cipher = FromVoid<Ciphertext>(thisptr);
    IfNullRet(cipher, E_POINTER);
    IfNullRet(size, E_POINTER);

    *size = cipher->size();
    return S_OK;
}

SEAL_C_FUNC Ciphertext_SizeCapacity(void *thisptr, uint64_t *size_capacity)
{
    Ciphertext *cipher = FromVoid<Ciphertext>(thisptr);
    IfNullRet(cipher, E_POINTER);
    IfNullRet(size_capacity, E_POINTER);

    *size_capacity = cipher->size_capacity();
    return S_OK;
}

SEAL_C_FUNC Ciphertext_PolyModulusDegree(void *thisptr, uint64_t *poly_modulus_degree)
{
    Ciphertext *cipher = FromVoid<Ciphertext>(thisptr);
    IfNullRet(cipher, E_POINTER);
    IfNullRet(poly_modulus_degree, E_POINTER);

    *poly_modulus_degree = cipher->poly_modulus_degree();
    return S_OK;
}

SEAL_C_FUNC Ciphertext_CoeffModulusSize(void *thisptr, uint64_t *coeff_modulus_size)
{
    Ciphertext *cipher = FromVoid<Ciphertext>(thisptr);
    IfNullRet(cipher, E_POINTER);
    IfNullRet(coeff_modulus_size, E_POINTER);

    *coeff_modulus_size = cipher->coeff_modulus_size();
    return S_OK;
}

SEAL_C_FUNC Ciphertext_ParmsId(void *thisptr, uint64_t *parms_id)
{
    Ciphertext *cipher = FromVoid<Ciphertext>(thisptr);
    IfNullRet(cipher, E_POINTER);
    IfNullRet(parms_id, E_POINTER);

    CopyParmsId(cipher->parms_id(), parms_id);
    return S_OK;
}

SEAL_C_FUNC Ciphertext_SetParmsId(void *thisptr, uint64_t *parms_id)
{
    Ciphertext *cipher = FromVoid<Ciphertext>(thisptr);
    IfNullRet(cipher, E_POINTER);
    IfNullRet(parms_id, E_POINTER);

    CopyParmsId(parms_id, cipher->parms_id());
    return S_OK;
}

SEAL_C_FUNC Ciphertext_Resize1(void *thisptr, void *context, uint64_t *parms_id, uint64_t size)
{
    Ciphertext *cipher = FromVoid<Ciphertext>(thisptr);
    IfNullRet(cipher, E_POINTER);

    const auto &sharedctx = SharedContextFromVoid(context);
    IfNullRet(sharedctx.get(), E_POINTER);

    parms_id_type parms;
    CopyParmsId(parms_id, parms);

    try
    {
        cipher->resize(sharedctx, parms, size);
        return S_OK;
    }
    catch (const invalid_argument &)
    {
        return E_INVALIDARG;
    }
}

SEAL_C_FUNC Ciphertext_Resize2(void *thisptr, void *context, uint64_t size)
{
    Ciphertext *cipher = FromVoid<Ciphertext>(thisptr);
    IfNullRet(cipher, E_POINTER);

    const auto &sharedctx = SharedContextFromVoid(context);
    IfNullRet(sharedctx.get(), E_POINTER);

    try
    {
        cipher->resize(sharedctx, size);
        return S_OK;
    }
    catch (const invalid_argument &)
    {
        return E_INVALIDARG;
    }
}

SEAL_C_FUNC Ciphertext_Resize3(void *thisptr, uint64_t size)
{
    Ciphertext *cipher = FromVoid<Ciphertext>(thisptr);
    IfNullRet(cipher, E_POINTER);

    try
    {
        cipher->resize(size);
        return S_OK;
    }
    catch (const invalid_argument &)
    {
        return E_INVALIDARG;
    }
}

SEAL_C_FUNC Ciphertext_Resize4(void *thisptr, uint64_t size, uint64_t polyModulusDegree, uint64_t coeffModCount)
{
    Ciphertext *cipher = FromVoid<Ciphertext>(thisptr);
    IfNullRet(cipher, E_POINTER);

    try
    {
        Ciphertext::CiphertextPrivateHelper::resize(cipher, size, polyModulusDegree, coeffModCount);
        return S_OK;
    }
    catch (const invalid_argument &)
    {
        return E_INVALIDARG;
    }
}

SEAL_C_FUNC Ciphertext_GetDataAt1(void *thisptr, uint64_t index, uint64_t *data)
{
    Ciphertext *cipher = FromVoid<Ciphertext>(thisptr);
    IfNullRet(cipher, E_POINTER);
    IfNullRet(data, E_POINTER);

    try
    {
        *data = (*cipher)[index];
        return S_OK;
    }
    catch (const out_of_range &)
    {
        return HRESULT_FROM_WIN32(ERROR_INVALID_INDEX);
    }
}

SEAL_C_FUNC Ciphertext_GetDataAt2(void *thisptr, uint64_t poly_index, uint64_t coeff_index, uint64_t *data)
{
    Ciphertext *cipher = FromVoid<Ciphertext>(thisptr);
    IfNullRet(cipher, E_POINTER);
    IfNullRet(data, E_POINTER);

    auto poly_uint64_count = util::mul_safe(cipher->poly_modulus_degree(), cipher->coeff_modulus_size());

    // poly_index is verified by the data method, we need to verify coeff_index ourselves.
    if (coeff_index >= poly_uint64_count)
        return HRESULT_FROM_WIN32(ERROR_INVALID_INDEX);

    try
    {
        *data = cipher->data(poly_index)[coeff_index];
        return S_OK;
    }
    catch (const out_of_range &)
    {
        return HRESULT_FROM_WIN32(ERROR_INVALID_INDEX);
    }
}

SEAL_C_FUNC Ciphertext_SetDataAt(void *thisptr, uint64_t index, uint64_t value)
{
    Ciphertext *cipher = FromVoid<Ciphertext>(thisptr);
    IfNullRet(cipher, E_POINTER);

    try
    {
        (*cipher)[index] = value;
        return S_OK;
    }
    catch (const out_of_range &)
    {
        return HRESULT_FROM_WIN32(ERROR_INVALID_INDEX);
    }
}

SEAL_C_FUNC Ciphertext_IsNTTForm(void *thisptr, bool *is_ntt_form)
{
    Ciphertext *cipher = FromVoid<Ciphertext>(thisptr);
    IfNullRet(cipher, E_POINTER);
    IfNullRet(is_ntt_form, E_POINTER);

    *is_ntt_form = cipher->is_ntt_form();
    return S_OK;
}

SEAL_C_FUNC Ciphertext_SetIsNTTForm(void *thisptr, bool is_ntt_form)
{
    Ciphertext *cipher = FromVoid<Ciphertext>(thisptr);
    IfNullRet(cipher, E_POINTER);

    Ciphertext::CiphertextPrivateHelper::set_ntt_form(cipher, is_ntt_form);
    return S_OK;
}

SEAL_C_FUNC Ciphertext_Scale(void *thisptr, double *scale)
{
    Ciphertext *cipher = FromVoid<Ciphertext>(thisptr);
    IfNullRet(cipher, E_POINTER);
    IfNullRet(scale, E_POINTER);

    *scale = cipher->scale();
    return S_OK;
}

SEAL_C_FUNC Ciphertext_SetScale(void *thisptr, double scale)
{
    Ciphertext *cipher = FromVoid<Ciphertext>(thisptr);
    IfNullRet(cipher, E_POINTER);

    cipher->scale() = scale;
    return S_OK;
}

SEAL_C_FUNC Ciphertext_Release(void *thisptr)
{
    Ciphertext *cipher = FromVoid<Ciphertext>(thisptr);
    IfNullRet(cipher, E_POINTER);

    cipher->release();
    return S_OK;
}

SEAL_C_FUNC Ciphertext_IsTransparent(void *thisptr, bool *result)
{
    Ciphertext *cipher = FromVoid<Ciphertext>(thisptr);
    IfNullRet(cipher, E_POINTER);
    IfNullRet(result, E_POINTER);

    *result = cipher->is_transparent();
    return S_OK;
}

SEAL_C_FUNC Ciphertext_Pool(void *thisptr, void **pool)
{
    Ciphertext *cipher = FromVoid<Ciphertext>(thisptr);
    IfNullRet(cipher, E_POINTER);
    IfNullRet(pool, E_POINTER);

    MemoryPoolHandle *handleptr = new MemoryPoolHandle(cipher->pool());
    *pool = handleptr;
    return S_OK;
}

SEAL_C_FUNC Ciphertext_SaveSize(void *thisptr, uint8_t compr_mode, int64_t *result)
{
    Ciphertext *cipher = FromVoid<Ciphertext>(thisptr);
    IfNullRet(cipher, E_POINTER);
    IfNullRet(result, E_POINTER);

    try
    {
        *result = static_cast<int64_t>(cipher->save_size(static_cast<compr_mode_type>(compr_mode)));
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

SEAL_C_FUNC Ciphertext_Save(void *thisptr, uint8_t *outptr, uint64_t size, uint8_t compr_mode, int64_t *out_bytes)
{
    Ciphertext *cipher = FromVoid<Ciphertext>(thisptr);
    IfNullRet(cipher, E_POINTER);
    IfNullRet(outptr, E_POINTER);
    IfNullRet(out_bytes, E_POINTER);

    try
    {
        *out_bytes = util::safe_cast<int64_t>(cipher->save(
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

SEAL_C_FUNC Ciphertext_UnsafeLoad(void *thisptr, void *context, uint8_t *inptr, uint64_t size, int64_t *in_bytes)
{
    Ciphertext *cipher = FromVoid<Ciphertext>(thisptr);
    IfNullRet(cipher, E_POINTER);
    const auto &sharedctx = SharedContextFromVoid(context);
    IfNullRet(sharedctx.get(), E_POINTER);
    IfNullRet(inptr, E_POINTER);
    IfNullRet(in_bytes, E_POINTER);

    try
    {
        *in_bytes = util::safe_cast<int64_t>(
            cipher->unsafe_load(sharedctx, reinterpret_cast<SEAL_BYTE *>(inptr), util::safe_cast<size_t>(size)));
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

SEAL_C_FUNC Ciphertext_Load(void *thisptr, void *context, uint8_t *inptr, uint64_t size, int64_t *in_bytes)
{
    Ciphertext *cipher = FromVoid<Ciphertext>(thisptr);
    IfNullRet(cipher, E_POINTER);
    const auto &sharedctx = SharedContextFromVoid(context);
    IfNullRet(sharedctx.get(), E_POINTER);
    IfNullRet(inptr, E_POINTER);
    IfNullRet(in_bytes, E_POINTER);

    try
    {
        *in_bytes = util::safe_cast<int64_t>(
            cipher->load(sharedctx, reinterpret_cast<SEAL_BYTE *>(inptr), util::safe_cast<size_t>(size)));
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
