// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

// STD
#include <algorithm>
#include <iterator>

// SEALNet
#include "seal/c/evaluator.h"
#include "seal/c/stdafx.h"
#include "seal/c/utilities.h"

// SEAL
#include "seal/context.h"
#include "seal/evaluator.h"
#include "seal/util/common.h"

using namespace std;
using namespace seal;
using namespace seal::c;
using namespace seal::util;

struct seal::Evaluator::EvaluatorPrivateHelper
{
    static bool using_keyswitching(const Evaluator &ev)
    {
        return ev.context_->using_keyswitching();
    }
};

SEAL_C_FUNC Evaluator_Create(void *sealContext, void **evaluator)
{
    SEALContext *context = FromVoid<SEALContext>(sealContext);
    IfNullRet(context, E_POINTER);
    const auto &sharedctx = SharedContextFromVoid(sealContext);
    IfNullRet(sharedctx.get(), E_POINTER);
    IfNullRet(evaluator, E_POINTER);

    try
    {
        Evaluator *eval = new Evaluator(sharedctx);
        *evaluator = eval;
        return S_OK;
    }
    catch (const invalid_argument &)
    {
        return E_INVALIDARG;
    }
}

SEAL_C_FUNC Evaluator_Destroy(void *thisptr)
{
    Evaluator *eval = FromVoid<Evaluator>(thisptr);
    IfNullRet(eval, E_POINTER);

    delete eval;
    return S_OK;
}

SEAL_C_FUNC Evaluator_Negate(void *thisptr, void *encrypted, void *destination)
{
    Evaluator *eval = FromVoid<Evaluator>(thisptr);
    IfNullRet(eval, E_POINTER);
    Ciphertext *encrypted_ptr = FromVoid<Ciphertext>(encrypted);
    IfNullRet(encrypted_ptr, E_POINTER);
    Ciphertext *destination_ptr = FromVoid<Ciphertext>(destination);
    IfNullRet(destination_ptr, E_POINTER);

    try
    {
        eval->negate(*encrypted_ptr, *destination_ptr);
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

SEAL_C_FUNC Evaluator_Add(void *thisptr, void *encrypted1, void *encrypted2, void *destination)
{
    Evaluator *eval = FromVoid<Evaluator>(thisptr);
    IfNullRet(eval, E_POINTER);
    Ciphertext *encrypted1_ptr = FromVoid<Ciphertext>(encrypted1);
    IfNullRet(encrypted1_ptr, E_POINTER);
    Ciphertext *encrypted2_ptr = FromVoid<Ciphertext>(encrypted2);
    IfNullRet(encrypted2_ptr, E_POINTER);
    Ciphertext *destination_ptr = FromVoid<Ciphertext>(destination);
    IfNullRet(destination_ptr, E_POINTER);

    try
    {
        eval->add(*encrypted1_ptr, *encrypted2_ptr, *destination_ptr);
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

SEAL_C_FUNC Evaluator_AddMany(void *thisptr, uint64_t count, void **encrypteds, void *destination)
{
    Evaluator *eval = FromVoid<Evaluator>(thisptr);
    IfNullRet(eval, E_POINTER);
    IfNullRet(encrypteds, E_POINTER);
    Ciphertext *destination_ptr = FromVoid<Ciphertext>(destination);
    IfNullRet(destination_ptr, E_POINTER);

    Ciphertext **encrypteds_pp = reinterpret_cast<Ciphertext **>(encrypteds);
    vector<Ciphertext> encrypteds_vec;

    encrypteds_vec.reserve(count);
    for (uint64_t i = 0; i < count; i++)
    {
        encrypteds_vec.emplace_back(*encrypteds_pp[i]);
    }

    try
    {
        eval->add_many(encrypteds_vec, *destination_ptr);
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

SEAL_C_FUNC Evaluator_AddPlain(void *thisptr, void *encrypted, void *plain, void *destination)
{
    Evaluator *eval = FromVoid<Evaluator>(thisptr);
    IfNullRet(eval, E_POINTER);
    Ciphertext *encrypted_ptr = FromVoid<Ciphertext>(encrypted);
    IfNullRet(encrypted_ptr, E_POINTER);
    Plaintext *plain_ptr = FromVoid<Plaintext>(plain);
    IfNullRet(plain_ptr, E_POINTER);
    Ciphertext *destination_ptr = FromVoid<Ciphertext>(destination);
    IfNullRet(destination_ptr, E_POINTER);

    try
    {
        eval->add_plain(*encrypted_ptr, *plain_ptr, *destination_ptr);
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

SEAL_C_FUNC Evaluator_Sub(void *thisptr, void *encrypted1, void *encrypted2, void *destination)
{
    Evaluator *eval = FromVoid<Evaluator>(thisptr);
    IfNullRet(eval, E_POINTER);
    Ciphertext *encrypted1_ptr = FromVoid<Ciphertext>(encrypted1);
    IfNullRet(encrypted1_ptr, E_POINTER);
    Ciphertext *encrypted2_ptr = FromVoid<Ciphertext>(encrypted2);
    IfNullRet(encrypted2_ptr, E_POINTER);
    Ciphertext *destination_ptr = FromVoid<Ciphertext>(destination);
    IfNullRet(destination_ptr, E_POINTER);

    try
    {
        eval->sub(*encrypted1_ptr, *encrypted2_ptr, *destination_ptr);
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

SEAL_C_FUNC Evaluator_SubPlain(void *thisptr, void *encrypted, void *plain, void *destination)
{
    Evaluator *eval = FromVoid<Evaluator>(thisptr);
    IfNullRet(eval, E_POINTER);
    Ciphertext *encrypted_ptr = FromVoid<Ciphertext>(encrypted);
    IfNullRet(encrypted_ptr, E_POINTER);
    Plaintext *plain_ptr = FromVoid<Plaintext>(plain);
    IfNullRet(plain_ptr, E_POINTER);
    Ciphertext *destination_ptr = FromVoid<Ciphertext>(destination);
    IfNullRet(destination_ptr, E_POINTER);

    try
    {
        eval->sub_plain(*encrypted_ptr, *plain_ptr, *destination_ptr);
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

SEAL_C_FUNC Evaluator_Multiply(void *thisptr, void *encrypted1, void *encrypted2, void *destination, void *pool)
{
    Evaluator *eval = FromVoid<Evaluator>(thisptr);
    IfNullRet(eval, E_POINTER);
    Ciphertext *encrypted1_ptr = FromVoid<Ciphertext>(encrypted1);
    IfNullRet(encrypted1_ptr, E_POINTER);
    Ciphertext *encrypted2_ptr = FromVoid<Ciphertext>(encrypted2);
    IfNullRet(encrypted2_ptr, E_POINTER);
    Ciphertext *destination_ptr = FromVoid<Ciphertext>(destination);
    IfNullRet(destination_ptr, E_POINTER);
    unique_ptr<MemoryPoolHandle> pool_ptr = MemHandleFromVoid(pool);

    try
    {
        eval->multiply(*encrypted1_ptr, *encrypted2_ptr, *destination_ptr, *pool_ptr);
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

SEAL_C_FUNC Evaluator_MultiplyMany(
    void *thisptr, uint64_t count, void **encrypteds, void *relin_keys, void *destination, void *pool)
{
    Evaluator *eval = FromVoid<Evaluator>(thisptr);
    IfNullRet(eval, E_POINTER);
    IfNullRet(encrypteds, E_POINTER);
    RelinKeys *relin_keys_ptr = FromVoid<RelinKeys>(relin_keys);
    IfNullRet(relin_keys_ptr, E_POINTER);
    Ciphertext *destination_ptr = FromVoid<Ciphertext>(destination);
    IfNullRet(destination_ptr, E_POINTER);
    unique_ptr<MemoryPoolHandle> pool_ptr = MemHandleFromVoid(pool);

    Ciphertext **encrypteds_pp = reinterpret_cast<Ciphertext **>(encrypteds);
    vector<Ciphertext> encrypteds_vec;

    encrypteds_vec.reserve(count);
    for (uint64_t i = 0; i < count; i++)
    {
        encrypteds_vec.emplace_back(*encrypteds_pp[i]);
    }

    try
    {
        eval->multiply_many(encrypteds_vec, *relin_keys_ptr, *destination_ptr, *pool_ptr);
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

SEAL_C_FUNC Evaluator_MultiplyPlain(void *thisptr, void *encrypted, void *plain, void *destination, void *pool)
{
    Evaluator *eval = FromVoid<Evaluator>(thisptr);
    IfNullRet(eval, E_POINTER);
    Ciphertext *encrypted_ptr = FromVoid<Ciphertext>(encrypted);
    IfNullRet(encrypted_ptr, E_POINTER);
    Plaintext *plain_ptr = FromVoid<Plaintext>(plain);
    IfNullRet(plain_ptr, E_POINTER);
    Ciphertext *destination_ptr = FromVoid<Ciphertext>(destination);
    IfNullRet(destination_ptr, E_POINTER);
    unique_ptr<MemoryPoolHandle> pool_ptr = MemHandleFromVoid(pool);

    try
    {
        eval->multiply_plain(*encrypted_ptr, *plain_ptr, *destination_ptr, *pool_ptr);
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

SEAL_C_FUNC Evaluator_Square(void *thisptr, void *encrypted, void *destination, void *pool)
{
    Evaluator *eval = FromVoid<Evaluator>(thisptr);
    IfNullRet(eval, E_POINTER);
    Ciphertext *encrypted_ptr = FromVoid<Ciphertext>(encrypted);
    IfNullRet(encrypted_ptr, E_POINTER);
    Ciphertext *destination_ptr = FromVoid<Ciphertext>(destination);
    IfNullRet(destination_ptr, E_POINTER);
    unique_ptr<MemoryPoolHandle> pool_ptr = MemHandleFromVoid(pool);

    try
    {
        eval->square(*encrypted_ptr, *destination_ptr, *pool_ptr);
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

SEAL_C_FUNC Evaluator_Relinearize(void *thisptr, void *encrypted, void *relin_keys, void *destination, void *pool)
{
    Evaluator *eval = FromVoid<Evaluator>(thisptr);
    IfNullRet(eval, E_POINTER);
    Ciphertext *encrypted_ptr = FromVoid<Ciphertext>(encrypted);
    IfNullRet(encrypted_ptr, E_POINTER);
    RelinKeys *relin_keys_ptr = FromVoid<RelinKeys>(relin_keys);
    IfNullRet(relin_keys_ptr, E_POINTER);
    Ciphertext *destination_ptr = FromVoid<Ciphertext>(destination);
    IfNullRet(destination_ptr, E_POINTER);
    unique_ptr<MemoryPoolHandle> pool_ptr = MemHandleFromVoid(pool);

    try
    {
        eval->relinearize(*encrypted_ptr, *relin_keys_ptr, *destination_ptr, *pool_ptr);
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

SEAL_C_FUNC Evaluator_ModSwitchToNext1(void *thisptr, void *encrypted, void *destination, void *pool)
{
    Evaluator *eval = FromVoid<Evaluator>(thisptr);
    IfNullRet(eval, E_POINTER);
    Ciphertext *encrypted_ptr = FromVoid<Ciphertext>(encrypted);
    IfNullRet(encrypted_ptr, E_POINTER);
    Ciphertext *destination_ptr = FromVoid<Ciphertext>(destination);
    IfNullRet(destination_ptr, E_POINTER);
    unique_ptr<MemoryPoolHandle> pool_ptr = MemHandleFromVoid(pool);

    try
    {
        eval->mod_switch_to_next(*encrypted_ptr, *destination_ptr, *pool_ptr);
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

SEAL_C_FUNC Evaluator_ModSwitchToNext2(void *thisptr, void *plain, void *destination)
{
    Evaluator *eval = FromVoid<Evaluator>(thisptr);
    IfNullRet(eval, E_POINTER);
    Plaintext *plain_ptr = FromVoid<Plaintext>(plain);
    IfNullRet(plain_ptr, E_POINTER);
    Plaintext *destination_ptr = FromVoid<Plaintext>(destination);
    IfNullRet(destination_ptr, E_POINTER);

    try
    {
        eval->mod_switch_to_next(*plain_ptr, *destination_ptr);
        return S_OK;
    }
    catch (const invalid_argument &)
    {
        return E_INVALIDARG;
    }
}

SEAL_C_FUNC Evaluator_ModSwitchTo1(void *thisptr, void *encrypted, uint64_t *parms_id, void *destination, void *pool)
{
    Evaluator *eval = FromVoid<Evaluator>(thisptr);
    IfNullRet(eval, E_POINTER);
    Ciphertext *encrypted_ptr = FromVoid<Ciphertext>(encrypted);
    IfNullRet(encrypted_ptr, E_POINTER);
    IfNullRet(parms_id, E_POINTER);
    Ciphertext *destination_ptr = FromVoid<Ciphertext>(destination);
    IfNullRet(destination_ptr, E_POINTER);
    unique_ptr<MemoryPoolHandle> pool_ptr = MemHandleFromVoid(pool);

    parms_id_type parms;
    CopyParmsId(parms_id, parms);

    try
    {
        eval->mod_switch_to(*encrypted_ptr, parms, *destination_ptr, *pool_ptr);
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

SEAL_C_FUNC Evaluator_ModSwitchTo2(void *thisptr, void *plain, uint64_t *parms_id, void *destination)
{
    Evaluator *eval = FromVoid<Evaluator>(thisptr);
    IfNullRet(eval, E_POINTER);
    Plaintext *plain_ptr = FromVoid<Plaintext>(plain);
    IfNullRet(plain_ptr, E_POINTER);
    IfNullRet(parms_id, E_POINTER);
    Plaintext *destination_ptr = FromVoid<Plaintext>(destination);
    IfNullRet(destination_ptr, E_POINTER);

    parms_id_type parms;
    CopyParmsId(parms_id, parms);

    try
    {
        eval->mod_switch_to(*plain_ptr, parms, *destination_ptr);
        return S_OK;
    }
    catch (const invalid_argument &)
    {
        return E_INVALIDARG;
    }
}

SEAL_C_FUNC Evaluator_RescaleToNext(void *thisptr, void *encrypted, void *destination, void *pool)
{
    Evaluator *eval = FromVoid<Evaluator>(thisptr);
    IfNullRet(eval, E_POINTER);
    Ciphertext *encrypted_ptr = FromVoid<Ciphertext>(encrypted);
    IfNullRet(encrypted_ptr, E_POINTER);
    Ciphertext *destination_ptr = FromVoid<Ciphertext>(destination);
    IfNullRet(destination_ptr, E_POINTER);
    unique_ptr<MemoryPoolHandle> pool_ptr = MemHandleFromVoid(pool);

    try
    {
        eval->rescale_to_next(*encrypted_ptr, *destination_ptr, *pool_ptr);
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

SEAL_C_FUNC Evaluator_RescaleTo(void *thisptr, void *encrypted, uint64_t *parms_id, void *destination, void *pool)
{
    Evaluator *eval = FromVoid<Evaluator>(thisptr);
    IfNullRet(eval, E_POINTER);
    Ciphertext *encrypted_ptr = FromVoid<Ciphertext>(encrypted);
    IfNullRet(encrypted_ptr, E_POINTER);
    IfNullRet(parms_id, E_POINTER);
    Ciphertext *destination_ptr = FromVoid<Ciphertext>(destination);
    IfNullRet(destination_ptr, E_POINTER);
    unique_ptr<MemoryPoolHandle> pool_ptr = MemHandleFromVoid(pool);

    parms_id_type parms;
    CopyParmsId(parms_id, parms);

    try
    {
        eval->rescale_to(*encrypted_ptr, parms, *destination_ptr, *pool_ptr);
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

SEAL_C_FUNC Evaluator_Exponentiate(
    void *thisptr, void *encrypted, uint64_t exponent, void *relin_keys, void *destination, void *pool)
{
    Evaluator *eval = FromVoid<Evaluator>(thisptr);
    IfNullRet(eval, E_POINTER);
    Ciphertext *encrypted_ptr = FromVoid<Ciphertext>(encrypted);
    IfNullRet(encrypted_ptr, E_POINTER);
    RelinKeys *relin_keys_ptr = FromVoid<RelinKeys>(relin_keys);
    IfNullRet(relin_keys_ptr, E_POINTER);
    Ciphertext *destination_ptr = FromVoid<Ciphertext>(destination);
    IfNullRet(destination_ptr, E_POINTER);
    unique_ptr<MemoryPoolHandle> pool_ptr = MemHandleFromVoid(pool);

    try
    {
        eval->exponentiate(*encrypted_ptr, exponent, *relin_keys_ptr, *destination_ptr, *pool_ptr);
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

SEAL_C_FUNC Evaluator_TransformToNTT1(void *thisptr, void *plain, uint64_t *parms_id, void *destination_ntt, void *pool)
{
    Evaluator *eval = FromVoid<Evaluator>(thisptr);
    IfNullRet(eval, E_POINTER);
    Plaintext *plain_ptr = FromVoid<Plaintext>(plain);
    IfNullRet(plain_ptr, E_POINTER);
    IfNullRet(parms_id, E_POINTER);
    Plaintext *destination_ptr = FromVoid<Plaintext>(destination_ntt);
    IfNullRet(destination_ptr, E_POINTER);
    unique_ptr<MemoryPoolHandle> pool_ptr = MemHandleFromVoid(pool);

    parms_id_type parms;
    CopyParmsId(parms_id, parms);

    try
    {
        eval->transform_to_ntt(*plain_ptr, parms, *destination_ptr, *pool_ptr);
        return S_OK;
    }
    catch (const invalid_argument &)
    {
        return E_INVALIDARG;
    }
}

SEAL_C_FUNC Evaluator_TransformToNTT2(void *thisptr, void *encrypted, void *destination_ntt)
{
    Evaluator *eval = FromVoid<Evaluator>(thisptr);
    IfNullRet(eval, E_POINTER);
    Ciphertext *encrypted_ptr = FromVoid<Ciphertext>(encrypted);
    IfNullRet(encrypted_ptr, E_POINTER);
    Ciphertext *destination_ptr = FromVoid<Ciphertext>(destination_ntt);
    IfNullRet(destination_ptr, E_POINTER);

    try
    {
        eval->transform_to_ntt(*encrypted_ptr, *destination_ptr);
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

SEAL_C_FUNC Evaluator_TransformFromNTT(void *thisptr, void *encrypted_ntt, void *destination)
{
    Evaluator *eval = FromVoid<Evaluator>(thisptr);
    IfNullRet(eval, E_POINTER);
    Ciphertext *encrypted_ptr = FromVoid<Ciphertext>(encrypted_ntt);
    IfNullRet(encrypted_ptr, E_POINTER);
    Ciphertext *destination_ptr = FromVoid<Ciphertext>(destination);
    IfNullRet(destination_ptr, E_POINTER);

    try
    {
        eval->transform_from_ntt(*encrypted_ptr, *destination_ptr);
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

SEAL_C_FUNC Evaluator_ApplyGalois(
    void *thisptr, void *encrypted, uint32_t galois_elt, void *galois_keys, void *destination, void *pool)
{
    Evaluator *eval = FromVoid<Evaluator>(thisptr);
    IfNullRet(eval, E_POINTER);
    Ciphertext *encrypted_ptr = FromVoid<Ciphertext>(encrypted);
    IfNullRet(encrypted_ptr, E_POINTER);
    GaloisKeys *galois_keys_ptr = FromVoid<GaloisKeys>(galois_keys);
    IfNullRet(galois_keys_ptr, E_POINTER);
    Ciphertext *destination_ptr = FromVoid<Ciphertext>(destination);
    IfNullRet(destination_ptr, E_POINTER);
    unique_ptr<MemoryPoolHandle> pool_ptr = MemHandleFromVoid(pool);

    try
    {
        eval->apply_galois(*encrypted_ptr, galois_elt, *galois_keys_ptr, *destination_ptr, *pool_ptr);
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

SEAL_C_FUNC Evaluator_RotateRows(
    void *thisptr, void *encrypted, int steps, void *galoisKeys, void *destination, void *pool)
{
    Evaluator *eval = FromVoid<Evaluator>(thisptr);
    IfNullRet(eval, E_POINTER);
    Ciphertext *encrypted_ptr = FromVoid<Ciphertext>(encrypted);
    IfNullRet(encrypted_ptr, E_POINTER);
    GaloisKeys *galois_keys_ptr = FromVoid<GaloisKeys>(galoisKeys);
    IfNullRet(galois_keys_ptr, E_POINTER);
    Ciphertext *destination_ptr = FromVoid<Ciphertext>(destination);
    IfNullRet(destination_ptr, E_POINTER);
    unique_ptr<MemoryPoolHandle> pool_ptr = MemHandleFromVoid(pool);

    try
    {
        eval->rotate_rows(*encrypted_ptr, steps, *galois_keys_ptr, *destination_ptr, *pool_ptr);
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

SEAL_C_FUNC Evaluator_RotateColumns(void *thisptr, void *encrypted, void *galois_keys, void *destination, void *pool)
{
    Evaluator *eval = FromVoid<Evaluator>(thisptr);
    IfNullRet(eval, E_POINTER);
    Ciphertext *encrypted_ptr = FromVoid<Ciphertext>(encrypted);
    IfNullRet(encrypted_ptr, E_POINTER);
    GaloisKeys *galois_keys_ptr = FromVoid<GaloisKeys>(galois_keys);
    IfNullRet(galois_keys_ptr, E_POINTER);
    Ciphertext *destination_ptr = FromVoid<Ciphertext>(destination);
    IfNullRet(destination_ptr, E_POINTER);
    unique_ptr<MemoryPoolHandle> pool_ptr = MemHandleFromVoid(pool);

    try
    {
        eval->rotate_columns(*encrypted_ptr, *galois_keys_ptr, *destination_ptr, *pool_ptr);
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

SEAL_C_FUNC Evaluator_RotateVector(
    void *thisptr, void *encrypted, int steps, void *galois_keys, void *destination, void *pool)
{
    Evaluator *eval = FromVoid<Evaluator>(thisptr);
    IfNullRet(eval, E_POINTER);
    Ciphertext *encrypted_ptr = FromVoid<Ciphertext>(encrypted);
    IfNullRet(encrypted_ptr, E_POINTER);
    GaloisKeys *galois_keys_ptr = FromVoid<GaloisKeys>(galois_keys);
    IfNullRet(galois_keys_ptr, E_POINTER);
    Ciphertext *destination_ptr = FromVoid<Ciphertext>(destination);
    IfNullRet(destination_ptr, E_POINTER);
    unique_ptr<MemoryPoolHandle> pool_ptr = MemHandleFromVoid(pool);

    try
    {
        eval->rotate_vector(*encrypted_ptr, steps, *galois_keys_ptr, *destination_ptr, *pool_ptr);
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

SEAL_C_FUNC Evaluator_ComplexConjugate(void *thisptr, void *encrypted, void *galois_keys, void *destination, void *pool)
{
    Evaluator *eval = FromVoid<Evaluator>(thisptr);
    IfNullRet(eval, E_POINTER);
    Ciphertext *encrypted_ptr = FromVoid<Ciphertext>(encrypted);
    IfNullRet(encrypted_ptr, E_POINTER);
    GaloisKeys *galois_keys_ptr = FromVoid<GaloisKeys>(galois_keys);
    IfNullRet(galois_keys_ptr, E_POINTER);
    Ciphertext *destination_ptr = FromVoid<Ciphertext>(destination);
    IfNullRet(destination_ptr, E_POINTER);
    unique_ptr<MemoryPoolHandle> pool_ptr = MemHandleFromVoid(pool);

    try
    {
        eval->complex_conjugate(*encrypted_ptr, *galois_keys_ptr, *destination_ptr, *pool_ptr);
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

SEAL_C_FUNC Evaluator_ContextUsingKeyswitching(void *thisptr, bool *using_keyswitching)
{
    Evaluator *eval = FromVoid<Evaluator>(thisptr);
    IfNullRet(eval, E_POINTER);
    IfNullRet(using_keyswitching, E_POINTER);

    *using_keyswitching = Evaluator::EvaluatorPrivateHelper::using_keyswitching(*eval);
    return S_OK;
}