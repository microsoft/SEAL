// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

// SEALNet
#include "seal/c/contextdata.h"
#include "seal/c/stdafx.h"
#include "seal/c/utilities.h"

// SEAL
#include "seal/context.h"

using namespace std;
using namespace seal;
using namespace seal::c;

SEAL_C_FUNC ContextData_Destroy(void *thisptr)
{
    SEALContext::ContextData *cont_data = FromVoid<SEALContext::ContextData>(thisptr);
    IfNullRet(cont_data, E_POINTER);

    delete cont_data;
    return S_OK;
}

SEAL_C_FUNC ContextData_TotalCoeffModulus(void *thisptr, uint64_t *count, uint64_t *total_coeff_modulus)
{
    SEALContext::ContextData *cont_data = FromVoid<SEALContext::ContextData>(thisptr);
    IfNullRet(cont_data, E_POINTER);
    IfNullRet(count, E_POINTER);

    *count = cont_data->parms().coeff_modulus().size();

    if (nullptr == total_coeff_modulus)
    {
        // We only wanted the count.
        return S_OK;
    }

    for (uint64_t i = 0; i < *count; i++)
    {
        total_coeff_modulus[i] = cont_data->total_coeff_modulus()[i];
    }

    return S_OK;
}

SEAL_C_FUNC ContextData_TotalCoeffModulusBitCount(void *thisptr, int *bit_count)
{
    SEALContext::ContextData *cont_data = FromVoid<SEALContext::ContextData>(thisptr);
    IfNullRet(cont_data, E_POINTER);
    IfNullRet(bit_count, E_POINTER);

    *bit_count = cont_data->total_coeff_modulus_bit_count();
    return S_OK;
}

SEAL_C_FUNC ContextData_Parms(void *thisptr, void **parms)
{
    SEALContext::ContextData *cont_data = FromVoid<SEALContext::ContextData>(thisptr);
    IfNullRet(cont_data, E_POINTER);

    EncryptionParameters *enc_params = new EncryptionParameters(cont_data->parms());
    *parms = enc_params;
    return S_OK;
}

SEAL_C_FUNC ContextData_Qualifiers(void *thisptr, void **epq)
{
    SEALContext::ContextData *cont_data = FromVoid<SEALContext::ContextData>(thisptr);
    IfNullRet(cont_data, E_POINTER);
    IfNullRet(epq, E_POINTER);

    EncryptionParameterQualifiers *qualifiers = new EncryptionParameterQualifiers(cont_data->qualifiers());
    *epq = qualifiers;
    return S_OK;
}

SEAL_C_FUNC ContextData_CoeffDivPlainModulus(void *thisptr, uint64_t *count, uint64_t *coeff_div)
{
    SEALContext::ContextData *cont_data = FromVoid<SEALContext::ContextData>(thisptr);
    IfNullRet(cont_data, E_POINTER);
    IfNullRet(count, E_POINTER);

    *count = cont_data->parms().coeff_modulus().size();

    if (nullptr == coeff_div)
    {
        // We only wanted the size
        return S_OK;
    }

    for (uint64_t i = 0; i < *count; i++)
    {
        coeff_div[i] = cont_data->coeff_div_plain_modulus()[i].operand;
    }

    return S_OK;
}

SEAL_C_FUNC ContextData_PlainUpperHalfThreshold(void *thisptr, uint64_t *puht)
{
    SEALContext::ContextData *cont_data = FromVoid<SEALContext::ContextData>(thisptr);
    IfNullRet(cont_data, E_POINTER);
    IfNullRet(puht, E_POINTER);

    *puht = cont_data->plain_upper_half_threshold();
    return S_OK;
}

SEAL_C_FUNC ContextData_PlainUpperHalfIncrement(void *thisptr, uint64_t *count, uint64_t *puhi)
{
    SEALContext::ContextData *cont_data = FromVoid<SEALContext::ContextData>(thisptr);
    IfNullRet(cont_data, E_POINTER);
    IfNullRet(count, E_POINTER);

    *count = cont_data->parms().coeff_modulus().size();

    if (nullptr == puhi)
    {
        // We only wanted the size
        return S_OK;
    }

    for (uint64_t i = 0; i < *count; i++)
    {
        puhi[i] = cont_data->plain_upper_half_increment()[i];
    }

    return S_OK;
}

SEAL_C_FUNC ContextData_UpperHalfThreshold(void *thisptr, uint64_t *count, uint64_t *uht)
{
    SEALContext::ContextData *cont_data = FromVoid<SEALContext::ContextData>(thisptr);
    IfNullRet(cont_data, E_POINTER);
    IfNullRet(count, E_POINTER);

    // This is only available for CKKS
    if (cont_data->upper_half_threshold() == nullptr)
    {
        *count = 0;
        return S_OK;
    }

    *count = cont_data->parms().coeff_modulus().size();

    if (nullptr == uht)
    {
        // We only wanted the count
        return S_OK;
    }

    for (uint64_t i = 0; i < *count; i++)
    {
        uht[i] = cont_data->upper_half_threshold()[i];
    }

    return S_OK;
}

SEAL_C_FUNC ContextData_UpperHalfIncrement(void *thisptr, uint64_t *count, uint64_t *uhi)
{
    SEALContext::ContextData *cont_data = FromVoid<SEALContext::ContextData>(thisptr);
    IfNullRet(cont_data, E_POINTER);
    IfNullRet(count, E_POINTER);

    if (cont_data->upper_half_increment() == nullptr)
    {
        *count = 0;
        return S_OK;
    }

    *count = cont_data->parms().coeff_modulus().size();

    if (nullptr == uhi)
    {
        // We only wanted the size
        return S_OK;
    }

    for (uint64_t i = 0; i < *count; i++)
    {
        uhi[i] = cont_data->upper_half_increment()[i];
    }

    return S_OK;
}

SEAL_C_FUNC ContextData_PrevContextData(void *thisptr, void **prev_data)
{
    SEALContext::ContextData *cont_data = FromVoid<SEALContext::ContextData>(thisptr);
    IfNullRet(cont_data, E_POINTER);
    IfNullRet(prev_data, E_POINTER);

    // The caller should not try to delete the returned pointer
    *prev_data = const_cast<SEALContext::ContextData *>(cont_data->prev_context_data().get());
    return S_OK;
}

SEAL_C_FUNC ContextData_NextContextData(void *thisptr, void **next_data)
{
    SEALContext::ContextData *cont_data = FromVoid<SEALContext::ContextData>(thisptr);
    IfNullRet(cont_data, E_POINTER);
    IfNullRet(next_data, E_POINTER);

    // The caller should not try to delete the returned pointer
    *next_data = const_cast<SEALContext::ContextData *>(cont_data->next_context_data().get());
    return S_OK;
}

SEAL_C_FUNC ContextData_ChainIndex(void *thisptr, uint64_t *index)
{
    SEALContext::ContextData *cont_data = FromVoid<SEALContext::ContextData>(thisptr);
    IfNullRet(cont_data, E_POINTER);
    IfNullRet(index, E_POINTER);

    *index = cont_data->chain_index();
    return S_OK;
}
