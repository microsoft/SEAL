// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

// SEALNet
#include "sealnet/stdafx.h"
#include "sealnet/encryptionparameterqualifiers_wrapper.h"
#include "sealnet/utilities.h"

// SEAL
#include "seal/context.h"

using namespace seal;
using namespace sealnet;

SEALNETNATIVE HRESULT SEALCALL EPQ_Create(void *copy, void **epq)
{
    EncryptionParameterQualifiers *copyptr = FromVoid<EncryptionParameterQualifiers>(copy);
    IfNullRet(copyptr, E_POINTER);
    IfNullRet(epq, E_POINTER);

    EncryptionParameterQualifiers *result = new EncryptionParameterQualifiers(*copyptr);
    *epq = result;
    return S_OK;
}

SEALNETNATIVE HRESULT SEALCALL EPQ_Destroy(void *thisptr)
{
    EncryptionParameterQualifiers *epq = FromVoid<EncryptionParameterQualifiers>(thisptr);
    IfNullRet(epq, E_POINTER);

    delete epq;
    return S_OK;
}

SEALNETNATIVE HRESULT SEALCALL EPQ_ParametersSet(void *thisptr, bool *parameters_set)
{
    EncryptionParameterQualifiers *epq = FromVoid<EncryptionParameterQualifiers>(thisptr);
    IfNullRet(epq, E_POINTER);
    IfNullRet(parameters_set, E_POINTER);

    *parameters_set = epq->parameters_set;
    return S_OK;
}

SEALNETNATIVE HRESULT SEALCALL EPQ_UsingFFT(void *thisptr, bool *using_fft)
{
    EncryptionParameterQualifiers *epq = FromVoid<EncryptionParameterQualifiers>(thisptr);
    IfNullRet(epq, E_POINTER);
    IfNullRet(using_fft, E_POINTER);

    *using_fft = epq->using_fft;
    return S_OK;
}

SEALNETNATIVE HRESULT SEALCALL EPQ_UsingNTT(void *thisptr, bool *using_ntt)
{
    EncryptionParameterQualifiers *epq = FromVoid<EncryptionParameterQualifiers>(thisptr);
    IfNullRet(epq, E_POINTER);
    IfNullRet(using_ntt, E_POINTER);

    *using_ntt = epq->using_ntt;
    return S_OK;
}

SEALNETNATIVE HRESULT SEALCALL EPQ_UsingBatching(void *thisptr, bool *using_batching)
{
    EncryptionParameterQualifiers *epq = FromVoid<EncryptionParameterQualifiers>(thisptr);
    IfNullRet(epq, E_POINTER);
    IfNullRet(using_batching, E_POINTER);

    *using_batching = epq->using_batching;
    return S_OK;
}

SEALNETNATIVE HRESULT SEALCALL EPQ_UsingFastPlainLift(void *thisptr, bool *using_fast_plain_lift)
{
    EncryptionParameterQualifiers *epq = FromVoid<EncryptionParameterQualifiers>(thisptr);
    IfNullRet(epq, E_POINTER);
    IfNullRet(using_fast_plain_lift, E_POINTER);

    *using_fast_plain_lift = epq->using_fast_plain_lift;
    return S_OK;
}

SEALNETNATIVE HRESULT SEALCALL EPQ_UsingHEStdSecurity(void *thisptr, bool *using_HE_std_security)
{
    EncryptionParameterQualifiers *epq = FromVoid<EncryptionParameterQualifiers>(thisptr);
    IfNullRet(epq, E_POINTER);
    IfNullRet(using_HE_std_security, E_POINTER);

    *using_HE_std_security = epq->using_he_std_security;
    return S_OK;
}

