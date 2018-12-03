// SEALDll
#include "stdafx.h"
#include "encryptionparameterqualifiers.h"
#include "utilities.h"

// SEAL
#include "seal/context.h"

using namespace seal;
using namespace seal::dll;


SEALDLL HRESULT SEALCALL EPQ_Create(void* copy, void** epq)
{
    EncryptionParameterQualifiers* copyptr = FromVoid<EncryptionParameterQualifiers>(copy);
    IfNullRet(copyptr, E_POINTER);
    IfNullRet(epq, E_POINTER);

    EncryptionParameterQualifiers* result = new EncryptionParameterQualifiers(*copyptr);
    *epq = result;
    return S_OK;
}

SEALDLL HRESULT SEALCALL EPQ_Destroy(void* thisptr)
{
    EncryptionParameterQualifiers* epq = FromVoid<EncryptionParameterQualifiers>(thisptr);
    IfNullRet(epq, E_POINTER);

    delete epq;
    return S_OK;
}

SEALDLL HRESULT SEALCALL EPQ_ParametersSet(void* thisptr, bool* parameters_set)
{
    EncryptionParameterQualifiers* epq = FromVoid<EncryptionParameterQualifiers>(thisptr);
    IfNullRet(epq, E_POINTER);
    IfNullRet(parameters_set, E_POINTER);

    *parameters_set = epq->parameters_set;
    return S_OK;
}

SEALDLL HRESULT SEALCALL EPQ_EnableFFT(void* thisptr, bool* enable_fft)
{
    EncryptionParameterQualifiers* epq = FromVoid<EncryptionParameterQualifiers>(thisptr);
    IfNullRet(epq, E_POINTER);
    IfNullRet(enable_fft, E_POINTER);

    *enable_fft = epq->using_fft;
    return S_OK;
}

SEALDLL HRESULT SEALCALL EPQ_EnableNTT(void* thisptr, bool* enable_ntt)
{
    EncryptionParameterQualifiers* epq = FromVoid<EncryptionParameterQualifiers>(thisptr);
    IfNullRet(epq, E_POINTER);
    IfNullRet(enable_ntt, E_POINTER);

    *enable_ntt = epq->using_ntt;
    return S_OK;
}

SEALDLL HRESULT SEALCALL EPQ_EnableBatching(void* thisptr, bool* enable_batching)
{
    EncryptionParameterQualifiers* epq = FromVoid<EncryptionParameterQualifiers>(thisptr);
    IfNullRet(epq, E_POINTER);
    IfNullRet(enable_batching, E_POINTER);

    *enable_batching = epq->using_batching;
    return S_OK;
}

SEALDLL HRESULT SEALCALL EPQ_EnableFastPlainLift(void* thisptr, bool* enable_fast_plain_lift)
{
    EncryptionParameterQualifiers* epq = FromVoid<EncryptionParameterQualifiers>(thisptr);
    IfNullRet(epq, E_POINTER);
    IfNullRet(enable_fast_plain_lift, E_POINTER);

    *enable_fast_plain_lift = epq->using_fast_plain_lift;
    return S_OK;
}
