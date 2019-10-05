// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

// SEALNet
#include "sealnet/stdafx.h"
#include "sealnet/serialization_wrapper.h"
#include "sealnet/utilities.h"

// SEAL
#include "seal/serialization.h"

using namespace std;
using namespace seal;
using namespace sealnet;

SEALNETNATIVE HRESULT SEALCALL Serialization_SEALMagic(uint16_t *result)
{
    IfNullRet(result, E_POINTER);

    *result = Serialization::seal_magic;
    return S_OK;
}

SEALNETNATIVE HRESULT SEALCALL Serialization_IsSupportedComprMode(uint8_t compr_mode, bool *result)
{
    IfNullRet(result, E_POINTER);

    *result = Serialization::IsSupportedComprMode(compr_mode);
    return S_OK;
}

SEALNETNATIVE HRESULT SEALCALL Serialization_ComprModeDefault(uint8_t *result)
{
    IfNullRet(result, E_POINTER);

    *result = static_cast<uint8_t>(Serialization::compr_mode_default);
    return S_OK;
}

SEALNETNATIVE HRESULT SEALCALL Serialization_IsValidHeader(uint8_t *headerptr, uint64_t size, bool *result)
{
    IfNullRet(headerptr, E_POINTER);
    IfNullRet(result, E_POINTER);
    if (size != static_cast<uint64_t>(sizeof(Serialization::SEALHeader)))
    {
        *result = false;
    }

    Serialization::SEALHeader header;
    memcpy(
        reinterpret_cast<SEAL_BYTE*>(&header),
        reinterpret_cast<SEAL_BYTE*>(headerptr),
        sizeof(Serialization::SEALHeader));
    *result = Serialization::IsValidHeader(header);
    return S_OK;
}
