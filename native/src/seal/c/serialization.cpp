// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

// SEALNet
#include "seal/c/serialization.h"
#include "seal/c/stdafx.h"
#include "seal/c/utilities.h"

// SEAL
#include "seal/serialization.h"

using namespace std;
using namespace seal;
using namespace seal::c;

SEAL_C_FUNC Serialization_SEALMagic(uint16_t *result)
{
    IfNullRet(result, E_POINTER);

    *result = Serialization::seal_magic;
    return S_OK;
}

SEAL_C_FUNC Serialization_SEALHeaderSize(uint8_t *result)
{
    IfNullRet(result, E_POINTER);

    *result = Serialization::seal_header_size;
    return S_OK;
}

SEAL_C_FUNC Serialization_IsSupportedComprMode(uint8_t compr_mode, bool *result)
{
    IfNullRet(result, E_POINTER);

    *result = Serialization::IsSupportedComprMode(compr_mode);
    return S_OK;
}

SEAL_C_FUNC Serialization_ComprModeDefault(uint8_t *result)
{
    IfNullRet(result, E_POINTER);

    *result = static_cast<uint8_t>(Serialization::compr_mode_default);
    return S_OK;
}

SEAL_C_FUNC Serialization_IsCompatibleVersion(uint8_t *headerptr, uint64_t size, bool *result)
{
    IfNullRet(headerptr, E_POINTER);
    IfNullRet(result, E_POINTER);
    if (size != static_cast<uint64_t>(sizeof(Serialization::SEALHeader)))
    {
        *result = false;
    }

    Serialization::SEALHeader header;
    memcpy(
        reinterpret_cast<SEAL_BYTE *>(&header), reinterpret_cast<SEAL_BYTE *>(headerptr),
        sizeof(Serialization::SEALHeader));
    *result = Serialization::IsCompatibleVersion(header);
    return S_OK;
}

SEAL_C_FUNC Serialization_IsValidHeader(uint8_t *headerptr, uint64_t size, bool *result)
{
    IfNullRet(headerptr, E_POINTER);
    IfNullRet(result, E_POINTER);
    if (size != static_cast<uint64_t>(sizeof(Serialization::SEALHeader)))
    {
        *result = false;
    }

    Serialization::SEALHeader header;
    memcpy(
        reinterpret_cast<SEAL_BYTE *>(&header), reinterpret_cast<SEAL_BYTE *>(headerptr),
        sizeof(Serialization::SEALHeader));
    *result = Serialization::IsValidHeader(header);
    return S_OK;
}
