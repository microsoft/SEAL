// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

// SEALNet
#include "seal/c/stdafx.h"
#include "seal/c/utilities.h"
#include "seal/c/version.h"

// SEAL
#include "seal/util/config.h"

using namespace std;
using namespace seal::c;

SEAL_C_FUNC Version_Major(uint8_t *result)
{
    IfNullRet(result, E_POINTER);

    *result = (uint8_t)SEAL_VERSION_MAJOR;
    return S_OK;
}

SEAL_C_FUNC Version_Minor(uint8_t *result)
{
    IfNullRet(result, E_POINTER);

    *result = (uint8_t)SEAL_VERSION_MINOR;
    return S_OK;
}

SEAL_C_FUNC Version_Patch(uint8_t *result)
{
    IfNullRet(result, E_POINTER);

    *result = (uint8_t)SEAL_VERSION_PATCH;
    return S_OK;
}
