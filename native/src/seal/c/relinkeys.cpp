// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

// SEALNet
#include "seal/c/relinkeys.h"
#include "seal/c/stdafx.h"
#include "seal/c/utilities.h"

// SEAL
#include "seal/relinkeys.h"

using namespace std;
using namespace seal;
using namespace seal::c;

SEAL_C_FUNC RelinKeys_GetIndex(uint64_t key_power, uint64_t *index)
{
    IfNullRet(index, E_POINTER);

    try
    {
        *index = RelinKeys::get_index(key_power);
        return S_OK;
    }
    catch (const invalid_argument &)
    {
        return E_INVALIDARG;
    }
}