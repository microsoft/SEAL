// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

// SEALNet
#include "sealnet/stdafx.h"
#include "sealnet/relinkeys_wrapper.h"
#include "sealnet/utilities.h"

// SEAL
#include "seal/relinkeys.h"

using namespace std;
using namespace seal;
using namespace sealnet;

SEALNETNATIVE HRESULT SEALCALL RelinKeys_GetIndex(uint64_t key_power, uint64_t *index)
{
    IfNullRet(index, E_POINTER);

    try
    {
        *index = RelinKeys::get_index(key_power);
        return S_OK;
    }
    catch (const invalid_argument&)
    {
        return E_INVALIDARG;
    }
}