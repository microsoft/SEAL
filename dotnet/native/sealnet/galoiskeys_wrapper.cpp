// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

// SEALNet
#include "sealnet/galoiskeys_wrapper.h"
#include "sealnet/stdafx.h"
#include "sealnet/utilities.h"

// SEAL
#include "seal/galoiskeys.h"

using namespace std;
using namespace seal;
using namespace sealnet;

SEALMETHOD GaloisKeys_GetIndex(uint64_t galois_elt, uint64_t *index)
{
    IfNullRet(index, E_POINTER);

    try
    {
        *index = GaloisKeys::get_index(galois_elt);
        return S_OK;
    }
    catch (const invalid_argument &)
    {
        return E_INVALIDARG;
    }
}