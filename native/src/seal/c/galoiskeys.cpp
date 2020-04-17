// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

// SEALNet
#include "seal/c/galoiskeys.h"
#include "seal/c/stdafx.h"
#include "seal/c/utilities.h"

// SEAL
#include "seal/galoiskeys.h"

using namespace std;
using namespace seal;
using namespace seal::c;

SEAL_C_FUNC GaloisKeys_GetIndex(uint32_t galois_elt, uint64_t *index)
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