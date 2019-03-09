// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

// STD
#include <algorithm>
#include <iterator>

// SEALNet
#include "sealnet/stdafx.h"
#include "sealnet/utilities.h"

// SEAL
#include "seal/smallmodulus.h"
#include "seal/encryptionparams.h"
#include "seal/context.h"
#include "seal/util/common.h"

using namespace std;
using namespace seal;
using namespace sealnet;
using namespace seal::util;

namespace sealnet
{
    extern unordered_map<SEALContext*, shared_ptr<SEALContext>> pointer_store_;

    // This is here only so we have a null shared pointer to return.
    shared_ptr<SEALContext> null_context_;
}

unique_ptr<MemoryPoolHandle> sealnet::MemHandleFromVoid(void *voidptr)
{
    if (nullptr == voidptr)
    {
        return make_unique<MemoryPoolHandle>(MemoryManager::GetPool());
    }

    MemoryPoolHandle *handle = reinterpret_cast<MemoryPoolHandle*>(voidptr);
    return make_unique<MemoryPoolHandle>(*handle);
}

void sealnet::BuildCoeffPointers(const vector<SmallModulus> &coefficients, uint64_t *length, void **coeffs)
{
    *length = safe_cast<uint64_t>(coefficients.size());

    if (coeffs == nullptr)
    {
        // The caller is only interested in the size
        return;
    }

    uint64_t count = 0;
    SmallModulus* *coeff_array = reinterpret_cast<SmallModulus**>(coeffs);

    for (const auto &coeff : coefficients)
    {
        coeff_array[count++] = new SmallModulus(coeff);
    }
}

const shared_ptr<SEALContext> &sealnet::SharedContextFromVoid(void *context)
{
    SEALContext *contextptr = FromVoid<SEALContext>(context);
    if (nullptr == contextptr)
    {
        return null_context_;
    }

    const auto &ctxiter = pointer_store_.find(contextptr);
    if (ctxiter == pointer_store_.end())
    {
        return null_context_;
    }

    return ctxiter->second;
}

void sealnet::CopyParmsId(const uint64_t *src, parms_id_type &dest)
{
    if (nullptr != src)
    {
        copy_n(src, dest.size(), begin(dest));
    }
}

void sealnet::CopyParmsId(const parms_id_type &src, uint64_t *dest)
{
    if (nullptr != dest)
    {
        copy_n(cbegin(src), src.size(), dest);
    }
}

HRESULT sealnet::ToStringHelper(const string &str, char *outstr, uint64_t *length)
{
    uint64_t result_length = add_safe(static_cast<uint64_t>(str.length()), uint64_t(1));
    if (nullptr == outstr)
    {
        // We need to return the string length.
        // The string length will include the terminating character.
        *length = result_length;
        return S_OK;
    }

    // Verify the string fits
    if (*length < result_length)
    {
        *length = result_length;
        return HRESULT_FROM_WIN32(ERROR_INSUFFICIENT_BUFFER);
    }

    fill_n(outstr, *length, char(0));
    str.copy(outstr, str.length());

    return S_OK;
}

