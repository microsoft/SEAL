// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

// SEALDll
#include "stdafx.h"
#include "utilities.h"

// SEAL
#include "seal/smallmodulus.h"
#include "seal/encryptionparams.h"
#include "seal/context.h"


using namespace std;
using namespace seal;
using namespace seal::dll;

namespace seal
{
    namespace dll
    {
        extern unordered_map<SEALContext*, shared_ptr<SEALContext>> pointer_store_;

        // This is here only so we have a null shared pointer to return.
        shared_ptr<SEALContext> null_context_;
    }
}

unique_ptr<MemoryPoolHandle> seal::dll::MemHandleFromVoid(void* voidptr)
{
    if (nullptr == voidptr)
    {
        return make_unique<MemoryPoolHandle>(MemoryManager::GetPool());
    }

    MemoryPoolHandle* handle = reinterpret_cast<MemoryPoolHandle*>(voidptr);
    return make_unique<MemoryPoolHandle>(*handle);
}

void seal::dll::BuildCoeffPointers(const vector<SmallModulus>& coefficients, uint64_t* length, void** coeffs)
{
    *length = coefficients.size();

    if (coeffs == nullptr)
    {
        // The caller is only interested in the size
        return;
    }

    uint64_t count = 0;
    SmallModulus** coeff_array = reinterpret_cast<SmallModulus**>(coeffs);

    for (const auto& coeff : coefficients)
    {
        coeff_array[count++] = new SmallModulus(coeff);
    }
}

const shared_ptr<SEALContext>& seal::dll::SharedContextFromVoid(void* context)
{
    SEALContext* contextptr = FromVoid<SEALContext>(context);
    if (nullptr == contextptr)
    {
        return null_context_;
    }

    const auto& ctxiter = pointer_store_.find(contextptr);
    if (ctxiter == pointer_store_.end())
    {
        return null_context_;
    }

    return ctxiter->second;
}

void seal::dll::CopyParmsId(const uint64_t* src, parms_id_type& dest)
{
    if (nullptr != src)
    {
        for (int i = 0; i < dest.size(); i++)
        {
            dest[i] = src[i];
        }
    }
}

void seal::dll::CopyParmsId(const parms_id_type& src, uint64_t* dest)
{
    if (nullptr != dest)
    {
        for (int i = 0; i < src.size(); i++)
        {
            dest[i] = src[i];
        }
    }
}

HRESULT seal::dll::ToStringHelper(const string& str, char* outstr, int* length)
{
    if (nullptr == outstr)
    {
        // We need to return the string length.
        // The string length will include the terminating character.
        *length = static_cast<int>(str.length() + 1);
        return S_OK;
    }

    // Verify the string fits
    if (*length < (str.length() + 1))
    {
        *length = static_cast<int>(str.length() + 1);
        return HRESULT_FROM_WIN32(ERROR_INSUFFICIENT_BUFFER);
    }

    memset(outstr, 0, *length);
    str.copy(outstr, str.length());
    return S_OK;
}

