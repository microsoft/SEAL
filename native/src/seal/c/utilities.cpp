// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

// STD
#include <algorithm>
#include <iterator>

// SEALNet
#include "seal/c/utilities.h"

// SEAL
#include "seal/context.h"
#include "seal/encryptionparams.h"
#include "seal/modulus.h"
#include "seal/util/common.h"
#include "seal/util/locks.h"

using namespace std;
using namespace seal;
using namespace seal::c;
using namespace seal::util;

unique_ptr<MemoryPoolHandle> seal::c::MemHandleFromVoid(void *voidptr)
{
    if (nullptr == voidptr)
    {
        return make_unique<MemoryPoolHandle>(MemoryManager::GetPool());
    }

    MemoryPoolHandle *handle = reinterpret_cast<MemoryPoolHandle *>(voidptr);
    return make_unique<MemoryPoolHandle>(*handle);
}

HRESULT seal::c::PrepareOutputBuffer(uint64_t required, uint64_t *size, const void *output)
{
    uint64_t capacity = output ? *size : 0;
    *size = required;
    return output && capacity < required ? HRESULT_FROM_WIN32(ERROR_INSUFFICIENT_BUFFER) : S_OK;
}

HRESULT seal::c::BuildModulusPointers(const vector<Modulus> &in_mods, uint64_t *length, void **out_mods)
{
    uint64_t required = static_cast<uint64_t>(in_mods.size());
    HRESULT result = PrepareOutputBuffer(required, length, out_mods);
    if (result != S_OK || out_mods == nullptr)
    {
        return result;
    }

    vector<unique_ptr<Modulus>> moduli;
    moduli.reserve(in_mods.size());
    transform(in_mods.cbegin(), in_mods.cend(), back_inserter(moduli), [](const auto &mod) {
        return make_unique<Modulus>(mod);
    });

    Modulus **mod_ptr_array = reinterpret_cast<Modulus **>(out_mods);
    transform(moduli.begin(), moduli.end(), mod_ptr_array, [](auto &mod) { return mod.release(); });
    return S_OK;
}

HRESULT seal::c::ToStringHelper(const string &str, char *outstr, uint64_t *length)
{
    uint64_t required = static_cast<uint64_t>(str.size());
    HRESULT result = PrepareOutputBuffer(required, length, outstr);

    if (result == S_OK && nullptr != outstr)
    {
        memcpy(outstr, str.c_str(), util::add_safe(required, uint64_t(1)));
    }
    return result;
}

HRESULT seal::c::ToStringHelper2(const char *str, char *outstr, uint64_t *length)
{
    uint64_t required = static_cast<uint64_t>(strlen(str));
    HRESULT result = PrepareOutputBuffer(required, length, outstr);

    if (result == S_OK && nullptr != outstr)
    {
        memcpy(outstr, str, util::add_safe(required, uint64_t(1)));
    }
    return result;
}
