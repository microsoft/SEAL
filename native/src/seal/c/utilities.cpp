// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

// STD
#include <algorithm>
#include <iterator>

// SEALNet
#include "seal/c/stdafx.h"
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

namespace seal
{
    namespace c
    {
        extern unordered_map<SEALContext *, shared_ptr<SEALContext>> pointer_store_;

        extern ReaderWriterLocker pointer_store_locker_;

        // This is here only so we have a null shared pointer to return.
        shared_ptr<SEALContext> null_context_;
    } // namespace c
} // namespace seal

unique_ptr<MemoryPoolHandle> seal::c::MemHandleFromVoid(void *voidptr)
{
    if (nullptr == voidptr)
    {
        return make_unique<MemoryPoolHandle>(MemoryManager::GetPool());
    }

    MemoryPoolHandle *handle = reinterpret_cast<MemoryPoolHandle *>(voidptr);
    return make_unique<MemoryPoolHandle>(*handle);
}

void seal::c::BuildModulusPointers(const vector<Modulus> &in_mods, uint64_t *length, void **out_mods)
{
    *length = static_cast<uint64_t>(in_mods.size());
    if (out_mods == nullptr)
    {
        // The caller is only interested in the size
        return;
    }

    Modulus **mod_ptr_array = reinterpret_cast<Modulus **>(out_mods);
    transform(in_mods.begin(), in_mods.end(), mod_ptr_array, [](const auto &mod) { return new Modulus(mod); });
}

const shared_ptr<SEALContext> &seal::c::SharedContextFromVoid(void *context)
{
    SEALContext *ctx = FromVoid<SEALContext>(context);
    if (nullptr == ctx)
    {
        return null_context_;
    }

    ReaderLock lock(pointer_store_locker_.acquire_read());

    const auto &ctxiter = pointer_store_.find(ctx);
    if (ctxiter == pointer_store_.end())
    {
        return null_context_;
    }

    return ctxiter->second;
}

HRESULT seal::c::ToStringHelper(const string &str, char *outstr, uint64_t *length)
{
    *length = static_cast<uint64_t>(str.size());

    if (nullptr != outstr)
    {
        memcpy(outstr, str.c_str(), util::add_safe(*length, uint64_t(1)));
    }
    return S_OK;
}

HRESULT seal::c::ToStringHelper2(const char *str, char *outstr, uint64_t *length)
{
    *length = static_cast<uint64_t>(strlen(str));

    if (nullptr != outstr)
    {
        memcpy(outstr, str, util::add_safe(*length, uint64_t(1)));
    }
    return S_OK;
}