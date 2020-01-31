// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

// SEALNet
#include "seal/c/memorymanager.h"
#include "seal/c/stdafx.h"
#include "seal/c/utilities.h"

// SEAL
#include "seal/memorymanager.h"

using namespace std;
using namespace seal;
using namespace seal::c;

namespace
{
    template <class T>
    HRESULT GenericCreateProfileCopy(T *original, MMProf **copyptr)
    {
        T *copy = new T(*original);
        *copyptr = copy;
        return S_OK;
    }

    HRESULT CreateProfileCopy(MMProf *profile, MMProf **copyptr)
    {
        IfNullRet(profile, E_POINTER);
        IfNullRet(copyptr, E_POINTER);

        MMProfGlobal *global = dynamic_cast<MMProfGlobal *>(profile);
        if (nullptr != global)
        {
            return GenericCreateProfileCopy(global, copyptr);
        }

        MMProfFixed *fixed = dynamic_cast<MMProfFixed *>(profile);
        if (nullptr != fixed)
        {
            return GenericCreateProfileCopy(fixed, copyptr);
        }

        MMProfNew *newprof = dynamic_cast<MMProfNew *>(profile);
        if (nullptr != newprof)
        {
            return GenericCreateProfileCopy(newprof, copyptr);
        }

        MMProfThreadLocal *threadlocal = dynamic_cast<MMProfThreadLocal *>(profile);
        if (nullptr != threadlocal)
        {
            return GenericCreateProfileCopy(threadlocal, copyptr);
        }

        // No matching profile.
        return E_UNEXPECTED;
    }
} // namespace

SEAL_C_FUNC MemoryManager_GetPool1(int prof_opt, bool clear_on_destruction, void **pool_handle)
{
    IfNullRet(pool_handle, E_POINTER);

    mm_prof_opt profile_opt = static_cast<mm_prof_opt>(prof_opt);
    MemoryPoolHandle handle;

    // clear_on_destruction is only used when using FORCE_NEW
    if (profile_opt == mm_prof_opt::FORCE_NEW)
    {
        handle = MemoryManager::GetPool(profile_opt, clear_on_destruction);
    }
    else
    {
        handle = MemoryManager::GetPool(profile_opt);
    }

    MemoryPoolHandle *handle_ptr = new MemoryPoolHandle(move(handle));
    *pool_handle = handle_ptr;
    return S_OK;
}

SEAL_C_FUNC MemoryManager_GetPool2(void **pool_handle)
{
    IfNullRet(pool_handle, E_POINTER);

    MemoryPoolHandle handle = MemoryManager::GetPool();
    MemoryPoolHandle *handle_ptr = new MemoryPoolHandle(move(handle));
    *pool_handle = handle_ptr;
    return S_OK;
}

SEAL_C_FUNC MemoryManager_SwitchProfile(void *new_profile)
{
    MMProf *profile = FromVoid<MMProf>(new_profile);
    IfNullRet(profile, E_POINTER);

    // SwitchProfile takes ownership of the profile pointer that is passed.
    // The managed side will keep ownership of the new_profile parameter, so we
    // need to make a copy that will be owned by the Memory Manager.
    MMProf *new_mm_profile = nullptr;
    IfFailRet(CreateProfileCopy(profile, &new_mm_profile));

    MemoryManager::SwitchProfile(static_cast<MMProf *>(new_mm_profile));
    return S_OK;
}

SEAL_C_FUNC MMProf_CreateGlobal(void **profile)
{
    IfNullRet(profile, E_POINTER);

    MMProfGlobal *global = new MMProfGlobal();
    *profile = global;
    return S_OK;
}

SEAL_C_FUNC MMProf_CreateFixed(void *pool, void **profile)
{
    MemoryPoolHandle *poolptr = FromVoid<MemoryPoolHandle>(pool);
    IfNullRet(poolptr, E_POINTER);
    IfNullRet(profile, E_POINTER);

    MemoryPoolHandle myhandle(*poolptr);
    MMProfFixed *fixed = new MMProfFixed(myhandle);
    *profile = fixed;
    return S_OK;
}

SEAL_C_FUNC MMProf_CreateNew(void **profile)
{
    IfNullRet(profile, E_POINTER);

    MMProfNew *newprof = new MMProfNew();
    *profile = newprof;
    return S_OK;
}

SEAL_C_FUNC MMProf_CreateThreadLocal(void **profile)
{
    IfNullRet(profile, E_POINTER);

    MMProfThreadLocal *threadlocal = new MMProfThreadLocal();
    *profile = threadlocal;
    return S_OK;
}

SEAL_C_FUNC MMProf_GetPool(void *thisptr, void **pool_handle)
{
    MMProf *profile = FromVoid<MMProf>(thisptr);
    IfNullRet(profile, E_POINTER);
    IfNullRet(pool_handle, E_POINTER);

    // The parameter to get_pool is always ignored, so just pass 0
    MemoryPoolHandle *handle_ptr = new MemoryPoolHandle(profile->get_pool(0));
    *pool_handle = handle_ptr;
    return S_OK;
}

SEAL_C_FUNC MMProf_Destroy(void *thisptr)
{
    MMProf *profile = FromVoid<MMProf>(thisptr);
    IfNullRet(profile, E_POINTER);

    delete profile;
    return S_OK;
}