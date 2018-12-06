// SEALDll
#include "stdafx.h"
#include "memorymanager.h"
#include "utilities.h"

// SEAL
#include "seal/memorymanager.h"

using namespace std;
using namespace seal;
using namespace seal::dll;

namespace
{
    // Keep instance of old profile alive, as it may be used in the native side.
    unique_ptr<MMProf> old_profile_;

    template<class T>
    HRESULT CreateProfileCopy(T* original, void** copyptr)
    {
        T* copy = new T(*original);
        *copyptr = copy;
        return S_OK;
    }
}


SEALDLL HRESULT SEALCALL MemoryManager_GetPool1(int prof_opt, bool clear_on_destruction, void** pool_handle)
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

    MemoryPoolHandle* handle_ptr = new MemoryPoolHandle(move(handle));
    *pool_handle = handle_ptr;
    return S_OK;
}

SEALDLL HRESULT SEALCALL MemoryManager_GetPool2(void** pool_handle)
{
    IfNullRet(pool_handle, E_POINTER);

    MemoryPoolHandle handle = MemoryManager::GetPool();
    MemoryPoolHandle* handle_ptr = new MemoryPoolHandle(move(handle));
    *pool_handle = handle_ptr;
    return S_OK;
}

void Test()
{
    MemoryPoolHandle handle = MemoryManager::GetPool(mm_prof_opt::FORCE_NEW);
    MMProfFixed* myf = new MMProfFixed(handle);
    MMProfFixed* my2 = new MMProfFixed(*myf);
}

SEALDLL HRESULT SEALCALL MemoryManager_SwitchProfile(void* new_profile, void** old_profile)
{
    MMProf* profile = FromVoid<MMProf>(new_profile);
    IfNullRet(profile, E_POINTER);
    IfNullRet(old_profile, E_POINTER);

    old_profile_ = MemoryManager::SwitchProfile(static_cast<MMProf*>(profile));
    *old_profile = old_profile_.get();
    return S_OK;
}

SEALDLL HRESULT SEALCALL MMProf_CreateGlobal(void** profile)
{
    IfNullRet(profile, E_POINTER);

    MMProfGlobal* global = new MMProfGlobal();
    *profile = global;
    return S_OK;
}

SEALDLL HRESULT SEALCALL MMProf_CreateFixed(void* pool, void** profile)
{
    MemoryPoolHandle* poolptr = FromVoid<MemoryPoolHandle>(pool);
    IfNullRet(poolptr, E_POINTER);
    IfNullRet(profile, E_POINTER);

    MemoryPoolHandle myhandle(*poolptr);
    MMProfFixed* fixed = new MMProfFixed(myhandle);
    *profile = fixed;
    return S_OK;

}

SEALDLL HRESULT SEALCALL MMProf_CreateNew(void** profile)
{
    IfNullRet(profile, E_POINTER);

    MMProfNew* newprof = new MMProfNew();
    *profile = newprof;
    return S_OK;
}

SEALDLL HRESULT SEALCALL MMProf_CreateThreadLocal(void** profile)
{
    IfNullRet(profile, E_POINTER);

    MMProfThreadLocal* threadlocal = new MMProfThreadLocal();
    *profile = threadlocal;
    return S_OK;
}

SEALDLL HRESULT SEALCALL MMProf_CreateCopy(void* thisptr, void** copyptr)
{
    MMProf* profile = FromVoid<MMProf>(thisptr);
    IfNullRet(profile, E_POINTER);
    IfNullRet(copyptr, E_POINTER);

    MMProfGlobal* global = dynamic_cast<MMProfGlobal*>(profile);
    if (nullptr != global)
    {
        return CreateProfileCopy(global, copyptr);
    }

    MMProfFixed* fixed = dynamic_cast<MMProfFixed*>(profile);
    if (nullptr != fixed)
    {
        return CreateProfileCopy(fixed, copyptr);
    }

    MMProfNew* newprof = dynamic_cast<MMProfNew*>(profile);
    if (nullptr != newprof)
    {
        return CreateProfileCopy(newprof, copyptr);
    }

    MMProfThreadLocal* threadlocal = dynamic_cast<MMProfThreadLocal*>(profile);
    if (nullptr != threadlocal)
    {
        return CreateProfileCopy(threadlocal, copyptr);
    }

    // No matching profile.
    return E_UNEXPECTED;
}

SEALDLL HRESULT SEALCALL MMProf_GetPool(void* thisptr, void** pool_handle)
{
    MMProf* profile = FromVoid<MMProf>(thisptr);
    IfNullRet(profile, E_POINTER);
    IfNullRet(pool_handle, E_POINTER);

    // The parameter to get_pool is always ignored, so just pass 0
    MemoryPoolHandle* handle_ptr = new MemoryPoolHandle(profile->get_pool(0));
    *pool_handle = handle_ptr;
    return S_OK;
}

SEALDLL HRESULT SEALCALL MMProf_Destroy(void* thisptr)
{
    MMProf* profile = FromVoid<MMProf>(thisptr);
    IfNullRet(profile, E_POINTER);

    delete profile;
    return S_OK;
}

SEALDLL HRESULT SEALCALL MMProf_DestroyGlobal(void* thisptr)
{
    MMProfGlobal* profile = FromVoid<MMProfGlobal>(thisptr);
    IfNullRet(profile, E_POINTER);

    delete profile;
    return S_OK;
}

SEALDLL HRESULT SEALCALL MMProf_DestroyFixed(void* thisptr)
{
    MMProfFixed* profile = FromVoid<MMProfFixed>(thisptr);
    IfNullRet(profile, E_POINTER);

    delete profile;
    return S_OK;
}

SEALDLL HRESULT SEALCALL MMProf_DestroyNew(void* thisptr)
{
    MMProfNew* profile = FromVoid<MMProfNew>(thisptr);
    IfNullRet(profile, E_POINTER);

    delete profile;
    return S_OK;
}

SEALDLL HRESULT SEALCALL MMProf_DestroyThreadLocal(void* thisptr)
{
    MMProfThreadLocal* profile = FromVoid<MMProfThreadLocal>(thisptr);
    IfNullRet(profile, E_POINTER);

    delete profile;
    return S_OK;
}
