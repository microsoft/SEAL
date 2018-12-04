// SEALDll
#include "stdafx.h"
#include "memorymanager.h"
#include "utilities.h"

// SEAL
#include "seal/memorymanager.h"

using namespace std;
using namespace seal;
using namespace seal::dll;


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

