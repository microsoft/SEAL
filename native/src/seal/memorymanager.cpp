// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include "seal/memorymanager.h"

namespace seal
{
    std::unique_ptr<MMProf>
        MemoryManager::mm_prof_{ new MMProfGlobal };
#ifndef _M_CEE
    std::mutex MemoryManager::switch_mutex_;
#else
#pragma message("WARNING: MemoryManager compiled thread-unsafe and MMProfGuard disabled to support /clr")
#endif
}