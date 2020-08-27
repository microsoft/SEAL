// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef __STDC_WANT_LIB_EXT1__
#define __STDC_WANT_LIB_EXT1__ 1
#endif

#include "seal/util/common.h"
#include <string.h>

#if SEAL_SYSTEM == SEAL_SYSTEM_WINDOWS
#include <Windows.h>
#endif


void seal::util::memzero(void *const data, const size_t size)
{
#if SEAL_SYSTEM == SEAL_SYSTEM_WINDOWS
    SecureZeroMemory(data, size);
#elif defined(SEAL_USE_MEMSET_S)
    if (size > 0U && memset_s(data, (rsize_t)size, 0, (rsize_t)size) != 0)
    {
        throw std::runtime_error("Error calling memset_s");
    }
#elif defined(SEAL_USE_EXPLICIT_BZERO)
    explicit_bzero(data, size);
#elif defined(SEAL_USE_EXPLICIT_MEMSET)
    explicit_memset(data, 0, size);
#else
    volatile SEAL_BYTE *data_ptr = reinterpret_cast<SEAL_BYTE *>(data);
    size_t i = 0;
    while (i < size)
    {
        *data_ptr++ = static_cast<SEAL_BYTE>(0);
    }

#endif
}
