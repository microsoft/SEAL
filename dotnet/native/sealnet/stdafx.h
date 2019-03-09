// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

// stdafx.h : include file for standard system include files,
// or project specific include files that are used frequently, but
// are changed infrequently
//

#pragma once

#ifdef _MSC_VER
#include "sealnet/targetver.h"

#define WIN32_LEAN_AND_MEAN             // Exclude rarely-used stuff from Windows headers
// Windows Header Files
#include <windows.h>
#endif // _MSC_VER

#define IfNullRet(expr, ret) {\
    if ((expr) == nullptr) \
    { \
        return ret; \
    } \
}

#define IfFailRet(expr) { \
    HRESULT __hr__ = (expr); \
    if (FAILED(__hr__)) \
    { \
        return __hr__; \
    } \
}
