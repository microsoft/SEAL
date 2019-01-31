// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#pragma once

// STD
#include <cstddef>

#ifdef _MSC_VER

// Check that size_t is 64 bits
static_assert(sizeof(std::size_t) == 8, "Require sizeof(std::size_t) == 8");

// Check that architecture (platform) is x64
#ifndef _WIN64
static_assert(false, "Require architecture == x64");
#endif

#ifdef SEALNETNATIVE_EXPORTS
#define SEALNETNATIVE extern "C" __declspec(dllexport)
#else
#define SEALNETNATIVE extern "C" __declspec(dllimport)
#endif

#define SEALCALL __cdecl

#else // _MSC_VER

#define SEALNETNATIVE extern "C"
#define SEALCALL

#define HRESULT long

#define _HRESULT_TYPEDEF_(hr)   ((HRESULT)hr)

#define E_POINTER               _HRESULT_TYPEDEF_(0x80004003L)
#define E_INVALIDARG            _HRESULT_TYPEDEF_(0x80070057L)
#define E_OUTOFMEMORY           _HRESULT_TYPEDEF_(0x8007000EL)
#define E_UNEXPECTED            _HRESULT_TYPEDEF_(0x8000FFFFL)

#define S_OK                    _HRESULT_TYPEDEF_(0L)
#define S_FALSE                 _HRESULT_TYPEDEF_(1L)


#define FACILITY_WIN32                 7
#define HRESULT_FROM_WIN32(x) ((HRESULT)(x) <= 0 ? ((HRESULT)(x)) : ((HRESULT) (((x) & 0x0000FFFF) | (FACILITY_WIN32 << 16) | 0x80000000)))

#define ERROR_INSUFFICIENT_BUFFER        122L
#define ERROR_INVALID_INDEX              1413L
#define ERROR_INVALID_OPERATION          4317L

#define SUCCEEDED(hr) (((HRESULT)(hr)) >= 0)
#define FAILED(hr) (((HRESULT)(hr)) < 0)

#endif // _MSC_VER

