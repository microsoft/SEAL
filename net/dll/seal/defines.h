// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#pragma once

#ifdef _MSC_VER

#ifdef SEALDLL_EXPORTS
#define SEALDLL extern "C" __declspec(dllexport)
#else
#define SEALDLL extern "C" __declspec(dllimport)
#endif

#define SEALCALL __cdecl

#else // _MSC_VER

#define SEALDLL extern "C"
#define SEALCALL

#define HRESULT long

#define _HRESULT_TYPEDEF_(hr)   ((HRESULT)hr)

#define E_POINTER               _HRESULT_TYPEDEF_(0x80004003L)
#define E_INVALIDARG            _HRESULT_TYPEDEF_(0x80070057L)
#define E_OUTOFMEMORY           _HRESULT_TYPEDEF_(0x8007000EL)
#define E_UNEXPECTED            _HRESULT_TYPEDEF_(0x8000FFFFL)
//#define E_POINTER               _HRESULT_TYPEDEF_(0x80004003L)
//#define E_POINTER               _HRESULT_TYPEDEF_(0x80004003L)

#define S_OK                    _HRESULT_TYPEDEF_(0L)

#endif // _MSC_VER

