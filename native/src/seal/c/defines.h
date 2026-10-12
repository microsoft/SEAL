// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#pragma once

// STD
#include <cstddef>
#include <new>
#include <stdexcept>

// SEALNet
#include "seal/c/stdafx.h"

// Check that std::size_t is 64 bits
static_assert(sizeof(std::size_t) == 8, "Require sizeof(std::size_t) == 8");

#ifdef _MSC_VER

// Check that architecture (platform) is x64
#ifndef _WIN64
static_assert(false, "Require architecture == x64");
#endif

#ifdef SEAL_BUILD_STATIC_SEAL_C
#define SEAL_C_DECOR extern "C"
#else // SEAL_BUILD_STATIC_SEAL_C
#if defined(SEAL_C_EXPORTS) || defined(seal_c_EXPORTS) || defined(sealc_EXPORTS)
#define SEAL_C_DECOR extern "C" __declspec(dllexport)
#else
#define SEAL_C_DECOR extern "C" __declspec(dllimport)
#endif
#endif // SEAL_BUILD_STATIC_SEAL_C

#define SEAL_C_CALL __cdecl

#else // _MSC_VER

#define SEAL_C_DECOR extern "C"
#define SEAL_C_CALL

#define HRESULT long

#define _HRESULT_TYPEDEF_(hr) ((HRESULT)hr)

#define E_POINTER _HRESULT_TYPEDEF_(0x80004003L)
#define E_INVALIDARG _HRESULT_TYPEDEF_(0x80070057L)
#define E_OUTOFMEMORY _HRESULT_TYPEDEF_(0x8007000EL)
#define E_UNEXPECTED _HRESULT_TYPEDEF_(0x8000FFFFL)

#define S_OK _HRESULT_TYPEDEF_(0L)
#define S_FALSE _HRESULT_TYPEDEF_(1L)

#define FACILITY_WIN32 7
#define HRESULT_FROM_WIN32(x) \
    ((HRESULT)(x) <= 0 ? ((HRESULT)(x)) : ((HRESULT)(((x) & 0x0000FFFF) | (FACILITY_WIN32 << 16) | 0x80000000)))

#define ERROR_INSUFFICIENT_BUFFER 122L
#define ERROR_INVALID_INDEX 1413L
#define ERROR_INVALID_OPERATION 4317L

#define SUCCEEDED(hr) (((HRESULT)(hr)) >= 0)
#define FAILED(hr) (((HRESULT)(hr)) < 0)

#endif // _MSC_VER

// On Windows, these would be defined in <corerror.h>, but we don't
// want .NET as a dependency just to build C bindings.
#define COR_E_IO _HRESULT_TYPEDEF_(0x80131620L)
#define COR_E_INVALIDOPERATION _HRESULT_TYPEDEF_(0x80131509L)

#define SEAL_C_FUNC SEAL_C_DECOR HRESULT SEAL_C_CALL

// Canonical exception-to-HRESULT translation for the C export layer. Every export
// that can throw closes its body with this so no C++ exception crosses the extern "C"
// boundary into the managed/native caller. The typed rungs reproduce the mappings the
// individual exports already used; the bad_alloc and catch-all rungs convert an
// out-of-memory or otherwise-unlisted throw into a defined HRESULT instead of aborting
// the host. Derived types are caught before their bases (invalid_argument/out_of_range
// before logic_error).
#define SEAL_C_CATCH_ALL                                \
    catch (const std::invalid_argument &)               \
    {                                                   \
        return E_INVALIDARG;                            \
    }                                                   \
    catch (const std::out_of_range &)                   \
    {                                                   \
        return HRESULT_FROM_WIN32(ERROR_INVALID_INDEX); \
    }                                                   \
    catch (const std::logic_error &)                    \
    {                                                   \
        return COR_E_INVALIDOPERATION;                  \
    }                                                   \
    catch (const std::runtime_error &)                  \
    {                                                   \
        return COR_E_IO;                                \
    }                                                   \
    catch (const std::bad_alloc &)                      \
    {                                                   \
        return E_OUTOFMEMORY;                           \
    }                                                   \
    catch (...)                                         \
    {                                                   \
        return E_UNEXPECTED;                            \
    }
