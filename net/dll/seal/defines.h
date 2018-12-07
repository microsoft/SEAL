// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#pragma once

#ifdef SEALDLL_EXPORTS
#define SEALDLL extern "C" __declspec(dllexport)
#else
#define SEALDLL extern "C" __declspec(dllimport)
#endif

#define SEALCALL __cdecl
