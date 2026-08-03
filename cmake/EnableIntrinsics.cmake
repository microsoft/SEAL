# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT license.

include(CheckCXXIntrinsicsHeader)
include(CheckCXXIntrinsicsSpecific)

macro(seal_make_intrin_option id docstring)
    cmake_dependent_option(SEAL_USE_${id} "${docstring}" ON "SEAL_USE_INTRIN;SEAL_${id}_FOUND" OFF)
    mark_as_advanced(FORCE SEAL_USE_${id})
endmacro()

if(SEAL_USE_INTRIN)
    seal_detect__umul128()
    seal_detect___umulh()
    seal_detect___int128()
    seal_detect__BitScanReverse64()
    seal_detect___builtin_clzll()
    seal_detect__addcarry_u64()
    seal_detect__subborrow_u64()
    seal_detect___builtin_addcll()
    seal_detect___builtin_subcll()
else()
    set(SEAL__UMUL128_FOUND OFF)
    set(SEAL___UMULH_FOUND OFF)
    set(SEAL___INT128_FOUND OFF)
    set(SEAL__BITSCANREVERSE64_FOUND OFF)
    set(SEAL___BUILTIN_CLZLL_FOUND OFF)
    set(SEAL__ADDCARRY_U64_FOUND OFF)
    set(SEAL__SUBBORROW_U64_FOUND OFF)
    set(SEAL___BUILTIN_ADDCLL_FOUND OFF)
    set(SEAL___BUILTIN_SUBCLL_FOUND OFF)
endif()

# The options are created outside the check above, so that clearing SEAL_USE_INTRIN in an existing
# build tree also clears every intrinsic option that was enabled in it.
seal_make_intrin_option(_UMUL128 "Use _umul128")
message(STATUS "Using _umul128: ${SEAL_USE__UMUL128}")

seal_make_intrin_option(__UMULH "Use __umulh")
message(STATUS "Using __umulh: ${SEAL_USE___UMULH}")

seal_make_intrin_option(__INT128 "Use __int128")
message(STATUS "Using __int128: ${SEAL_USE___INT128}")

seal_make_intrin_option(_BITSCANREVERSE64 "Use _BitScanReverse64")
message(STATUS "Using _BitScanReverse64: ${SEAL_USE__BITSCANREVERSE64}")

seal_make_intrin_option(__BUILTIN_CLZLL "Use __builtin_clzll")
message(STATUS "Using __builtin_clzll: ${SEAL_USE___BUILTIN_CLZLL}")

seal_make_intrin_option(_ADDCARRY_U64 "Use _addcarry_u64")
message(STATUS "Using _addcarry_u64: ${SEAL_USE__ADDCARRY_U64}")

seal_make_intrin_option(_SUBBORROW_U64 "Use _subborrow_u64")
message(STATUS "Using _subborrow_u64: ${SEAL_USE__SUBBORROW_U64}")

seal_make_intrin_option(__BUILTIN_ADDCLL "Use __builtin_addcll")
message(STATUS "Using __builtin_addcll: ${SEAL_USE___BUILTIN_ADDCLL}")

seal_make_intrin_option(__BUILTIN_SUBCLL "Use __builtin_subcll")
message(STATUS "Using __builtin_subcll: ${SEAL_USE___BUILTIN_SUBCLL}")
