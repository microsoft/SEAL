// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#pragma once

///////////////////////////////////////////////////////////////////////////
//
// This API is provided as a simple interface for Microsoft SEAL library
// that can be PInvoked by .Net code.
//
///////////////////////////////////////////////////////////////////////////

#include "sealnet/defines.h"
#include <stdint.h>

SEALNETNATIVE HRESULT SEALCALL BigUInt_Create1(void **bui);

SEALNETNATIVE HRESULT SEALCALL BigUInt_Create2(int bitCount, void **bui);

SEALNETNATIVE HRESULT SEALCALL BigUInt_Create3(int bitCount, char *hex_string, void **bui);

SEALNETNATIVE HRESULT SEALCALL BigUInt_Create4(int bitCount, uint64_t value, void **bui);

SEALNETNATIVE HRESULT SEALCALL BigUInt_Create5(char *hex_string, void **bui);

SEALNETNATIVE HRESULT SEALCALL BigUInt_Create6(void *copy, void **bui);

SEALNETNATIVE HRESULT SEALCALL BigUInt_Destroy(void *thispt);

SEALNETNATIVE HRESULT SEALCALL BigUInt_IsAlias(void *thispt, bool *is_alias);

SEALNETNATIVE HRESULT SEALCALL BigUInt_BitCount(void *thispt, int *bit_count);

SEALNETNATIVE HRESULT SEALCALL BigUInt_ByteCount(void *thispt, uint64_t *byte_count);

SEALNETNATIVE HRESULT SEALCALL BigUInt_UInt64Count(void *thispt, uint64_t *uint64_count);

SEALNETNATIVE HRESULT SEALCALL BigUInt_IsZero(void *thispt, bool *is_zero);

SEALNETNATIVE HRESULT SEALCALL BigUInt_Get(void *thispt, uint64_t index, uint8_t *value);

SEALNETNATIVE HRESULT SEALCALL BigUInt_GetU64(void *thispt, uint64_t index, uint64_t *value);

SEALNETNATIVE HRESULT SEALCALL BigUInt_Set1(void *thispt, uint64_t index, uint8_t value);

SEALNETNATIVE HRESULT SEALCALL BigUInt_GetSignificantBitCount(void *thispt, int *significant_bit_count);

SEALNETNATIVE HRESULT SEALCALL BigUInt_Set2(void *thispt, void *assign);

SEALNETNATIVE HRESULT SEALCALL BigUInt_Set3(void *thispt, uint64_t value);

SEALNETNATIVE HRESULT SEALCALL BigUInt_Set4(void *thispt, char *assign);

SEALNETNATIVE HRESULT SEALCALL BigUInt_SetZero(void *thispt);

SEALNETNATIVE HRESULT SEALCALL BigUInt_Resize(void *thispt, int bitCount);

SEALNETNATIVE HRESULT SEALCALL BigUInt_Equals(void *thispt, void *compare, bool *result);

SEALNETNATIVE HRESULT SEALCALL BigUInt_CompareTo1(void *thispt, void *compare, int *result);

SEALNETNATIVE HRESULT SEALCALL BigUInt_CompareTo2(void *thispt, uint64_t compare, int *result);

SEALNETNATIVE HRESULT SEALCALL BigUInt_DivideRemainder1(void *thispt, void *operand2, void *remainder, void **result);

SEALNETNATIVE HRESULT SEALCALL BigUInt_DivideRemainder2(void *thispt, uint64_t operand2, void *remainder, void **result);

SEALNETNATIVE HRESULT SEALCALL BigUInt_ToString(void *thispt, char *outstr, uint64_t *length);

SEALNETNATIVE HRESULT SEALCALL BigUInt_ToDecimalString(void *thispt, char *outstr, uint64_t *length);

SEALNETNATIVE HRESULT SEALCALL BigUInt_DuplicateTo(void *thispt, void *destination);

SEALNETNATIVE HRESULT SEALCALL BigUInt_DuplicateFrom(void *thispt, void *value);

SEALNETNATIVE HRESULT SEALCALL BigUInt_ModuloInvert1(void *thispt, void *modulus, void **result);

SEALNETNATIVE HRESULT SEALCALL BigUInt_ModuloInvert2(void *thispt, uint64_t modulus, void **result);

SEALNETNATIVE HRESULT SEALCALL BigUInt_TryModuloInvert1(void *thispt, void *modulus, void *inverse, bool *result);

SEALNETNATIVE HRESULT SEALCALL BigUInt_TryModuloInvert2(void *thispt, uint64_t modulus, void *inverse, bool *result);

SEALNETNATIVE HRESULT SEALCALL BigUInt_OperatorNeg(void *thispt, void **result);

SEALNETNATIVE HRESULT SEALCALL BigUInt_OperatorTilde(void *thispt, void **result);

SEALNETNATIVE HRESULT SEALCALL BigUInt_OperatorPlus1(void *thispt, void *operand, void **result);

SEALNETNATIVE HRESULT SEALCALL BigUInt_OperatorPlus2(void *thispt, uint64_t operand, void **result);

SEALNETNATIVE HRESULT SEALCALL BigUInt_OperatorMinus1(void *thispt, void *operand, void **result);

SEALNETNATIVE HRESULT SEALCALL BigUInt_OperatorMinus2(void *thispt, uint64_t operand, void **result);

SEALNETNATIVE HRESULT SEALCALL BigUInt_OperatorMult1(void *thispt, void *operand, void **result);

SEALNETNATIVE HRESULT SEALCALL BigUInt_OperatorMult2(void *thispt, uint64_t operand, void **result);

SEALNETNATIVE HRESULT SEALCALL BigUInt_OperatorDiv1(void *thispt, void *operand, void **result);

SEALNETNATIVE HRESULT SEALCALL BigUInt_OperatorDiv2(void *thispt, uint64_t operand, void **result);

SEALNETNATIVE HRESULT SEALCALL BigUInt_OperatorXor1(void *thispt, void *operand, void **result);

SEALNETNATIVE HRESULT SEALCALL BigUInt_OperatorXor2(void *thispt, uint64_t operand, void **result);

SEALNETNATIVE HRESULT SEALCALL BigUInt_OperatorAnd1(void *thispt, void *operand, void **result);

SEALNETNATIVE HRESULT SEALCALL BigUInt_OperatorAnd2(void *thispt, uint64_t operand, void **result);

SEALNETNATIVE HRESULT SEALCALL BigUInt_OperatorOr1(void *thispt, void *operand, void **result);

SEALNETNATIVE HRESULT SEALCALL BigUInt_OperatorOr2(void *thispt, uint64_t operand, void **result);

SEALNETNATIVE HRESULT SEALCALL BigUInt_OperatorShiftLeft(void *thispt, int shift, void **result);

SEALNETNATIVE HRESULT SEALCALL BigUInt_OperatorShiftRight(void *thispt, int shift, void **result);

SEALNETNATIVE HRESULT SEALCALL BigUInt_ToDouble(void *thispt, double *result);
