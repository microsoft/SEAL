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

SEALNETNATIVE HRESULT SEALCALL BigUInt_IsAlias(void *thisptr, bool *is_alias);

SEALNETNATIVE HRESULT SEALCALL BigUInt_BitCount(void *thisptr, int *bit_count);

SEALNETNATIVE HRESULT SEALCALL BigUInt_ByteCount(void *thisptr, uint64_t *byte_count);

SEALNETNATIVE HRESULT SEALCALL BigUInt_UInt64Count(void *thisptr, uint64_t *uint64_count);

SEALNETNATIVE HRESULT SEALCALL BigUInt_IsZero(void *thisptr, bool *is_zero);

SEALNETNATIVE HRESULT SEALCALL BigUInt_Get(void *thisptr, uint64_t index, uint8_t *value);

SEALNETNATIVE HRESULT SEALCALL BigUInt_GetU64(void *thisptr, uint64_t index, uint64_t *value);

SEALNETNATIVE HRESULT SEALCALL BigUInt_Set1(void *thisptr, uint64_t index, uint8_t value);

SEALNETNATIVE HRESULT SEALCALL BigUInt_GetSignificantBitCount(void *thisptr, int *significant_bit_count);

SEALNETNATIVE HRESULT SEALCALL BigUInt_Set2(void *thisptr, void *assign);

SEALNETNATIVE HRESULT SEALCALL BigUInt_Set3(void *thisptr, uint64_t value);

SEALNETNATIVE HRESULT SEALCALL BigUInt_Set4(void *thisptr, char *assign);

SEALNETNATIVE HRESULT SEALCALL BigUInt_SetZero(void *thispt);

SEALNETNATIVE HRESULT SEALCALL BigUInt_Resize(void *thisptr, int bitCount);

SEALNETNATIVE HRESULT SEALCALL BigUInt_Equals(void *thisptr, void *compare, bool *result);

SEALNETNATIVE HRESULT SEALCALL BigUInt_CompareTo1(void *thisptr, void *compare, int *result);

SEALNETNATIVE HRESULT SEALCALL BigUInt_CompareTo2(void *thisptr, uint64_t compare, int *result);

SEALNETNATIVE HRESULT SEALCALL BigUInt_DivideRemainder1(void *thisptr, void *operand2, void *remainder, void **result);

SEALNETNATIVE HRESULT SEALCALL BigUInt_DivideRemainder2(void *thisptr, uint64_t operand2, void *remainder, void **result);

SEALNETNATIVE HRESULT SEALCALL BigUInt_ToString(void *thisptr, char *outstr, uint64_t *length);

SEALNETNATIVE HRESULT SEALCALL BigUInt_ToDecimalString(void *thisptr, char *outstr, uint64_t *length);

SEALNETNATIVE HRESULT SEALCALL BigUInt_DuplicateTo(void *thisptr, void *destination);

SEALNETNATIVE HRESULT SEALCALL BigUInt_DuplicateFrom(void *thisptr, void *value);

SEALNETNATIVE HRESULT SEALCALL BigUInt_ModuloInvert1(void *thisptr, void *modulus, void **result);

SEALNETNATIVE HRESULT SEALCALL BigUInt_ModuloInvert2(void *thisptr, uint64_t modulus, void **result);

SEALNETNATIVE HRESULT SEALCALL BigUInt_TryModuloInvert1(void *thisptr, void *modulus, void *inverse, bool *result);

SEALNETNATIVE HRESULT SEALCALL BigUInt_TryModuloInvert2(void *thisptr, uint64_t modulus, void *inverse, bool *result);

SEALNETNATIVE HRESULT SEALCALL BigUInt_OperatorNeg(void *thisptr, void **result);

SEALNETNATIVE HRESULT SEALCALL BigUInt_OperatorTilde(void *thisptr, void **result);

SEALNETNATIVE HRESULT SEALCALL BigUInt_OperatorPlus1(void *thisptr, void *operand, void **result);

SEALNETNATIVE HRESULT SEALCALL BigUInt_OperatorPlus2(void *thisptr, uint64_t operand, void **result);

SEALNETNATIVE HRESULT SEALCALL BigUInt_OperatorMinus1(void *thisptr, void *operand, void **result);

SEALNETNATIVE HRESULT SEALCALL BigUInt_OperatorMinus2(void *thisptr, uint64_t operand, void **result);

SEALNETNATIVE HRESULT SEALCALL BigUInt_OperatorMult1(void *thisptr, void *operand, void **result);

SEALNETNATIVE HRESULT SEALCALL BigUInt_OperatorMult2(void *thisptr, uint64_t operand, void **result);

SEALNETNATIVE HRESULT SEALCALL BigUInt_OperatorDiv1(void *thisptr, void *operand, void **result);

SEALNETNATIVE HRESULT SEALCALL BigUInt_OperatorDiv2(void *thisptr, uint64_t operand, void **result);

SEALNETNATIVE HRESULT SEALCALL BigUInt_OperatorXor1(void *thisptr, void *operand, void **result);

SEALNETNATIVE HRESULT SEALCALL BigUInt_OperatorXor2(void *thisptr, uint64_t operand, void **result);

SEALNETNATIVE HRESULT SEALCALL BigUInt_OperatorAnd1(void *thisptr, void *operand, void **result);

SEALNETNATIVE HRESULT SEALCALL BigUInt_OperatorAnd2(void *thisptr, uint64_t operand, void **result);

SEALNETNATIVE HRESULT SEALCALL BigUInt_OperatorOr1(void *thisptr, void *operand, void **result);

SEALNETNATIVE HRESULT SEALCALL BigUInt_OperatorOr2(void *thisptr, uint64_t operand, void **result);

SEALNETNATIVE HRESULT SEALCALL BigUInt_OperatorShiftLeft(void *thisptr, int shift, void **result);

SEALNETNATIVE HRESULT SEALCALL BigUInt_OperatorShiftRight(void *thisptr, int shift, void **result);

SEALNETNATIVE HRESULT SEALCALL BigUInt_ToDouble(void *thisptr, double *result);

SEALNETNATIVE HRESULT SEALCALL BigUInt_SaveSize(void *thisptr, uint8_t compr_mode, int64_t *result);

SEALNETNATIVE HRESULT SEALCALL BigUInt_Save(void *thisptr, uint8_t *outptr, uint64_t size, uint8_t compr_mode, int64_t *out_bytes);

SEALNETNATIVE HRESULT SEALCALL BigUInt_Load(void *thisptr, uint8_t *inptr, uint64_t size, int64_t *in_bytes);
