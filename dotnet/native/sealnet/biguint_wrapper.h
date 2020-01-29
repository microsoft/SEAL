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

SEALMETHOD BigUInt_Create1(void **bui);

SEALMETHOD BigUInt_Create2(int bitCount, void **bui);

SEALMETHOD BigUInt_Create3(int bitCount, char *hex_string, void **bui);

SEALMETHOD BigUInt_Create4(int bitCount, uint64_t value, void **bui);

SEALMETHOD BigUInt_Create5(char *hex_string, void **bui);

SEALMETHOD BigUInt_Create6(void *copy, void **bui);

SEALMETHOD BigUInt_Destroy(void *thispt);

SEALMETHOD BigUInt_IsAlias(void *thisptr, bool *is_alias);

SEALMETHOD BigUInt_BitCount(void *thisptr, int *bit_count);

SEALMETHOD BigUInt_ByteCount(void *thisptr, uint64_t *byte_count);

SEALMETHOD BigUInt_UInt64Count(void *thisptr, uint64_t *uint64_count);

SEALMETHOD BigUInt_IsZero(void *thisptr, bool *is_zero);

SEALMETHOD BigUInt_Get(void *thisptr, uint64_t index, uint8_t *value);

SEALMETHOD BigUInt_GetU64(void *thisptr, uint64_t index, uint64_t *value);

SEALMETHOD BigUInt_Set1(void *thisptr, uint64_t index, uint8_t value);

SEALMETHOD BigUInt_GetSignificantBitCount(void *thisptr, int *significant_bit_count);

SEALMETHOD BigUInt_Set2(void *thisptr, void *assign);

SEALMETHOD BigUInt_Set3(void *thisptr, uint64_t value);

SEALMETHOD BigUInt_Set4(void *thisptr, char *assign);

SEALMETHOD BigUInt_SetZero(void *thispt);

SEALMETHOD BigUInt_Resize(void *thisptr, int bitCount);

SEALMETHOD BigUInt_Equals(void *thisptr, void *compare, bool *result);

SEALMETHOD BigUInt_CompareTo1(void *thisptr, void *compare, int *result);

SEALMETHOD BigUInt_CompareTo2(void *thisptr, uint64_t compare, int *result);

SEALMETHOD BigUInt_DivideRemainder1(void *thisptr, void *operand2, void *remainder, void **result);

SEALMETHOD BigUInt_DivideRemainder2(void *thisptr, uint64_t operand2, void *remainder, void **result);

SEALMETHOD BigUInt_ToString(void *thisptr, char *outstr, uint64_t *length);

SEALMETHOD BigUInt_ToDecimalString(void *thisptr, char *outstr, uint64_t *length);

SEALMETHOD BigUInt_DuplicateTo(void *thisptr, void *destination);

SEALMETHOD BigUInt_DuplicateFrom(void *thisptr, void *value);

SEALMETHOD BigUInt_ModuloInvert1(void *thisptr, void *modulus, void **result);

SEALMETHOD BigUInt_ModuloInvert2(void *thisptr, uint64_t modulus, void **result);

SEALMETHOD BigUInt_TryModuloInvert1(void *thisptr, void *modulus, void *inverse, bool *result);

SEALMETHOD BigUInt_TryModuloInvert2(void *thisptr, uint64_t modulus, void *inverse, bool *result);

SEALMETHOD BigUInt_OperatorNeg(void *thisptr, void **result);

SEALMETHOD BigUInt_OperatorTilde(void *thisptr, void **result);

SEALMETHOD BigUInt_OperatorPlus1(void *thisptr, void *operand, void **result);

SEALMETHOD BigUInt_OperatorPlus2(void *thisptr, uint64_t operand, void **result);

SEALMETHOD BigUInt_OperatorMinus1(void *thisptr, void *operand, void **result);

SEALMETHOD BigUInt_OperatorMinus2(void *thisptr, uint64_t operand, void **result);

SEALMETHOD BigUInt_OperatorMult1(void *thisptr, void *operand, void **result);

SEALMETHOD BigUInt_OperatorMult2(void *thisptr, uint64_t operand, void **result);

SEALMETHOD BigUInt_OperatorDiv1(void *thisptr, void *operand, void **result);

SEALMETHOD BigUInt_OperatorDiv2(void *thisptr, uint64_t operand, void **result);

SEALMETHOD BigUInt_OperatorXor1(void *thisptr, void *operand, void **result);

SEALMETHOD BigUInt_OperatorXor2(void *thisptr, uint64_t operand, void **result);

SEALMETHOD BigUInt_OperatorAnd1(void *thisptr, void *operand, void **result);

SEALMETHOD BigUInt_OperatorAnd2(void *thisptr, uint64_t operand, void **result);

SEALMETHOD BigUInt_OperatorOr1(void *thisptr, void *operand, void **result);

SEALMETHOD BigUInt_OperatorOr2(void *thisptr, uint64_t operand, void **result);

SEALMETHOD BigUInt_OperatorShiftLeft(void *thisptr, int shift, void **result);

SEALMETHOD BigUInt_OperatorShiftRight(void *thisptr, int shift, void **result);

SEALMETHOD BigUInt_ToDouble(void *thisptr, double *result);

SEALMETHOD BigUInt_SaveSize(void *thisptr, uint8_t compr_mode, int64_t *result);

SEALMETHOD BigUInt_Save(void *thisptr, uint8_t *outptr, uint64_t size, uint8_t compr_mode, int64_t *out_bytes);

SEALMETHOD BigUInt_Load(void *thisptr, uint8_t *inptr, uint64_t size, int64_t *in_bytes);
