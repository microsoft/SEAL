// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#pragma once

///////////////////////////////////////////////////////////////////////////
//
// This API is provided as a simple interface for Microsoft SEAL library
// that can be PInvoked by .Net code.
//
///////////////////////////////////////////////////////////////////////////

#include "seal/c/defines.h"
#include <stdint.h>

SEAL_C_FUNC BigUInt_Create1(void **bui);

SEAL_C_FUNC BigUInt_Create2(int bitCount, void **bui);

SEAL_C_FUNC BigUInt_Create3(int bitCount, char *hex_string, void **bui);

SEAL_C_FUNC BigUInt_Create4(int bitCount, uint64_t value, void **bui);

SEAL_C_FUNC BigUInt_Create5(char *hex_string, void **bui);

SEAL_C_FUNC BigUInt_Create6(void *copy, void **bui);

SEAL_C_FUNC BigUInt_Destroy(void *thispt);

SEAL_C_FUNC BigUInt_IsAlias(void *thisptr, bool *is_alias);

SEAL_C_FUNC BigUInt_BitCount(void *thisptr, int *bit_count);

SEAL_C_FUNC BigUInt_ByteCount(void *thisptr, uint64_t *byte_count);

SEAL_C_FUNC BigUInt_UInt64Count(void *thisptr, uint64_t *uint64_count);

SEAL_C_FUNC BigUInt_IsZero(void *thisptr, bool *is_zero);

SEAL_C_FUNC BigUInt_Get(void *thisptr, uint64_t index, uint8_t *value);

SEAL_C_FUNC BigUInt_GetU64(void *thisptr, uint64_t index, uint64_t *value);

SEAL_C_FUNC BigUInt_Set1(void *thisptr, uint64_t index, uint8_t value);

SEAL_C_FUNC BigUInt_GetSignificantBitCount(void *thisptr, int *significant_bit_count);

SEAL_C_FUNC BigUInt_Set2(void *thisptr, void *assign);

SEAL_C_FUNC BigUInt_Set3(void *thisptr, uint64_t value);

SEAL_C_FUNC BigUInt_Set4(void *thisptr, char *assign);

SEAL_C_FUNC BigUInt_SetZero(void *thispt);

SEAL_C_FUNC BigUInt_Resize(void *thisptr, int bitCount);

SEAL_C_FUNC BigUInt_Equals(void *thisptr, void *compare, bool *result);

SEAL_C_FUNC BigUInt_CompareTo1(void *thisptr, void *compare, int *result);

SEAL_C_FUNC BigUInt_CompareTo2(void *thisptr, uint64_t compare, int *result);

SEAL_C_FUNC BigUInt_DivideRemainder1(void *thisptr, void *operand2, void *remainder, void **result);

SEAL_C_FUNC BigUInt_DivideRemainder2(void *thisptr, uint64_t operand2, void *remainder, void **result);

SEAL_C_FUNC BigUInt_ToString(void *thisptr, char *outstr, uint64_t *length);

SEAL_C_FUNC BigUInt_ToDecimalString(void *thisptr, char *outstr, uint64_t *length);

SEAL_C_FUNC BigUInt_DuplicateTo(void *thisptr, void *destination);

SEAL_C_FUNC BigUInt_DuplicateFrom(void *thisptr, void *value);

SEAL_C_FUNC BigUInt_ModuloInvert1(void *thisptr, void *modulus, void **result);

SEAL_C_FUNC BigUInt_ModuloInvert2(void *thisptr, uint64_t modulus, void **result);

SEAL_C_FUNC BigUInt_TryModuloInvert1(void *thisptr, void *modulus, void *inverse, bool *result);

SEAL_C_FUNC BigUInt_TryModuloInvert2(void *thisptr, uint64_t modulus, void *inverse, bool *result);

SEAL_C_FUNC BigUInt_OperatorNeg(void *thisptr, void **result);

SEAL_C_FUNC BigUInt_OperatorTilde(void *thisptr, void **result);

SEAL_C_FUNC BigUInt_OperatorPlus1(void *thisptr, void *operand, void **result);

SEAL_C_FUNC BigUInt_OperatorPlus2(void *thisptr, uint64_t operand, void **result);

SEAL_C_FUNC BigUInt_OperatorMinus1(void *thisptr, void *operand, void **result);

SEAL_C_FUNC BigUInt_OperatorMinus2(void *thisptr, uint64_t operand, void **result);

SEAL_C_FUNC BigUInt_OperatorMult1(void *thisptr, void *operand, void **result);

SEAL_C_FUNC BigUInt_OperatorMult2(void *thisptr, uint64_t operand, void **result);

SEAL_C_FUNC BigUInt_OperatorDiv1(void *thisptr, void *operand, void **result);

SEAL_C_FUNC BigUInt_OperatorDiv2(void *thisptr, uint64_t operand, void **result);

SEAL_C_FUNC BigUInt_OperatorXor1(void *thisptr, void *operand, void **result);

SEAL_C_FUNC BigUInt_OperatorXor2(void *thisptr, uint64_t operand, void **result);

SEAL_C_FUNC BigUInt_OperatorAnd1(void *thisptr, void *operand, void **result);

SEAL_C_FUNC BigUInt_OperatorAnd2(void *thisptr, uint64_t operand, void **result);

SEAL_C_FUNC BigUInt_OperatorOr1(void *thisptr, void *operand, void **result);

SEAL_C_FUNC BigUInt_OperatorOr2(void *thisptr, uint64_t operand, void **result);

SEAL_C_FUNC BigUInt_OperatorShiftLeft(void *thisptr, int shift, void **result);

SEAL_C_FUNC BigUInt_OperatorShiftRight(void *thisptr, int shift, void **result);

SEAL_C_FUNC BigUInt_ToDouble(void *thisptr, double *result);

SEAL_C_FUNC BigUInt_SaveSize(void *thisptr, uint8_t compr_mode, int64_t *result);

SEAL_C_FUNC BigUInt_Save(void *thisptr, uint8_t *outptr, uint64_t size, uint8_t compr_mode, int64_t *out_bytes);

SEAL_C_FUNC BigUInt_Load(void *thisptr, uint8_t *inptr, uint64_t size, int64_t *in_bytes);
