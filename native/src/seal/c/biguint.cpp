// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

// STD
#include <string>

// SEALNet
#include "seal/c/biguint.h"
#include "seal/c/stdafx.h"
#include "seal/c/utilities.h"

// SEAL
#include "seal/biguint.h"

using namespace std;
using namespace seal;
using namespace seal::c;

SEAL_C_FUNC BigUInt_Create1(void **bui)
{
    IfNullRet(bui, E_POINTER);

    BigUInt *biguint = new BigUInt();
    *bui = biguint;
    return S_OK;
}

SEAL_C_FUNC BigUInt_Create2(int bitCount, void **bui)
{
    IfNullRet(bui, E_POINTER);

    try
    {
        BigUInt *biguint = new BigUInt(bitCount, /* value */ static_cast<uint64_t>(0));
        *bui = biguint;
        return S_OK;
    }
    catch (const invalid_argument &)
    {
        return E_INVALIDARG;
    }
}

SEAL_C_FUNC BigUInt_Create3(int bitCount, char *hex_string, void **bui)
{
    IfNullRet(hex_string, E_POINTER);
    IfNullRet(bui, E_POINTER);

    string hexstring(hex_string);
    BigUInt *biguint = nullptr;

    try
    {
        biguint = new BigUInt(bitCount, hexstring);
        *bui = biguint;
        return S_OK;
    }
    catch (const invalid_argument &)
    {
        return E_INVALIDARG;
    }
}

SEAL_C_FUNC BigUInt_Create4(int bitCount, uint64_t value, void **bui)
{
    IfNullRet(bui, E_POINTER);

    try
    {
        BigUInt *biguint = new BigUInt(bitCount, value);
        *bui = biguint;
        return S_OK;
    }
    catch (const invalid_argument &)
    {
        return E_INVALIDARG;
    }
}

SEAL_C_FUNC BigUInt_Create5(char *hex_string, void **bui)
{
    IfNullRet(hex_string, E_POINTER);
    IfNullRet(bui, E_POINTER);

    string hexstring(hex_string);
    BigUInt *biguint = nullptr;

    try
    {
        biguint = new BigUInt(hexstring);
        *bui = biguint;
        return S_OK;
    }
    catch (const invalid_argument &)
    {
        return E_INVALIDARG;
    }
}

SEAL_C_FUNC BigUInt_Create6(void *copy, void **bui)
{
    BigUInt *other = FromVoid<BigUInt>(copy);
    IfNullRet(other, E_POINTER);
    IfNullRet(bui, E_POINTER);

    BigUInt *biguint = new BigUInt(*other);
    *bui = biguint;
    return S_OK;
}

SEAL_C_FUNC BigUInt_Destroy(void *thisptr)
{
    BigUInt *biguint = FromVoid<BigUInt>(thisptr);
    IfNullRet(thisptr, E_POINTER);

    delete biguint;
    return S_OK;
}

SEAL_C_FUNC BigUInt_IsAlias(void *thisptr, bool *is_alias)
{
    BigUInt *biguint = FromVoid<BigUInt>(thisptr);
    IfNullRet(biguint, E_POINTER);
    IfNullRet(is_alias, E_POINTER);

    *is_alias = biguint->is_alias();
    return S_OK;
}

SEAL_C_FUNC BigUInt_BitCount(void *thisptr, int *bit_count)
{
    BigUInt *biguint = FromVoid<BigUInt>(thisptr);
    IfNullRet(biguint, E_POINTER);
    IfNullRet(bit_count, E_POINTER);

    *bit_count = biguint->bit_count();
    return S_OK;
}

SEAL_C_FUNC BigUInt_ByteCount(void *thisptr, uint64_t *byte_count)
{
    BigUInt *biguint = FromVoid<BigUInt>(thisptr);
    IfNullRet(biguint, E_POINTER);
    IfNullRet(byte_count, E_POINTER);

    *byte_count = biguint->byte_count();
    return S_OK;
}

SEAL_C_FUNC BigUInt_UInt64Count(void *thisptr, uint64_t *uint64_count)
{
    BigUInt *biguint = FromVoid<BigUInt>(thisptr);
    IfNullRet(biguint, E_POINTER);
    IfNullRet(uint64_count, E_POINTER);

    *uint64_count = biguint->uint64_count();
    return S_OK;
}

SEAL_C_FUNC BigUInt_IsZero(void *thisptr, bool *is_zero)
{
    BigUInt *biguint = FromVoid<BigUInt>(thisptr);
    IfNullRet(biguint, E_POINTER);
    IfNullRet(is_zero, E_POINTER);

    *is_zero = biguint->is_zero();
    return S_OK;
}

SEAL_C_FUNC BigUInt_Get(void *thisptr, uint64_t index, uint8_t *value)
{
    BigUInt *biguint = FromVoid<BigUInt>(thisptr);
    IfNullRet(biguint, E_POINTER);
    IfNullRet(value, E_POINTER)

        if (index >= biguint->byte_count())
    {
        return HRESULT_FROM_WIN32(ERROR_INVALID_INDEX);
    }

    auto result = (*biguint)[index];
    *value = static_cast<uint8_t>(result);
    return S_OK;
}

SEAL_C_FUNC BigUInt_GetU64(void *thisptr, uint64_t index, uint64_t *value)
{
    BigUInt *biguint = FromVoid<BigUInt>(thisptr);
    IfNullRet(biguint, E_POINTER);
    IfNullRet(value, E_POINTER);

    if (index >= biguint->uint64_count())
    {
        return HRESULT_FROM_WIN32(ERROR_INVALID_INDEX);
    }

    *value = biguint->data()[index];
    return S_OK;
}

SEAL_C_FUNC BigUInt_Set1(void *thisptr, uint64_t index, uint8_t value)
{
    BigUInt *biguint = FromVoid<BigUInt>(thisptr);
    IfNullRet(biguint, E_POINTER);

    if (index >= biguint->byte_count())
    {
        return HRESULT_FROM_WIN32(ERROR_INVALID_INDEX);
    }

    (*biguint)[index] = static_cast<SEAL_BYTE>(value);
    return S_OK;
}

SEAL_C_FUNC BigUInt_GetSignificantBitCount(void *thisptr, int *significant_bit_count)
{
    BigUInt *biguint = FromVoid<BigUInt>(thisptr);
    IfNullRet(biguint, E_POINTER);
    IfNullRet(significant_bit_count, E_POINTER);

    *significant_bit_count = biguint->significant_bit_count();
    return S_OK;
}

SEAL_C_FUNC BigUInt_Set2(void *thisptr, void *assign)
{
    BigUInt *biguint = FromVoid<BigUInt>(thisptr);
    IfNullRet(biguint, E_POINTER);
    BigUInt *other = FromVoid<BigUInt>(assign);
    IfNullRet(other, E_POINTER);

    *biguint = *other;
    return S_OK;
}

SEAL_C_FUNC BigUInt_Set3(void *thisptr, uint64_t value)
{
    BigUInt *biguint = FromVoid<BigUInt>(thisptr);
    IfNullRet(biguint, E_POINTER);

    try
    {
        *biguint = value;
        return S_OK;
    }
    catch (const logic_error &)
    {
        return COR_E_INVALIDOPERATION;
    }
}

SEAL_C_FUNC BigUInt_Set4(void *thisptr, char *assign)
{
    BigUInt *biguint = FromVoid<BigUInt>(thisptr);
    IfNullRet(biguint, E_POINTER);
    IfNullRet(assign, E_POINTER);

    string assign_str(assign);

    try
    {
        *biguint = assign_str;
        return S_OK;
    }
    catch (const invalid_argument &)
    {
        return E_INVALIDARG;
    }
    catch (const logic_error &)
    {
        return COR_E_INVALIDOPERATION;
    }
}

SEAL_C_FUNC BigUInt_SetZero(void *thisptr)
{
    BigUInt *biguint = FromVoid<BigUInt>(thisptr);
    IfNullRet(biguint, E_POINTER);

    biguint->set_zero();
    return S_OK;
}

SEAL_C_FUNC BigUInt_Resize(void *thisptr, int bitCount)
{
    BigUInt *biguint = FromVoid<BigUInt>(thisptr);
    IfNullRet(biguint, E_POINTER);

    biguint->resize(bitCount);
    return S_OK;
}

SEAL_C_FUNC BigUInt_Equals(void *thisptr, void *compare, bool *result)
{
    BigUInt *biguint = FromVoid<BigUInt>(thisptr);
    IfNullRet(biguint, E_POINTER);
    BigUInt *other = FromVoid<BigUInt>(compare);
    IfNullRet(other, E_POINTER);
    IfNullRet(result, E_POINTER);

    *result = (*biguint) == (*other);
    return S_OK;
}

SEAL_C_FUNC BigUInt_CompareTo1(void *thisptr, void *compare, int *result)
{
    BigUInt *biguint = FromVoid<BigUInt>(thisptr);
    IfNullRet(biguint, E_POINTER);
    BigUInt *other = FromVoid<BigUInt>(compare);
    IfNullRet(other, E_POINTER);
    IfNullRet(result, E_POINTER);

    *result = biguint->compareto(*other);
    return S_OK;
}

SEAL_C_FUNC BigUInt_CompareTo2(void *thisptr, uint64_t compare, int *result)
{
    BigUInt *biguint = FromVoid<BigUInt>(thisptr);
    IfNullRet(biguint, E_POINTER);

    *result = biguint->compareto(compare);
    return S_OK;
}

SEAL_C_FUNC BigUInt_DivideRemainder1(void *thisptr, void *operand2, void *remainder, void **result)
{
    BigUInt *biguint = FromVoid<BigUInt>(thisptr);
    IfNullRet(biguint, E_POINTER);
    BigUInt *operand2bui = FromVoid<BigUInt>(operand2);
    IfNullRet(operand2bui, E_POINTER);
    BigUInt *remainderbui = FromVoid<BigUInt>(remainder);
    IfNullRet(remainderbui, E_POINTER);
    IfNullRet(result, E_POINTER);

    BigUInt *resultbui = new BigUInt(biguint->divrem(*operand2bui, *remainderbui));
    *result = resultbui;
    return S_OK;
}

SEAL_C_FUNC BigUInt_DivideRemainder2(void *thisptr, uint64_t operand2, void *remainder, void **result)
{
    BigUInt *biguint = FromVoid<BigUInt>(thisptr);
    IfNullRet(biguint, E_POINTER);
    BigUInt *remainderbui = FromVoid<BigUInt>(remainder);
    IfNullRet(remainderbui, E_POINTER);
    IfNullRet(result, E_POINTER);

    BigUInt *resultbui = new BigUInt(biguint->divrem(operand2, *remainderbui));
    *result = resultbui;
    return S_OK;
}

SEAL_C_FUNC BigUInt_ToString(void *thisptr, char *outstr, uint64_t *length)
{
    BigUInt *biguint = FromVoid<BigUInt>(thisptr);
    IfNullRet(biguint, E_POINTER);
    IfNullRet(length, E_POINTER);

    return ToStringHelper(biguint->to_string(), outstr, length);
}

SEAL_C_FUNC BigUInt_ToDecimalString(void *thisptr, char *outstr, uint64_t *length)
{
    BigUInt *biguint = FromVoid<BigUInt>(thisptr);
    IfNullRet(biguint, E_POINTER);
    IfNullRet(length, E_POINTER);

    return ToStringHelper(biguint->to_dec_string(), outstr, length);
}

SEAL_C_FUNC BigUInt_DuplicateTo(void *thisptr, void *destination)
{
    BigUInt *biguint = FromVoid<BigUInt>(thisptr);
    IfNullRet(biguint, E_POINTER);
    BigUInt *destbui = FromVoid<BigUInt>(destination);
    IfNullRet(destbui, E_POINTER);

    biguint->duplicate_to(*destbui);
    return S_OK;
}

SEAL_C_FUNC BigUInt_DuplicateFrom(void *thisptr, void *value)
{
    BigUInt *biguint = FromVoid<BigUInt>(thisptr);
    IfNullRet(biguint, E_POINTER);
    BigUInt *valuebui = FromVoid<BigUInt>(value);
    IfNullRet(valuebui, E_POINTER);

    biguint->duplicate_from(*valuebui);
    return S_OK;
}

SEAL_C_FUNC BigUInt_ModuloInvert1(void *thisptr, void *modulus, void **result)
{
    BigUInt *biguint = FromVoid<BigUInt>(thisptr);
    IfNullRet(biguint, E_POINTER);
    BigUInt *modulusui = FromVoid<BigUInt>(modulus);
    IfNullRet(modulusui, E_POINTER);
    IfNullRet(result, E_POINTER);
    BigUInt *resultbui = nullptr;

    try
    {
        resultbui = new BigUInt(biguint->modinv(*modulusui));
        *result = resultbui;
        return S_OK;
    }
    catch (const invalid_argument &)
    {
        return E_INVALIDARG;
    }
    catch (const logic_error &)
    {
        return COR_E_INVALIDOPERATION;
    }
}

SEAL_C_FUNC BigUInt_ModuloInvert2(void *thisptr, uint64_t modulus, void **result)
{
    BigUInt *biguint = FromVoid<BigUInt>(thisptr);
    IfNullRet(biguint, E_POINTER);
    BigUInt *resultbui = nullptr;

    try
    {
        resultbui = new BigUInt(biguint->modinv(modulus));
        *result = resultbui;
        return S_OK;
    }
    catch (const invalid_argument &)
    {
        return E_INVALIDARG;
    }
    catch (const logic_error &)
    {
        return COR_E_INVALIDOPERATION;
    }
}

SEAL_C_FUNC BigUInt_TryModuloInvert1(void *thisptr, void *modulus, void *inverse, bool *result)
{
    BigUInt *biguint = FromVoid<BigUInt>(thisptr);
    IfNullRet(biguint, E_POINTER);
    BigUInt *modulusui = FromVoid<BigUInt>(modulus);
    IfNullRet(modulusui, E_POINTER);
    BigUInt *inverseui = FromVoid<BigUInt>(inverse);
    IfNullRet(inverseui, E_POINTER);
    IfNullRet(result, E_POINTER);

    try
    {
        *result = biguint->trymodinv(*modulusui, *inverseui);
        return S_OK;
    }
    catch (const invalid_argument &)
    {
        return E_INVALIDARG;
    }
}

SEAL_C_FUNC BigUInt_TryModuloInvert2(void *thisptr, uint64_t modulus, void *inverse, bool *result)
{
    BigUInt *biguint = FromVoid<BigUInt>(thisptr);
    IfNullRet(biguint, E_POINTER);
    BigUInt *inverseui = FromVoid<BigUInt>(inverse);
    IfNullRet(inverseui, E_POINTER);
    IfNullRet(result, E_POINTER);

    try
    {
        *result = biguint->trymodinv(modulus, *inverseui);
        return S_OK;
    }
    catch (const invalid_argument &)
    {
        return E_INVALIDARG;
    }
}

SEAL_C_FUNC BigUInt_OperatorNeg(void *thisptr, void **result)
{
    BigUInt *biguint = FromVoid<BigUInt>(thisptr);
    IfNullRet(biguint, E_POINTER);
    IfNullRet(result, E_POINTER);

    BigUInt *resultbui = new BigUInt(biguint->operator-());
    *result = resultbui;
    return S_OK;
}

SEAL_C_FUNC BigUInt_OperatorTilde(void *thisptr, void **result)
{
    BigUInt *biguint = FromVoid<BigUInt>(thisptr);
    IfNullRet(biguint, E_POINTER);
    IfNullRet(result, E_POINTER);

    BigUInt *resultbui = new BigUInt(biguint->operator~());
    *result = resultbui;
    return S_OK;
}

SEAL_C_FUNC BigUInt_OperatorPlus1(void *thisptr, void *operand, void **result)
{
    BigUInt *biguint = FromVoid<BigUInt>(thisptr);
    IfNullRet(biguint, E_POINTER);
    BigUInt *operandui = FromVoid<BigUInt>(operand);
    IfNullRet(operandui, E_POINTER);
    IfNullRet(result, E_POINTER);

    BigUInt *resultbui = new BigUInt(*biguint + *operandui);
    *result = resultbui;
    return S_OK;
}

SEAL_C_FUNC BigUInt_OperatorPlus2(void *thisptr, uint64_t operand, void **result)
{
    BigUInt *biguint = FromVoid<BigUInt>(thisptr);
    IfNullRet(biguint, E_POINTER);
    IfNullRet(result, E_POINTER);

    BigUInt *resultbui = new BigUInt(*biguint + operand);
    *result = resultbui;
    return S_OK;
}

SEAL_C_FUNC BigUInt_OperatorMinus1(void *thisptr, void *operand, void **result)
{
    BigUInt *biguint = FromVoid<BigUInt>(thisptr);
    IfNullRet(biguint, E_POINTER);
    BigUInt *operandui = FromVoid<BigUInt>(operand);
    IfNullRet(operandui, E_POINTER);
    IfNullRet(result, E_POINTER);

    BigUInt *resultbui = new BigUInt(*biguint - *operandui);
    *result = resultbui;
    return S_OK;
}

SEAL_C_FUNC BigUInt_OperatorMinus2(void *thisptr, uint64_t operand, void **result)
{
    BigUInt *biguint = FromVoid<BigUInt>(thisptr);
    IfNullRet(biguint, E_POINTER);
    IfNullRet(result, E_POINTER);

    BigUInt *resultbui = new BigUInt(*biguint - operand);
    *result = resultbui;
    return S_OK;
}

SEAL_C_FUNC BigUInt_OperatorMult1(void *thisptr, void *operand, void **result)
{
    BigUInt *biguint = FromVoid<BigUInt>(thisptr);
    IfNullRet(biguint, E_POINTER);
    BigUInt *operandui = FromVoid<BigUInt>(operand);
    IfNullRet(operandui, E_POINTER);
    IfNullRet(result, E_POINTER);

    BigUInt *resultbui = new BigUInt(*biguint * *operandui);
    *result = resultbui;
    return S_OK;
}

SEAL_C_FUNC BigUInt_OperatorMult2(void *thisptr, uint64_t operand, void **result)
{
    BigUInt *biguint = FromVoid<BigUInt>(thisptr);
    IfNullRet(biguint, E_POINTER);
    IfNullRet(result, E_POINTER);

    BigUInt *resultbui = new BigUInt(*biguint * operand);
    *result = resultbui;
    return S_OK;
}

SEAL_C_FUNC BigUInt_OperatorDiv1(void *thisptr, void *operand, void **result)
{
    BigUInt *biguint = FromVoid<BigUInt>(thisptr);
    IfNullRet(biguint, E_POINTER);
    BigUInt *operandui = FromVoid<BigUInt>(operand);
    IfNullRet(operandui, E_POINTER);
    IfNullRet(result, E_POINTER);

    BigUInt *resultbui = new BigUInt(*biguint / *operandui);
    *result = resultbui;
    return S_OK;
}

SEAL_C_FUNC BigUInt_OperatorDiv2(void *thisptr, uint64_t operand, void **result)
{
    BigUInt *biguint = FromVoid<BigUInt>(thisptr);
    IfNullRet(biguint, E_POINTER);
    IfNullRet(result, E_POINTER);

    BigUInt *resultbui = new BigUInt(*biguint / operand);
    *result = resultbui;
    return S_OK;
}

SEAL_C_FUNC BigUInt_OperatorXor1(void *thisptr, void *operand, void **result)
{
    BigUInt *biguint = FromVoid<BigUInt>(thisptr);
    IfNullRet(biguint, E_POINTER);
    BigUInt *operandui = FromVoid<BigUInt>(operand);
    IfNullRet(operandui, E_POINTER);
    IfNullRet(result, E_POINTER);

    BigUInt *resultbui = new BigUInt(*biguint ^ *operandui);
    *result = resultbui;
    return S_OK;
}

SEAL_C_FUNC BigUInt_OperatorXor2(void *thisptr, uint64_t operand, void **result)
{
    BigUInt *biguint = FromVoid<BigUInt>(thisptr);
    IfNullRet(biguint, E_POINTER);
    IfNullRet(result, E_POINTER);

    BigUInt *resultbui = new BigUInt(*biguint ^ operand);
    *result = resultbui;
    return S_OK;
}

SEAL_C_FUNC BigUInt_OperatorAnd1(void *thisptr, void *operand, void **result)
{
    BigUInt *biguint = FromVoid<BigUInt>(thisptr);
    IfNullRet(biguint, E_POINTER);
    BigUInt *operandui = FromVoid<BigUInt>(operand);
    IfNullRet(operandui, E_POINTER);
    IfNullRet(result, E_POINTER);

    BigUInt *resultbui = new BigUInt(*biguint & *operandui);
    *result = resultbui;
    return S_OK;
}

SEAL_C_FUNC BigUInt_OperatorAnd2(void *thisptr, uint64_t operand, void **result)
{
    BigUInt *biguint = FromVoid<BigUInt>(thisptr);
    IfNullRet(biguint, E_POINTER);
    IfNullRet(result, E_POINTER);

    BigUInt *resultbui = new BigUInt(*biguint & operand);
    *result = resultbui;
    return S_OK;
}

SEAL_C_FUNC BigUInt_OperatorOr1(void *thisptr, void *operand, void **result)
{
    BigUInt *biguint = FromVoid<BigUInt>(thisptr);
    IfNullRet(biguint, E_POINTER);
    BigUInt *operandui = FromVoid<BigUInt>(operand);
    IfNullRet(operandui, E_POINTER);
    IfNullRet(result, E_POINTER);

    BigUInt *resultbui = new BigUInt(*biguint | *operandui);
    *result = resultbui;
    return S_OK;
}

SEAL_C_FUNC BigUInt_OperatorOr2(void *thisptr, uint64_t operand, void **result)
{
    BigUInt *biguint = FromVoid<BigUInt>(thisptr);
    IfNullRet(biguint, E_POINTER);
    IfNullRet(result, E_POINTER);

    BigUInt *resultbui = new BigUInt(*biguint | operand);
    *result = resultbui;
    return S_OK;
}

SEAL_C_FUNC BigUInt_OperatorShiftLeft(void *thisptr, int shift, void **result)
{
    BigUInt *biguint = FromVoid<BigUInt>(thisptr);
    IfNullRet(biguint, E_POINTER);
    IfNullRet(result, E_POINTER);

    BigUInt *resultbui = new BigUInt(*biguint << shift);
    *result = resultbui;
    return S_OK;
}

SEAL_C_FUNC BigUInt_OperatorShiftRight(void *thisptr, int shift, void **result)
{
    BigUInt *biguint = FromVoid<BigUInt>(thisptr);
    IfNullRet(biguint, E_POINTER);
    IfNullRet(result, E_POINTER);

    BigUInt *resultbui = new BigUInt(*biguint >> shift);
    *result = resultbui;
    return S_OK;
}

SEAL_C_FUNC BigUInt_ToDouble(void *thisptr, double *result)
{
    BigUInt *biguint = FromVoid<BigUInt>(thisptr);
    IfNullRet(biguint, E_POINTER);
    IfNullRet(result, E_POINTER);

    *result = biguint->to_double();
    return S_OK;
}

SEAL_C_FUNC BigUInt_SaveSize(void *thisptr, uint8_t compr_mode, int64_t *result)
{
    BigUInt *biguint = FromVoid<BigUInt>(thisptr);
    IfNullRet(biguint, E_POINTER);
    IfNullRet(result, E_POINTER);

    try
    {
        *result = static_cast<int64_t>(biguint->save_size(static_cast<compr_mode_type>(compr_mode)));
        return S_OK;
    }
    catch (const invalid_argument &)
    {
        return E_INVALIDARG;
    }
    catch (const logic_error &)
    {
        return COR_E_INVALIDOPERATION;
    }
}

SEAL_C_FUNC BigUInt_Save(void *thisptr, uint8_t *outptr, uint64_t size, uint8_t compr_mode, int64_t *out_bytes)
{
    BigUInt *biguint = FromVoid<BigUInt>(thisptr);
    IfNullRet(biguint, E_POINTER);
    IfNullRet(outptr, E_POINTER);
    IfNullRet(out_bytes, E_POINTER);

    try
    {
        *out_bytes = util::safe_cast<int64_t>(biguint->save(
            reinterpret_cast<SEAL_BYTE *>(outptr), util::safe_cast<size_t>(size),
            static_cast<compr_mode_type>(compr_mode)));
        return S_OK;
    }
    catch (const invalid_argument &)
    {
        return E_INVALIDARG;
    }
    catch (const logic_error &)
    {
        return COR_E_INVALIDOPERATION;
    }
    catch (const runtime_error &)
    {
        return COR_E_IO;
    }
}

SEAL_C_FUNC BigUInt_Load(void *thisptr, uint8_t *inptr, uint64_t size, int64_t *in_bytes)
{
    BigUInt *biguint = FromVoid<BigUInt>(thisptr);
    IfNullRet(biguint, E_POINTER);
    IfNullRet(inptr, E_POINTER);
    IfNullRet(in_bytes, E_POINTER);

    try
    {
        *in_bytes = util::safe_cast<int64_t>(
            biguint->load(reinterpret_cast<SEAL_BYTE *>(inptr), util::safe_cast<size_t>(size)));
        return S_OK;
    }
    catch (const invalid_argument &)
    {
        return E_INVALIDARG;
    }
    catch (const logic_error &)
    {
        return COR_E_INVALIDOPERATION;
    }
    catch (const runtime_error &)
    {
        return COR_E_IO;
    }
}
