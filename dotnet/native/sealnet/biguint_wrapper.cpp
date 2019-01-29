// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

// STD
#include <string>

// SEALNet
#include "sealnet/stdafx.h"
#include "sealnet/biguint_wrapper.h"
#include "sealnet/utilities.h"

// SEAL
#include "seal/biguint.h"

using namespace std;
using namespace seal;
using namespace sealnet;

SEALNETNATIVE HRESULT SEALCALL BigUInt_Create1(void **bui)
{
    IfNullRet(bui, E_POINTER);

    BigUInt *biguint = new BigUInt();
    *bui = biguint;
    return S_OK;
}

SEALNETNATIVE HRESULT SEALCALL BigUInt_Create2(int bitCount, void **bui)
{
    IfNullRet(bui, E_POINTER);

    try
    {
        BigUInt *biguint = new BigUInt(bitCount, /* value */ static_cast<uint64_t>(0));
        *bui = biguint;
        return S_OK;
    }
    catch (const invalid_argument&)
    {
        return E_INVALIDARG;
    }

    return E_UNEXPECTED;
}

SEALNETNATIVE HRESULT SEALCALL BigUInt_Create3(int bitCount, char *hex_string, void **bui)
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
    catch (const invalid_argument&)
    {
        return E_INVALIDARG;
    }

    return E_UNEXPECTED;
}

SEALNETNATIVE HRESULT SEALCALL BigUInt_Create4(int bitCount, uint64_t value, void **bui)
{
    IfNullRet(bui, E_POINTER);

    try
    {
        BigUInt *biguint = new BigUInt(bitCount, value);
        *bui = biguint;
        return S_OK;
    }
    catch (const invalid_argument&)
    {
        return E_INVALIDARG;
    }

    return E_UNEXPECTED;
}

SEALNETNATIVE HRESULT SEALCALL BigUInt_Create5(char *hex_string, void **bui)
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
    catch (const invalid_argument&)
    {
        return E_INVALIDARG;
    }

    return E_UNEXPECTED;
}

SEALNETNATIVE HRESULT SEALCALL BigUInt_Create6(void *copy, void **bui)
{
    BigUInt *other = FromVoid<BigUInt>(copy);
    IfNullRet(other, E_POINTER);
    IfNullRet(bui, E_POINTER);

    BigUInt *biguint = new BigUInt(*other);
    *bui = biguint;
    return S_OK;
}

SEALNETNATIVE HRESULT SEALCALL BigUInt_Destroy(void *thisptr)
{
    BigUInt *biguint = FromVoid<BigUInt>(thisptr);
    IfNullRet(thisptr, E_POINTER);

    delete biguint;
    return S_OK;
}

SEALNETNATIVE HRESULT SEALCALL BigUInt_IsAlias(void *thispt, bool *is_alias)
{
    BigUInt *biguint = FromVoid<BigUInt>(thispt);
    IfNullRet(biguint, E_POINTER);
    IfNullRet(is_alias, E_POINTER);

    *is_alias = biguint->is_alias();
    return S_OK;
}

SEALNETNATIVE HRESULT SEALCALL BigUInt_BitCount(void *thispt, int *bit_count)
{
    BigUInt *biguint = FromVoid<BigUInt>(thispt);
    IfNullRet(biguint, E_POINTER);
    IfNullRet(bit_count, E_POINTER);

    *bit_count = biguint->bit_count();
    return S_OK;
}

SEALNETNATIVE HRESULT SEALCALL BigUInt_ByteCount(void *thispt, uint64_t *byte_count)
{
    BigUInt *biguint = FromVoid<BigUInt>(thispt);
    IfNullRet(biguint, E_POINTER);
    IfNullRet(byte_count, E_POINTER);

    *byte_count = biguint->byte_count();
    return S_OK;
}

SEALNETNATIVE HRESULT SEALCALL BigUInt_UInt64Count(void *thispt, uint64_t *uint64_count)
{
    BigUInt *biguint = FromVoid<BigUInt>(thispt);
    IfNullRet(biguint, E_POINTER);
    IfNullRet(uint64_count, E_POINTER);

    *uint64_count = biguint->uint64_count();
    return S_OK;
}

SEALNETNATIVE HRESULT SEALCALL BigUInt_IsZero(void *thispt, bool *is_zero)
{
    BigUInt *biguint = FromVoid<BigUInt>(thispt);
    IfNullRet(biguint, E_POINTER);
    IfNullRet(is_zero, E_POINTER);

    *is_zero = biguint->is_zero();
    return S_OK;
}

SEALNETNATIVE HRESULT SEALCALL BigUInt_Get(void *thispt, uint64_t index, uint8_t *value)
{
    BigUInt *biguint = FromVoid<BigUInt>(thispt);
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

SEALNETNATIVE HRESULT SEALCALL BigUInt_GetU64(void *thispt, uint64_t index, uint64_t *value)
{
    BigUInt *biguint = FromVoid<BigUInt>(thispt);
    IfNullRet(biguint, E_POINTER);
    IfNullRet(value, E_POINTER);

    if (index >= biguint->uint64_count())
    {
        return HRESULT_FROM_WIN32(ERROR_INVALID_INDEX);
    }

    *value = biguint->data()[index];
    return S_OK;
}

SEALNETNATIVE HRESULT SEALCALL BigUInt_Set1(void *thispt, uint64_t index, uint8_t value)
{
    BigUInt *biguint = FromVoid<BigUInt>(thispt);
    IfNullRet(biguint, E_POINTER);

    if (index >= biguint->byte_count())
    {
        return HRESULT_FROM_WIN32(ERROR_INVALID_INDEX);
    }

    (*biguint)[index] = static_cast<SEAL_BYTE>(value);
    return S_OK;
}

SEALNETNATIVE HRESULT SEALCALL BigUInt_GetSignificantBitCount(void *thispt, int *significant_bit_count)
{
    BigUInt *biguint = FromVoid<BigUInt>(thispt);
    IfNullRet(biguint, E_POINTER);
    IfNullRet(significant_bit_count, E_POINTER);

    *significant_bit_count = biguint->significant_bit_count();
    return S_OK;
}

SEALNETNATIVE HRESULT SEALCALL BigUInt_Set2(void *thispt, void *assign)
{
    BigUInt *biguint = FromVoid<BigUInt>(thispt);
    IfNullRet(biguint, E_POINTER);
    BigUInt *other = FromVoid<BigUInt>(assign);
    IfNullRet(other, E_POINTER);

    *biguint = *other;
    return S_OK;
}

SEALNETNATIVE HRESULT SEALCALL BigUInt_Set3(void *thispt, uint64_t value)
{
    BigUInt *biguint = FromVoid<BigUInt>(thispt);
    IfNullRet(biguint, E_POINTER);

    try
    {
        *biguint = value;
        return S_OK;
    }
    catch (const logic_error&)
    {
        return HRESULT_FROM_WIN32(ERROR_INVALID_OPERATION);
    }

    return E_UNEXPECTED;
}

SEALNETNATIVE HRESULT SEALCALL BigUInt_Set4(void *thispt, char *assign)
{
    BigUInt *biguint = FromVoid<BigUInt>(thispt);
    IfNullRet(biguint, E_POINTER);
    IfNullRet(assign, E_POINTER);

    string assign_str(assign);

    try
    {
        *biguint = assign_str;
        return S_OK;
    }
    catch (const invalid_argument&)
    {
        return E_INVALIDARG;
    }
    catch (const logic_error&)
    {
        return HRESULT_FROM_WIN32(ERROR_INVALID_OPERATION);
    }

    return E_UNEXPECTED;
}

SEALNETNATIVE HRESULT SEALCALL BigUInt_SetZero(void *thispt)
{
    BigUInt *biguint = FromVoid<BigUInt>(thispt);
    IfNullRet(biguint, E_POINTER);

    biguint->set_zero();
    return S_OK;
}

SEALNETNATIVE HRESULT SEALCALL BigUInt_Resize(void *thispt, int bitCount)
{
    BigUInt *biguint = FromVoid<BigUInt>(thispt);
    IfNullRet(biguint, E_POINTER);

    biguint->resize(bitCount);
    return S_OK;
}

SEALNETNATIVE HRESULT SEALCALL BigUInt_Equals(void *thispt, void *compare, bool *result)
{
    BigUInt *biguint = FromVoid<BigUInt>(thispt);
    IfNullRet(biguint, E_POINTER);
    BigUInt *other = FromVoid<BigUInt>(compare);
    IfNullRet(other, E_POINTER);
    IfNullRet(result, E_POINTER);

    *result = (*biguint) == (*other);
    return S_OK;
}

SEALNETNATIVE HRESULT SEALCALL BigUInt_CompareTo1(void *thispt, void *compare, int *result)
{
    BigUInt *biguint = FromVoid<BigUInt>(thispt);
    IfNullRet(biguint, E_POINTER);
    BigUInt *other = FromVoid<BigUInt>(compare);
    IfNullRet(other, E_POINTER);
    IfNullRet(result, E_POINTER);

    *result = biguint->compareto(*other);
    return S_OK;
}

SEALNETNATIVE HRESULT SEALCALL BigUInt_CompareTo2(void *thispt, uint64_t compare, int *result)
{
    BigUInt *biguint = FromVoid<BigUInt>(thispt);
    IfNullRet(biguint, E_POINTER);

    *result = biguint->compareto(compare);
    return S_OK;
}

SEALNETNATIVE HRESULT SEALCALL BigUInt_DivideRemainder1(void *thispt, void *operand2, void *remainder, void **result)
{
    BigUInt *biguint = FromVoid<BigUInt>(thispt);
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

SEALNETNATIVE HRESULT SEALCALL BigUInt_DivideRemainder2(void *thispt, uint64_t operand2, void *remainder, void **result)
{
    BigUInt *biguint = FromVoid<BigUInt>(thispt);
    IfNullRet(biguint, E_POINTER);
    BigUInt *remainderbui = FromVoid<BigUInt>(remainder);
    IfNullRet(remainderbui, E_POINTER);
    IfNullRet(result, E_POINTER);

    BigUInt *resultbui = new BigUInt(biguint->divrem(operand2, *remainderbui));
    *result = resultbui;
    return S_OK;
}

SEALNETNATIVE HRESULT SEALCALL BigUInt_ToString(void *thispt, char *outstr, uint64_t *length)
{
    BigUInt *biguint = FromVoid<BigUInt>(thispt);
    IfNullRet(biguint, E_POINTER);
    IfNullRet(length, E_POINTER);

    string str = biguint->to_string();
    return ToStringHelper(str, outstr, length);
}

SEALNETNATIVE HRESULT SEALCALL BigUInt_ToDecimalString(void *thispt, char *outstr, uint64_t *length)
{
    BigUInt *biguint = FromVoid<BigUInt>(thispt);
    IfNullRet(biguint, E_POINTER);
    IfNullRet(length, E_POINTER);

    string str = biguint->to_dec_string();
    return ToStringHelper(str, outstr, length);
}

SEALNETNATIVE HRESULT SEALCALL BigUInt_DuplicateTo(void *thispt, void *destination)
{
    BigUInt *biguint = FromVoid<BigUInt>(thispt);
    IfNullRet(biguint, E_POINTER);
    BigUInt *destbui = FromVoid<BigUInt>(destination);
    IfNullRet(destbui, E_POINTER);

    biguint->duplicate_to(*destbui);
    return S_OK;
}

SEALNETNATIVE HRESULT SEALCALL BigUInt_DuplicateFrom(void *thispt, void *value)
{
    BigUInt *biguint = FromVoid<BigUInt>(thispt);
    IfNullRet(biguint, E_POINTER);
    BigUInt *valuebui = FromVoid<BigUInt>(value);
    IfNullRet(valuebui, E_POINTER);

    biguint->duplicate_from(*valuebui);
    return S_OK;
}

SEALNETNATIVE HRESULT SEALCALL BigUInt_ModuloInvert1(void *thispt, void *modulus, void **result)
{
    BigUInt *biguint = FromVoid<BigUInt>(thispt);
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
    catch (const invalid_argument&)
    {
        return E_INVALIDARG;
    }

    return E_UNEXPECTED;
}

SEALNETNATIVE HRESULT SEALCALL BigUInt_ModuloInvert2(void *thispt, uint64_t modulus, void **result)
{
    BigUInt *biguint = FromVoid<BigUInt>(thispt);
    IfNullRet(biguint, E_POINTER);
    BigUInt *resultbui = nullptr;

    try
    {
        resultbui = new BigUInt(biguint->modinv(modulus));
        *result = resultbui;
        return S_OK;
    }
    catch (const invalid_argument&)
    {
        return E_INVALIDARG;
    }

    return E_UNEXPECTED;
}

SEALNETNATIVE HRESULT SEALCALL BigUInt_TryModuloInvert1(void *thispt, void *modulus, void *inverse, bool *result)
{
    BigUInt *biguint = FromVoid<BigUInt>(thispt);
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
    catch (const invalid_argument&)
    {
        return E_INVALIDARG;
    }

    return E_UNEXPECTED;
}

SEALNETNATIVE HRESULT SEALCALL BigUInt_TryModuloInvert2(void *thispt, uint64_t modulus, void *inverse, bool *result)
{
    BigUInt *biguint = FromVoid<BigUInt>(thispt);
    IfNullRet(biguint, E_POINTER);
    BigUInt *inverseui = FromVoid<BigUInt>(inverse);
    IfNullRet(inverseui, E_POINTER);
    IfNullRet(result, E_POINTER);

    try
    {
        *result = biguint->trymodinv(modulus, *inverseui);
        return S_OK;
    }
    catch (const invalid_argument&)
    {
        return E_INVALIDARG;
    }

    return E_UNEXPECTED;
}

SEALNETNATIVE HRESULT SEALCALL BigUInt_OperatorNeg(void *thispt, void **result)
{
    BigUInt *biguint = FromVoid<BigUInt>(thispt);
    IfNullRet(biguint, E_POINTER);
    IfNullRet(result, E_POINTER);

    BigUInt *resultbui = new BigUInt(biguint->operator-());
    *result = resultbui;
    return S_OK;
}

SEALNETNATIVE HRESULT SEALCALL BigUInt_OperatorTilde(void *thispt, void **result)
{
    BigUInt *biguint = FromVoid<BigUInt>(thispt);
    IfNullRet(biguint, E_POINTER);
    IfNullRet(result, E_POINTER);

    BigUInt *resultbui = new BigUInt(biguint->operator~());
    *result = resultbui;
    return S_OK;
}

SEALNETNATIVE HRESULT SEALCALL BigUInt_OperatorPlus1(void *thispt, void *operand, void **result)
{
    BigUInt *biguint = FromVoid<BigUInt>(thispt);
    IfNullRet(biguint, E_POINTER);
    BigUInt *operandui = FromVoid<BigUInt>(operand);
    IfNullRet(operandui, E_POINTER);
    IfNullRet(result, E_POINTER);

    BigUInt *resultbui = new BigUInt(*biguint + *operandui);
    *result = resultbui;
    return S_OK;
}

SEALNETNATIVE HRESULT SEALCALL BigUInt_OperatorPlus2(void *thispt, uint64_t operand, void **result)
{
    BigUInt *biguint = FromVoid<BigUInt>(thispt);
    IfNullRet(biguint, E_POINTER);
    IfNullRet(result, E_POINTER);

    BigUInt *resultbui = new BigUInt(*biguint + operand);
    *result = resultbui;
    return S_OK;
}

SEALNETNATIVE HRESULT SEALCALL BigUInt_OperatorMinus1(void *thispt, void *operand, void **result)
{
    BigUInt *biguint = FromVoid<BigUInt>(thispt);
    IfNullRet(biguint, E_POINTER);
    BigUInt *operandui = FromVoid<BigUInt>(operand);
    IfNullRet(operandui, E_POINTER);
    IfNullRet(result, E_POINTER);

    BigUInt *resultbui = new BigUInt(*biguint - *operandui);
    *result = resultbui;
    return S_OK;
}

SEALNETNATIVE HRESULT SEALCALL BigUInt_OperatorMinus2(void *thispt, uint64_t operand, void **result)
{
    BigUInt *biguint = FromVoid<BigUInt>(thispt);
    IfNullRet(biguint, E_POINTER);
    IfNullRet(result, E_POINTER);

    BigUInt *resultbui = new BigUInt(*biguint - operand);
    *result = resultbui;
    return S_OK;
}

SEALNETNATIVE HRESULT SEALCALL BigUInt_OperatorMult1(void *thispt, void *operand, void **result)
{
    BigUInt *biguint = FromVoid<BigUInt>(thispt);
    IfNullRet(biguint, E_POINTER);
    BigUInt *operandui = FromVoid<BigUInt>(operand);
    IfNullRet(operandui, E_POINTER);
    IfNullRet(result, E_POINTER);

    BigUInt *resultbui = new BigUInt(*biguint * *operandui);
    *result = resultbui;
    return S_OK;
}

SEALNETNATIVE HRESULT SEALCALL BigUInt_OperatorMult2(void *thispt, uint64_t operand, void * *result)
{
    BigUInt *biguint = FromVoid<BigUInt>(thispt);
    IfNullRet(biguint, E_POINTER);
    IfNullRet(result, E_POINTER);

    BigUInt *resultbui = new BigUInt(*biguint * operand);
    *result = resultbui;
    return S_OK;
}

SEALNETNATIVE HRESULT SEALCALL BigUInt_OperatorDiv1(void *thispt, void *operand, void **result)
{
    BigUInt *biguint = FromVoid<BigUInt>(thispt);
    IfNullRet(biguint, E_POINTER);
    BigUInt *operandui = FromVoid<BigUInt>(operand);
    IfNullRet(operandui, E_POINTER);
    IfNullRet(result, E_POINTER);

    BigUInt *resultbui = new BigUInt(*biguint / *operandui);
    *result = resultbui;
    return S_OK;
}

SEALNETNATIVE HRESULT SEALCALL BigUInt_OperatorDiv2(void *thispt, uint64_t operand, void **result)
{
    BigUInt *biguint = FromVoid<BigUInt>(thispt);
    IfNullRet(biguint, E_POINTER);
    IfNullRet(result, E_POINTER);

    BigUInt *resultbui = new BigUInt(*biguint / operand);
    *result = resultbui;
    return S_OK;
}

SEALNETNATIVE HRESULT SEALCALL BigUInt_OperatorXor1(void *thispt, void *operand, void **result)
{
    BigUInt *biguint = FromVoid<BigUInt>(thispt);
    IfNullRet(biguint, E_POINTER);
    BigUInt *operandui = FromVoid<BigUInt>(operand);
    IfNullRet(operandui, E_POINTER);
    IfNullRet(result, E_POINTER);

    BigUInt *resultbui = new BigUInt(*biguint ^ *operandui);
    *result = resultbui;
    return S_OK;
}

SEALNETNATIVE HRESULT SEALCALL BigUInt_OperatorXor2(void *thispt, uint64_t operand, void **result)
{
    BigUInt *biguint = FromVoid<BigUInt>(thispt);
    IfNullRet(biguint, E_POINTER);
    IfNullRet(result, E_POINTER);

    BigUInt *resultbui = new BigUInt(*biguint ^ operand);
    *result = resultbui;
    return S_OK;
}

SEALNETNATIVE HRESULT SEALCALL BigUInt_OperatorAnd1(void *thispt, void *operand, void **result)
{
    BigUInt *biguint = FromVoid<BigUInt>(thispt);
    IfNullRet(biguint, E_POINTER);
    BigUInt *operandui = FromVoid<BigUInt>(operand);
    IfNullRet(operandui, E_POINTER);
    IfNullRet(result, E_POINTER);

    BigUInt *resultbui = new BigUInt(*biguint & *operandui);
    *result = resultbui;
    return S_OK;
}

SEALNETNATIVE HRESULT SEALCALL BigUInt_OperatorAnd2(void *thispt, uint64_t operand, void **result)
{
    BigUInt *biguint = FromVoid<BigUInt>(thispt);
    IfNullRet(biguint, E_POINTER);
    IfNullRet(result, E_POINTER);

    BigUInt *resultbui = new BigUInt(*biguint & operand);
    *result = resultbui;
    return S_OK;
}

SEALNETNATIVE HRESULT SEALCALL BigUInt_OperatorOr1(void *thispt, void *operand, void **result)
{
    BigUInt *biguint = FromVoid<BigUInt>(thispt);
    IfNullRet(biguint, E_POINTER);
    BigUInt *operandui = FromVoid<BigUInt>(operand);
    IfNullRet(operandui, E_POINTER);
    IfNullRet(result, E_POINTER);

    BigUInt *resultbui = new BigUInt(*biguint | *operandui);
    *result = resultbui;
    return S_OK;
}

SEALNETNATIVE HRESULT SEALCALL BigUInt_OperatorOr2(void *thispt, uint64_t operand, void **result)
{
    BigUInt *biguint = FromVoid<BigUInt>(thispt);
    IfNullRet(biguint, E_POINTER);
    IfNullRet(result, E_POINTER);

    BigUInt *resultbui = new BigUInt(*biguint | operand);
    *result = resultbui;
    return S_OK;
}

SEALNETNATIVE HRESULT SEALCALL BigUInt_OperatorShiftLeft(void *thispt, int shift, void **result)
{
    BigUInt *biguint = FromVoid<BigUInt>(thispt);
    IfNullRet(biguint, E_POINTER);
    IfNullRet(result, E_POINTER);

    BigUInt *resultbui = new BigUInt(*biguint << shift);
    *result = resultbui;
    return S_OK;
}

SEALNETNATIVE HRESULT SEALCALL BigUInt_OperatorShiftRight(void *thispt, int shift, void **result)
{
    BigUInt *biguint = FromVoid<BigUInt>(thispt);
    IfNullRet(biguint, E_POINTER);
    IfNullRet(result, E_POINTER);

    BigUInt *resultbui = new BigUInt(*biguint >> shift);
    *result = resultbui;
    return S_OK;
}

SEALNETNATIVE HRESULT SEALCALL BigUInt_ToDouble(void *thispt, double *result)
{
    BigUInt *biguint = FromVoid<BigUInt>(thispt);
    IfNullRet(biguint, E_POINTER);
    IfNullRet(result, E_POINTER);

    *result = biguint->to_double();
    return S_OK;
}
