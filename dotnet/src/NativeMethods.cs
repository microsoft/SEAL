// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

using System;
using System.Runtime.InteropServices;
using System.Text;

namespace Microsoft.Research.SEAL
{
    [Guid("A7AAD62F-3A48-4188-B6C3-523C294CFDAD")]
    static class NativeMethods
    {
        private const string sealc = "sealc";

        #region Version methods

        [DllImport(sealc, PreserveSig = false)]
        internal static extern void Version_Major(out byte value);

        [DllImport(sealc, PreserveSig = false)]
        internal static extern void Version_Minor(out byte value);

        [DllImport(sealc, PreserveSig = false)]
        internal static extern void Version_Patch(out byte value);

        #endregion

        #region BigUInt methods

        [DllImport(sealc, EntryPoint = "BigUInt_Create1", PreserveSig = false)]
        internal static extern void BigUInt_Create(out IntPtr bigUInt);

        [DllImport(sealc, EntryPoint = "BigUInt_Create2", PreserveSig = false)]
        internal static extern void BigUInt_Create(int bitCount, out IntPtr bigUInt);

        [DllImport(sealc, EntryPoint = "BigUInt_Create3", PreserveSig = false, CharSet = CharSet.Ansi)]
        internal static extern void BigUInt_Create(int bitCount, string hexString, out IntPtr bigUInt);

        [DllImport(sealc, EntryPoint = "BigUInt_Create4", PreserveSig = false)]
        internal static extern void BigUInt_Create(int bitCount, ulong value, out IntPtr bigUInt);

        [DllImport(sealc, EntryPoint = "BigUInt_Create5", PreserveSig = false, CharSet = CharSet.Ansi)]
        internal static extern void BigUInt_Create(string hexString, out IntPtr bigUInt);

        [DllImport(sealc, EntryPoint = "BigUInt_Create6", PreserveSig = false)]
        internal static extern void BigUInt_Create(IntPtr copy, out IntPtr bigUInt);

        [DllImport(sealc, PreserveSig = false)]
        internal static extern void BigUInt_Destroy(IntPtr thisptr);

        [DllImport(sealc, PreserveSig = false)]
        internal static extern void BigUInt_IsAlias(IntPtr thisptr, out bool isAlias);

        [DllImport(sealc, PreserveSig = false)]
        internal static extern void BigUInt_BitCount(IntPtr thisptr, out int bitCount);

        [DllImport(sealc, PreserveSig = false)]
        internal static extern void BigUInt_ByteCount(IntPtr thisptr, out ulong byteCount);

        [DllImport(sealc, PreserveSig = false)]
        internal static extern void BigUInt_UInt64Count(IntPtr thisptr, out ulong uint64Count);

        [DllImport(sealc, PreserveSig = false)]
        internal static extern void BigUInt_IsZero(IntPtr thisptr, out bool isZero);

        [DllImport(sealc, PreserveSig = false)]
        internal static extern void BigUInt_Get(IntPtr thisptr, ulong index, out byte value);

        [DllImport(sealc, PreserveSig = false)]
        internal static extern void BigUInt_GetU64(IntPtr thisptr, ulong index, out ulong value);

        [DllImport(sealc, PreserveSig = false)]
        internal static extern void BigUInt_GetSignificantBitCount(IntPtr thisptr, out int significantBitCount);

        [DllImport(sealc, EntryPoint = "BigUInt_Set1", PreserveSig = false)]
        internal static extern void BigUInt_Set(IntPtr thisptr, ulong index, byte value);

        [DllImport(sealc, EntryPoint = "BigUInt_Set2", PreserveSig = false)]
        internal static extern void BigUInt_Set(IntPtr thisptr, IntPtr assign);

        [DllImport(sealc, EntryPoint = "BigUInt_Set3", PreserveSig = false)]
        internal static extern void BigUInt_Set(IntPtr thisptr, ulong value);

        [DllImport(sealc, EntryPoint = "BigUInt_Set4", PreserveSig = false, CharSet = CharSet.Ansi)]
        internal static extern void BigUInt_Set(IntPtr thisptr, string assign);

        [DllImport(sealc, PreserveSig = false)]
        internal static extern void BigUInt_SetZero(IntPtr thisptr);

        [DllImport(sealc, PreserveSig = false)]
        internal static extern void BigUInt_Resize(IntPtr thisptr, int bitCount);

        [DllImport(sealc, PreserveSig = false)]
        internal static extern void BigUInt_Equals(IntPtr thisptr, IntPtr compare, out bool result);

        [DllImport(sealc, EntryPoint = "BigUInt_CompareTo1", PreserveSig = false)]
        internal static extern void BigUInt_CompareTo(IntPtr thisptr, IntPtr compare, out int result);

        [DllImport(sealc, EntryPoint = "BigUInt_CompareTo2", PreserveSig = false)]
        internal static extern void BigUInt_CompareTo(IntPtr thisptr, ulong compare, out int result);

        [DllImport(sealc, EntryPoint = "BigUInt_DivideRemainder1", PreserveSig = false)]
        internal static extern void BigUInt_DivideRemainder(IntPtr thisptr, IntPtr operand2, IntPtr remainder, out IntPtr result);

        [DllImport(sealc, EntryPoint = "BigUInt_DivideRemainder2", PreserveSig = false)]
        internal static extern void BigUInt_DivideRemainder(IntPtr thisptr, ulong operand2, IntPtr remainder, out IntPtr result);

        [DllImport(sealc, PreserveSig = false, CharSet = CharSet.Ansi)]
        internal static extern void BigUInt_ToString(IntPtr thisptr, StringBuilder outstr, out ulong length);

        [DllImport(sealc, PreserveSig = false, CharSet = CharSet.Ansi)]
        internal static extern void BigUInt_ToDecimalString(IntPtr thisptr, StringBuilder outstr, out ulong length);

        [DllImport(sealc, PreserveSig = false, CharSet = CharSet.Ansi)]
        internal static extern void BigUInt_DuplicateTo(IntPtr thisptr, IntPtr destination);

        [DllImport(sealc, PreserveSig = false, CharSet = CharSet.Ansi)]
        internal static extern void BigUInt_DuplicateFrom(IntPtr thisptr, IntPtr value);

        [DllImport(sealc, EntryPoint = "BigUInt_ModuloInvert1", PreserveSig = false)]
        internal static extern void BigUInt_ModuloInvert(IntPtr thisptr, IntPtr modulus, out IntPtr result);

        [DllImport(sealc, EntryPoint = "BigUInt_ModuloInvert2", PreserveSig = false)]
        internal static extern void BigUInt_ModuloInvert(IntPtr thisptr, ulong modulus, out IntPtr result);

        [DllImport(sealc, EntryPoint = "BigUInt_TryModuloInvert1", PreserveSig = false)]
        internal static extern void BigUInt_TryModuloInvert(IntPtr thisptr, IntPtr modulus, IntPtr inverse, out bool result);

        [DllImport(sealc, EntryPoint = "BigUInt_TryModuloInvert2", PreserveSig = false)]
        internal static extern void BigUInt_TryModuloInvert(IntPtr thisptr, ulong modulus, IntPtr inverse, out bool result);

        [DllImport(sealc, PreserveSig = false)]
        internal static extern void BigUInt_OperatorNeg(IntPtr thisptr, out IntPtr result);

        [DllImport(sealc, PreserveSig = false)]
        internal static extern void BigUInt_OperatorTilde(IntPtr thisptr, out IntPtr result);

        [DllImport(sealc, EntryPoint = "BigUInt_OperatorPlus1", PreserveSig = false)]
        internal static extern void BigUInt_OperatorPlus(IntPtr thisptr, IntPtr operand, out IntPtr result);

        [DllImport(sealc, EntryPoint = "BigUInt_OperatorPlus2", PreserveSig = false)]
        internal static extern void BigUInt_OperatorPlus(IntPtr thisptr, ulong operand, out IntPtr result);

        [DllImport(sealc, EntryPoint = "BigUInt_OperatorMinus1", PreserveSig = false)]
        internal static extern void BigUInt_OperatorMinus(IntPtr thisptr, IntPtr operand, out IntPtr result);

        [DllImport(sealc, EntryPoint = "BigUInt_OperatorMinus2", PreserveSig = false)]
        internal static extern void BigUInt_OperatorMinus(IntPtr thisptr, ulong operand, out IntPtr result);

        [DllImport(sealc, EntryPoint = "BigUInt_OperatorMult1", PreserveSig = false)]
        internal static extern void BigUInt_OperatorMult(IntPtr thisptr, IntPtr operand, out IntPtr result);

        [DllImport(sealc, EntryPoint = "BigUInt_OperatorMult2", PreserveSig = false)]
        internal static extern void BigUInt_OperatorMult(IntPtr thisptr, ulong operand, out IntPtr result);

        [DllImport(sealc, EntryPoint = "BigUInt_OperatorDiv1", PreserveSig = false)]
        internal static extern void BigUInt_OperatorDiv(IntPtr thisptr, IntPtr operand, out IntPtr result);

        [DllImport(sealc, EntryPoint = "BigUInt_OperatorDiv2", PreserveSig = false)]
        internal static extern void BigUInt_OperatorDiv(IntPtr thisptr, ulong operand, out IntPtr result);

        [DllImport(sealc, EntryPoint = "BigUInt_OperatorXor1", PreserveSig = false)]
        internal static extern void BigUInt_OperatorXor(IntPtr thisptr, IntPtr operand, out IntPtr result);

        [DllImport(sealc, EntryPoint = "BigUInt_OperatorXor2", PreserveSig = false)]
        internal static extern void BigUInt_OperatorXor(IntPtr thisptr, ulong operand, out IntPtr result);

        [DllImport(sealc, EntryPoint = "BigUInt_OperatorAnd1", PreserveSig = false)]
        internal static extern void BigUInt_OperatorAnd(IntPtr thisptr, IntPtr operand, out IntPtr result);

        [DllImport(sealc, EntryPoint = "BigUInt_OperatorAnd2", PreserveSig = false)]
        internal static extern void BigUInt_OperatorAnd(IntPtr thisptr, ulong operand, out IntPtr result);

        [DllImport(sealc, EntryPoint = "BigUInt_OperatorOr1", PreserveSig = false)]
        internal static extern void BigUInt_OperatorOr(IntPtr thisptr, IntPtr operand, out IntPtr result);

        [DllImport(sealc, EntryPoint = "BigUInt_OperatorOr2", PreserveSig = false)]
        internal static extern void BigUInt_OperatorOr(IntPtr thisptr, ulong operand, out IntPtr result);

        [DllImport(sealc, PreserveSig = false)]
        internal static extern void BigUInt_OperatorShiftLeft(IntPtr thisptr, int shift, out IntPtr result);

        [DllImport(sealc, PreserveSig = false)]
        internal static extern void BigUInt_OperatorShiftRight(IntPtr thisptr, int shift, out IntPtr result);

        [DllImport(sealc, PreserveSig = false)]
        internal static extern void BigUInt_ToDouble(IntPtr thisptr, out double result);

        [DllImport(sealc, PreserveSig = false)]
        internal static extern void BigUInt_SaveSize(IntPtr thisptr, byte comprMode, out long result);

        [DllImport(sealc, PreserveSig = false)]
        internal static extern void BigUInt_Save(IntPtr thisptr, byte[] outptr, ulong size, byte comprMode, out long outBytes);

        [DllImport(sealc, PreserveSig = false)]
        internal static extern void BigUInt_Load(IntPtr thisptr, byte[] inptr, ulong size, out long inBytes);

        #endregion

        #region EncryptionParameterQualifiers methods

        [DllImport(sealc, PreserveSig = false)]
        internal static extern void EPQ_Create(IntPtr copy, out IntPtr epq);

        [DllImport(sealc, PreserveSig = false)]
        internal static extern void EPQ_Destroy(IntPtr thisptr);

        [DllImport(sealc, PreserveSig = false)]
        internal static extern void EPQ_ParametersSet(IntPtr thisptr, out bool parametersSet);

        [DllImport(sealc, PreserveSig = false)]
        internal static extern void EPQ_UsingFFT(IntPtr thisptr, out bool usingFFT);

        [DllImport(sealc, PreserveSig = false)]
        internal static extern void EPQ_UsingNTT(IntPtr thisptr, out bool usingNTT);

        [DllImport(sealc, PreserveSig = false)]
        internal static extern void EPQ_UsingBatching(IntPtr thisptr, out bool usingBatching);

        [DllImport(sealc, PreserveSig = false)]
        internal static extern void EPQ_UsingFastPlainLift(IntPtr thisptr, out bool usingFastPlainLift);

        [DllImport(sealc, PreserveSig = false)]
        internal static extern void EPQ_UsingDescendingModulusChain(IntPtr thisptr, out bool usingDescendingModulusChain);

        [DllImport(sealc, PreserveSig = false)]
        internal static extern void EPQ_SecLevel(IntPtr thisptr, out int secLevel);

        [DllImport(sealc, PreserveSig = false, CharSet = CharSet.Ansi)]
        internal static extern void EPQ_ParameterErrorName(IntPtr thisptr, StringBuilder outstr, out ulong length);

        [DllImport(sealc, PreserveSig = false, CharSet = CharSet.Ansi)]
        internal static extern void EPQ_ParameterErrorMessage(IntPtr thisptr, StringBuilder outstr, out ulong length);

        #endregion

        #region Modulus methods

        [DllImport(sealc, EntryPoint = "Modulus_Create1", PreserveSig = false)]
        internal static extern void Modulus_Create(ulong value, out IntPtr smallModulus);

        [DllImport(sealc, EntryPoint = "Modulus_Create2", PreserveSig = false)]
        internal static extern void Modulus_Create(IntPtr copy, out IntPtr smallModulus);

        [DllImport(sealc, PreserveSig = false)]
        internal static extern void Modulus_Destroy(IntPtr thisptr);

        [DllImport(sealc, PreserveSig = false)]
        internal static extern void Modulus_IsZero(IntPtr thisptr, out bool isZero);

        [DllImport(sealc, PreserveSig = false)]
        internal static extern void Modulus_IsPrime(IntPtr thisptr, out bool isPrime);

        [DllImport(sealc, PreserveSig = false)]
        internal static extern void Modulus_Value(IntPtr thisptr, out ulong value);

        [DllImport(sealc, PreserveSig = false)]
        internal static extern void Modulus_BitCount(IntPtr thisptr, out int bitCount);

        [DllImport(sealc, PreserveSig = false)]
        internal static extern void Modulus_UInt64Count(IntPtr thisptr, out ulong uint64Count);

        [DllImport(sealc, EntryPoint = "Modulus_Set1", PreserveSig = false)]
        internal static extern void Modulus_Set(IntPtr thisptr, IntPtr assign);

        [DllImport(sealc, EntryPoint = "Modulus_Set2", PreserveSig = false)]
        internal static extern void Modulus_Set(IntPtr thisptr, ulong value);

        [DllImport(sealc, PreserveSig = false)]
        internal static extern void Modulus_ConstRatio(
            IntPtr thisptr,
            ulong length,
            [MarshalAs(UnmanagedType.LPArray)] ulong[] ratio);

        [DllImport(sealc, EntryPoint = "Modulus_Equals1", PreserveSig = false)]
        internal static extern void Modulus_Equals(IntPtr thisptr, IntPtr other, out bool result);

        [DllImport(sealc, EntryPoint = "Modulus_Equals2", PreserveSig = false)]
        internal static extern void Modulus_Equals(IntPtr thisptr, ulong other, out bool result);

        [DllImport(sealc, PreserveSig = false)]
        internal static extern void Modulus_SaveSize(IntPtr thisptr, byte comprMode, out long result);

        [DllImport(sealc, PreserveSig = false)]
        internal static extern void Modulus_Save(IntPtr thisptr, byte[] outptr, ulong size, byte comprMode, out long outBytes);

        [DllImport(sealc, PreserveSig = false)]
        internal static extern void Modulus_Load(IntPtr thisptr, byte[] inptr, ulong size, out long inBytes);

        #endregion

        #region EncryptionParameters methods

        [DllImport(sealc, EntryPoint = "EncParams_Create1", PreserveSig = false)]
        internal static extern void EncParams_Create(byte scheme, out IntPtr encParams);

        [DllImport(sealc, EntryPoint = "EncParams_Create2", PreserveSig = false)]
        internal static extern void EncParams_Create(IntPtr copy, out IntPtr encParams);

        [DllImport(sealc, PreserveSig = false)]
        internal static extern void EncParams_Destroy(IntPtr thisptr);

        [DllImport(sealc, PreserveSig = false)]
        internal static extern void EncParams_Set(IntPtr thisptr, IntPtr assign);

        [DllImport(sealc, PreserveSig = false)]
        internal static extern void EncParams_GetPolyModulusDegree(IntPtr thisptr, out ulong polyModulusDegree);

        [DllImport(sealc, PreserveSig = false)]
        internal static extern void EncParams_SetPolyModulusDegree(IntPtr thisptr, ulong polyModulusDegree);

        [DllImport(sealc, PreserveSig = false)]
        internal static extern void EncParams_GetCoeffModulus(
            IntPtr thisptr,
            ref ulong length,
            [MarshalAs(UnmanagedType.LPArray)] IntPtr[] coeffs);

        [DllImport(sealc, PreserveSig = false)]
        internal static extern void EncParams_SetCoeffModulus(
            IntPtr thisptr,
            ulong length,
            [MarshalAs(UnmanagedType.LPArray)] IntPtr[] coeffs);

        [DllImport(sealc, PreserveSig = false)]
        internal static extern void EncParams_GetScheme(IntPtr thisptr, out byte scheme);

        [DllImport(sealc, PreserveSig = false)]
        internal static extern void EncParams_GetParmsId(IntPtr thisptr, ulong[] parmsId);

        [DllImport(sealc, PreserveSig = false)]
        internal static extern void EncParams_GetPlainModulus(IntPtr thisptr, out IntPtr plainModulus);

        [DllImport(sealc, EntryPoint = "EncParams_SetPlainModulus1", PreserveSig = false)]
        internal static extern void EncParams_SetPlainModulus(IntPtr thisptr, IntPtr plainModulus);

        [DllImport(sealc, EntryPoint = "EncParams_SetPlainModulus2", PreserveSig = false)]
        internal static extern void EncParams_SetPlainModulus(IntPtr thisptr, ulong plainModulus);

        [DllImport(sealc, PreserveSig = false)]
        internal static extern void EncParams_Equals(IntPtr thisptr, IntPtr otherptr, out bool result);

        [DllImport(sealc, PreserveSig = false)]
        internal static extern void EncParams_SaveSize(IntPtr thisptr, byte comprMode, out long result);

        [DllImport(sealc, PreserveSig = false)]
        internal static extern void EncParams_Save(IntPtr thisptr, byte[] outptr, ulong size, byte comprMode, out long outBytes);

        [DllImport(sealc, PreserveSig = false)]
        internal static extern void EncParams_Load(IntPtr thisptr, byte[] inptr, ulong size, out long inBytes);

        #endregion

        #region CoeffModulus methods

        [DllImport(sealc, PreserveSig = false)]
        internal static extern void CoeffModulus_MaxBitCount(ulong polyModulusDegree, int secLevel, out int bitCount);

        [DllImport(sealc, PreserveSig = false)]
        internal static extern void CoeffModulus_BFVDefault(
            ulong polyModulusDegree,
            int secLevel,
            ref ulong length,
            [MarshalAs(UnmanagedType.LPArray)] IntPtr[] coeffArray);

        [DllImport(sealc, PreserveSig = false)]
        internal static extern void CoeffModulus_Create(
            ulong polyModulusDegree,
            ulong length,
            int[] bitSizes,
            [MarshalAs(UnmanagedType.LPArray)] IntPtr[] coeffArray);

        #endregion

        #region SEALContext methods

        [DllImport(sealc, PreserveSig = false)]
        internal static extern void SEALContext_Create(
            IntPtr encryptionParams,
            bool expandModChain,
            int secLevel,
            out IntPtr context);

        [DllImport(sealc, PreserveSig = false)]
        internal static extern void SEALContext_Destroy(IntPtr thisptr);

        [DllImport(sealc, PreserveSig = false)]
        internal static extern void SEALContext_KeyParmsId(IntPtr thisptr, ulong[] parmsId);

        [DllImport(sealc, PreserveSig = false)]
        internal static extern void SEALContext_FirstParmsId(IntPtr thisptr, ulong[] parmsId);

        [DllImport(sealc, PreserveSig = false)]
        internal static extern void SEALContext_LastParmsId(IntPtr thisptr, ulong[] parmsId);

        [DllImport(sealc, PreserveSig = false)]
        internal static extern void SEALContext_ParametersSet(IntPtr thisptr, out bool paramsSet);

        [DllImport(sealc, PreserveSig = false)]
        internal static extern void SEALContext_ParameterErrorName(IntPtr thisptr, byte[] outstr, out ulong length);

        [DllImport(sealc, PreserveSig = false)]
        internal static extern void SEALContext_ParameterErrorMessage(IntPtr thisptr, byte[] outstr, out ulong length);

        [DllImport(sealc, PreserveSig = false)]
        internal static extern void SEALContext_KeyContextData(IntPtr thisptr, out IntPtr contextData);

        [DllImport(sealc, PreserveSig = false)]
        internal static extern void SEALContext_FirstContextData(IntPtr thisptr, out IntPtr contextData);

        [DllImport(sealc, PreserveSig = false)]
        internal static extern void SEALContext_LastContextData(IntPtr thisptr, out IntPtr contextData);

        [DllImport(sealc, PreserveSig = false)]
        internal static extern void SEALContext_GetContextData(IntPtr thisptr, ulong[] parmsId, out IntPtr contextData);

        [DllImport(sealc, PreserveSig = false)]
        internal static extern void SEALContext_UsingKeyswitching(IntPtr thisptr, out bool usingKeySwitching);

        #endregion

        #region ContextData methods

        [DllImport(sealc, PreserveSig = false)]
        internal static extern void ContextData_Destroy(IntPtr thisptr);

        [DllImport(sealc, PreserveSig = false)]
        internal static extern void ContextData_TotalCoeffModulus(IntPtr thisptr, ref ulong count, ulong[] totalCoeffModulus);

        [DllImport(sealc, PreserveSig = false)]
        internal static extern void ContextData_TotalCoeffModulusBitCount(IntPtr thisptr, out int bitCount);

        [DllImport(sealc, PreserveSig = false)]
        internal static extern void ContextData_Parms(IntPtr thisptr, out IntPtr parms);

        [DllImport(sealc, PreserveSig = false)]
        internal static extern void ContextData_Qualifiers(IntPtr thisptr, out IntPtr epq);

        [DllImport(sealc, PreserveSig = false)]
        internal static extern void ContextData_CoeffDivPlainModulus(IntPtr thisptr, ref ulong count, ulong[] coefDivPlainMod);

        [DllImport(sealc, PreserveSig = false)]
        internal static extern void ContextData_PlainUpperHalfThreshold(IntPtr thisptr, out ulong puht);

        [DllImport(sealc, PreserveSig = false)]
        internal static extern void ContextData_PlainUpperHalfIncrement(IntPtr thisptr, ref ulong count, ulong[] puhi);

        [DllImport(sealc, PreserveSig = false)]
        internal static extern void ContextData_UpperHalfThreshold(IntPtr thisptr, ref ulong count, ulong[] uht);

        [DllImport(sealc, PreserveSig = false)]
        internal static extern void ContextData_UpperHalfIncrement(IntPtr thisptr, ref ulong count, ulong[] uhi);

        [DllImport(sealc, PreserveSig = false)]
        internal static extern void ContextData_PrevContextData(IntPtr thisptr, out IntPtr prevContextData);

        [DllImport(sealc, PreserveSig = false)]
        internal static extern void ContextData_NextContextData(IntPtr thisptr, out IntPtr nextContextData);

        [DllImport(sealc, PreserveSig = false)]
        internal static extern void ContextData_ChainIndex(IntPtr thisptr, out ulong index);

        #endregion

        #region Evaluator methods

        [DllImport(sealc, PreserveSig = false)]
        internal static extern void Evaluator_Create(IntPtr sealContext, out IntPtr evaluator);

        [DllImport(sealc, PreserveSig = false)]
        internal static extern void Evaluator_Destroy(IntPtr thisptr);

        [DllImport(sealc, PreserveSig = false)]
        internal static extern void Evaluator_Negate(IntPtr thisptr, IntPtr encrypted, IntPtr destination);

        [DllImport(sealc, PreserveSig = false)]
        internal static extern void Evaluator_Add(IntPtr thisptr, IntPtr encrypted1, IntPtr encrypted2, IntPtr destination);

        [DllImport(sealc, PreserveSig = false)]
        internal static extern void Evaluator_AddMany(IntPtr thisptr, ulong count, IntPtr[] encrypteds, IntPtr destination);

        [DllImport(sealc, PreserveSig = false)]
        internal static extern void Evaluator_AddPlain(IntPtr thisptr, IntPtr encrypted, IntPtr plain, IntPtr destination);

        [DllImport(sealc, PreserveSig = false)]
        internal static extern void Evaluator_Sub(IntPtr thisptr, IntPtr encrypted1, IntPtr encrypted2, IntPtr destination);

        [DllImport(sealc, PreserveSig = false)]
        internal static extern void Evaluator_SubPlain(IntPtr thisptr, IntPtr encrypted, IntPtr plain, IntPtr destination);

        [DllImport(sealc, PreserveSig = false)]
        internal static extern void Evaluator_Multiply(IntPtr thisptr, IntPtr encrypted1, IntPtr encrypted2, IntPtr destination, IntPtr pool);

        [DllImport(sealc, PreserveSig = false)]
        internal static extern void Evaluator_MultiplyMany(IntPtr thisptr, ulong count, IntPtr[] encrypteds, IntPtr relinKeys, IntPtr destination, IntPtr pool);

        [DllImport(sealc, PreserveSig = false)]
        internal static extern void Evaluator_MultiplyPlain(IntPtr thisptr, IntPtr encrypted, IntPtr plain, IntPtr destination, IntPtr pool);

        [DllImport(sealc, PreserveSig = false)]
        internal static extern void Evaluator_Square(IntPtr thisptr, IntPtr encrypted, IntPtr destination, IntPtr pool);

        [DllImport(sealc, PreserveSig = false)]
        internal static extern void Evaluator_Relinearize(IntPtr thisptr, IntPtr encrypted, IntPtr relinKeys, IntPtr destination, IntPtr pool);

        [DllImport(sealc, EntryPoint = "Evaluator_ModSwitchToNext1", PreserveSig = false)]
        internal static extern void Evaluator_ModSwitchToNext(IntPtr thisptr, IntPtr encrypted, IntPtr destination, IntPtr pool);

        [DllImport(sealc, EntryPoint = "Evaluator_ModSwitchToNext2", PreserveSig = false)]
        internal static extern void Evaluator_ModSwitchToNext(IntPtr thisptr, IntPtr plain, IntPtr destination);

        [DllImport(sealc, EntryPoint = "Evaluator_ModSwitchTo1", PreserveSig = false)]
        internal static extern void Evaluator_ModSwitchTo(IntPtr thisptr, IntPtr encrypted, ulong[] parmsId, IntPtr destination, IntPtr pool);

        [DllImport(sealc, EntryPoint = "Evaluator_ModSwitchTo2", PreserveSig = false)]
        internal static extern void Evaluator_ModSwitchTo(IntPtr thisptr, IntPtr plain, ulong[] parmsId, IntPtr destination);

        [DllImport(sealc, PreserveSig = false)]
        internal static extern void Evaluator_RescaleToNext(IntPtr thisptr, IntPtr encrypted, IntPtr destination, IntPtr pool);

        [DllImport(sealc, PreserveSig = false)]
        internal static extern void Evaluator_RescaleTo(IntPtr thisptr, IntPtr encrypted, ulong[] parmsId, IntPtr destination, IntPtr pool);

        [DllImport(sealc, PreserveSig = false)]
        internal static extern void Evaluator_Exponentiate(IntPtr thisptr, IntPtr encrypted, ulong exponent, IntPtr relinKeys, IntPtr destination, IntPtr pool);

        [DllImport(sealc, EntryPoint = "Evaluator_TransformToNTT1", PreserveSig = false)]
        internal static extern void Evaluator_TransformToNTT(IntPtr thisptr, IntPtr plain, ulong[] parmsId, IntPtr destinationNTT, IntPtr pool);

        [DllImport(sealc, EntryPoint = "Evaluator_TransformToNTT2", PreserveSig = false)]
        internal static extern void Evaluator_TransformToNTT(IntPtr thisptr, IntPtr encrypted, IntPtr destinationNTT);

        [DllImport(sealc, PreserveSig = false)]
        internal static extern void Evaluator_TransformFromNTT(IntPtr thisptr, IntPtr encryptedNTT, IntPtr destination);

        [DllImport(sealc, PreserveSig = false)]
        internal static extern void Evaluator_ApplyGalois(IntPtr thisptr, IntPtr encrypted, uint galoisElt, IntPtr galoisKeys, IntPtr destination, IntPtr pool);

        [DllImport(sealc, PreserveSig = false)]
        internal static extern void Evaluator_RotateRows(IntPtr thisptr, IntPtr encrypted, int steps, IntPtr galoisKeys, IntPtr destination, IntPtr pool);

        [DllImport(sealc, PreserveSig = false)]
        internal static extern void Evaluator_RotateColumns(IntPtr thisptr, IntPtr encrypted, IntPtr galoisKeys, IntPtr destination, IntPtr pool);

        [DllImport(sealc, PreserveSig = false)]
        internal static extern void Evaluator_RotateVector(IntPtr thisptr, IntPtr encrypted, int steps, IntPtr galoisKeys, IntPtr destination, IntPtr pool);

        [DllImport(sealc, PreserveSig = false)]
        internal static extern void Evaluator_ComplexConjugate(IntPtr thisptr, IntPtr encrypted, IntPtr galoisKeys, IntPtr destination, IntPtr pool);

        [DllImport(sealc, PreserveSig = false)]
        internal static extern void Evaluator_ContextUsingKeyswitching(IntPtr thisptr, out bool usingKeySwitching);

        #endregion

        #region Ciphertext methods

        [DllImport(sealc, PreserveSig = false)]
        internal static extern void Ciphertext_Create1(IntPtr pool, out IntPtr cipher);

        [DllImport(sealc, PreserveSig = false)]
        internal static extern void Ciphertext_Create2(IntPtr copy, out IntPtr cipher);

        [DllImport(sealc, PreserveSig = false)]
        internal static extern void Ciphertext_Create3(IntPtr context, IntPtr pool, out IntPtr cipher);

        [DllImport(sealc, PreserveSig = false)]
        internal static extern void Ciphertext_Create4(IntPtr context, ulong[] parmsId, IntPtr pool, out IntPtr cipher);

        [DllImport(sealc, PreserveSig = false)]
        internal static extern void Ciphertext_Create5(IntPtr context, ulong[] parmsId, ulong capacity, IntPtr pool, out IntPtr cipher);

        [DllImport(sealc, EntryPoint = "Ciphertext_Reserve1", PreserveSig = false)]
        internal static extern void Ciphertext_Reserve(IntPtr thisptr, IntPtr context, ulong[] parmsId, ulong sizeCapacity);

        [DllImport(sealc, EntryPoint = "Ciphertext_Reserve2", PreserveSig = false)]
        internal static extern void Ciphertext_Reserve(IntPtr thisptr, IntPtr context, ulong sizeCapacity);

        [DllImport(sealc, EntryPoint = "Ciphertext_Reserve3", PreserveSig = false)]
        internal static extern void Ciphertext_Reserve(IntPtr thisptr, ulong sizeCapacity);

        [DllImport(sealc, PreserveSig = false)]
        internal static extern void Ciphertext_Set(IntPtr thisptr, IntPtr assign);

        [DllImport(sealc, PreserveSig = false)]
        internal static extern void Ciphertext_Destroy(IntPtr thisptr);

        [DllImport(sealc, PreserveSig = false)]
        internal static extern void Ciphertext_UInt64Count(IntPtr thisptr, out ulong uint64Count);

        [DllImport(sealc, PreserveSig = false)]
        internal static extern void Ciphertext_UInt64CountCapacity(IntPtr thisptr, out ulong uint64CountCapacity);

        [DllImport(sealc, PreserveSig = false)]
        internal static extern void Ciphertext_Size(IntPtr thisptr, out ulong size);

        [DllImport(sealc, PreserveSig = false)]
        internal static extern void Ciphertext_SizeCapacity(IntPtr thisptr, out ulong sizeCapacity);

        [DllImport(sealc, PreserveSig = false)]
        internal static extern void Ciphertext_PolyModulusDegree(IntPtr thisptr, out ulong polyModulusDegree);

        [DllImport(sealc, PreserveSig = false)]
        internal static extern void Ciphertext_CoeffModulusSize(IntPtr thisptr, out ulong coeffModCount);

        [DllImport(sealc, PreserveSig = false)]
        internal static extern void Ciphertext_ParmsId(IntPtr thisptr, ulong[] parmsId);

        [DllImport(sealc, PreserveSig = false)]
        internal static extern void Ciphertext_SetParmsId(IntPtr thisptr, ulong[] parmsId);

        [DllImport(sealc, EntryPoint = "Ciphertext_Resize1", PreserveSig = false)]
        internal static extern void Ciphertext_Resize(IntPtr thisptr, IntPtr context, ulong[] parms_id, ulong size);

        [DllImport(sealc, EntryPoint = "Ciphertext_Resize2", PreserveSig = false)]
        internal static extern void Ciphertext_Resize(IntPtr thisptr, IntPtr context, ulong size);

        [DllImport(sealc, EntryPoint = "Ciphertext_Resize3", PreserveSig = false)]
        internal static extern void Ciphertext_Resize(IntPtr thisptr, ulong size);

        [DllImport(sealc, EntryPoint = "Ciphertext_Resize4", PreserveSig = false)]
        internal static extern void Ciphertext_Resize(IntPtr thisptr, ulong size, ulong polyModulusDegree, ulong coeffModCount);

        [DllImport(sealc, EntryPoint = "Ciphertext_GetDataAt1", PreserveSig = false)]
        internal static extern void Ciphertext_GetDataAt(IntPtr thisptr, ulong index, out ulong data);

        [DllImport(sealc, EntryPoint = "Ciphertext_GetDataAt2", PreserveSig = false)]
        internal static extern void Ciphertext_GetDataAt(IntPtr thisptr, ulong polyIndex, ulong coeffIndex, out ulong data);

        [DllImport(sealc, PreserveSig = false)]
        internal static extern void Ciphertext_SetDataAt(IntPtr thisptr, ulong index, ulong value);

        [DllImport(sealc, PreserveSig = false)]
        internal static extern void Ciphertext_IsNTTForm(IntPtr thisptr, out bool isNTTForm);

        [DllImport(sealc, PreserveSig = false)]
        internal static extern void Ciphertext_SetIsNTTForm(IntPtr thisptr, bool isNTTForm);

        [DllImport(sealc, PreserveSig = false)]
        internal static extern void Ciphertext_Scale(IntPtr thisptr, out double scale);

        [DllImport(sealc, PreserveSig = false)]
        internal static extern void Ciphertext_SetScale(IntPtr thisptr, double scale);

        [DllImport(sealc, PreserveSig = false)]
        internal static extern void Ciphertext_Release(IntPtr thisptr);

        [DllImport(sealc, PreserveSig = false)]
        internal static extern void Ciphertext_IsTransparent(IntPtr thisptr, out bool result);

        [DllImport(sealc, PreserveSig = false)]
        internal static extern void Ciphertext_Pool(IntPtr thisptr, out IntPtr pool);

        [DllImport(sealc, PreserveSig = false)]
        internal static extern void Ciphertext_SaveSize(IntPtr thisptr, byte comprMode, out long result);

        [DllImport(sealc, PreserveSig = false)]
        internal static extern void Ciphertext_Save(IntPtr thisptr, byte[] outptr, ulong size, byte comprMode, out long outBytes);

        [DllImport(sealc, PreserveSig = false)]
        internal static extern void Ciphertext_Load(IntPtr thisptr, IntPtr context, byte[] inptr, ulong size, out long inBytes);

        [DllImport(sealc, PreserveSig = false)]
        internal static extern void Ciphertext_UnsafeLoad(IntPtr thisptr, IntPtr context, byte[] inptr, ulong size, out long inBytes);

        #endregion

        #region Plaintext methods

        [DllImport(sealc, PreserveSig = false)]
        internal static extern void Plaintext_Create1(IntPtr memoryPoolHandle, out IntPtr plainText);

        [DllImport(sealc, PreserveSig = false)]
        internal static extern void Plaintext_Create2(ulong coeffCount, IntPtr memoryPoolHandle, out IntPtr plainText);

        [DllImport(sealc, PreserveSig = false)]
        internal static extern void Plaintext_Create3(ulong capacity, ulong coeffCount, IntPtr memoryPoolHandle, out IntPtr plainText);

        [DllImport(sealc, PreserveSig = false, CharSet = CharSet.Ansi)]
        internal static extern void Plaintext_Create4(string hexPoly, IntPtr memoryPoolHandle, out IntPtr plainText);

        [DllImport(sealc, PreserveSig = false)]
        internal static extern void Plaintext_Create5(IntPtr copy, out IntPtr plainText);

        [DllImport(sealc, EntryPoint = "Plaintext_Set1", PreserveSig = false)]
        internal static extern void Plaintext_Set(IntPtr thisptr, IntPtr assign);

        [DllImport(sealc, EntryPoint = "Plaintext_Set2", PreserveSig = false, CharSet = CharSet.Ansi)]
        internal static extern void Plaintext_Set(IntPtr thisptr, string hexPoly);

        [DllImport(sealc, EntryPoint = "Plaintext_Set3", PreserveSig = false)]
        internal static extern void Plaintext_Set(IntPtr thisptr, ulong constCoeff);

        [DllImport(sealc, PreserveSig = false)]
        internal static extern void Plaintext_Destroy(IntPtr thisptr);

        [DllImport(sealc, PreserveSig = false)]
        internal static extern void Plaintext_CoeffCount(IntPtr thisptr, out ulong coeffCount);

        [DllImport(sealc, PreserveSig = false)]
        internal static extern void Plaintext_CoeffAt(IntPtr thisptr, ulong index, out ulong coeff);

        [DllImport(sealc, PreserveSig = false)]
        internal static extern void Plaintext_SetCoeffAt(IntPtr thisptr, ulong index, ulong value);

        [DllImport(sealc, PreserveSig = false, CharSet = CharSet.Ansi)]
        internal static extern void Plaintext_ToString(IntPtr thisptr, StringBuilder outstr, out ulong length);

        [DllImport(sealc, PreserveSig = false)]
        internal static extern void Plaintext_IsNTTForm(IntPtr thisptr, out bool isNTTForm);

        [DllImport(sealc, PreserveSig = false)]
        internal static extern void Plaintext_IsZero(IntPtr thisptr, out bool isZero);

        [DllImport(sealc, EntryPoint = "Plaintext_SetZero1", PreserveSig = false)]
        internal static extern void Plaintext_SetZero(IntPtr thisptr);

        [DllImport(sealc, EntryPoint = "Plaintext_SetZero2", PreserveSig = false)]
        internal static extern void Plaintext_SetZero(IntPtr thisptr, ulong startCoeff);

        [DllImport(sealc, EntryPoint = "Plaintext_SetZero3", PreserveSig = false)]
        internal static extern void Plaintext_SetZero(IntPtr thisptr, ulong startCoeff, ulong length);

        [DllImport(sealc, PreserveSig = false)]
        internal static extern void Plaintext_GetParmsId(IntPtr thisptr, ulong[] parmsId);

        [DllImport(sealc, PreserveSig = false)]
        internal static extern void Plaintext_SetParmsId(IntPtr thisptr, ulong[] parmsId);

        [DllImport(sealc, PreserveSig = false)]
        internal static extern void Plaintext_Reserve(IntPtr thisptr, ulong capacity);

        [DllImport(sealc, PreserveSig = false)]
        internal static extern void Plaintext_Resize(IntPtr thisptr, ulong coeffCount);

        [DllImport(sealc, PreserveSig = false)]
        internal static extern void Plaintext_ShrinkToFit(IntPtr thisptr);

        [DllImport(sealc, PreserveSig = false)]
        internal static extern void Plaintext_Release(IntPtr thisptr);

        [DllImport(sealc, PreserveSig = false)]
        internal static extern void Plaintext_Capacity(IntPtr thisptr, out ulong capacity);

        [DllImport(sealc, PreserveSig = false)]
        internal static extern void Plaintext_UInt64Count(IntPtr thisptr, out ulong uint64Count);

        [DllImport(sealc, PreserveSig = false)]
        internal static extern void Plaintext_UInt64CountCapacity(IntPtr thisptr, out ulong uint64CountCapacity);

        [DllImport(sealc, PreserveSig = false)]
        internal static extern void Plaintext_SignificantCoeffCount(IntPtr thisptr, out ulong significantCoeffCount);

        [DllImport(sealc, PreserveSig = false)]
        internal static extern void Plaintext_NonZeroCoeffCount(IntPtr thisptr, out ulong nonZeroCoeffCount);

        [DllImport(sealc, PreserveSig = false)]
        internal static extern void Plaintext_Scale(IntPtr thisptr, out double scale);

        [DllImport(sealc, PreserveSig = false)]
        internal static extern void Plaintext_SetScale(IntPtr thisptr, double scale);

        [DllImport(sealc, PreserveSig = false)]
        internal static extern void Plaintext_Equals(IntPtr thisptr, IntPtr otherptr, out bool result);

        [DllImport(sealc, PreserveSig = false)]
        internal static extern void Plaintext_SwapData(IntPtr thisptr, ulong count, ulong[] newData);

        [DllImport(sealc, PreserveSig = false)]
        internal static extern void Plaintext_Pool(IntPtr thisptr, out IntPtr pool);

        [DllImport(sealc, PreserveSig = false)]
        internal static extern void Plaintext_SaveSize(IntPtr thisptr, byte comprMode, out long result);

        [DllImport(sealc, PreserveSig = false)]
        internal static extern void Plaintext_Save(IntPtr thisptr, byte[] outptr, ulong size, byte comprMode, out long outBytes);

        [DllImport(sealc, PreserveSig = false)]
        internal static extern void Plaintext_Load(IntPtr thisptr, IntPtr context, byte[] inptr, ulong size, out long inBytes);

        [DllImport(sealc, PreserveSig = false)]
        internal static extern void Plaintext_UnsafeLoad(IntPtr thisptr, IntPtr context, byte[] inptr, ulong size, out long inBytes);

        #endregion

        #region KSwitchKeys methods

        [DllImport(sealc, EntryPoint = "KSwitchKeys_Create1", PreserveSig = false)]
        internal static extern void KSwitchKeys_Create(out IntPtr kswitchKeys);

        [DllImport(sealc, EntryPoint = "KSwitchKeys_Create2", PreserveSig = false)]
        internal static extern void KSwitchKeys_Create(IntPtr copy, out IntPtr kswitchKeys);

        [DllImport(sealc, PreserveSig = false)]
        internal static extern void KSwitchKeys_Destroy(IntPtr thisptr);

        [DllImport(sealc, PreserveSig = false)]
        internal static extern void KSwitchKeys_Set(IntPtr thisptr, IntPtr assignptr);

        [DllImport(sealc, PreserveSig = false)]
        internal static extern void KSwitchKeys_Size(IntPtr thisptr, out ulong size);

        [DllImport(sealc, PreserveSig = false)]
        internal static extern void KSwitchKeys_ClearDataAndReserve(IntPtr thisptr, ulong size);

        [DllImport(sealc, PreserveSig = false)]
        internal static extern void KSwitchKeys_RawSize(IntPtr thisptr, out ulong keyCount);

        [DllImport(sealc, PreserveSig = false)]
        internal static extern void KSwitchKeys_GetKeyList(IntPtr thisptr, ulong index, ref ulong count, IntPtr[] key_list);

        [DllImport(sealc, PreserveSig = false)]
        internal static extern void KSwitchKeys_AddKeyList(IntPtr thisptr, ulong count, IntPtr[] key_list);

        [DllImport(sealc, PreserveSig = false)]
        internal static extern void KSwitchKeys_GetParmsId(IntPtr thisptr, ulong[] parmsId);

        [DllImport(sealc, PreserveSig = false)]
        internal static extern void KSwitchKeys_SetParmsId(IntPtr thisptr, ulong[] parmsId);

        [DllImport(sealc, PreserveSig = false)]
        internal static extern void KSwitchKeys_Pool(IntPtr thisptr, out IntPtr pool);

        [DllImport(sealc, PreserveSig = false)]
        internal static extern void KSwitchKeys_SaveSize(IntPtr thisptr, byte comprMode, out long result);

        [DllImport(sealc, PreserveSig = false)]
        internal static extern void KSwitchKeys_Save(IntPtr thisptr, byte[] outptr, ulong size, byte comprMode, out long outBytes);

        [DllImport(sealc, PreserveSig = false)]
        internal static extern void KSwitchKeys_Load(IntPtr thisptr, IntPtr context, byte[] inptr, ulong size, out long inBytes);

        [DllImport(sealc, PreserveSig = false)]
        internal static extern void KSwitchKeys_UnsafeLoad(IntPtr thisptr, IntPtr context, byte[] inptr, ulong size, out long inBytes);

        #endregion

        #region GaloisKeys methods

        [DllImport(sealc, EntryPoint = "GaloisKeys_GetIndex", PreserveSig = false)]
        internal static extern void GaloisKeys_GetIndex(uint galoisElt, out ulong index);

        #endregion

        #region KeyGenerator methods

        [DllImport(sealc, EntryPoint = "KeyGenerator_Create1", PreserveSig = false)]
        internal static extern void KeyGenerator_Create(IntPtr sealContext, out IntPtr keyGenerator);

        [DllImport(sealc, EntryPoint = "KeyGenerator_Create2", PreserveSig = false)]
        internal static extern void KeyGenerator_Create(IntPtr sealContext, IntPtr secretKey, out IntPtr keyGenerator);

        [DllImport(sealc, PreserveSig = false)]
        internal static extern void KeyGenerator_Destroy(IntPtr thisptr);

        [DllImport(sealc, PreserveSig = false)]
        internal static extern void KeyGenerator_RelinKeys(IntPtr thisptr, bool save_seed, out IntPtr relin_keys);

        [DllImport(sealc, EntryPoint = "KeyGenerator_GaloisKeysAll", PreserveSig = false)]
        internal static extern void KeyGenerator_GaloisKeysAll(IntPtr thisptr, bool save_seed, out IntPtr galoisKeys);

        [DllImport(sealc, EntryPoint = "KeyGenerator_GaloisKeysFromElts", PreserveSig = false)]
        internal static extern void KeyGenerator_GaloisKeysFromElts(IntPtr thisptr, ulong count, uint[] galoisElts, bool save_seed, out IntPtr galoisKeys);

        [DllImport(sealc, EntryPoint = "KeyGenerator_GaloisKeysFromSteps", PreserveSig = false)]
        internal static extern void KeyGenerator_GaloisKeysFromSteps(IntPtr thisptr, ulong count, int[] steps, bool save_seed, out IntPtr galoisKeys);

        [DllImport(sealc, PreserveSig = false)]
        internal static extern void KeyGenerator_PublicKey(IntPtr thisptr, out IntPtr publicKey);

        [DllImport(sealc, PreserveSig = false)]
        internal static extern void KeyGenerator_SecretKey(IntPtr thisptr, out IntPtr secretKey);

        [DllImport(sealc, PreserveSig = false)]
        internal static extern void KeyGenerator_ContextUsingKeyswitching(IntPtr thisptr, out bool result);

        #endregion

        #region RelinKeys methods

        [DllImport(sealc, EntryPoint = "RelinKeys_GetIndex", PreserveSig = false)]
        internal static extern void RelinKeys_GetIndex(ulong keyPower, out ulong index);

        #endregion

        #region PublicKey methods

        [DllImport(sealc, EntryPoint = "PublicKey_Create1", PreserveSig = false)]
        internal static extern void PublicKey_Create(out IntPtr publicKey);

        [DllImport(sealc, EntryPoint = "PublicKey_Create2", PreserveSig = false)]
        internal static extern void PublicKey_Create(IntPtr copy, out IntPtr publicKey);

        [DllImport(sealc, PreserveSig = false)]
        internal static extern void PublicKey_Set(IntPtr thisptr, IntPtr assign);

        [DllImport(sealc, PreserveSig = false)]
        internal static extern void PublicKey_Data(IntPtr thisptr, out IntPtr data);

        [DllImport(sealc, PreserveSig = false)]
        internal static extern void PublicKey_ParmsId(IntPtr thisptr, ulong[] parmsId);

        [DllImport(sealc, PreserveSig = false)]
        internal static extern void PublicKey_Pool(IntPtr thisptr, out IntPtr pool);

        [DllImport(sealc, PreserveSig = false)]
        internal static extern void PublicKey_Destroy(IntPtr thisptr);

        [DllImport(sealc, PreserveSig = false)]
        internal static extern void PublicKey_SaveSize(IntPtr thisptr, byte comprMode, out long result);

        [DllImport(sealc, PreserveSig = false)]
        internal static extern void PublicKey_Save(IntPtr thisptr, byte[] outptr, ulong size, byte comprMode, out long outBytes);

        [DllImport(sealc, PreserveSig = false)]
        internal static extern void PublicKey_Load(IntPtr thisptr, IntPtr context, byte[] inptr, ulong size, out long inBytes);

        [DllImport(sealc, PreserveSig = false)]
        internal static extern void PublicKey_UnsafeLoad(IntPtr thisptr, IntPtr context, byte[] inptr, ulong size, out long inBytes);

        #endregion

        #region SecretKey methods

        [DllImport(sealc, EntryPoint = "SecretKey_Create1", PreserveSig = false)]
        internal static extern void SecretKey_Create(out IntPtr secretKey);

        [DllImport(sealc, EntryPoint = "SecretKey_Create2", PreserveSig = false)]
        internal static extern void SecretKey_Create(IntPtr copy, out IntPtr secretKey);

        [DllImport(sealc, PreserveSig = false)]
        internal static extern void SecretKey_Set(IntPtr thisptr, IntPtr assign);

        [DllImport(sealc, PreserveSig = false)]
        internal static extern void SecretKey_Data(IntPtr thisptr, out IntPtr data);

        [DllImport(sealc, PreserveSig = false)]
        internal static extern void SecretKey_Destroy(IntPtr thisptr);

        [DllImport(sealc, PreserveSig = false)]
        internal static extern void SecretKey_ParmsId(IntPtr thisptr, ulong[] parmsId);

        [DllImport(sealc, PreserveSig = false)]
        internal static extern void SecretKey_Pool(IntPtr thisptr, out IntPtr pool);

        [DllImport(sealc, PreserveSig = false)]
        internal static extern void SecretKey_SaveSize(IntPtr thisptr, byte comprMode, out long result);

        [DllImport(sealc, PreserveSig = false)]
        internal static extern void SecretKey_Save(IntPtr thisptr, byte[] outptr, ulong size, byte comprMode, out long outBytes);

        [DllImport(sealc, PreserveSig = false)]
        internal static extern void SecretKey_Load(IntPtr thisptr, IntPtr context, byte[] inptr, ulong size, out long inBytes);

        [DllImport(sealc, PreserveSig = false)]
        internal static extern void SecretKey_UnsafeLoad(IntPtr thisptr, IntPtr context, byte[] inptr, ulong size, out long inBytes);

        #endregion

        #region MemoryManager methods

        [DllImport(sealc, EntryPoint = "MemoryManager_GetPool1", PreserveSig = false)]
        internal static extern void MemoryManager_GetPool(int profOpt, bool clearOnDestruction, out IntPtr handle);

        [DllImport(sealc, EntryPoint = "MemoryManager_GetPool2", PreserveSig = false)]
        internal static extern void MemoryManager_GetPool(out IntPtr handle);

        [DllImport(sealc, PreserveSig = false)]
        internal static extern void MemoryManager_SwitchProfile(IntPtr newProfile);

        #endregion

        #region MMProf methods

        [DllImport(sealc, PreserveSig = false)]
        internal static extern void MMProf_CreateGlobal(out IntPtr profile);

        [DllImport(sealc, PreserveSig = false)]
        internal static extern void MMProf_CreateFixed(IntPtr pool, out IntPtr profile);

        [DllImport(sealc, PreserveSig = false)]
        internal static extern void MMProf_CreateNew(out IntPtr profile);

        [DllImport(sealc, PreserveSig = false)]
        internal static extern void MMProf_CreateThreadLocal(out IntPtr profile);

        [DllImport(sealc, PreserveSig = false)]
        internal static extern void MMProf_GetPool(IntPtr thisptr, out IntPtr pool);

        [DllImport(sealc, PreserveSig = false)]
        internal static extern void MMProf_Destroy(IntPtr thisptr);

        #endregion

        #region MemoryPoolHandle methods

        [DllImport(sealc, EntryPoint = "MemoryPoolHandle_Create1", PreserveSig = false)]
        internal static extern void MemoryPoolHandle_Create(out IntPtr handlePtr);

        [DllImport(sealc, EntryPoint = "MemoryPoolHandle_Create2", PreserveSig = false)]
        internal static extern void MemoryPoolHandle_Create(IntPtr other, out IntPtr handlePtr);

        [DllImport(sealc, PreserveSig = false)]
        internal static extern void MemoryPoolHandle_Destroy(IntPtr thisptr);

        [DllImport(sealc, PreserveSig = false)]
        internal static extern void MemoryPoolHandle_Set(IntPtr thisptr, IntPtr assignptr);

        [DllImport(sealc, PreserveSig = false)]
        internal static extern void MemoryPoolHandle_Global(out IntPtr handlePtr);

        [DllImport(sealc, PreserveSig = false)]
        internal static extern void MemoryPoolHandle_ThreadLocal(out IntPtr handlePtr);

        [DllImport(sealc, PreserveSig = false)]
        internal static extern void MemoryPoolHandle_New(bool clearOnDestruction, out IntPtr handlePtr);

        [DllImport(sealc, PreserveSig = false)]
        internal static extern void MemoryPoolHandle_PoolCount(IntPtr thisptr, out ulong count);

        [DllImport(sealc, PreserveSig = false)]
        internal static extern void MemoryPoolHandle_AllocByteCount(IntPtr thisptr, out ulong count);

        [DllImport(sealc, PreserveSig = false)]
        internal static extern void MemoryPoolHandle_UseCount(IntPtr thisptr, out long count);

        [DllImport(sealc, PreserveSig = false)]
        internal static extern void MemoryPoolHandle_IsInitialized(IntPtr thisptr, out bool initialized);

        [DllImport(sealc, PreserveSig = false)]
        internal static extern void MemoryPoolHandle_Equals(IntPtr thisptr, IntPtr otherptr, out bool result);

        #endregion

        #region Encryptor methods

        [DllImport(sealc, PreserveSig = false)]
        internal static extern void Encryptor_Create(IntPtr context, IntPtr publicKey, IntPtr secretKey, out IntPtr encryptor);

        [DllImport(sealc, PreserveSig = false)]
        internal static extern void Encryptor_SetPublicKey(IntPtr thisptr, IntPtr publicKey);

        [DllImport(sealc, PreserveSig = false)]
        internal static extern void Encryptor_SetSecretKey(IntPtr thisptr, IntPtr secretKey);

        [DllImport(sealc, PreserveSig = false)]
        internal static extern void Encryptor_Encrypt(IntPtr thisptr, IntPtr plaintext, IntPtr destination, IntPtr poolHandle);

        [DllImport(sealc, PreserveSig = false)]
        internal static extern void Encryptor_EncryptZero1(IntPtr thisptr, ulong[] parmsId, IntPtr destination, IntPtr poolHandle);

        [DllImport(sealc, PreserveSig = false)]
        internal static extern void Encryptor_EncryptZero2(IntPtr thisptr, IntPtr destination, IntPtr poolHandle);

        [DllImport(sealc, PreserveSig = false)]
        internal static extern void Encryptor_EncryptSymmetric(IntPtr thisptr, IntPtr plaintext, bool save_seed, IntPtr destination, IntPtr poolHandle);

        [DllImport(sealc, PreserveSig = false)]
        internal static extern void Encryptor_EncryptZeroSymmetric1(IntPtr thisptr, ulong[] parmsId, bool save_seed, IntPtr destination, IntPtr poolHandle);

        [DllImport(sealc, PreserveSig = false)]
        internal static extern void Encryptor_EncryptZeroSymmetric2(IntPtr thisptr, bool save_seed, IntPtr destination, IntPtr poolHandle);

        [DllImport(sealc, PreserveSig = false)]
        internal static extern void Encryptor_Destroy(IntPtr thisptr);

        #endregion

        #region Decryptor methods

        [DllImport(sealc, PreserveSig = false)]
        internal static extern void Decryptor_Create(IntPtr context, IntPtr secretKey, out IntPtr decryptor);

        [DllImport(sealc, PreserveSig = false)]
        internal static extern void Decryptor_Destroy(IntPtr thisptr);

        [DllImport(sealc, PreserveSig = false)]
        internal static extern void Decryptor_Decrypt(IntPtr thisptr, IntPtr encrypted, IntPtr destination);

        [DllImport(sealc, PreserveSig = false)]
        internal static extern void Decryptor_InvariantNoiseBudget(IntPtr thisptr, IntPtr encrypted, out int invariantNoiseBudget);

        #endregion

        #region CKKSEncoder methods

        [DllImport(sealc, PreserveSig = false)]
        internal static extern void CKKSEncoder_Create(IntPtr context, out IntPtr ckksEncoder);

        [DllImport(sealc, PreserveSig = false)]
        internal static extern void CKKSEncoder_Destroy(IntPtr thisptr);

        [DllImport(sealc, EntryPoint = "CKKSEncoder_Encode1", PreserveSig = false)]
        internal static extern void CKKSEncoder_EncodeDouble(IntPtr thisptr, ulong valueCount, double[] values, ulong[] parms_id, double scale, IntPtr destination, IntPtr pool);

        [DllImport(sealc, EntryPoint = "CKKSEncoder_Encode2", PreserveSig = false)]
        internal static extern void CKKSEncoder_EncodeComplex(IntPtr thisptr, ulong valueCount, double[] values, ulong[] parms_id, double scale, IntPtr destination, IntPtr pool);

        [DllImport(sealc, EntryPoint = "CKKSEncoder_Encode3", PreserveSig = false)]
        internal static extern void CKKSEncoder_Encode(IntPtr thisptr, double value, ulong[] parms_id, double scale, IntPtr destination, IntPtr pool);

        [DllImport(sealc, EntryPoint = "CKKSEncoder_Encode4", PreserveSig = false)]
        internal static extern void CKKSEncoder_Encode(IntPtr thisptr, double valueRe, double valueIm, ulong[] parms_id, double scale, IntPtr destination, IntPtr pool);

        [DllImport(sealc, EntryPoint = "CKKSEncoder_Encode5", PreserveSig = false)]
        internal static extern void CKKSEncoder_Encode(IntPtr thisptr, long value, ulong[] parms_id, IntPtr destination);

        [DllImport(sealc, EntryPoint = "CKKSEncoder_Decode1", PreserveSig = false)]
        internal static extern void CKKSEncoder_DecodeDouble(IntPtr thisptr, IntPtr plain, ref ulong valueCount, double[] values, IntPtr pool);

        [DllImport(sealc, EntryPoint = "CKKSEncoder_Decode2", PreserveSig = false)]
        internal static extern void CKKSEncoder_DecodeComplex(IntPtr thisptr, IntPtr plain, ref ulong valueCount, double[] values, IntPtr pool);

        [DllImport(sealc, PreserveSig = false)]
        internal static extern void CKKSEncoder_SlotCount(IntPtr thisptr, out ulong slotCount);

        #endregion

        #region BatchEncoder methods

        [DllImport(sealc, PreserveSig = false)]
        internal static extern void BatchEncoder_Create(IntPtr context, out IntPtr batchEncoder);

        [DllImport(sealc, PreserveSig = false)]
        internal static extern void BatchEncoder_Destroy(IntPtr thisptr);

        [DllImport(sealc, EntryPoint = "BatchEncoder_Encode1", PreserveSig = false)]
        internal static extern void BatchEncoder_Encode(IntPtr thisptr, ulong count, ulong[] values, IntPtr destination);

        [DllImport(sealc, EntryPoint = "BatchEncoder_Encode2", PreserveSig = false)]
        internal static extern void BatchEncoder_Encode(IntPtr thisptr, ulong count, long[] values, IntPtr destination);

        [DllImport(sealc, EntryPoint = "BatchEncoder_Encode3", PreserveSig = false)]
        internal static extern void BatchEncoder_Encode(IntPtr thisptr, IntPtr plain, IntPtr pool);

        [DllImport(sealc, EntryPoint = "BatchEncoder_Decode1", PreserveSig = false)]
        internal static extern void BatchEncoder_Decode(IntPtr thisptr, IntPtr plain, ref ulong count, ulong[] destination, IntPtr pool);

        [DllImport(sealc, EntryPoint = "BatchEncoder_Decode2", PreserveSig = false)]
        internal static extern void BatchEncoder_Decode(IntPtr thisptr, IntPtr plain, ref ulong count, long[] destination, IntPtr pool);

        [DllImport(sealc, EntryPoint = "BatchEncoder_Decode3", PreserveSig = false)]
        internal static extern void BatchEncoder_Decode(IntPtr thisptr, IntPtr plain, IntPtr pool);

        [DllImport(sealc, PreserveSig = false)]
        internal static extern void BatchEncoder_GetSlotCount(IntPtr thisptr, out ulong slotCount);

        #endregion

        #region IntegerEncoder methods

        [DllImport(sealc, PreserveSig = false)]
        internal static extern void IntegerEncoder_Create(IntPtr context, out IntPtr encoder);

        [DllImport(sealc, PreserveSig = false)]
        internal static extern void IntegerEncoder_Destroy(IntPtr thisptr);

        [DllImport(sealc, EntryPoint = "IntegerEncoder_Encode1", PreserveSig = false)]
        internal static extern void IntegerEncoder_Encode(IntPtr thisptr, int value, IntPtr plain);

        [DllImport(sealc, EntryPoint = "IntegerEncoder_Encode2", PreserveSig = false)]
        internal static extern void IntegerEncoder_Encode(IntPtr thisptr, uint value, IntPtr plain);

        [DllImport(sealc, EntryPoint = "IntegerEncoder_Encode3", PreserveSig = false)]
        internal static extern void IntegerEncoder_Encode(IntPtr thisptr, ulong value, IntPtr plain);

        [DllImport(sealc, EntryPoint = "IntegerEncoder_Encode4", PreserveSig = false)]
        internal static extern void IntegerEncoder_Encode(IntPtr thisptr, long value, IntPtr plain);

        [DllImport(sealc, EntryPoint = "IntegerEncoder_Encode5", PreserveSig = false)]
        internal static extern void IntegerEncoder_Encode(IntPtr thisptr, IntPtr bigUInt, IntPtr plain);

        [DllImport(sealc, PreserveSig = false)]
        internal static extern void IntegerEncoder_DecodeUInt32(IntPtr thisptr, IntPtr plain, out uint result);

        [DllImport(sealc, PreserveSig = false)]
        internal static extern void IntegerEncoder_DecodeUInt64(IntPtr thisptr, IntPtr plain, out ulong result);

        [DllImport(sealc, PreserveSig = false)]
        internal static extern void IntegerEncoder_DecodeInt32(IntPtr thisptr, IntPtr plain, out int result);

        [DllImport(sealc, PreserveSig = false)]
        internal static extern void IntegerEncoder_DecodeInt64(IntPtr thisptr, IntPtr plain, out long result);

        [DllImport(sealc, PreserveSig = false)]
        internal static extern void IntegerEncoder_DecodeBigUInt(IntPtr thisptr, IntPtr plain, out IntPtr bigUInt);

        [DllImport(sealc, PreserveSig = false)]
        internal static extern void IntegerEncoder_PlainModulus(IntPtr thisptr, out IntPtr smallModulus);

        #endregion

        #region ValCheck methods

        [DllImport(sealc, PreserveSig = false)]
        internal static extern void ValCheck_Plaintext_IsValidFor(IntPtr plaintext, IntPtr context, out bool result);

        [DllImport(sealc, PreserveSig = false)]
        internal static extern void ValCheck_Ciphertext_IsValidFor(IntPtr ciphertext, IntPtr context, out bool result);

        [DllImport(sealc, PreserveSig = false)]
        internal static extern void ValCheck_SecretKey_IsValidFor(IntPtr secretKey, IntPtr context, out bool result);

        [DllImport(sealc, PreserveSig = false)]
        internal static extern void ValCheck_PublicKey_IsValidFor(IntPtr publicKey, IntPtr context, out bool result);

        [DllImport(sealc, PreserveSig = false)]
        internal static extern void ValCheck_KSwitchKeys_IsValidFor(IntPtr kswitchKeys, IntPtr context, out bool result);

        [DllImport(sealc, PreserveSig = false)]
        internal static extern void ValCheck_RelinKeys_IsValidFor(IntPtr relinKeys, IntPtr context, out bool result);

        [DllImport(sealc, PreserveSig = false)]
        internal static extern void ValCheck_GaloisKeys_IsValidFor(IntPtr galoisKeys, IntPtr context, out bool result);

        #endregion

        #region Serialization methods

        [DllImport(sealc, PreserveSig = false)]
        internal static extern void Serialization_SEALMagic(out ushort result);

        [DllImport(sealc, PreserveSig = false)]
        internal static extern void Serialization_SEALHeaderSize(out byte result);

        [DllImport(sealc, PreserveSig = false)]
        internal static extern void Serialization_IsSupportedComprMode(byte comprMode, out bool result);

        [DllImport(sealc, PreserveSig = false)]
        internal static extern void Serialization_ComprModeDefault(out byte result);

        [DllImport(sealc, PreserveSig = false)]
        internal static extern void Serialization_IsCompatibleVersion(byte[] headerptr, ulong size, out bool result);

        [DllImport(sealc, PreserveSig = false)]
        internal static extern void Serialization_IsValidHeader(byte[] headerptr, ulong size, out bool result);

        #endregion

        public static class Errors
        {
            public const uint NoError = 0;
            public const uint InsufficientBuffer = 122;
            public const uint BadArguments = 160;
            public const uint InvalidIndex = 1413;
            public const uint InvalidOperation = 4317;
            public const uint HRPointer = 0x80004003;
            public const uint HRInvalidIndex = 0x80070585;
            public const uint HRInvalidOperation = 0x800710DD;
        }
    }
}
