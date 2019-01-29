// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

using System;
using System.Runtime.InteropServices;
using System.Text;

namespace Microsoft.Research.SEAL
{
    static class NativeMethods
    {
        private const string sealnetnative = "sealnetnative";

        #region BigUInt methods

        [DllImport(sealnetnative, EntryPoint = "BigUInt_Create1", PreserveSig = false)]
        internal static extern void BigUInt_Create(out IntPtr bigUInt);

        [DllImport(sealnetnative, EntryPoint = "BigUInt_Create2", PreserveSig = false)]
        internal static extern void BigUInt_Create(int bitCount, out IntPtr bigUInt);

        [DllImport(sealnetnative, EntryPoint = "BigUInt_Create3", PreserveSig = false, CharSet = CharSet.Ansi)]
        internal static extern void BigUInt_Create(int bitCount, string hexString, out IntPtr bigUInt);

        [DllImport(sealnetnative, EntryPoint = "BigUInt_Create4", PreserveSig = false)]
        internal static extern void BigUInt_Create(int bitCount, ulong value, out IntPtr bigUInt);

        [DllImport(sealnetnative, EntryPoint = "BigUInt_Create5", PreserveSig = false, CharSet = CharSet.Ansi)]
        internal static extern void BigUInt_Create(string hexString, out IntPtr bigUInt);

        [DllImport(sealnetnative, EntryPoint = "BigUInt_Create6", PreserveSig = false)]
        internal static extern void BigUInt_Create(IntPtr copy, out IntPtr bigUInt);

        [DllImport(sealnetnative, PreserveSig = false)]
        internal static extern void BigUInt_Destroy(IntPtr thisptr);

        [DllImport(sealnetnative, PreserveSig = false)]
        internal static extern void BigUInt_IsAlias(IntPtr thisptr, out bool isAlias);

        [DllImport(sealnetnative, PreserveSig = false)]
        internal static extern void BigUInt_BitCount(IntPtr thisptr, out int bitCount);

        [DllImport(sealnetnative, PreserveSig = false)]
        internal static extern void BigUInt_ByteCount(IntPtr thisptr, out ulong byteCount);

        [DllImport(sealnetnative, PreserveSig = false)]
        internal static extern void BigUInt_UInt64Count(IntPtr thisptr, out ulong uint64Count);

        [DllImport(sealnetnative, PreserveSig = false)]
        internal static extern void BigUInt_IsZero(IntPtr thisptr, out bool isZero);

        [DllImport(sealnetnative, PreserveSig = false)]
        internal static extern void BigUInt_Get(IntPtr thisptr, ulong index, out byte value);

        [DllImport(sealnetnative, PreserveSig = false)]
        internal static extern void BigUInt_GetU64(IntPtr thisptr, ulong index, out ulong value);

        [DllImport(sealnetnative, PreserveSig = false)]
        internal static extern void BigUInt_GetSignificantBitCount(IntPtr thisptr, out int significantBitCount);

        [DllImport(sealnetnative, EntryPoint = "BigUInt_Set1", PreserveSig = false)]
        internal static extern void BigUInt_Set(IntPtr thisptr, ulong index, byte value);

        [DllImport(sealnetnative, EntryPoint = "BigUInt_Set2", PreserveSig = false)]
        internal static extern void BigUInt_Set(IntPtr thisptr, IntPtr assign);

        [DllImport(sealnetnative, EntryPoint = "BigUInt_Set3", PreserveSig = false)]
        internal static extern void BigUInt_Set(IntPtr thisptr, ulong value);

        [DllImport(sealnetnative, EntryPoint = "BigUInt_Set4", PreserveSig = false, CharSet = CharSet.Ansi)]
        internal static extern void BigUInt_Set(IntPtr thisptr, string assign);

        [DllImport(sealnetnative, PreserveSig = false)]
        internal static extern void BigUInt_SetZero(IntPtr thisptr);

        [DllImport(sealnetnative, PreserveSig = false)]
        internal static extern void BigUInt_Resize(IntPtr thisptr, int bitCount);

        [DllImport(sealnetnative, PreserveSig = false)]
        internal static extern void BigUInt_Equals(IntPtr thisptr, IntPtr compare, out bool result);

        [DllImport(sealnetnative, EntryPoint = "BigUInt_CompareTo1", PreserveSig = false)]
        internal static extern void BigUInt_CompareTo(IntPtr thisptr, IntPtr compare, out int result);

        [DllImport(sealnetnative, EntryPoint = "BigUInt_CompareTo2", PreserveSig = false)]
        internal static extern void BigUInt_CompareTo(IntPtr thisptr, ulong compare, out int result);

        [DllImport(sealnetnative, EntryPoint = "BigUInt_DivideRemainder1", PreserveSig = false)]
        internal static extern void BigUInt_DivideRemainder(IntPtr thisptr, IntPtr operand2, IntPtr remainder, out IntPtr result);

        [DllImport(sealnetnative, EntryPoint = "BigUInt_DivideRemainder2", PreserveSig = false)]
        internal static extern void BigUInt_DivideRemainder(IntPtr thisptr, ulong operand2, IntPtr remainder, out IntPtr result);

        [DllImport(sealnetnative, PreserveSig = false, CharSet = CharSet.Ansi)]
        internal static extern void BigUInt_ToString(IntPtr thisptr, StringBuilder outstr, ref ulong length);

        [DllImport(sealnetnative, PreserveSig = false, CharSet = CharSet.Ansi)]
        internal static extern void BigUInt_ToDecimalString(IntPtr thisptr, StringBuilder outstr, ref ulong length);

        [DllImport(sealnetnative, PreserveSig = false, CharSet = CharSet.Ansi)]
        internal static extern void BigUInt_DuplicateTo(IntPtr thisptr, IntPtr destination);

        [DllImport(sealnetnative, PreserveSig = false, CharSet = CharSet.Ansi)]
        internal static extern void BigUInt_DuplicateFrom(IntPtr thisptr, IntPtr value);

        [DllImport(sealnetnative, EntryPoint = "BigUInt_ModuloInvert1", PreserveSig = false)]
        internal static extern void BigUInt_ModuloInvert(IntPtr thisptr, IntPtr modulus, out IntPtr result);

        [DllImport(sealnetnative, EntryPoint = "BigUInt_ModuloInvert2", PreserveSig = false)]
        internal static extern void BigUInt_ModuloInvert(IntPtr thisptr, ulong modulus, out IntPtr result);

        [DllImport(sealnetnative, EntryPoint = "BigUInt_TryModuloInvert1", PreserveSig = false)]
        internal static extern void BigUInt_TryModuloInvert(IntPtr thisptr, IntPtr modulus, IntPtr inverse, out bool result);

        [DllImport(sealnetnative, EntryPoint = "BigUInt_TryModuloInvert2", PreserveSig = false)]
        internal static extern void BigUInt_TryModuloInvert(IntPtr thisptr, ulong modulus, IntPtr inverse, out bool result);

        [DllImport(sealnetnative, PreserveSig = false)]
        internal static extern void BigUInt_OperatorNeg(IntPtr thisptr, out IntPtr result);

        [DllImport(sealnetnative, PreserveSig = false)]
        internal static extern void BigUInt_OperatorTilde(IntPtr thisptr, out IntPtr result);

        [DllImport(sealnetnative, EntryPoint = "BigUInt_OperatorPlus1", PreserveSig = false)]
        internal static extern void BigUInt_OperatorPlus(IntPtr thisptr, IntPtr operand, out IntPtr result);

        [DllImport(sealnetnative, EntryPoint = "BigUInt_OperatorPlus2", PreserveSig = false)]
        internal static extern void BigUInt_OperatorPlus(IntPtr thisptr, ulong operand, out IntPtr result);

        [DllImport(sealnetnative, EntryPoint = "BigUInt_OperatorMinus1", PreserveSig = false)]
        internal static extern void BigUInt_OperatorMinus(IntPtr thisptr, IntPtr operand, out IntPtr result);

        [DllImport(sealnetnative, EntryPoint = "BigUInt_OperatorMinus2", PreserveSig = false)]
        internal static extern void BigUInt_OperatorMinus(IntPtr thisptr, ulong operand, out IntPtr result);

        [DllImport(sealnetnative, EntryPoint = "BigUInt_OperatorMult1", PreserveSig = false)]
        internal static extern void BigUInt_OperatorMult(IntPtr thisptr, IntPtr operand, out IntPtr result);

        [DllImport(sealnetnative, EntryPoint = "BigUInt_OperatorMult2", PreserveSig = false)]
        internal static extern void BigUInt_OperatorMult(IntPtr thisptr, ulong operand, out IntPtr result);

        [DllImport(sealnetnative, EntryPoint = "BigUInt_OperatorDiv1", PreserveSig = false)]
        internal static extern void BigUInt_OperatorDiv(IntPtr thisptr, IntPtr operand, out IntPtr result);

        [DllImport(sealnetnative, EntryPoint = "BigUInt_OperatorDiv2", PreserveSig = false)]
        internal static extern void BigUInt_OperatorDiv(IntPtr thisptr, ulong operand, out IntPtr result);

        [DllImport(sealnetnative, EntryPoint = "BigUInt_OperatorXor1", PreserveSig = false)]
        internal static extern void BigUInt_OperatorXor(IntPtr thisptr, IntPtr operand, out IntPtr result);

        [DllImport(sealnetnative, EntryPoint = "BigUInt_OperatorXor2", PreserveSig = false)]
        internal static extern void BigUInt_OperatorXor(IntPtr thisptr, ulong operand, out IntPtr result);

        [DllImport(sealnetnative, EntryPoint = "BigUInt_OperatorAnd1", PreserveSig = false)]
        internal static extern void BigUInt_OperatorAnd(IntPtr thisptr, IntPtr operand, out IntPtr result);

        [DllImport(sealnetnative, EntryPoint = "BigUInt_OperatorAnd2", PreserveSig = false)]
        internal static extern void BigUInt_OperatorAnd(IntPtr thisptr, ulong operand, out IntPtr result);

        [DllImport(sealnetnative, EntryPoint = "BigUInt_OperatorOr1", PreserveSig = false)]
        internal static extern void BigUInt_OperatorOr(IntPtr thisptr, IntPtr operand, out IntPtr result);

        [DllImport(sealnetnative, EntryPoint = "BigUInt_OperatorOr2", PreserveSig = false)]
        internal static extern void BigUInt_OperatorOr(IntPtr thisptr, ulong operand, out IntPtr result);

        [DllImport(sealnetnative, PreserveSig = false)]
        internal static extern void BigUInt_OperatorShiftLeft(IntPtr thisptr, int shift, out IntPtr result);

        [DllImport(sealnetnative, PreserveSig = false)]
        internal static extern void BigUInt_OperatorShiftRight(IntPtr thisptr, int shift, out IntPtr result);

        [DllImport(sealnetnative, PreserveSig = false)]
        internal static extern void BigUInt_ToDouble(IntPtr thisptr, out double result);

        #endregion

        #region EncryptionParameterQualifiers methods

        [DllImport(sealnetnative, PreserveSig = false)]
        internal static extern void EPQ_Create(IntPtr copy, out IntPtr epq);

        [DllImport(sealnetnative, PreserveSig = false)]
        internal static extern void EPQ_Destroy(IntPtr thisptr);

        [DllImport(sealnetnative, PreserveSig = false)]
        internal static extern void EPQ_ParametersSet(IntPtr thisptr, out bool parametersSet);

        [DllImport(sealnetnative, PreserveSig = false)]
        internal static extern void EPQ_UsingFFT(IntPtr thisptr, out bool usingFFT);

        [DllImport(sealnetnative, PreserveSig = false)]
        internal static extern void EPQ_UsingNTT(IntPtr thisptr, out bool usingNTT);

        [DllImport(sealnetnative, PreserveSig = false)]
        internal static extern void EPQ_UsingBatching(IntPtr thisptr, out bool usingBatching);

        [DllImport(sealnetnative, PreserveSig = false)]
        internal static extern void EPQ_UsingFastPlainLift(IntPtr thisptr, out bool usingFastPlainLift);

        [DllImport(sealnetnative, PreserveSig = false)]
        internal static extern void EPQ_UsingHEStdSecurity(IntPtr thisptr, out bool usingHEStdSecurity);

        #endregion

        #region SmallModulus methods

        [DllImport(sealnetnative, EntryPoint = "SmallModulus_Create1", PreserveSig = false)]
        internal static extern void SmallModulus_Create(ulong value, out IntPtr smallModulus);

        [DllImport(sealnetnative, EntryPoint = "SmallModulus_Create2", PreserveSig = false)]
        internal static extern void SmallModulus_Create(IntPtr copy, out IntPtr smallModulus);

        [DllImport(sealnetnative, PreserveSig = false)]
        internal static extern void SmallModulus_Destroy(IntPtr thisptr);

        [DllImport(sealnetnative, PreserveSig = false)]
        internal static extern void SmallModulus_IsZero(IntPtr thisptr, out bool isZero);

        [DllImport(sealnetnative, PreserveSig = false)]
        internal static extern void SmallModulus_Value(IntPtr thisptr, out ulong value);

        [DllImport(sealnetnative, PreserveSig = false)]
        internal static extern void SmallModulus_BitCount(IntPtr thisptr, out int bitCount);

        [DllImport(sealnetnative, PreserveSig = false)]
        internal static extern void SmallModulus_UInt64Count(IntPtr thisptr, out ulong uint64Count);

        [DllImport(sealnetnative, EntryPoint = "SmallModulus_Set1", PreserveSig = false)]
        internal static extern void SmallModulus_Set(IntPtr thisptr, IntPtr assign);

        [DllImport(sealnetnative, EntryPoint = "SmallModulus_Set2", PreserveSig = false)]
        internal static extern void SmallModulus_Set(IntPtr thisptr, ulong value);

        [DllImport(sealnetnative, PreserveSig = false)]
        internal static extern void SmallModulus_ConstRatio(
            IntPtr thisptr, 
            ulong length, 
            [MarshalAs(UnmanagedType.LPArray)] ulong[] ratio);

        [DllImport(sealnetnative, EntryPoint = "SmallModulus_Equals1", PreserveSig = false)]
        internal static extern void SmallModulus_Equals(IntPtr thisptr, IntPtr other, out bool result);

        [DllImport(sealnetnative, EntryPoint = "SmallModulus_Equals2", PreserveSig = false)]
        internal static extern void SmallModulus_Equals(IntPtr thisptr, ulong other, out bool result);

        #endregion

        #region EncryptionParameters methods

        [DllImport(sealnetnative, EntryPoint = "EncParams_Create1", PreserveSig = false)]
        internal static extern void EncParams_Create(int scheme, out IntPtr encParams);

        [DllImport(sealnetnative, EntryPoint = "EncParams_Create2", PreserveSig = false)]
        internal static extern void EncParams_Create(IntPtr copy, out IntPtr encParams);

        [DllImport(sealnetnative, PreserveSig = false)]
        internal static extern void EncParams_Destroy(IntPtr thisptr);

        [DllImport(sealnetnative, PreserveSig = false)]
        internal static extern void EncParams_Set(IntPtr thisptr, IntPtr assign);

        [DllImport(sealnetnative, PreserveSig = false)]
        internal static extern void EncParams_GetPolyModulusDegree(IntPtr thisptr, out ulong polyModulusDegree);

        [DllImport(sealnetnative, PreserveSig = false)]
        internal static extern void EncParams_SetPolyModulusDegree(IntPtr thisptr, ulong polyModulusDegree);

        [DllImport(sealnetnative, PreserveSig = false)]
        internal static extern void EncParams_GetCoeffModulus(
            IntPtr thisptr, 
            ref ulong length, 
            [MarshalAs(UnmanagedType.LPArray)] IntPtr[] coeffs);

        [DllImport(sealnetnative, PreserveSig = false)]
        internal static extern void EncParams_SetCoeffModulus(
            IntPtr thisptr, 
            ulong length, 
            [MarshalAs(UnmanagedType.LPArray)] IntPtr[] coeffs);

        [DllImport(sealnetnative, PreserveSig = false)]
        internal static extern void EncParams_GetScheme(IntPtr thisptr, out int scheme);

        [DllImport(sealnetnative, PreserveSig = false)]
        internal static extern void EncParams_GetParmsId(IntPtr thisptr, ulong[] parmsId);

        [DllImport(sealnetnative, PreserveSig = false)]
        internal static extern void EncParams_GetPlainModulus(IntPtr thisptr, out IntPtr plainModulus);

        [DllImport(sealnetnative, EntryPoint = "EncParams_SetPlainModulus1", PreserveSig = false)]
        internal static extern void EncParams_SetPlainModulus(IntPtr thisptr, IntPtr plainModulus);

        [DllImport(sealnetnative, EntryPoint = "EncParams_SetPlainModulus2", PreserveSig = false)]
        internal static extern void EncParams_SetPlainModulus(IntPtr thisptr, ulong plainModulus);

        [DllImport(sealnetnative, PreserveSig = false)]
        internal static extern void EncParams_NoiseStandardDeviation(IntPtr thisptr, out double nsd);

        [DllImport(sealnetnative, PreserveSig = false)]
        internal static extern void EncParams_SetNoiseStandardDeviation(IntPtr thisptr, double nsd);

        [DllImport(sealnetnative, PreserveSig = false)]
        internal static extern void EncParams_NoiseMaxDeviation(IntPtr thisptr, out double nmd);

        [DllImport(sealnetnative, PreserveSig = false)]
        internal static extern void EncParams_Equals(IntPtr thisptr, IntPtr otherptr, out bool result);

        #endregion

        #region DefaultParams methods

        [DllImport(sealnetnative, PreserveSig = false)]
        internal static extern void DefParams_CoeffModulus128(
            ulong polyModulusDegree,
            ref ulong length,
            [MarshalAs(UnmanagedType.LPArray)] IntPtr[] coeffs);

        [DllImport(sealnetnative, PreserveSig = false)]
        internal static extern void DefParams_CoeffModulus192(
            ulong polyModulusDegree,
            ref ulong length,
            [MarshalAs(UnmanagedType.LPArray)] IntPtr[] coeffs);

        [DllImport(sealnetnative, PreserveSig = false)]
        internal static extern void DefParams_CoeffModulus256(
            ulong polyModulusDegree,
            ref ulong length,
            [MarshalAs(UnmanagedType.LPArray)] IntPtr[] coeffs);

        [DllImport(sealnetnative, PreserveSig = false)]
        internal static extern void DefParams_SmallMods60Bit(ulong index, out IntPtr smallModulus);

        [DllImport(sealnetnative, PreserveSig = false)]
        internal static extern void DefParams_SmallMods50Bit(ulong index, out IntPtr smallModulus);

        [DllImport(sealnetnative, PreserveSig = false)]
        internal static extern void DefParams_SmallMods40Bit(ulong index, out IntPtr smallModulus);

        [DllImport(sealnetnative, PreserveSig = false)]
        internal static extern void DefParams_SmallMods30Bit(ulong index, out IntPtr smallModulus);

        [DllImport(sealnetnative, PreserveSig = false)]
        internal static extern void DefParams_DBCMax(out int dbcMax);

        [DllImport(sealnetnative, PreserveSig = false)]
        internal static extern void DefParams_DBCMin(out int dbcMin);

        #endregion

        #region SEALContext methods

        [DllImport(sealnetnative, PreserveSig = false)]
        internal static extern void SEALContext_Create(IntPtr encryptionParams, bool expandModChain, out IntPtr context);

        [DllImport(sealnetnative, PreserveSig = false)]
        internal static extern void SEALContext_Destroy(IntPtr thisptr);

        [DllImport(sealnetnative, PreserveSig = false)]
        internal static extern void SEALContext_FirstParmsId(IntPtr thisptr, ulong[] parmsId);

        [DllImport(sealnetnative, PreserveSig = false)]
        internal static extern void SEALContext_LastParmsId(IntPtr thisptr, ulong[] parmsId);

        [DllImport(sealnetnative, PreserveSig = false)]
        internal static extern void SEALContext_ParametersSet(IntPtr thisptr, out bool paramsSet);

        [DllImport(sealnetnative, PreserveSig = false)]
        internal static extern void SEALContext_FirstContextData(IntPtr thisptr, out IntPtr contextData);

        [DllImport(sealnetnative, PreserveSig = false)]
        internal static extern void SEALContext_GetContextData(IntPtr thisptr, ulong[] parmsId, out IntPtr contextData);

        #endregion

        #region ContextData methods

        [DllImport(sealnetnative, PreserveSig = false)]
        internal static extern void ContextData_Destroy(IntPtr thisptr);

        [DllImport(sealnetnative, PreserveSig = false)]
        internal static extern void ContextData_TotalCoeffModulus(IntPtr thisptr, ref ulong count, ulong[] totalCoeffModulus);

        [DllImport(sealnetnative, PreserveSig = false)]
        internal static extern void ContextData_TotalCoeffModulusBitCount(IntPtr thisptr, out int bitCount);

        [DllImport(sealnetnative, PreserveSig = false)]
        internal static extern void ContextData_Parms(IntPtr thisptr, out IntPtr parms);

        [DllImport(sealnetnative, PreserveSig = false)]
        internal static extern void ContextData_Qualifiers(IntPtr thisptr, out IntPtr epq);

        [DllImport(sealnetnative, PreserveSig = false)]
        internal static extern void ContextData_CoeffDivPlainModulus(IntPtr thisptr, ref ulong count, ulong[] coefDivPlainMod);

        [DllImport(sealnetnative, PreserveSig = false)]
        internal static extern void ContextData_PlainUpperHalfThreshold(IntPtr thisptr, out ulong puht);

        [DllImport(sealnetnative, PreserveSig = false)]
        internal static extern void ContextData_PlainUpperHalfIncrement(IntPtr thisptr, ref ulong count, ulong[] puhi);

        [DllImport(sealnetnative, PreserveSig = false)]
        internal static extern void ContextData_UpperHalfThreshold(IntPtr thisptr, ref ulong count, ulong[] uht);

        [DllImport(sealnetnative, PreserveSig = false)]
        internal static extern void ContextData_UpperHalfIncrement(IntPtr thisptr, ref ulong count, ulong[] uhi);

        [DllImport(sealnetnative, PreserveSig = false)]
        internal static extern void ContextData_NextContextData(IntPtr thisptr, out IntPtr nextContextData);

        [DllImport(sealnetnative, PreserveSig = false)]
        internal static extern void ContextData_ChainIndex(IntPtr thisptr, out ulong index);

        #endregion

        #region Evaluator methods

        [DllImport(sealnetnative, PreserveSig = false)]
        internal static extern void Evaluator_Create(IntPtr sealContext, out IntPtr evaluator);

        [DllImport(sealnetnative, PreserveSig = false)]
        internal static extern void Evaluator_Destroy(IntPtr thisptr);

        [DllImport(sealnetnative, PreserveSig = false)]
        internal static extern void Evaluator_Negate(IntPtr thisptr, IntPtr encrypted, IntPtr destination);

        [DllImport(sealnetnative, PreserveSig = false)]
        internal static extern void Evaluator_Add(IntPtr thisptr, IntPtr encrypted1, IntPtr encrypted2, IntPtr destination);

        [DllImport(sealnetnative, PreserveSig = false)]
        internal static extern void Evaluator_AddMany(IntPtr thisptr, ulong count, IntPtr[] encrypteds, IntPtr destination);

        [DllImport(sealnetnative, PreserveSig = false)]
        internal static extern void Evaluator_AddPlain(IntPtr thisptr, IntPtr encrypted, IntPtr plain, IntPtr destination);

        [DllImport(sealnetnative, PreserveSig = false)]
        internal static extern void Evaluator_Sub(IntPtr thisptr, IntPtr encrypted1, IntPtr encrypted2, IntPtr destination);

        [DllImport(sealnetnative, PreserveSig = false)]
        internal static extern void Evaluator_SubPlain(IntPtr thisptr, IntPtr encrypted, IntPtr plain, IntPtr destination);

        [DllImport(sealnetnative, PreserveSig = false)]
        internal static extern void Evaluator_Multiply(IntPtr thisptr, IntPtr encrypted1, IntPtr encrypted2, IntPtr destination, IntPtr pool);

        [DllImport(sealnetnative, PreserveSig = false)]
        internal static extern void Evaluator_MultiplyMany(IntPtr thisptr, ulong count, IntPtr[] encrypteds, IntPtr relinKeys, IntPtr destination, IntPtr pool);

        [DllImport(sealnetnative, PreserveSig = false)]
        internal static extern void Evaluator_MultiplyPlain(IntPtr thisptr, IntPtr encrypted, IntPtr plain, IntPtr destination, IntPtr pool);

        [DllImport(sealnetnative, PreserveSig = false)]
        internal static extern void Evaluator_Square(IntPtr thisptr, IntPtr encrypted, IntPtr destination, IntPtr pool);

        [DllImport(sealnetnative, PreserveSig = false)]
        internal static extern void Evaluator_Relinearize(IntPtr thisptr, IntPtr encrypted, IntPtr relinKeys, IntPtr destination, IntPtr pool);

        [DllImport(sealnetnative, EntryPoint = "Evaluator_ModSwitchToNext1", PreserveSig = false)]
        internal static extern void Evaluator_ModSwitchToNext(IntPtr thisptr, IntPtr encrypted, IntPtr destination, IntPtr pool);

        [DllImport(sealnetnative, EntryPoint = "Evaluator_ModSwitchToNext2", PreserveSig = false)]
        internal static extern void Evaluator_ModSwitchToNext(IntPtr thisptr, IntPtr plain, IntPtr destination);

        [DllImport(sealnetnative, EntryPoint = "Evaluator_ModSwitchTo1", PreserveSig = false)]
        internal static extern void Evaluator_ModSwitchTo(IntPtr thisptr, IntPtr encrypted, ulong[] parmsId, IntPtr destination, IntPtr pool);

        [DllImport(sealnetnative, EntryPoint = "Evaluator_ModSwitchTo2", PreserveSig = false)]
        internal static extern void Evaluator_ModSwitchTo(IntPtr thisptr, IntPtr plain, ulong[] parmsId, IntPtr destination);

        [DllImport(sealnetnative, PreserveSig = false)]
        internal static extern void Evaluator_RescaleToNext(IntPtr thisptr, IntPtr encrypted, IntPtr destination, IntPtr pool);

        [DllImport(sealnetnative, PreserveSig = false)]
        internal static extern void Evaluator_RescaleTo(IntPtr thisptr, IntPtr encrypted, ulong[] parmsId, IntPtr destination, IntPtr pool);

        [DllImport(sealnetnative, PreserveSig = false)]
        internal static extern void Evaluator_Exponentiate(IntPtr thisptr, IntPtr encrypted, ulong exponent, IntPtr relinKeys, IntPtr destination, IntPtr pool);

        [DllImport(sealnetnative, EntryPoint = "Evaluator_TransformToNTT1", PreserveSig = false)]
        internal static extern void Evaluator_TransformToNTT(IntPtr thisptr, IntPtr plain, ulong[] parmsId, IntPtr destinationNTT, IntPtr pool);

        [DllImport(sealnetnative, EntryPoint = "Evaluator_TransformToNTT2", PreserveSig = false)]
        internal static extern void Evaluator_TransformToNTT(IntPtr thisptr, IntPtr encrypted, IntPtr destinationNTT);

        [DllImport(sealnetnative, PreserveSig = false)]
        internal static extern void Evaluator_TransformFromNTT(IntPtr thisptr, IntPtr encryptedNTT, IntPtr destination);

        [DllImport(sealnetnative, PreserveSig = false)]
        internal static extern void Evaluator_ApplyGalois(IntPtr thisptr, IntPtr encrypted, ulong galoisElt, IntPtr galoisKeys, IntPtr destination, IntPtr pool);

        [DllImport(sealnetnative, PreserveSig = false)]
        internal static extern void Evaluator_RotateRows(IntPtr thisptr, IntPtr encrypted, int steps, IntPtr galoisKeys, IntPtr destination, IntPtr pool);

        [DllImport(sealnetnative, PreserveSig = false)]
        internal static extern void Evaluator_RotateColumns(IntPtr thisptr, IntPtr encrypted, IntPtr galoisKeys, IntPtr destination, IntPtr pool);

        [DllImport(sealnetnative, PreserveSig = false)]
        internal static extern void Evaluator_RotateVector(IntPtr thisptr, IntPtr encrypted, int steps, IntPtr galoisKeys, IntPtr destination, IntPtr pool);

        [DllImport(sealnetnative, PreserveSig = false)]
        internal static extern void Evaluator_ComplexConjugate(IntPtr thisptr, IntPtr encrypted, IntPtr galoisKeys, IntPtr destination, IntPtr pool);

        #endregion

        #region Ciphertext methods

        [DllImport(sealnetnative, PreserveSig = false)]
        internal static extern void Ciphertext_Create1(IntPtr pool, out IntPtr cipher);

        [DllImport(sealnetnative, PreserveSig = false)]
        internal static extern void Ciphertext_Create2(IntPtr copy, out IntPtr cipher);

        [DllImport(sealnetnative, PreserveSig = false)]
        internal static extern void Ciphertext_Create3(IntPtr context, IntPtr pool, out IntPtr cipher);

        [DllImport(sealnetnative, PreserveSig = false)]
        internal static extern void Ciphertext_Create4(IntPtr context, ulong[] parmsId, IntPtr pool, out IntPtr cipher);

        [DllImport(sealnetnative, PreserveSig = false)]
        internal static extern void Ciphertext_Create5(IntPtr context, ulong[] parmsId, ulong capacity, IntPtr pool, out IntPtr cipher);

        [DllImport(sealnetnative, EntryPoint = "Ciphertext_Reserve1", PreserveSig = false)]
        internal static extern void Ciphertext_Reserve(IntPtr thisptr, IntPtr context, ulong[] parmsId, ulong sizeCapacity);

        [DllImport(sealnetnative, EntryPoint = "Ciphertext_Reserve2", PreserveSig = false)]
        internal static extern void Ciphertext_Reserve(IntPtr thisptr, IntPtr context, ulong sizeCapacity);

        [DllImport(sealnetnative, EntryPoint = "Ciphertext_Reserve3", PreserveSig = false)]
        internal static extern void Ciphertext_Reserve(IntPtr thisptr, ulong sizeCapacity);

        [DllImport(sealnetnative, PreserveSig = false)]
        internal static extern void Ciphertext_Set(IntPtr thisptr, IntPtr assign);

        [DllImport(sealnetnative, PreserveSig = false)]
        internal static extern void Ciphertext_Destroy(IntPtr thisptr);

        [DllImport(sealnetnative, PreserveSig = false)]
        internal static extern void Ciphertext_UInt64Count(IntPtr thisptr, out ulong uint64Count);

        [DllImport(sealnetnative, PreserveSig = false)]
        internal static extern void Ciphertext_UInt64CountCapacity(IntPtr thisptr, out ulong uint64CountCapacity);

        [DllImport(sealnetnative, PreserveSig = false)]
        internal static extern void Ciphertext_Size(IntPtr thisptr, out ulong size);

        [DllImport(sealnetnative, PreserveSig = false)]
        internal static extern void Ciphertext_SizeCapacity(IntPtr thisptr, out ulong sizeCapacity);

        [DllImport(sealnetnative, PreserveSig = false)]
        internal static extern void Ciphertext_PolyModulusDegree(IntPtr thisptr, out ulong polyModulusDegree);

        [DllImport(sealnetnative, PreserveSig = false)]
        internal static extern void Ciphertext_CoeffModCount(IntPtr thisptr, out ulong coeffModCount);

        [DllImport(sealnetnative, PreserveSig = false)]
        internal static extern void Ciphertext_ParmsId(IntPtr thisptr, ulong[] parmsId);

        [DllImport(sealnetnative, PreserveSig = false)]
        internal static extern void Ciphertext_SetParmsId(IntPtr thisptr, ulong[] parmsId);

        [DllImport(sealnetnative, EntryPoint = "Ciphertext_Resize1", PreserveSig = false)]
        internal static extern void Ciphertext_Resize(IntPtr thisptr, IntPtr context, ulong[] parms_id, ulong size);

        [DllImport(sealnetnative, EntryPoint = "Ciphertext_Resize2", PreserveSig = false)]
        internal static extern void Ciphertext_Resize(IntPtr thisptr, IntPtr context, ulong size);

        [DllImport(sealnetnative, EntryPoint = "Ciphertext_Resize3", PreserveSig = false)]
        internal static extern void Ciphertext_Resize(IntPtr thisptr, ulong size);

        [DllImport(sealnetnative, EntryPoint = "Ciphertext_Resize4", PreserveSig = false)]
        internal static extern void Ciphertext_Resize(IntPtr thisptr, ulong size, ulong polyModulusDegree, ulong coeffModCount);

        [DllImport(sealnetnative, EntryPoint = "Ciphertext_GetDataAt1", PreserveSig = false)]
        internal static extern void Ciphertext_GetDataAt(IntPtr thisptr, ulong index, out ulong data);

        [DllImport(sealnetnative, EntryPoint = "Ciphertext_GetDataAt2", PreserveSig = false)]
        internal static extern void Ciphertext_GetDataAt(IntPtr thisptr, ulong polyIndex, ulong coeffIndex, out ulong data);

        [DllImport(sealnetnative, PreserveSig = false)]
        internal static extern void Ciphertext_SetDataAt(IntPtr thisptr, ulong index, ulong value);

        [DllImport(sealnetnative, PreserveSig = false)]
        internal static extern void Ciphertext_IsNTTForm(IntPtr thisptr, out bool isNTTForm);

        [DllImport(sealnetnative, PreserveSig = false)]
        internal static extern void Ciphertext_SetIsNTTForm(IntPtr thisptr, bool isNTTForm);

        [DllImport(sealnetnative, PreserveSig = false)]
        internal static extern void Ciphertext_Scale(IntPtr thisptr, out double scale);

        [DllImport(sealnetnative, PreserveSig = false)]
        internal static extern void Ciphertext_SetScale(IntPtr thisptr, double scale);

        [DllImport(sealnetnative, PreserveSig = false)]
        internal static extern void Ciphertext_Release(IntPtr thisptr);

        [DllImport(sealnetnative, PreserveSig = false)]
        internal static extern void Ciphertext_IsValidFor(IntPtr thisptr, IntPtr context, out bool result);

        [DllImport(sealnetnative, PreserveSig = false)]
        internal static extern void Ciphertext_IsMetadataValidFor(IntPtr thisptr, IntPtr context, out bool result);

        [DllImport(sealnetnative, PreserveSig = false)]
        internal static extern void Ciphertext_IsTransparent(IntPtr thisptr, out bool result);

        [DllImport(sealnetnative, PreserveSig = false)]
        internal static extern void Ciphertext_Pool(IntPtr thisptr, out IntPtr pool);

        #endregion

        #region Plaintext methods

        [DllImport(sealnetnative, EntryPoint = "Plaintext_Create1", PreserveSig = false)]
        internal static extern void Plaintext_Create(IntPtr memoryPoolHandle, out IntPtr plainText);

        [DllImport(sealnetnative, EntryPoint = "Plaintext_Create2", PreserveSig = false)]
        internal static extern void Plaintext_Create(ulong coeffCount, IntPtr memoryPoolHandle, out IntPtr plainText);

        [DllImport(sealnetnative, EntryPoint = "Plaintext_Create3", PreserveSig = false)]
        internal static extern void Plaintext_Create(ulong capacity, ulong coeffCount, IntPtr memoryPoolHandle, out IntPtr plainText);

        [DllImport(sealnetnative, EntryPoint = "Plaintext_Create4", PreserveSig = false, CharSet = CharSet.Ansi)]
        internal static extern void Plaintext_Create(string hexPoly, IntPtr memoryPoolHandle, out IntPtr plainText);

        [DllImport(sealnetnative, EntryPoint = "Plaintext_Set1", PreserveSig = false)]
        internal static extern void Plaintext_Set(IntPtr thisptr, IntPtr assign);

        [DllImport(sealnetnative, EntryPoint = "Plaintext_Set2", PreserveSig = false, CharSet = CharSet.Ansi)]
        internal static extern void Plaintext_Set(IntPtr thisptr, string hexPoly);

        [DllImport(sealnetnative, EntryPoint = "Plaintext_Set3", PreserveSig = false)]
        internal static extern void Plaintext_Set(IntPtr thisptr, ulong constCoeff);

        [DllImport(sealnetnative, PreserveSig = false)]
        internal static extern void Plaintext_Destroy(IntPtr thisptr);

        [DllImport(sealnetnative, PreserveSig = false)]
        internal static extern void Plaintext_CoeffCount(IntPtr thisptr, out ulong coeffCount);

        [DllImport(sealnetnative, PreserveSig = false)]
        internal static extern void Plaintext_CoeffAt(IntPtr thisptr, ulong index, out ulong coeff);

        [DllImport(sealnetnative, PreserveSig = false)]
        internal static extern void Plaintext_SetCoeffAt(IntPtr thisptr, ulong index, ulong value);

        [DllImport(sealnetnative, PreserveSig = false, CharSet = CharSet.Ansi)]
        internal static extern void Plaintext_ToString(IntPtr thisptr, ref ulong length, StringBuilder outstr);

        [DllImport(sealnetnative, PreserveSig = false)]
        internal static extern void Plaintext_IsNTTForm(IntPtr thisptr, out bool isNTTForm);

        [DllImport(sealnetnative, PreserveSig = false)]
        internal static extern void Plaintext_IsZero(IntPtr thisptr, out bool isZero);

        [DllImport(sealnetnative, EntryPoint = "Plaintext_SetZero1", PreserveSig = false)]
        internal static extern void Plaintext_SetZero(IntPtr thisptr);

        [DllImport(sealnetnative, EntryPoint = "Plaintext_SetZero2", PreserveSig = false)]
        internal static extern void Plaintext_SetZero(IntPtr thisptr, ulong startCoeff);

        [DllImport(sealnetnative, EntryPoint = "Plaintext_SetZero3", PreserveSig = false)]
        internal static extern void Plaintext_SetZero(IntPtr thisptr, ulong startCoeff, ulong length);

        [DllImport(sealnetnative, PreserveSig = false)]
        internal static extern void Plaintext_GetParmsId(IntPtr thisptr, ulong[] parmsId);

        [DllImport(sealnetnative, PreserveSig = false)]
        internal static extern void Plaintext_SetParmsId(IntPtr thisptr, ulong[] parmsId);

        [DllImport(sealnetnative, PreserveSig = false)]
        internal static extern void Plaintext_Reserve(IntPtr thisptr, ulong capacity);

        [DllImport(sealnetnative, PreserveSig = false)]
        internal static extern void Plaintext_Resize(IntPtr thisptr, ulong coeffCount);

        [DllImport(sealnetnative, PreserveSig = false)]
        internal static extern void Plaintext_ShrinkToFit(IntPtr thisptr);

        [DllImport(sealnetnative, PreserveSig = false)]
        internal static extern void Plaintext_Release(IntPtr thisptr);

        [DllImport(sealnetnative, PreserveSig = false)]
        internal static extern void Plaintext_Capacity(IntPtr thisptr, out ulong capacity);

        [DllImport(sealnetnative, PreserveSig = false)]
        internal static extern void Plaintext_SignificantCoeffCount(IntPtr thisptr, out ulong significantCoeffCount);

        [DllImport(sealnetnative, PreserveSig = false)]
        internal static extern void Plaintext_Scale(IntPtr thisptr, out double scale);

        [DllImport(sealnetnative, PreserveSig = false)]
        internal static extern void Plaintext_SetScale(IntPtr thisptr, double scale);

        [DllImport(sealnetnative, PreserveSig = false)]
        internal static extern void Plaintext_Equals(IntPtr thisptr, IntPtr otherptr, out bool result);

        [DllImport(sealnetnative, PreserveSig = false)]
        internal static extern void Plaintext_IsValidFor(IntPtr thisptr, IntPtr context, out bool result);

        [DllImport(sealnetnative, PreserveSig = false)]
        internal static extern void Plaintext_IsMetadataValidFor(IntPtr thisptr, IntPtr context, out bool result);

        [DllImport(sealnetnative, PreserveSig = false)]
        internal static extern void Plaintext_SwapData(IntPtr thisptr, ulong count, ulong[] newData);

        [DllImport(sealnetnative, PreserveSig = false)]
        internal static extern void Plaintext_Pool(IntPtr thisptr, out IntPtr pool);

        #endregion

        #region GaloisKeys methods

        [DllImport(sealnetnative, EntryPoint = "GaloisKeys_Create1", PreserveSig = false)]
        internal static extern void GaloisKeys_Create(out IntPtr galoisKeys);

        [DllImport(sealnetnative, EntryPoint = "GaloisKeys_Create2", PreserveSig = false)]
        internal static extern void GaloisKeys_Create(IntPtr copy, out IntPtr galoisKeys);

        [DllImport(sealnetnative, PreserveSig = false)]
        internal static extern void GaloisKeys_Destroy(IntPtr thisptr);

        [DllImport(sealnetnative, PreserveSig = false)]
        internal static extern void GaloisKeys_Set(IntPtr thisptr, IntPtr assignptr);

        [DllImport(sealnetnative, PreserveSig = false)]
        internal static extern void GaloisKeys_Size(IntPtr thisptr, out ulong size);

        [DllImport(sealnetnative, PreserveSig = false)]
        internal static extern void GaloisKeys_DBC(IntPtr thisptr, out int dbc);

        [DllImport(sealnetnative, PreserveSig = false)]
        internal static extern void GaloisKeys_SetDBC(IntPtr thisptr, int value);

        [DllImport(sealnetnative, PreserveSig = false)]
        internal static extern void GaloisKeys_ClearDataAndReserve(IntPtr thisptr, ulong size);

        [DllImport(sealnetnative, PreserveSig = false)]
        internal static extern void GaloisKeys_GetKeyCount(IntPtr thisptr, out ulong keyCount);

        [DllImport(sealnetnative, PreserveSig = false)]
        internal static extern void GaloisKeys_GetKeyList(IntPtr thisptr, ulong index, ref ulong count, IntPtr[] ciphers);

        [DllImport(sealnetnative, PreserveSig = false)]
        internal static extern void GaloisKeys_GetKey(IntPtr thisptr, ulong galoisElt, ref ulong count, IntPtr[] ciphers);

        [DllImport(sealnetnative, PreserveSig = false)]
        internal static extern void GaloisKeys_AddKeyList(IntPtr thisptr, ulong count, IntPtr[] ciphers);

        [DllImport(sealnetnative, PreserveSig = false)]
        internal static extern void GaloisKeys_GetParmsId(IntPtr thisptr, ulong[] parmsId);

        [DllImport(sealnetnative, PreserveSig = false)]
        internal static extern void GaloisKeys_SetParmsId(IntPtr thisptr, ulong[] parmsId);

        [DllImport(sealnetnative, PreserveSig = false)]
        internal static extern void GaloisKeys_HasKey(IntPtr thisptr, ulong galoisElt, out bool hasKey);

        [DllImport(sealnetnative, PreserveSig = false)]
        internal static extern void GaloisKeys_IsValidFor(IntPtr thisptr, IntPtr context, out bool result);

        [DllImport(sealnetnative, PreserveSig = false)]
        internal static extern void GaloisKeys_IsMetadataValidFor(IntPtr thisptr, IntPtr context, out bool result);

        [DllImport(sealnetnative, PreserveSig = false)]
        internal static extern void GaloisKeys_Pool(IntPtr thisptr, out IntPtr pool);

        #endregion

        #region KeyGenerator methods

        [DllImport(sealnetnative, EntryPoint = "KeyGenerator_Create1", PreserveSig = false)]
        internal static extern void KeyGenerator_Create(IntPtr sealContext, out IntPtr keyGenerator);

        [DllImport(sealnetnative, EntryPoint = "KeyGenerator_Create2", PreserveSig = false)]
        internal static extern void KeyGenerator_Create(IntPtr sealContext, IntPtr secretKey, out IntPtr keyGenerator);

        [DllImport(sealnetnative, EntryPoint = "KeyGenerator_Create3", PreserveSig = false)]
        internal static extern void KeyGenerator_Create(IntPtr sealContext, IntPtr secretKey, IntPtr publicKey, out IntPtr keyGenerator);

        [DllImport(sealnetnative, PreserveSig = false)]
        internal static extern void KeyGenerator_Destroy(IntPtr thisptr);

        [DllImport(sealnetnative, PreserveSig = false)]
        internal static extern void KeyGenerator_RelinKeys(IntPtr thisptr, int decompositionBitCount, ulong count, out IntPtr relinKeys);

        [DllImport(sealnetnative, EntryPoint = "KeyGenerator_GaloisKeys1", PreserveSig = false)]
        internal static extern void KeyGenerator_GaloisKeys(IntPtr thisptr, int decompositionBitCount, out IntPtr galoisKeys);

        [DllImport(sealnetnative, EntryPoint = "KeyGenerator_GaloisKeys2", PreserveSig = false)]
        internal static extern void KeyGenerator_GaloisKeys(IntPtr thisptr, int decompositionBitCount, ulong count, ulong[] galoisElts, out IntPtr galoisKeys);

        [DllImport(sealnetnative, EntryPoint = "KeyGenerator_GaloisKeys3", PreserveSig = false)]
        internal static extern void KeyGenerator_GaloisKeys(IntPtr thisptr, int decompositionBitCount, ulong count, int[] steps, out IntPtr galoisKeys);

        [DllImport(sealnetnative, PreserveSig = false)]
        internal static extern void KeyGenerator_PublicKey(IntPtr thisptr, out IntPtr publicKey);

        [DllImport(sealnetnative, PreserveSig = false)]
        internal static extern void KeyGenerator_SecretKey(IntPtr thisptr, out IntPtr secretKey);

        #endregion

        #region RelinKeys methods

        [DllImport(sealnetnative, EntryPoint = "RelinKeys_Create1", PreserveSig = false)]
        internal static extern void RelinKeys_Create(out IntPtr relinKeys);

        [DllImport(sealnetnative, EntryPoint = "RelinKeys_Create2", PreserveSig = false)]
        internal static extern void RelinKeys_Create(IntPtr copy, out IntPtr relinKeys);

        [DllImport(sealnetnative, PreserveSig = false)]
        internal static extern void RelinKeys_Set(IntPtr thisptr, IntPtr copy);

        [DllImport(sealnetnative, PreserveSig = false)]
        internal static extern void RelinKeys_Destroy(IntPtr thisptr);

        [DllImport(sealnetnative, PreserveSig = false)]
        internal static extern void RelinKeys_Size(IntPtr thisptr, out ulong size);

        [DllImport(sealnetnative, PreserveSig = false)]
        internal static extern void RelinKeys_DBC(IntPtr thisptr, out int dbc);

        [DllImport(sealnetnative, PreserveSig = false)]
        internal static extern void RelinKeys_SetDBC(IntPtr thisptr, int value);

        [DllImport(sealnetnative, PreserveSig = false)]
        internal static extern void RelinKeys_ClearDataAndReserve(IntPtr thisptr, ulong size);

        [DllImport(sealnetnative, PreserveSig = false)]
        internal static extern void RelinKeys_GetKeyList(IntPtr thisptr, ulong index, ref ulong count, IntPtr[] ciphers);

        [DllImport(sealnetnative, PreserveSig = false)]
        internal static extern void RelinKeys_GetKey(IntPtr thisptr, ulong keyPower, ref ulong count, IntPtr[] ciphers);

        [DllImport(sealnetnative, PreserveSig = false)]
        internal static extern void RelinKeys_HasKey(IntPtr thisptr, ulong keyPower, out bool hasKey);

        [DllImport(sealnetnative, PreserveSig = false)]
        internal static extern void RelinKeys_AddKeyList(IntPtr thisptr, ulong count, IntPtr[] ciphers);

        [DllImport(sealnetnative, PreserveSig = false)]
        internal static extern void RelinKeys_GetParmsId(IntPtr thisptr, ulong[] parmsId);

        [DllImport(sealnetnative, PreserveSig = false)]
        internal static extern void RelinKeys_SetParmsId(IntPtr thisptr, ulong[] parmsId);

        [DllImport(sealnetnative, PreserveSig = false)]
        internal static extern void RelinKeys_IsValidFor(IntPtr thisptr, IntPtr context, out bool result);

        [DllImport(sealnetnative, PreserveSig = false)]
        internal static extern void RelinKeys_IsMetadataValidFor(IntPtr thisptr, IntPtr context, out bool result);

        [DllImport(sealnetnative, PreserveSig = false)]
        internal static extern void RelinKeys_Pool(IntPtr thisptr, out IntPtr pool);

        #endregion

        #region PublicKey methods

        [DllImport(sealnetnative, EntryPoint = "PublicKey_Create1", PreserveSig = false)]
        internal static extern void PublicKey_Create(out IntPtr publicKey);

        [DllImport(sealnetnative, EntryPoint = "PublicKey_Create2", PreserveSig = false)]
        internal static extern void PublicKey_Create(IntPtr copy, out IntPtr publicKey);

        [DllImport(sealnetnative, PreserveSig = false)]
        internal static extern void PublicKey_Set(IntPtr thisptr, IntPtr assign);

        [DllImport(sealnetnative, PreserveSig = false)]
        internal static extern void PublicKey_Data(IntPtr thisptr, out IntPtr data);

        [DllImport(sealnetnative, PreserveSig = false)]
        internal static extern void PublicKey_ParmsId(IntPtr thisptr, ulong[] parmsId);

        [DllImport(sealnetnative, PreserveSig = false)]
        internal static extern void PublicKey_IsValidFor(IntPtr thisptr, IntPtr context, out bool result);

        [DllImport(sealnetnative, PreserveSig = false)]
        internal static extern void PublicKey_IsMetadataValidFor(IntPtr thisptr, IntPtr context, out bool result);

        [DllImport(sealnetnative, PreserveSig = false)]
        internal static extern void PublicKey_Pool(IntPtr thisptr, out IntPtr pool);

        [DllImport(sealnetnative, PreserveSig = false)]
        internal static extern void PublicKey_Destroy(IntPtr thisptr);

        #endregion

        #region SecretKey methods

        [DllImport(sealnetnative, EntryPoint = "SecretKey_Create1", PreserveSig = false)]
        internal static extern void SecretKey_Create(out IntPtr secretKey);

        [DllImport(sealnetnative, EntryPoint = "SecretKey_Create2", PreserveSig = false)]
        internal static extern void SecretKey_Create(IntPtr copy, out IntPtr secretKey);

        [DllImport(sealnetnative, PreserveSig = false)]
        internal static extern void SecretKey_Set(IntPtr thisptr, IntPtr assign);

        [DllImport(sealnetnative, PreserveSig = false)]
        internal static extern void SecretKey_Data(IntPtr thisptr, out IntPtr data);

        [DllImport(sealnetnative, PreserveSig = false)]
        internal static extern void SecretKey_Destroy(IntPtr thisptr);

        [DllImport(sealnetnative, PreserveSig = false)]
        internal static extern void SecretKey_IsValidFor(IntPtr thisptr, IntPtr context, out bool result);

        [DllImport(sealnetnative, PreserveSig = false)]
        internal static extern void SecretKey_IsMetadataValidFor(IntPtr thisptr, IntPtr context, out bool result);

        [DllImport(sealnetnative, PreserveSig = false)]
        internal static extern void SecretKey_ParmsId(IntPtr thisptr, ulong[] parmsId);

        [DllImport(sealnetnative, PreserveSig = false)]
        internal static extern void SecretKey_Pool(IntPtr thisptr, out IntPtr pool);

        #endregion

        #region MemoryManager methods

        [DllImport(sealnetnative, EntryPoint = "MemoryManager_GetPool1", PreserveSig = false)]
        internal static extern void MemoryManager_GetPool(int profOpt, bool clearOnDestruction, out IntPtr handle);

        [DllImport(sealnetnative, EntryPoint = "MemoryManager_GetPool2", PreserveSig = false)]
        internal static extern void MemoryManager_GetPool(out IntPtr handle);

        [DllImport(sealnetnative, PreserveSig = false)]
        internal static extern void MemoryManager_SwitchProfile(IntPtr newProfile);

        #endregion

        #region MMProf methods

        [DllImport(sealnetnative, PreserveSig = false)]
        internal static extern void MMProf_CreateGlobal(out IntPtr profile);

        [DllImport(sealnetnative, PreserveSig = false)]
        internal static extern void MMProf_CreateFixed(IntPtr pool, out IntPtr profile);

        [DllImport(sealnetnative, PreserveSig = false)]
        internal static extern void MMProf_CreateNew(out IntPtr profile);

        [DllImport(sealnetnative, PreserveSig = false)]
        internal static extern void MMProf_CreateThreadLocal(out IntPtr profile);

        [DllImport(sealnetnative, PreserveSig = false)]
        internal static extern void MMProf_GetPool(IntPtr thisptr, out IntPtr pool);

        [DllImport(sealnetnative, PreserveSig = false)]
        internal static extern void MMProf_Destroy(IntPtr thisptr);

        #endregion

        #region MemoryPoolHandle methods

        [DllImport(sealnetnative, EntryPoint = "MemoryPoolHandle_Create1", PreserveSig = false)]
        internal static extern void MemoryPoolHandle_Create(out IntPtr handlePtr);

        [DllImport(sealnetnative, EntryPoint = "MemoryPoolHandle_Create2", PreserveSig = false)]
        internal static extern void MemoryPoolHandle_Create(IntPtr other, out IntPtr handlePtr);

        [DllImport(sealnetnative, PreserveSig = false)]
        internal static extern void MemoryPoolHandle_Destroy(IntPtr thisptr);

        [DllImport(sealnetnative, PreserveSig = false)]
        internal static extern void MemoryPoolHandle_Set(IntPtr thisptr, IntPtr assignptr);

        [DllImport(sealnetnative, PreserveSig = false)]
        internal static extern void MemoryPoolHandle_Global(out IntPtr handlePtr);

        [DllImport(sealnetnative, PreserveSig = false)]
        internal static extern void MemoryPoolHandle_ThreadLocal(out IntPtr handlePtr);

        [DllImport(sealnetnative, PreserveSig = false)]
        internal static extern void MemoryPoolHandle_New(bool clearOnDestruction, out IntPtr handlePtr);

        [DllImport(sealnetnative, PreserveSig = false)]
        internal static extern void MemoryPoolHandle_PoolCount(IntPtr thisptr, out ulong count);

        [DllImport(sealnetnative, PreserveSig = false)]
        internal static extern void MemoryPoolHandle_AllocByteCount(IntPtr thisptr, out ulong count);

        [DllImport(sealnetnative, PreserveSig = false)]
        internal static extern void MemoryPoolHandle_IsInitialized(IntPtr thisptr, out bool initialized);

        [DllImport(sealnetnative, PreserveSig = false)]
        internal static extern void MemoryPoolHandle_Equals(IntPtr thisptr, IntPtr otherptr, out bool result);

        #endregion

        #region Encryptor methods

        [DllImport(sealnetnative, PreserveSig = false)]
        internal static extern void Encryptor_Create(IntPtr context, IntPtr publicKey, out IntPtr encryptor);

        [DllImport(sealnetnative, PreserveSig = false)]
        internal static extern void Encryptor_Encrypt(IntPtr thisptr, IntPtr plaintext, IntPtr destination, IntPtr poolHandle);

        [DllImport(sealnetnative, PreserveSig = false)]
        internal static extern void Encryptor_Destroy(IntPtr thisptr);

        #endregion

        #region Decryptor methods

        [DllImport(sealnetnative, PreserveSig = false)]
        internal static extern void Decryptor_Create(IntPtr context, IntPtr secretKey, out IntPtr decryptor);

        [DllImport(sealnetnative, PreserveSig = false)]
        internal static extern void Decryptor_Destroy(IntPtr thisptr);

        [DllImport(sealnetnative, PreserveSig = false)]
        internal static extern void Decryptor_Decrypt(IntPtr thisptr, IntPtr encrypted, IntPtr destination);

        [DllImport(sealnetnative, PreserveSig = false)]
        internal static extern void Decryptor_InvariantNoiseBudget(IntPtr thisptr, IntPtr encrypted, out int invariantNoiseBudget);

        #endregion

        #region CKKSEncoder methods

        [DllImport(sealnetnative, PreserveSig = false)]
        internal static extern void CKKSEncoder_Create(IntPtr context, out IntPtr ckksEncoder);

        [DllImport(sealnetnative, PreserveSig = false)]
        internal static extern void CKKSEncoder_Destroy(IntPtr thisptr);

        [DllImport(sealnetnative, EntryPoint = "CKKSEncoder_Encode1", PreserveSig = false)]
        internal static extern void CKKSEncoder_EncodeDouble(IntPtr thisptr, ulong valueCount, double[] values, ulong[] parms_id, double scale, IntPtr destination, IntPtr pool);

        [DllImport(sealnetnative, EntryPoint = "CKKSEncoder_Encode2", PreserveSig = false)]
        internal static extern void CKKSEncoder_EncodeComplex(IntPtr thisptr, ulong valueCount, double[] values, ulong[] parms_id, double scale, IntPtr destination, IntPtr pool);

        [DllImport(sealnetnative, EntryPoint = "CKKSEncoder_Encode3", PreserveSig = false)]
        internal static extern void CKKSEncoder_Encode(IntPtr thisptr, double value, ulong[] parms_id, double scale, IntPtr destination, IntPtr pool);

        [DllImport(sealnetnative, EntryPoint = "CKKSEncoder_Encode4", PreserveSig = false)]
        internal static extern void CKKSEncoder_Encode(IntPtr thisptr, double valueRe, double valueIm, ulong[] parms_id, double scale, IntPtr destination, IntPtr pool);

        [DllImport(sealnetnative, EntryPoint = "CKKSEncoder_Encode5", PreserveSig = false)]
        internal static extern void CKKSEncoder_Encode(IntPtr thisptr, long value, ulong[] parms_id, IntPtr destination);

        [DllImport(sealnetnative, EntryPoint = "CKKSEncoder_Decode1", PreserveSig = false)]
        internal static extern void CKKSEncoder_DecodeDouble(IntPtr thisptr, IntPtr plain, ref ulong valueCount, double[] values, IntPtr pool);

        [DllImport(sealnetnative, EntryPoint = "CKKSEncoder_Decode2", PreserveSig = false)]
        internal static extern void CKKSEncoder_DecodeComplex(IntPtr thisptr, IntPtr plain, ref ulong valueCount, double[] values, IntPtr pool);

        [DllImport(sealnetnative, PreserveSig = false)]
        internal static extern void CKKSEncoder_SlotCount(IntPtr thisptr, out ulong slotCount);

        #endregion

        #region BatchEncoder methods

        [DllImport(sealnetnative, PreserveSig = false)]
        internal static extern void BatchEncoder_Create(IntPtr context, out IntPtr batchEncoder);

        [DllImport(sealnetnative, PreserveSig = false)]
        internal static extern void BatchEncoder_Destroy(IntPtr thisptr);

        [DllImport(sealnetnative, EntryPoint = "BatchEncoder_Encode1", PreserveSig = false)]
        internal static extern void BatchEncoder_Encode(IntPtr thisptr, ulong count, ulong[] values, IntPtr destination);

        [DllImport(sealnetnative, EntryPoint = "BatchEncoder_Encode2", PreserveSig = false)]
        internal static extern void BatchEncoder_Encode(IntPtr thisptr, ulong count, long[] values, IntPtr destination);

        [DllImport(sealnetnative, EntryPoint = "BatchEncoder_Encode3", PreserveSig = false)]
        internal static extern void BatchEncoder_Encode(IntPtr thisptr, IntPtr plain, IntPtr pool);

        [DllImport(sealnetnative, EntryPoint = "BatchEncoder_Decode1", PreserveSig = false)]
        internal static extern void BatchEncoder_Decode(IntPtr thisptr, IntPtr plain, ref ulong count, ulong[] destination, IntPtr pool);

        [DllImport(sealnetnative, EntryPoint = "BatchEncoder_Decode2", PreserveSig = false)]
        internal static extern void BatchEncoder_Decode(IntPtr thisptr, IntPtr plain, ref ulong count, long[] destination, IntPtr pool);

        [DllImport(sealnetnative, EntryPoint = "BatchEncoder_Decode3", PreserveSig = false)]
        internal static extern void BatchEncoder_Decode(IntPtr thisptr, IntPtr plain, IntPtr pool);

        [DllImport(sealnetnative, PreserveSig = false)]
        internal static extern void BatchEncoder_GetSlotCount(IntPtr thisptr, out ulong slotCount);

        #endregion

        #region IntegerEncoder methods

        [DllImport(sealnetnative, PreserveSig = false)]
        internal static extern void IntegerEncoder_Create1(IntPtr context, out IntPtr encoder);

        [DllImport(sealnetnative, PreserveSig = false)]
        internal static extern void IntegerEncoder_Create2(IntPtr copy, out IntPtr encoder);

        [DllImport(sealnetnative, PreserveSig = false)]
        internal static extern void IntegerEncoder_Destroy(IntPtr thisptr);

        [DllImport(sealnetnative, EntryPoint = "IntegerEncoder_Encode1", PreserveSig = false)]
        internal static extern void IntegerEncoder_Encode(IntPtr thisptr, int value, IntPtr plain);

        [DllImport(sealnetnative, EntryPoint = "IntegerEncoder_Encode2", PreserveSig = false)]
        internal static extern void IntegerEncoder_Encode(IntPtr thisptr, uint value, IntPtr plain);

        [DllImport(sealnetnative, EntryPoint = "IntegerEncoder_Encode3", PreserveSig = false)]
        internal static extern void IntegerEncoder_Encode(IntPtr thisptr, ulong value, IntPtr plain);

        [DllImport(sealnetnative, EntryPoint = "IntegerEncoder_Encode4", PreserveSig = false)]
        internal static extern void IntegerEncoder_Encode(IntPtr thisptr, long value, IntPtr plain);

        [DllImport(sealnetnative, EntryPoint = "IntegerEncoder_Encode5", PreserveSig = false)]
        internal static extern void IntegerEncoder_Encode(IntPtr thisptr, IntPtr bigUInt, IntPtr plain);

        [DllImport(sealnetnative, PreserveSig = false)]
        internal static extern void IntegerEncoder_DecodeUInt32(IntPtr thisptr, IntPtr plain, out uint result);

        [DllImport(sealnetnative, PreserveSig = false)]
        internal static extern void IntegerEncoder_DecodeUInt64(IntPtr thisptr, IntPtr plain, out ulong result);

        [DllImport(sealnetnative, PreserveSig = false)]
        internal static extern void IntegerEncoder_DecodeInt32(IntPtr thisptr, IntPtr plain, out int result);

        [DllImport(sealnetnative, PreserveSig = false)]
        internal static extern void IntegerEncoder_DecodeInt64(IntPtr thisptr, IntPtr plain, out long result);

        [DllImport(sealnetnative, PreserveSig = false)]
        internal static extern void IntegerEncoder_DecodeBigUInt(IntPtr thisptr, IntPtr plain, out IntPtr bigUInt);

        [DllImport(sealnetnative, PreserveSig = false)]
        internal static extern void IntegerEncoder_PlainModulus(IntPtr thisptr, out IntPtr smallModulus);

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
