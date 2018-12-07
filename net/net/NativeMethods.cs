using System;
using System.Runtime.InteropServices;
using System.Text;

namespace Microsoft.Research.SEAL
{
    static class NativeMethods
    {
        private const string SEALdll = "SEALdll.dll";

        #region BigUInt methods

        [DllImport(SEALdll, EntryPoint = "BigUInt_Create1", PreserveSig = false)]
        internal static extern void BigUInt_Create(out IntPtr bigUInt);

        [DllImport(SEALdll, EntryPoint = "BigUInt_Create2", PreserveSig = false)]
        internal static extern void BigUInt_Create(int bitCount, out IntPtr bigUInt);

        [DllImport(SEALdll, EntryPoint = "BigUInt_Create3", PreserveSig = false, CharSet = CharSet.Ansi)]
        internal static extern void BigUInt_Create(int bitCount, string hexString, out IntPtr bigUInt);

        [DllImport(SEALdll, EntryPoint = "BigUInt_Create4", PreserveSig = false)]
        internal static extern void BigUInt_Create(int bitCount, ulong value, out IntPtr bigUInt);

        [DllImport(SEALdll, EntryPoint = "BigUInt_Create5", PreserveSig = false, CharSet = CharSet.Ansi)]
        internal static extern void BigUInt_Create(string hexString, out IntPtr bigUInt);

        [DllImport(SEALdll, EntryPoint = "BigUInt_Create6", PreserveSig = false)]
        internal static extern void BigUInt_Create(IntPtr copy, out IntPtr bigUInt);

        [DllImport(SEALdll, PreserveSig = false)]
        internal static extern void BigUInt_Destroy(IntPtr thisptr);

        [DllImport(SEALdll, PreserveSig = false)]
        internal static extern void BigUInt_IsAlias(IntPtr thisptr, out bool isAlias);

        [DllImport(SEALdll, PreserveSig = false)]
        internal static extern void BigUInt_BitCount(IntPtr thisptr, out int bitCount);

        [DllImport(SEALdll, PreserveSig = false)]
        internal static extern void BigUInt_ByteCount(IntPtr thisptr, out ulong byteCount);

        [DllImport(SEALdll, PreserveSig = false)]
        internal static extern void BigUInt_UInt64Count(IntPtr thisptr, out ulong uint64Count);

        [DllImport(SEALdll, PreserveSig = false)]
        internal static extern void BigUInt_IsZero(IntPtr thisptr, out bool isZero);

        [DllImport(SEALdll, PreserveSig = false)]
        internal static extern void BigUInt_Get(IntPtr thisptr, int index, out byte value);

        [DllImport(SEALdll, PreserveSig = false)]
        internal static extern void BigUInt_GetU64(IntPtr thisptr, int index, out ulong value);

        [DllImport(SEALdll, PreserveSig = false)]
        internal static extern void BigUInt_GetSignificantBitCount(IntPtr thisptr, out int significantBitCount);

        [DllImport(SEALdll, EntryPoint = "BigUInt_Set1", PreserveSig = false)]
        internal static extern void BigUInt_Set(IntPtr thisptr, int index, byte value);

        [DllImport(SEALdll, EntryPoint = "BigUInt_Set2", PreserveSig = false)]
        internal static extern void BigUInt_Set(IntPtr thisptr, IntPtr assign);

        [DllImport(SEALdll, EntryPoint = "BigUInt_Set3", PreserveSig = false)]
        internal static extern void BigUInt_Set(IntPtr thisptr, ulong value);

        [DllImport(SEALdll, EntryPoint = "BigUInt_Set4", PreserveSig = false, CharSet = CharSet.Ansi)]
        internal static extern void BigUInt_Set(IntPtr thisptr, string assign);

        [DllImport(SEALdll, PreserveSig = false)]
        internal static extern void BigUInt_SetZero(IntPtr thisptr);

        [DllImport(SEALdll, PreserveSig = false)]
        internal static extern void BigUInt_Resize(IntPtr thisptr, int bitCount);

        [DllImport(SEALdll, PreserveSig = false)]
        internal static extern void BigUInt_Equals(IntPtr thisptr, IntPtr compare, out bool result);

        [DllImport(SEALdll, EntryPoint = "BigUInt_CompareTo1", PreserveSig = false)]
        internal static extern void BigUInt_CompareTo(IntPtr thisptr, IntPtr compare, out int result);

        [DllImport(SEALdll, EntryPoint = "BigUInt_CompareTo2", PreserveSig = false)]
        internal static extern void BigUInt_CompareTo(IntPtr thisptr, ulong compare, out int result);

        [DllImport(SEALdll, EntryPoint = "BigUInt_DivideRemainder1", PreserveSig = false)]
        internal static extern void BigUInt_DivideRemainder(IntPtr thisptr, IntPtr operand2, IntPtr remainder, out IntPtr result);

        [DllImport(SEALdll, EntryPoint = "BigUInt_DivideRemainder2", PreserveSig = false)]
        internal static extern void BigUInt_DivideRemainder(IntPtr thisptr, ulong operand2, IntPtr remainder, out IntPtr result);

        [DllImport(SEALdll, PreserveSig = false, CharSet = CharSet.Ansi)]
        internal static extern void BigUInt_ToString(
            IntPtr thisptr,
            StringBuilder outstr,
            ref int length);

        [DllImport(SEALdll, PreserveSig = false, CharSet = CharSet.Ansi)]
        internal static extern void BigUInt_ToDecimalString(
            IntPtr thisptr,
            StringBuilder outstr,
            ref int length);

        [DllImport(SEALdll, PreserveSig = false, CharSet = CharSet.Ansi)]
        internal static extern void BigUInt_DuplicateTo(IntPtr thisptr, IntPtr destination);

        [DllImport(SEALdll, PreserveSig = false, CharSet = CharSet.Ansi)]
        internal static extern void BigUInt_DuplicateFrom(IntPtr thisptr, IntPtr value);

        [DllImport(SEALdll, EntryPoint = "BigUInt_ModuloInvert1", PreserveSig = false)]
        internal static extern void BigUInt_ModuloInvert(IntPtr thisptr, IntPtr modulus, out IntPtr result);

        [DllImport(SEALdll, EntryPoint = "BigUInt_ModuloInvert2", PreserveSig = false)]
        internal static extern void BigUInt_ModuloInvert(IntPtr thisptr, ulong modulus, out IntPtr result);

        [DllImport(SEALdll, EntryPoint = "BigUInt_TryModuloInvert1", PreserveSig = false)]
        internal static extern void BigUInt_TryModuloInvert(IntPtr thisptr, IntPtr modulus, IntPtr inverse, out bool result);

        [DllImport(SEALdll, EntryPoint = "BigUInt_TryModuloInvert2", PreserveSig = false)]
        internal static extern void BigUInt_TryModuloInvert(IntPtr thisptr, ulong modulus, IntPtr inverse, out bool result);

        [DllImport(SEALdll, PreserveSig = false)]
        internal static extern void BigUInt_OperatorNeg(IntPtr thisptr, out IntPtr result);

        [DllImport(SEALdll, PreserveSig = false)]
        internal static extern void BigUInt_OperatorTilde(IntPtr thisptr, out IntPtr result);

        [DllImport(SEALdll, EntryPoint = "BigUInt_OperatorPlus1", PreserveSig = false)]
        internal static extern void BigUInt_OperatorPlus(IntPtr thisptr, IntPtr operand, out IntPtr result);

        [DllImport(SEALdll, EntryPoint = "BigUInt_OperatorPlus2", PreserveSig = false)]
        internal static extern void BigUInt_OperatorPlus(IntPtr thisptr, ulong operand, out IntPtr result);

        [DllImport(SEALdll, EntryPoint = "BigUInt_OperatorMinus1", PreserveSig = false)]
        internal static extern void BigUInt_OperatorMinus(IntPtr thisptr, IntPtr operand, out IntPtr result);

        [DllImport(SEALdll, EntryPoint = "BigUInt_OperatorMinus2", PreserveSig = false)]
        internal static extern void BigUInt_OperatorMinus(IntPtr thisptr, ulong operand, out IntPtr result);

        [DllImport(SEALdll, EntryPoint = "BigUInt_OperatorMult1", PreserveSig = false)]
        internal static extern void BigUInt_OperatorMult(IntPtr thisptr, IntPtr operand, out IntPtr result);

        [DllImport(SEALdll, EntryPoint = "BigUInt_OperatorMult2", PreserveSig = false)]
        internal static extern void BigUInt_OperatorMult(IntPtr thisptr, ulong operand, out IntPtr result);

        [DllImport(SEALdll, EntryPoint = "BigUInt_OperatorDiv1", PreserveSig = false)]
        internal static extern void BigUInt_OperatorDiv(IntPtr thisptr, IntPtr operand, out IntPtr result);

        [DllImport(SEALdll, EntryPoint = "BigUInt_OperatorDiv2", PreserveSig = false)]
        internal static extern void BigUInt_OperatorDiv(IntPtr thisptr, ulong operand, out IntPtr result);

        [DllImport(SEALdll, EntryPoint = "BigUInt_OperatorXor1", PreserveSig = false)]
        internal static extern void BigUInt_OperatorXor(IntPtr thisptr, IntPtr operand, out IntPtr result);

        [DllImport(SEALdll, EntryPoint = "BigUInt_OperatorXor2", PreserveSig = false)]
        internal static extern void BigUInt_OperatorXor(IntPtr thisptr, ulong operand, out IntPtr result);

        [DllImport(SEALdll, EntryPoint = "BigUInt_OperatorAnd1", PreserveSig = false)]
        internal static extern void BigUInt_OperatorAnd(IntPtr thisptr, IntPtr operand, out IntPtr result);

        [DllImport(SEALdll, EntryPoint = "BigUInt_OperatorAnd2", PreserveSig = false)]
        internal static extern void BigUInt_OperatorAnd(IntPtr thisptr, ulong operand, out IntPtr result);

        [DllImport(SEALdll, EntryPoint = "BigUInt_OperatorOr1", PreserveSig = false)]
        internal static extern void BigUInt_OperatorOr(IntPtr thisptr, IntPtr operand, out IntPtr result);

        [DllImport(SEALdll, EntryPoint = "BigUInt_OperatorOr2", PreserveSig = false)]
        internal static extern void BigUInt_OperatorOr(IntPtr thisptr, ulong operand, out IntPtr result);

        [DllImport(SEALdll, PreserveSig = false)]
        internal static extern void BigUInt_OperatorShiftLeft(IntPtr thisptr, int shift, out IntPtr result);

        [DllImport(SEALdll, PreserveSig = false)]
        internal static extern void BigUInt_OperatorShiftRight(IntPtr thisptr, int shift, out IntPtr result);

        [DllImport(SEALdll, PreserveSig = false)]
        internal static extern void BigUInt_ToDouble(IntPtr thisptr, out double result);

        #endregion

        #region EncryptionParameterQualifiers methods

        [DllImport(SEALdll, PreserveSig = false)]
        internal static extern void EPQ_Create(IntPtr copy, out IntPtr epq);

        [DllImport(SEALdll, PreserveSig = false)]
        internal static extern void EPQ_Destroy(IntPtr thisptr);

        [DllImport(SEALdll, PreserveSig = false)]
        internal static extern void EPQ_ParametersSet(IntPtr thisptr, out bool parametersSet);

        [DllImport(SEALdll, PreserveSig = false)]
        internal static extern void EPQ_EnableFFT(IntPtr thisptr, out bool enableFFT);

        [DllImport(SEALdll, PreserveSig = false)]
        internal static extern void EPQ_EnableNTT(IntPtr thisptr, out bool enableNTT);

        [DllImport(SEALdll, PreserveSig = false)]
        internal static extern void EPQ_EnableBatching(IntPtr thisptr, out bool enableBatching);

        [DllImport(SEALdll, PreserveSig = false)]
        internal static extern void EPQ_EnableFastPlainLift(IntPtr thisptr, out bool enableFastPlainLift);

        #endregion

        #region SmallModulus methods

        [DllImport(SEALdll, EntryPoint = "SmallModulus_Create1", PreserveSig = false)]
        internal static extern void SmallModulus_Create(ulong value, out IntPtr smallModulus);

        [DllImport(SEALdll, EntryPoint = "SmallModulus_Create2", PreserveSig = false)]
        internal static extern void SmallModulus_Create(IntPtr copy, out IntPtr smallModulus);

        [DllImport(SEALdll, PreserveSig = false)]
        internal static extern void SmallModulus_Destroy(IntPtr thisptr);

        [DllImport(SEALdll, PreserveSig = false)]
        internal static extern void SmallModulus_IsZero(IntPtr thisptr, out bool isZero);

        [DllImport(SEALdll, PreserveSig = false)]
        internal static extern void SmallModulus_Value(IntPtr thisptr, out ulong value);

        [DllImport(SEALdll, PreserveSig = false)]
        internal static extern void SmallModulus_BitCount(IntPtr thisptr, out int bitCount);

        [DllImport(SEALdll, PreserveSig = false)]
        internal static extern void SmallModulus_UInt64Count(IntPtr thisptr, out ulong uint64Count);

        [DllImport(SEALdll, EntryPoint = "SmallModulus_Set1", PreserveSig = false)]
        internal static extern void SmallModulus_Set(IntPtr thisptr, IntPtr assign);

        [DllImport(SEALdll, EntryPoint = "SmallModulus_Set2", PreserveSig = false)]
        internal static extern void SmallModulus_Set(IntPtr thisptr, ulong value);

        [DllImport(SEALdll, PreserveSig = false)]
        internal static extern void SmallModulus_ConstRatio(
            IntPtr thisptr,
            int length,
            [MarshalAs(UnmanagedType.LPArray)] ulong[] ratio);

        [DllImport(SEALdll, EntryPoint = "SmallModulus_Equals1", PreserveSig = false)]
        internal static extern void SmallModulus_Equals(IntPtr thisptr, IntPtr other, out bool result);

        [DllImport(SEALdll, EntryPoint = "SmallModulus_Equals2", PreserveSig = false)]
        internal static extern void SmallModulus_Equals(IntPtr thisptr, ulong other, out bool result);

        #endregion

        #region EncryptionParameters methods

        [DllImport(SEALdll, EntryPoint = "EncParams_Create1", PreserveSig = false)]
        internal static extern void EncParams_Create(int scheme, out IntPtr encParams);

        [DllImport(SEALdll, EntryPoint = "EncParams_Create2", PreserveSig = false)]
        internal static extern void EncParams_Create(IntPtr copy, out IntPtr encParams);

        [DllImport(SEALdll, PreserveSig = false)]
        internal static extern void EncParams_Destroy(IntPtr thisptr);

        [DllImport(SEALdll, PreserveSig = false)]
        internal static extern void EncParams_Set(IntPtr thisptr, IntPtr assign);

        [DllImport(SEALdll, PreserveSig = false)]
        internal static extern void EncParams_GetPolyModulusDegree(IntPtr thisptr, out ulong polyModulusDegree);

        [DllImport(SEALdll, PreserveSig = false)]
        internal static extern void EncParams_SetPolyModulusDegree(IntPtr thisptr, ulong polyModulusDegree);

        [DllImport(SEALdll, PreserveSig = false)]
        internal static extern void EncParams_GetCoeffModulus(
            IntPtr thisptr,
            ref int length,
            [MarshalAs(UnmanagedType.LPArray)] IntPtr[] coeffs);

        [DllImport(SEALdll, PreserveSig = false)]
        internal static extern void EncParams_SetCoeffModulus(
            IntPtr thisptr,
            int length,
            [MarshalAs(UnmanagedType.LPArray)] IntPtr[] coeffs);

        [DllImport(SEALdll, PreserveSig = false)]
        internal static extern void EncParams_GetScheme(IntPtr thisptr, out int scheme);

        [DllImport(SEALdll, PreserveSig = false)]
        internal static extern void EncParams_GetParmsId(IntPtr thisptr, ulong[] parmsId);

        [DllImport(SEALdll, PreserveSig = false)]
        internal static extern void EncParams_GetPlainModulus(IntPtr thisptr, out IntPtr plainModulus);

        [DllImport(SEALdll, EntryPoint = "EncParams_SetPlainModulus1", PreserveSig = false)]
        internal static extern void EncParams_SetPlainModulus(IntPtr thisptr, IntPtr plainModulus);

        [DllImport(SEALdll, EntryPoint = "EncParams_SetPlainModulus2", PreserveSig = false)]
        internal static extern void EncParams_SetPlainModulus(IntPtr thisptr, ulong plainModulus);

        [DllImport(SEALdll, PreserveSig = false)]
        internal static extern void EncParams_NoiseStandardDeviation(IntPtr thisptr, out double nsd);

        [DllImport(SEALdll, PreserveSig = false)]
        internal static extern void EncParams_SetNoiseStandardDeviation(IntPtr thisptr, double nsd);

        [DllImport(SEALdll, PreserveSig = false)]
        internal static extern void EncParams_NoiseMaxDeviation(IntPtr thisptr, out double nmd);

        [DllImport(SEALdll, PreserveSig = false)]
        internal static extern void EncParams_Equals(IntPtr thisptr, IntPtr otherptr, out bool result);

        #endregion

        #region DefaultParams methods

        [DllImport(SEALdll, PreserveSig = false)]
        internal static extern void DefParams_CoeffModulus128(
            int polyModulusDegree,
            ref int length,
            [MarshalAs(UnmanagedType.LPArray)] IntPtr[] coeffs);

        [DllImport(SEALdll, PreserveSig = false)]
        internal static extern void DefParams_CoeffModulus192(
            int polyModulusDegree,
            ref int length,
            [MarshalAs(UnmanagedType.LPArray)] IntPtr[] coeffs);

        [DllImport(SEALdll, PreserveSig = false)]
        internal static extern void DefParams_CoeffModulus256(
            int polyModulusDegree,
            ref int length,
            [MarshalAs(UnmanagedType.LPArray)] IntPtr[] coeffs);

        [DllImport(SEALdll, PreserveSig = false)]
        internal static extern void DefParams_SmallMods60Bit(int index, out IntPtr smallModulus);

        [DllImport(SEALdll, PreserveSig = false)]
        internal static extern void DefParams_SmallMods50Bit(int index, out IntPtr smallModulus);

        [DllImport(SEALdll, PreserveSig = false)]
        internal static extern void DefParams_SmallMods40Bit(int index, out IntPtr smallModulus);

        [DllImport(SEALdll, PreserveSig = false)]
        internal static extern void DefParams_SmallMods30Bit(int index, out IntPtr smallModulus);

        [DllImport(SEALdll, PreserveSig = false)]
        internal static extern void DefParams_DBCMax(out int dbcMax);

        [DllImport(SEALdll, PreserveSig = false)]
        internal static extern void DefParams_DBCMin(out int dbcMin);

        #endregion

        #region SEALContext methods

        [DllImport(SEALdll, PreserveSig = false)]
        internal static extern void SEALContext_Create(IntPtr encryptionParams, out IntPtr context);

        [DllImport(SEALdll, PreserveSig = false)]
        internal static extern void SEALContext_Destroy(IntPtr thisptr);

        [DllImport(SEALdll, PreserveSig = false)]
        internal static extern void SEALContext_FirstParmsId(IntPtr thisptr, ulong[] parmsId);

        [DllImport(SEALdll, PreserveSig = false)]
        internal static extern void SEALContext_LastParmsId(IntPtr thisptr, ulong[] parmsId);

        [DllImport(SEALdll, PreserveSig = false)]
        internal static extern void SEALContext_ParametersSet(IntPtr thisptr, out bool paramsSet);

        [DllImport(SEALdll, PreserveSig = false)]
        internal static extern void SEALContext_FirstContextData(IntPtr thisptr, out IntPtr contextData);

        [DllImport(SEALdll, PreserveSig = false)]
        internal static extern void SEALContext_GetContextData(IntPtr thisptr, ulong[] parmsId, out IntPtr contextData);

        #endregion

        #region ContextData methods

        [DllImport(SEALdll, PreserveSig = false)]
        internal static extern void ContextData_Destroy(IntPtr thisptr);

        [DllImport(SEALdll, PreserveSig = false)]
        internal static extern void ContextData_TotalCoeffModulus(IntPtr thisptr, ref ulong count, ulong[] totalCoeffModulus);

        [DllImport(SEALdll, PreserveSig = false)]
        internal static extern void ContextData_TotalCoeffModulusBitCount(IntPtr thisptr, out int bitCount);

        [DllImport(SEALdll, PreserveSig = false)]
        internal static extern void ContextData_Parms(IntPtr thisptr, out IntPtr parms);

        [DllImport(SEALdll, PreserveSig = false)]
        internal static extern void ContextData_Qualifiers(IntPtr thisptr, out IntPtr epq);

        [DllImport(SEALdll, PreserveSig = false)]
        internal static extern void ContextData_CoeffDivPlainModulus(IntPtr thisptr, ref ulong count, ulong[] coefDivPlainMod);

        [DllImport(SEALdll, PreserveSig = false)]
        internal static extern void ContextData_PlainUpperHalfThreshold(IntPtr thisptr, out ulong puht);

        [DllImport(SEALdll, PreserveSig = false)]
        internal static extern void ContextData_PlainUpperHalfIncrement(IntPtr thisptr, ref ulong count, ulong[] puhi);

        [DllImport(SEALdll, PreserveSig = false)]
        internal static extern void ContextData_UpperHalfThreshold(IntPtr thisptr, ref ulong count, ulong[] uht);

        [DllImport(SEALdll, PreserveSig = false)]
        internal static extern void ContextData_UpperHalfIncrement(IntPtr thisptr, ref ulong count, ulong[] uhi);

        [DllImport(SEALdll, PreserveSig = false)]
        internal static extern void ContextData_NextContextData(IntPtr thisptr, out IntPtr nextContextData);

        [DllImport(SEALdll, PreserveSig = false)]
        internal static extern void ContextData_ChainIndex(IntPtr thisptr, out ulong index);

        #endregion

        #region Evaluator methods

        [DllImport(SEALdll, PreserveSig = false)]
        internal static extern void Evaluator_Create(IntPtr sealContext, out IntPtr evaluator);

        [DllImport(SEALdll, PreserveSig = false)]
        internal static extern void Evaluator_Destroy(IntPtr thisptr);

        [DllImport(SEALdll, PreserveSig = false)]
        internal static extern void Evaluator_Negate(IntPtr thisptr, IntPtr encrypted, IntPtr destination);

        [DllImport(SEALdll, PreserveSig = false)]
        internal static extern void Evaluator_Add(IntPtr thisptr, IntPtr encrypted1, IntPtr encrypted2, IntPtr destination);

        [DllImport(SEALdll, PreserveSig = false)]
        internal static extern void Evaluator_AddMany(IntPtr thisptr, int count, IntPtr[] encrypteds, IntPtr destination);

        [DllImport(SEALdll, PreserveSig = false)]
        internal static extern void Evaluator_AddPlain(IntPtr thisptr, IntPtr encrypted, IntPtr plain, IntPtr destination);

        [DllImport(SEALdll, PreserveSig = false)]
        internal static extern void Evaluator_Sub(IntPtr thisptr, IntPtr encrypted1, IntPtr encrypted2, IntPtr destination);

        [DllImport(SEALdll, PreserveSig = false)]
        internal static extern void Evaluator_SubPlain(IntPtr thisptr, IntPtr encrypted, IntPtr plain, IntPtr destination);

        [DllImport(SEALdll, PreserveSig = false)]
        internal static extern void Evaluator_Multiply(IntPtr thisptr, IntPtr encrypted1, IntPtr encrypted2, IntPtr destination, IntPtr pool);

        [DllImport(SEALdll, PreserveSig = false)]
        internal static extern void Evaluator_MultiplyMany(IntPtr thisptr, int count, IntPtr[] encrypteds, IntPtr relinKeys, IntPtr destination, IntPtr pool);

        [DllImport(SEALdll, PreserveSig = false)]
        internal static extern void Evaluator_MultiplyPlain(IntPtr thisptr, IntPtr encrypted, IntPtr plain, IntPtr destination, IntPtr pool);

        [DllImport(SEALdll, PreserveSig = false)]
        internal static extern void Evaluator_Square(IntPtr thisptr, IntPtr encrypted, IntPtr destination, IntPtr pool);

        [DllImport(SEALdll, PreserveSig = false)]
        internal static extern void Evaluator_Relinearize(IntPtr thisptr, IntPtr encrypted, IntPtr relinKeys, IntPtr destination, IntPtr pool);

        [DllImport(SEALdll, EntryPoint = "Evaluator_ModSwitchToNext1", PreserveSig = false)]
        internal static extern void Evaluator_ModSwitchToNext(IntPtr thisptr, IntPtr encrypted, IntPtr destination, IntPtr pool);

        [DllImport(SEALdll, EntryPoint = "Evaluator_ModSwitchToNext2", PreserveSig = false)]
        internal static extern void Evaluator_ModSwitchToNext(IntPtr thisptr, IntPtr plain, IntPtr destination);

        [DllImport(SEALdll, EntryPoint = "Evaluator_ModSwitchTo1", PreserveSig = false)]
        internal static extern void Evaluator_ModSwitchTo(IntPtr thisptr, IntPtr encrypted, ulong[] parmsId, IntPtr destination, IntPtr pool);

        [DllImport(SEALdll, EntryPoint = "Evaluator_ModSwitchTo2", PreserveSig = false)]
        internal static extern void Evaluator_ModSwitchTo(IntPtr thisptr, IntPtr plain, ulong[] parmsId, IntPtr destination);

        [DllImport(SEALdll, PreserveSig = false)]
        internal static extern void Evaluator_RescaleToNext(IntPtr thisptr, IntPtr encrypted, IntPtr destination, IntPtr pool);

        [DllImport(SEALdll, PreserveSig = false)]
        internal static extern void Evaluator_RescaleTo(IntPtr thisptr, IntPtr encrypted, ulong[] parmsId, IntPtr destination, IntPtr pool);

        [DllImport(SEALdll, PreserveSig = false)]
        internal static extern void Evaluator_Exponentiate(IntPtr thisptr, IntPtr encrypted, ulong exponent, IntPtr relinKeys, IntPtr destination, IntPtr pool);

        [DllImport(SEALdll, EntryPoint = "Evaluator_TransformToNTT1", PreserveSig = false)]
        internal static extern void Evaluator_TransformToNTT(IntPtr thisptr, IntPtr plain, ulong[] parmsId, IntPtr destinationNTT, IntPtr pool);

        [DllImport(SEALdll, EntryPoint = "Evaluator_TransformToNTT2", PreserveSig = false)]
        internal static extern void Evaluator_TransformToNTT(IntPtr thisptr, IntPtr encrypted, IntPtr destinationNTT);

        [DllImport(SEALdll, PreserveSig = false)]
        internal static extern void Evaluator_TransformFromNTT(IntPtr thisptr, IntPtr encryptedNTT, IntPtr destination);

        [DllImport(SEALdll, PreserveSig = false)]
        internal static extern void Evaluator_ApplyGalois(IntPtr thisptr, IntPtr encrypted, ulong galoisElt, IntPtr galoisKeys, IntPtr destination, IntPtr pool);

        [DllImport(SEALdll, PreserveSig = false)]
        internal static extern void Evaluator_RotateRows(IntPtr thisptr, IntPtr encrypted, int steps, IntPtr galoisKeys, IntPtr destination, IntPtr pool);

        [DllImport(SEALdll, PreserveSig = false)]
        internal static extern void Evaluator_RotateColumns(IntPtr thisptr, IntPtr encrypted, IntPtr galoisKeys, IntPtr destination, IntPtr pool);

        [DllImport(SEALdll, PreserveSig = false)]
        internal static extern void Evaluator_RotateVector(IntPtr thisptr, IntPtr encrypted, int steps, IntPtr galoisKeys, IntPtr destination, IntPtr pool);

        [DllImport(SEALdll, PreserveSig = false)]
        internal static extern void Evaluator_ComplexConjugate(IntPtr thisptr, IntPtr encrypted, IntPtr galoisKeys, IntPtr destination, IntPtr pool);

        #endregion

        #region Ciphertext methods

        [DllImport(SEALdll, PreserveSig = false)]
        internal static extern void Ciphertext_Create1(IntPtr pool, out IntPtr cipher);

        [DllImport(SEALdll, PreserveSig = false)]
        internal static extern void Ciphertext_Create2(IntPtr copy, out IntPtr cipher);

        [DllImport(SEALdll, PreserveSig = false)]
        internal static extern void Ciphertext_Create3(IntPtr context, IntPtr pool, out IntPtr cipher);

        [DllImport(SEALdll, PreserveSig = false)]
        internal static extern void Ciphertext_Create4(IntPtr context, ulong[] parmsId, IntPtr pool, out IntPtr cipher);

        [DllImport(SEALdll, PreserveSig = false)]
        internal static extern void Ciphertext_Create5(IntPtr context, ulong[] parmsId, ulong capacity, IntPtr pool, out IntPtr cipher);

        [DllImport(SEALdll, EntryPoint = "Ciphertext_Reserve1", PreserveSig = false)]
        internal static extern void Ciphertext_Reserve(IntPtr thisptr, IntPtr context, ulong[] parmsId, ulong sizeCapacity);

        [DllImport(SEALdll, EntryPoint = "Ciphertext_Reserve2", PreserveSig = false)]
        internal static extern void Ciphertext_Reserve(IntPtr thisptr, IntPtr context, ulong sizeCapacity);

        [DllImport(SEALdll, EntryPoint = "Ciphertext_Reserve3", PreserveSig = false)]
        internal static extern void Ciphertext_Reserve(IntPtr thisptr, ulong sizeCapacity);

        [DllImport(SEALdll, PreserveSig = false)]
        internal static extern void Ciphertext_Set(IntPtr thisptr, IntPtr assign);

        [DllImport(SEALdll, PreserveSig = false)]
        internal static extern void Ciphertext_Destroy(IntPtr thisptr);

        [DllImport(SEALdll, PreserveSig = false)]
        internal static extern void Ciphertext_UInt64Count(IntPtr thisptr, out ulong uint64Count);

        [DllImport(SEALdll, PreserveSig = false)]
        internal static extern void Ciphertext_UInt64CountCapacity(IntPtr thisptr, out ulong uint64CountCapacity);

        [DllImport(SEALdll, PreserveSig = false)]
        internal static extern void Ciphertext_Size(IntPtr thisptr, out ulong size);

        [DllImport(SEALdll, PreserveSig = false)]
        internal static extern void Ciphertext_SizeCapacity(IntPtr thisptr, out ulong size_capacity);

        [DllImport(SEALdll, PreserveSig = false)]
        internal static extern void Ciphertext_PolyModulusDegree(IntPtr thisptr, out ulong polyModulusDegree);

        [DllImport(SEALdll, PreserveSig = false)]
        internal static extern void Ciphertext_CoeffModCount(IntPtr thisptr, out ulong coeffModCount);

        [DllImport(SEALdll, PreserveSig = false)]
        internal static extern void Ciphertext_ParmsId(IntPtr thisptr, ulong[] parmsId);

        [DllImport(SEALdll, PreserveSig = false)]
        internal static extern void Ciphertext_SetParmsId(IntPtr thisptr, ulong[] parmsId);

        [DllImport(SEALdll, EntryPoint = "Ciphertext_Resize1", PreserveSig = false)]
        internal static extern void Ciphertext_Resize(IntPtr thisptr, IntPtr context, ulong[] parms_id, ulong size);

        [DllImport(SEALdll, EntryPoint = "Ciphertext_Resize2", PreserveSig = false)]
        internal static extern void Ciphertext_Resize(IntPtr thisptr, IntPtr context, ulong size);

        [DllImport(SEALdll, EntryPoint = "Ciphertext_Resize3", PreserveSig = false)]
        internal static extern void Ciphertext_Resize(IntPtr thisptr, ulong size);

        [DllImport(SEALdll, EntryPoint = "Ciphertext_Resize4", PreserveSig = false)]
        internal static extern void Ciphertext_Resize(IntPtr thisptr, ulong size, ulong polyModulusDegree, ulong coeffModCount);

        [DllImport(SEALdll, EntryPoint = "Ciphertext_GetDataAt1", PreserveSig = false)]
        internal static extern void Ciphertext_GetDataAt(IntPtr thisptr, ulong index, out ulong data);

        [DllImport(SEALdll, EntryPoint = "Ciphertext_GetDataAt2", PreserveSig = false)]
        internal static extern void Ciphertext_GetDataAt(IntPtr thisptr, ulong polyIndex, ulong coeffIndex, out ulong data);

        [DllImport(SEALdll, PreserveSig = false)]
        internal static extern void Ciphertext_SetDataAt(IntPtr thisptr, ulong index, ulong value);

        [DllImport(SEALdll, PreserveSig = false)]
        internal static extern void Ciphertext_IsNTTForm(IntPtr thisptr, out bool isNTTForm);

        [DllImport(SEALdll, PreserveSig = false)]
        internal static extern void Ciphertext_SetIsNTTForm(IntPtr thisptr, bool isNTTForm);

        [DllImport(SEALdll, PreserveSig = false)]
        internal static extern void Ciphertext_Scale(IntPtr thisptr, out double scale);

        [DllImport(SEALdll, PreserveSig = false)]
        internal static extern void Ciphertext_Release(IntPtr thisptr);

        [DllImport(SEALdll, PreserveSig = false)]
        internal static extern void Ciphertext_IsValidFor(IntPtr thisptr, IntPtr context, out bool result);

        [DllImport(SEALdll, PreserveSig = false)]
        internal static extern void Ciphertext_Pool(IntPtr thisptr, out IntPtr pool);

        #endregion

        #region Plaintext methods

        [DllImport(SEALdll, EntryPoint = "Plaintext_Create1", PreserveSig = false)]
        internal static extern void Plaintext_Create(IntPtr memoryPoolHandle, out IntPtr plainText);

        [DllImport(SEALdll, EntryPoint = "Plaintext_Create2", PreserveSig = false)]
        internal static extern void Plaintext_Create(ulong coeffCount, IntPtr memoryPoolHandle, out IntPtr plainText);

        [DllImport(SEALdll, EntryPoint = "Plaintext_Create3", PreserveSig = false)]
        internal static extern void Plaintext_Create(ulong capacity, ulong coeffCount, IntPtr memoryPoolHandle, out IntPtr plainText);

        [DllImport(SEALdll, EntryPoint = "Plaintext_Create4", PreserveSig = false, CharSet = CharSet.Ansi)]
        internal static extern void Plaintext_Create(string hexPoly, IntPtr memoryPoolHandle, out IntPtr plainText);

        [DllImport(SEALdll, EntryPoint = "Plaintext_Set1", PreserveSig = false)]
        internal static extern void Plaintext_Set(IntPtr thisptr, IntPtr assign);

        [DllImport(SEALdll, EntryPoint = "Plaintext_Set2", PreserveSig = false, CharSet = CharSet.Ansi)]
        internal static extern void Plaintext_Set(IntPtr thisptr, string hexPoly);

        [DllImport(SEALdll, EntryPoint = "Plaintext_Set3", PreserveSig = false)]
        internal static extern void Plaintext_Set(IntPtr thisptr, ulong constCoeff);

        [DllImport(SEALdll, PreserveSig = false)]
        internal static extern void Plaintext_Destroy(IntPtr thisptr);

        [DllImport(SEALdll, PreserveSig = false)]
        internal static extern void Plaintext_CoeffCount(IntPtr thisptr, out ulong coeffCount);

        [DllImport(SEALdll, PreserveSig = false)]
        internal static extern void Plaintext_CoeffAt(IntPtr thisptr, ulong index, out ulong coeff);

        [DllImport(SEALdll, PreserveSig = false)]
        internal static extern void Plaintext_SetCoeffAt(IntPtr thisptr, ulong index, ulong value);

        [DllImport(SEALdll, PreserveSig = false, CharSet = CharSet.Ansi)]
        internal static extern void Plaintext_ToString(
            IntPtr thisptr,
            ref int length,
            StringBuilder outstr);

        [DllImport(SEALdll, PreserveSig = false)]
        internal static extern void Plaintext_IsNTTForm(IntPtr thisptr, out bool isNTTForm);

        [DllImport(SEALdll, PreserveSig = false)]
        internal static extern void Plaintext_IsZero(IntPtr thisptr, out bool isZero);

        [DllImport(SEALdll, EntryPoint = "Plaintext_SetZero1", PreserveSig = false)]
        internal static extern void Plaintext_SetZero(IntPtr thisptr);

        [DllImport(SEALdll, EntryPoint = "Plaintext_SetZero2", PreserveSig = false)]
        internal static extern void Plaintext_SetZero(IntPtr thisptr, int startCoeff);

        [DllImport(SEALdll, EntryPoint = "Plaintext_SetZero3", PreserveSig = false)]
        internal static extern void Plaintext_SetZero(IntPtr thisptr, int startCoeff, int length);

        [DllImport(SEALdll, PreserveSig = false)]
        internal static extern void Plaintext_GetParmsId(IntPtr thisptr, ulong[] parmsId);

        [DllImport(SEALdll, PreserveSig = false)]
        internal static extern void Plaintext_SetParmsId(IntPtr thisptr, ulong[] parmsId);

        [DllImport(SEALdll, PreserveSig = false)]
        internal static extern void Plaintext_Reserve(IntPtr thisptr, ulong capacity);

        [DllImport(SEALdll, PreserveSig = false)]
        internal static extern void Plaintext_Resize(IntPtr thisptr, ulong coeffCount);

        [DllImport(SEALdll, PreserveSig = false)]
        internal static extern void Plaintext_ShrinkToFit(IntPtr thisptr);

        [DllImport(SEALdll, PreserveSig = false)]
        internal static extern void Plaintext_Release(IntPtr thisptr);

        [DllImport(SEALdll, PreserveSig = false)]
        internal static extern void Plaintext_Capacity(IntPtr thisptr, out ulong capacity);

        [DllImport(SEALdll, PreserveSig = false)]
        internal static extern void Plaintext_SignificantCoeffCount(IntPtr thisptr, out ulong significantCoeffCount);

        [DllImport(SEALdll, PreserveSig = false)]
        internal static extern void Plaintext_Scale(IntPtr thisptr, out double scale);

        [DllImport(SEALdll, PreserveSig = false)]
        internal static extern void Plaintext_SetScale(IntPtr thisptr, double scale);

        [DllImport(SEALdll, PreserveSig = false)]
        internal static extern void Plaintext_Equals(IntPtr thisptr, IntPtr otherptr, out bool result);

        [DllImport(SEALdll, PreserveSig = false)]
        internal static extern void Plaintext_IsValidFor(IntPtr thisptr, IntPtr context, out bool result);

        [DllImport(SEALdll, PreserveSig = false)]
        internal static extern void Plaintext_SwapData(IntPtr thisptr, ulong count, ulong[] newData);

        [DllImport(SEALdll, PreserveSig = false)]
        internal static extern void Plaintext_Pool(IntPtr thisptr, out IntPtr pool);

        #endregion

        #region GaloisKeys methods

        [DllImport(SEALdll, EntryPoint = "GaloisKeys_Create1", PreserveSig = false)]
        internal static extern void GaloisKeys_Create(out IntPtr galoisKeys);

        [DllImport(SEALdll, EntryPoint = "GaloisKeys_Create2", PreserveSig = false)]
        internal static extern void GaloisKeys_Create(IntPtr copy, out IntPtr galoisKeys);

        [DllImport(SEALdll, PreserveSig = false)]
        internal static extern void GaloisKeys_Destroy(IntPtr thisptr);

        [DllImport(SEALdll, PreserveSig = false)]
        internal static extern void GaloisKeys_Set(IntPtr thisptr, IntPtr assignptr);

        [DllImport(SEALdll, PreserveSig = false)]
        internal static extern void GaloisKeys_Size(IntPtr thisptr, out int size);

        [DllImport(SEALdll, PreserveSig = false)]
        internal static extern void GaloisKeys_DBC(IntPtr thisptr, out int dbc);

        [DllImport(SEALdll, PreserveSig = false)]
        internal static extern void GaloisKeys_SetDBC(IntPtr thisptr, int value);

        [DllImport(SEALdll, PreserveSig = false)]
        internal static extern void GaloisKeys_ClearDataAndReserve(IntPtr thisptr, ulong size);

        [DllImport(SEALdll, PreserveSig = false)]
        internal static extern void GaloisKeys_GetKeyCount(IntPtr thisptr, out ulong keyCount);

        [DllImport(SEALdll, PreserveSig = false)]
        internal static extern void GaloisKeys_GetKeyList(IntPtr thisptr, ulong index, ref ulong count, IntPtr[] ciphers);

        [DllImport(SEALdll, PreserveSig = false)]
        internal static extern void GaloisKeys_GetKey(IntPtr thisptr, ulong galoisElt, ref ulong count, IntPtr[] ciphers);

        [DllImport(SEALdll, PreserveSig = false)]
        internal static extern void GaloisKeys_AddKeyList(IntPtr thisptr, ulong count, IntPtr[] ciphers);

        [DllImport(SEALdll, PreserveSig = false)]
        internal static extern void GaloisKeys_GetParmsId(IntPtr thisptr, ulong[] parmsId);

        [DllImport(SEALdll, PreserveSig = false)]
        internal static extern void GaloisKeys_SetParmsId(IntPtr thisptr, ulong[] parmsId);

        [DllImport(SEALdll, PreserveSig = false)]
        internal static extern void GaloisKeys_HasKey(IntPtr thisptr, ulong galoisElt, out bool hasKey);

        [DllImport(SEALdll, PreserveSig = false)]
        internal static extern void GaloisKeys_IsValidFor(IntPtr thisptr, IntPtr context, out bool result);

        [DllImport(SEALdll, PreserveSig = false)]
        internal static extern void GaloisKeys_Pool(IntPtr thisptr, out IntPtr pool);

        #endregion

        #region KeyGenerator methods

        [DllImport(SEALdll, EntryPoint = "KeyGenerator_Create1", PreserveSig = false)]
        internal static extern void KeyGenerator_Create(IntPtr sealContext, out IntPtr keyGenerator);

        [DllImport(SEALdll, EntryPoint = "KeyGenerator_Create2", PreserveSig = false)]
        internal static extern void KeyGenerator_Create(IntPtr sealContext, IntPtr secretKey, out IntPtr keyGenerator);

        [DllImport(SEALdll, EntryPoint = "KeyGenerator_Create3", PreserveSig = false)]
        internal static extern void KeyGenerator_Create(IntPtr sealContext, IntPtr secretKey, IntPtr publicKey, out IntPtr keyGenerator);

        [DllImport(SEALdll, PreserveSig = false)]
        internal static extern void KeyGenerator_Destroy(IntPtr thisptr);

        [DllImport(SEALdll, PreserveSig = false)]
        internal static extern void KeyGenerator_RelinKeys(IntPtr thisptr, int decompositionBitCount, int count, out IntPtr relinKeys);

        [DllImport(SEALdll, EntryPoint = "KeyGenerator_GaloisKeys1", PreserveSig = false)]
        internal static extern void KeyGenerator_GaloisKeys(IntPtr thisptr, int decompositionBitCount, out IntPtr galoisKeys);

        [DllImport(SEALdll, EntryPoint = "KeyGenerator_GaloisKeys2", PreserveSig = false)]
        internal static extern void KeyGenerator_GaloisKeys(IntPtr thisptr, int decompositionBitCount, int count, ulong[] galoisElts, out IntPtr galoisKeys);

        [DllImport(SEALdll, PreserveSig = false)]
        internal static extern void KeyGenerator_PublicKey(IntPtr thisptr, out IntPtr publicKey);

        [DllImport(SEALdll, PreserveSig = false)]
        internal static extern void KeyGenerator_SecretKey(IntPtr thisptr, out IntPtr secretKey);

        #endregion

        #region RelinKeys methods

        [DllImport(SEALdll, EntryPoint = "RelinKeys_Create1", PreserveSig = false)]
        internal static extern void RelinKeys_Create(out IntPtr relinKeys);

        [DllImport(SEALdll, EntryPoint = "RelinKeys_Create2", PreserveSig = false)]
        internal static extern void RelinKeys_Create(IntPtr copy, out IntPtr relinKeys);

        [DllImport(SEALdll, PreserveSig = false)]
        internal static extern void RelinKeys_Set(IntPtr thisptr, IntPtr copy);

        [DllImport(SEALdll, PreserveSig = false)]
        internal static extern void RelinKeys_Destroy(IntPtr thisptr);

        [DllImport(SEALdll, PreserveSig = false)]
        internal static extern void RelinKeys_Size(IntPtr thisptr, out ulong size);

        [DllImport(SEALdll, PreserveSig = false)]
        internal static extern void RelinKeys_DBC(IntPtr thisptr, out int dbc);

        [DllImport(SEALdll, PreserveSig = false)]
        internal static extern void RelinKeys_SetDBC(IntPtr thisptr, int value);

        [DllImport(SEALdll, PreserveSig = false)]
        internal static extern void RelinKeys_ClearDataAndReserve(IntPtr thisptr, ulong size);

        [DllImport(SEALdll, PreserveSig = false)]
        internal static extern void RelinKeys_GetKeyList(IntPtr thisptr, ulong index, ref ulong count, IntPtr[] ciphers);

        [DllImport(SEALdll, PreserveSig = false)]
        internal static extern void RelinKeys_GetKey(IntPtr thisptr, ulong keyPower, ref ulong count, IntPtr[] ciphers);

        [DllImport(SEALdll, PreserveSig = false)]
        internal static extern void RelinKeys_HasKey(IntPtr thisptr, ulong keyPower, out bool hasKey);

        [DllImport(SEALdll, PreserveSig = false)]
        internal static extern void RelinKeys_AddKeyList(IntPtr thisptr, ulong count, IntPtr[] ciphers);

        [DllImport(SEALdll, PreserveSig = false)]
        internal static extern void RelinKeys_GetParmsId(IntPtr thisptr, ulong[] parmsId);

        [DllImport(SEALdll, PreserveSig = false)]
        internal static extern void RelinKeys_SetParmsId(IntPtr thisptr, ulong[] parmsId);

        [DllImport(SEALdll, PreserveSig = false)]
        internal static extern void RelinKeys_IsValidFor(IntPtr thisptr, IntPtr context, out bool result);

        [DllImport(SEALdll, PreserveSig = false)]
        internal static extern void RelinKeys_Pool(IntPtr thisptr, out IntPtr pool);

        #endregion

        #region PublicKey methods

        [DllImport(SEALdll, EntryPoint = "PublicKey_Create1", PreserveSig = false)]
        internal static extern void PublicKey_Create(out IntPtr publicKey);

        [DllImport(SEALdll, EntryPoint = "PublicKey_Create2", PreserveSig = false)]
        internal static extern void PublicKey_Create(IntPtr copy, out IntPtr publicKey);

        [DllImport(SEALdll, PreserveSig = false)]
        internal static extern void PublicKey_Set(IntPtr thisptr, IntPtr assign);

        [DllImport(SEALdll, PreserveSig = false)]
        internal static extern void PublicKey_Data(IntPtr thisptr, out IntPtr data);

        [DllImport(SEALdll, PreserveSig = false)]
        internal static extern void PublicKey_ParmsId(IntPtr thisptr, ulong[] parmsId);

        [DllImport(SEALdll, PreserveSig = false)]
        internal static extern void PublicKey_IsValidFor(IntPtr thisptr, IntPtr context, out bool result);

        [DllImport(SEALdll, PreserveSig = false)]
        internal static extern void PublicKey_Pool(IntPtr thisptr, out IntPtr pool);

        [DllImport(SEALdll, PreserveSig = false)]
        internal static extern void PublicKey_Destroy(IntPtr thisptr);

        #endregion

        #region SecretKey methods

        [DllImport(SEALdll, EntryPoint = "SecretKey_Create1", PreserveSig = false)]
        internal static extern void SecretKey_Create(out IntPtr secretKey);

        [DllImport(SEALdll, EntryPoint = "SecretKey_Create2", PreserveSig = false)]
        internal static extern void SecretKey_Create(IntPtr copy, out IntPtr secretKey);

        [DllImport(SEALdll, PreserveSig = false)]
        internal static extern void SecretKey_Set(IntPtr thisptr, IntPtr assign);

        [DllImport(SEALdll, PreserveSig = false)]
        internal static extern void SecretKey_Data(IntPtr thisptr, out IntPtr data);

        [DllImport(SEALdll, PreserveSig = false)]
        internal static extern void SecretKey_Destroy(IntPtr thisptr);

        [DllImport(SEALdll, PreserveSig = false)]
        internal static extern void SecretKey_IsValidFor(IntPtr thisptr, IntPtr context, out bool result);

        [DllImport(SEALdll, PreserveSig = false)]
        internal static extern void SecretKey_ParmsId(IntPtr thisptr, ulong[] parmsId);

        [DllImport(SEALdll, PreserveSig = false)]
        internal static extern void SecretKey_Pool(IntPtr thisptr, out IntPtr pool);

        #endregion

        #region MemoryManager methods

        [DllImport(SEALdll, EntryPoint = "MemoryManager_GetPool1", PreserveSig = false)]
        internal static extern void MemoryManager_GetPool(int profOpt, bool clearOnDestruction, out IntPtr handle);

        [DllImport(SEALdll, EntryPoint = "MemoryManager_GetPool2", PreserveSig = false)]
        internal static extern void MemoryManager_GetPool(out IntPtr handle);

        [DllImport(SEALdll, PreserveSig = false)]
        internal static extern void MemoryManager_SwitchProfile(IntPtr newProfile);

        #endregion

        #region MMProf methods

        [DllImport(SEALdll, PreserveSig = false)]
        internal static extern void MMProf_CreateGlobal(out IntPtr profile);

        [DllImport(SEALdll, PreserveSig = false)]
        internal static extern void MMProf_CreateFixed(IntPtr pool, out IntPtr profile);

        [DllImport(SEALdll, PreserveSig = false)]
        internal static extern void MMProf_CreateNew(out IntPtr profile);

        [DllImport(SEALdll, PreserveSig = false)]
        internal static extern void MMProf_CreateThreadLocal(out IntPtr profile);

        [DllImport(SEALdll, PreserveSig = false)]
        internal static extern void MMProf_GetPool(IntPtr thisptr, out IntPtr pool);

        [DllImport(SEALdll, PreserveSig = false)]
        internal static extern void MMProf_Destroy(IntPtr thisptr);

        #endregion

        #region MemoryPoolHandle methods

        [DllImport(SEALdll, EntryPoint = "MemoryPoolHandle_Create1", PreserveSig = false)]
        internal static extern void MemoryPoolHandle_Create(out IntPtr handlePtr);

        [DllImport(SEALdll, EntryPoint = "MemoryPoolHandle_Create2", PreserveSig = false)]
        internal static extern void MemoryPoolHandle_Create(IntPtr other, out IntPtr handlePtr);

        [DllImport(SEALdll, PreserveSig = false)]
        internal static extern void MemoryPoolHandle_Destroy(IntPtr thisptr);

        [DllImport(SEALdll, PreserveSig = false)]
        internal static extern void MemoryPoolHandle_Set(IntPtr thisptr, IntPtr assignptr);

        [DllImport(SEALdll, PreserveSig = false)]
        internal static extern void MemoryPoolHandle_Global(out IntPtr handlePtr);

        [DllImport(SEALdll, PreserveSig = false)]
        internal static extern void MemoryPoolHandle_ThreadLocal(out IntPtr handlePtr);

        [DllImport(SEALdll, PreserveSig = false)]
        internal static extern void MemoryPoolHandle_New(bool clearOnDestruction, out IntPtr handlePtr);

        [DllImport(SEALdll, PreserveSig = false)]
        internal static extern void MemoryPoolHandle_PoolCount(IntPtr thisptr, out ulong count);

        [DllImport(SEALdll, PreserveSig = false)]
        internal static extern void MemoryPoolHandle_AllocByteCount(IntPtr thisptr, out ulong count);

        [DllImport(SEALdll, PreserveSig = false)]
        internal static extern void MemoryPoolHandle_IsInitialized(IntPtr thisptr, out bool initialized);

        [DllImport(SEALdll, PreserveSig = false)]
        internal static extern void MemoryPoolHandle_Equals(IntPtr thisptr, IntPtr otherptr, out bool result);

        #endregion

        #region Encryptor methods

        [DllImport(SEALdll, PreserveSig = false)]
        internal static extern void Encryptor_Create(IntPtr context, IntPtr publicKey, out IntPtr encryptor);

        [DllImport(SEALdll, PreserveSig = false)]
        internal static extern void Encryptor_Encrypt(IntPtr thisptr, IntPtr plaintext, IntPtr destination, IntPtr poolHandle);

        [DllImport(SEALdll, PreserveSig = false)]
        internal static extern void Encryptor_Destroy(IntPtr thisptr);

        #endregion

        #region Decryptor methods

        [DllImport(SEALdll, PreserveSig = false)]
        internal static extern void Decryptor_Create(IntPtr context, IntPtr secretKey, out IntPtr decryptor);

        [DllImport(SEALdll, PreserveSig = false)]
        internal static extern void Decryptor_Destroy(IntPtr thisptr);

        [DllImport(SEALdll, PreserveSig = false)]
        internal static extern void Decryptor_Decrypt(IntPtr thisptr, IntPtr encrypted, IntPtr destination);

        [DllImport(SEALdll, PreserveSig = false)]
        internal static extern void Decryptor_InvariantNoiseBudget(IntPtr thisptr, IntPtr encrypted, out int invariantNoiseBudget);

        #endregion

        #region CKKSEncoder methods

        [DllImport(SEALdll, PreserveSig = false)]
        internal static extern void CKKSEncoder_Create(IntPtr context, out IntPtr ckksEncoder);

        [DllImport(SEALdll, PreserveSig = false)]
        internal static extern void CKKSEncoder_Destroy(IntPtr thisptr);

        [DllImport(SEALdll, EntryPoint = "CKKSEncoder_Encode1", PreserveSig = false)]
        internal static extern void CKKSEncoder_EncodeDouble(IntPtr thisptr, ulong valueCount, double[] values, ulong[] parms_id, double scale, IntPtr destination, IntPtr pool);

        [DllImport(SEALdll, EntryPoint = "CKKSEncoder_Encode2", PreserveSig = false)]
        internal static extern void CKKSEncoder_EncodeComplex(IntPtr thisptr, ulong valueCount, double[] values, ulong[] parms_id, double scale, IntPtr destination, IntPtr pool);

        [DllImport(SEALdll, EntryPoint = "CKKSEncoder_Encode3", PreserveSig = false)]
        internal static extern void CKKSEncoder_Encode(IntPtr thisptr, double value, ulong[] parms_id, double scale, IntPtr destination, IntPtr pool);

        [DllImport(SEALdll, EntryPoint = "CKKSEncoder_Encode4", PreserveSig = false)]
        internal static extern void CKKSEncoder_Encode(IntPtr thisptr, double real, double imaginary, ulong[] parms_id, double scale, IntPtr destination, IntPtr pool);

        [DllImport(SEALdll, EntryPoint = "CKKSEncoder_Encode5", PreserveSig = false)]
        internal static extern void CKKSEncoder_Encode(IntPtr thisptr, ulong value, ulong[] parms_id, IntPtr destination);

        [DllImport(SEALdll, EntryPoint = "CKKSEncoder_Decode1", PreserveSig = false)]
        internal static extern void CKKSEncoder_DecodeDouble(IntPtr thisptr, IntPtr plain, ref ulong valueCount, double[] values, IntPtr pool);

        [DllImport(SEALdll, EntryPoint = "CKKSEncoder_Decode2", PreserveSig = false)]
        internal static extern void CKKSEncoder_DecodeComplex(IntPtr thisptr, IntPtr plain, ref ulong valueCount, double[] values, IntPtr pool);

        [DllImport(SEALdll, PreserveSig = false)]
        internal static extern void CKKSEncoder_SlotCount(IntPtr thisptr, out ulong slotCount);

        #endregion

        #region BatchEncoder methods

        [DllImport(SEALdll, PreserveSig = false)]
        internal static extern void BatchEncoder_Create(IntPtr context, out IntPtr batchEncoder);

        [DllImport(SEALdll, PreserveSig = false)]
        internal static extern void BatchEncoder_Destroy(IntPtr thisptr);

        [DllImport(SEALdll, EntryPoint = "BatchEncoder_Encode1", PreserveSig = false)]
        internal static extern void BatchEncoder_Encode(IntPtr thisptr, ulong count, ulong[] values, IntPtr destination);

        [DllImport(SEALdll, EntryPoint = "BatchEncoder_Encode2", PreserveSig = false)]
        internal static extern void BatchEncoder_Encode(IntPtr thisptr, ulong count, long[] values, IntPtr destination);

        [DllImport(SEALdll, EntryPoint = "BatchEncoder_Encode3", PreserveSig = false)]
        internal static extern void BatchEncoder_Encode(IntPtr thisptr, IntPtr plain, IntPtr pool);

        [DllImport(SEALdll, EntryPoint = "BatchEncoder_Decode1", PreserveSig = false)]
        internal static extern void BatchEncoder_Decode(IntPtr thisptr, IntPtr plain, ref ulong count, ulong[] destination, IntPtr pool);

        [DllImport(SEALdll, EntryPoint = "BatchEncoder_Decode2", PreserveSig = false)]
        internal static extern void BatchEncoder_Decode(IntPtr thisptr, IntPtr plain, ref ulong count, long[] destination, IntPtr pool);

        [DllImport(SEALdll, EntryPoint = "BatchEncoder_Decode3", PreserveSig = false)]
        internal static extern void BatchEncoder_Decode(IntPtr thisptr, IntPtr plain, IntPtr pool);

        [DllImport(SEALdll, PreserveSig = false)]
        internal static extern void BatchEncoder_GetSlotCount(IntPtr thisptr, out ulong slotCount);

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
