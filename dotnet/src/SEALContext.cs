// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

using Microsoft.Research.SEAL.Tools;
using System;
using System.Text;

namespace Microsoft.Research.SEAL
{
    /// <summary>
    /// Performs sanity checks (validation) and pre-computations for a given set of encryption
    /// parameters.
    /// </summary>
    ///
    /// <remarks>
    /// <para>
    /// Performs sanity checks (validation) and pre-computations for a given set of encryption
    /// parameters. While the EncryptionParameters class is intended to be a light-weight class
    /// to store the encryption parameters, the SEALContext class is a heavy-weight class that
    /// is constructed from a given set of encryption parameters. It validates the parameters
    /// for correctness, evaluates their properties, and performs and stores the results of
    /// several costly pre-computations.
    /// </para>
    /// <para>
    /// After the user has set at least the PolyModulus, CoeffModulus, and PlainModulus
    /// parameters in a given EncryptionParameters instance, the parameters can be validated
    /// for correctness and functionality by constructing an instance of SEALContext. The
    /// constructor of SEALContext does all of its work automatically, and concludes by
    /// constructing and storing an instance of the EncryptionParameterQualifiers class, with
    /// its flags set according to the properties of the given parameters. If the created
    /// instance of EncryptionParameterQualifiers has the ParametersSet flag set to true, the
    /// given parameter set has been deemed valid and is ready to be used. If the parameters
    /// were for some reason not appropriately set, the ParametersSet flag will be false,
    /// and a new SEALContext will have to be created after the parameters are corrected.
    /// </para>
    /// <para>
    /// By default, SEALContext creates a chain of SEALContext.ContextData instances. The
    /// first one in the chain corresponds to special encryption parameters that are reserved
    /// to be used by the various key classes (SecretKey, PublicKey, etc.). These are the
    /// exact same encryption parameters that are created by the user and passed to the
    /// constructor of SEALContext. The properties KeyContextData and KeyParmsId return the
    /// ContextData and the ParmsId corresponding to these special parameters. The rest of the
    /// ContextData instances in the chain correspond to encryption parameters that are derived
    /// from the first encryption parameters by always removing the last one of the moduli in
    /// the CoeffModulus, until the resulting parameters are no longer valid, e.g., there are
    /// no more primes left. These derived encryption parameters are used by ciphertexts and
    /// plaintexts and their respective ContextData can be accessed through the
    /// GetContextData(ParmsId) function. The properties FirstContextData and LastContextData
    /// return the ContextData corresponding to the first and the last set of parameters in
    /// the "data" part of the chain, i.e., the second and the last element in the full chain.
    /// The chain is a doubly linked list and is referred to as the modulus switching chain.
    /// </para>
    /// </remarks>
    /// <see cref="EncryptionParameters">see EncryptionParameters for more details on the parameters.</see>
    /// <see cref="EncryptionParameterQualifiers">see EncryptionParameterQualifiers for more details on the qualifiers.</see>
    public class SEALContext : NativeObject
    {
        /// <summary>
        /// Creates an instance of SEALContext and performs several pre-computations
        /// on the given EncryptionParameters.
        /// </summary>
        /// <param name="parms">The encryption parameters.</param>
        /// <param name="expandModChain">Determines whether the modulus switching chain
        /// should be created</param>
        /// <param name="secLevel">Determines whether a specific security level should be
        /// enforced according to HomomorphicEncryption.org security standard</param>
        /// <exception cref="ArgumentNullException">if parms is null</exception>
        public SEALContext(EncryptionParameters parms,
            bool expandModChain = true, SecLevelType secLevel = SecLevelType.TC128)
        {
            if (null == parms)
                throw new ArgumentNullException(nameof(parms));

            NativeMethods.SEALContext_Create(parms.NativePtr,
                expandModChain, (int)secLevel, out IntPtr context);
            NativePtr = context;
        }

        /// <summary>
        /// Returns the ContextData corresponding to encryption parameters with a given
        /// parmsId. If parameters with the given ParmsId are not found then the function
        /// returns null.
        /// </summary>
        ///
        /// <param name="parmsId">The ParmsId of the encryption parameters</param>
        /// <exception cref="ArgumentNullException">if parmsId is null</exception>
        public ContextData GetContextData(ParmsId parmsId)
        {
            if (null == parmsId)
                throw new ArgumentNullException(nameof(parmsId));

            NativeMethods.SEALContext_GetContextData(NativePtr, parmsId.Block, out IntPtr contextData);
            if (IntPtr.Zero.Equals(contextData))
                return null;

            ContextData data = new ContextData(contextData, owned: false);
            return data;
        }

        /// <summary>
        /// Returns the ContextData corresponding to encryption parameters that are
        /// used for keys.
        /// </summary>
        public ContextData KeyContextData
        {
            get
            {
                NativeMethods.SEALContext_KeyContextData(NativePtr, out IntPtr contextData);
                ContextData data = new ContextData(contextData, owned: false);
                return data;
            }
        }

        /// <summary>
        /// Returns the ContextData corresponding to the first encryption parameters
        /// that are used for data.
        /// </summary>
        public ContextData FirstContextData
        {
            get
            {
                NativeMethods.SEALContext_FirstContextData(NativePtr, out IntPtr contextData);
                ContextData data = new ContextData(contextData, owned: false);
                return data;
            }
        }

        /// <summary>
        /// Returns the ContextData corresponding to the last encryption parameters
        /// that are used for data.
        /// </summary>
        public ContextData LastContextData
        {
            get
            {
                NativeMethods.SEALContext_LastContextData(NativePtr, out IntPtr contextData);
                ContextData data = new ContextData(contextData, owned: false);
                return data;
            }
        }

        /// <summary>
        /// Returns whether the encryption parameters are valid.
        /// </summary>
        public bool ParametersSet
        {
            get
            {
                NativeMethods.SEALContext_ParametersSet(NativePtr, out bool paramsSet);
                return paramsSet;
            }
        }

        /// <summary>
        /// If the encryption parameters are set in a way that is considered valid by SEAL, return "success".
        /// If the encryption parameters are set but not validated yet, return "none".
        /// Otherwise, return a brief reason.
        /// </summary>
        public string ParameterErrorName()
        {
            NativeMethods.SEALContext_ParameterErrorName(NativePtr, null, out ulong length);
            byte[] buffer = new byte[length];
            NativeMethods.SEALContext_ParameterErrorName(NativePtr, buffer, out length);
            return Encoding.ASCII.GetString(buffer);
        }

        /// <summary>
        /// If the encryption parameters are set in a way that is considered valid by SEAL, return "valid".
        /// Otherwise, return a comprehensive reason.
        /// </summary>
        public string ParameterErrorMessage()
        {
            NativeMethods.SEALContext_ParameterErrorMessage(NativePtr, null, out ulong length);
            byte[] buffer = new byte[length];
            NativeMethods.SEALContext_ParameterErrorMessage(NativePtr, buffer, out length);
            return Encoding.ASCII.GetString(buffer);
        }

        /// <summary>
        /// Returns a ParmsId corresponding to the set of encryption parameters
        /// that are used for keys.
        /// </summary>
        public ParmsId KeyParmsId
        {
            get
            {
                ParmsId parms = new ParmsId();
                NativeMethods.SEALContext_KeyParmsId(NativePtr, parms.Block);
                return parms;
            }
        }

        /// <summary>
        /// Returns a ParmsId corresponding to the first encryption parameters that
        /// are used for data.
        /// </summary>
        public ParmsId FirstParmsId
        {
            get
            {
                ParmsId parms = new ParmsId();
                NativeMethods.SEALContext_FirstParmsId(NativePtr, parms.Block);
                return parms;
            }
        }

        /// <summary>
        /// Returns a ParmsId corresponding to the last encryption parameters that
        /// are used for data.
        /// </summary>
        public ParmsId LastParmsId
        {
            get
            {
                ParmsId parms = new ParmsId();
                NativeMethods.SEALContext_LastParmsId(NativePtr, parms.Block);
                return parms;
            }
        }


        /// <summary>
        /// Returns whether the coefficient modulus supports keyswitching.
        /// </summary>
        /// <remarks>
        /// Returns whether the coefficient modulus supports keyswitching. In
        /// practice, support for keyswitching is required by Evaluator.Relinearize,
        /// Evaluator.ApplyGalois, and all rotation and conjugation operations.
        /// For keyswitching to be available, the coefficient modulus parameter must
        /// consist of at least two prime number factors.
        /// </remarks>
        public bool UsingKeyswitching
        {
            get
            {
                NativeMethods.SEALContext_UsingKeyswitching(NativePtr, out bool result);
                return result;
            }
        }

        /// <summary>
        /// Destroy native object.
        /// </summary>
        protected override void DestroyNativeObject()
        {
            NativeMethods.SEALContext_Destroy(NativePtr);
        }

        /// <summary>
        /// Class to hold pre-computation data for a given set of encryption parameters.
        /// </summary>
        public class ContextData : NativeObject
        {
            /// <summary>
            /// Build a ContextData object from a native pointer.
            /// </summary>
            /// <param name="ptr">Pointer to native object</param>
            /// <param name="owned">Whether this instance owns the native object</param>
            internal ContextData(IntPtr ptr, bool owned = true)
                : base(ptr, owned)
            {
            }

            /// <summary>
            /// Returns a copy of the underlying encryption parameters.
            /// </summary>
            public EncryptionParameters Parms
            {
                get
                {
                    NativeMethods.ContextData_Parms(NativePtr, out IntPtr parms);
                    return new EncryptionParameters(parms);
                }
            }

            /// <summary>
            /// Returns the ParmsId of the current parameters.
            /// </summary>
            public ParmsId ParmsId
            {
                get
                {
                    return Parms.ParmsId;
                }
            }


            /// <summary>
            /// Returns a copy of EncryptionParameterQualifiers corresponding to the
            /// current encryption parameters.
            /// </summary>
            /// <remarks>
            /// Returns a copy of EncryptionParameterQualifiers corresponding to the
            /// current encryption parameters. Note that to change the qualifiers it is
            /// necessary to create a new instance of SEALContext once appropriate changes
            /// to the encryption parameters have been made.
            /// </remarks>
            public EncryptionParameterQualifiers Qualifiers
            {
                get
                {
                    NativeMethods.ContextData_Qualifiers(NativePtr, out IntPtr epq);
                    EncryptionParameterQualifiers qualifiers = new EncryptionParameterQualifiers(epq);
                    return qualifiers;
                }
            }

            /// <summary>
            /// Returns a the pre-computed product of all primes in the
            /// coefficient modulus.
            /// </summary>
            /// <remarks>
            /// Returns a the pre-computed product of all primes in the
            /// coefficient modulus. The security of the encryption parameters largely depends
            /// on the bit-length of this product, and on the degree of the polynomial modulus.
            /// </remarks>
            public ulong[] TotalCoeffModulus
            {
                get
                {
                    ulong count = 0;
                    NativeMethods.ContextData_TotalCoeffModulus(NativePtr, ref count, null);

                    ulong[] result = new ulong[count];
                    NativeMethods.ContextData_TotalCoeffModulus(NativePtr, ref count, result);

                    return result;
                }
            }

            /// <summary>
            /// Returns the significant bit count of the total coefficient modulus.
            /// </summary>
            public int TotalCoeffModulusBitCount
            {
                get
                {
                    NativeMethods.ContextData_TotalCoeffModulusBitCount(NativePtr, out int bitCount);
                    return bitCount;
                }
            }

            /// <summary>
            /// Return a copy of BFV "Delta", i.e. coefficient modulus divided by
            /// plaintext modulus.
            /// </summary>
            public ulong[] CoeffDivPlainModulus
            {
                get
                {
                    ulong count = 0;
                    NativeMethods.ContextData_CoeffDivPlainModulus(NativePtr, ref count, null);

                    ulong[] cdpm = new ulong[count];
                    NativeMethods.ContextData_CoeffDivPlainModulus(NativePtr, ref count, cdpm);

                    return cdpm;
                }
            }

            /// <summary>
            /// Return the threshold for the upper half of integers modulo PlainModulus.
            /// This is simply(PlainModulus + 1) / 2.
            /// </summary>
            public ulong PlainUpperHalfThreshold
            {
                get
                {
                    NativeMethods.ContextData_PlainUpperHalfThreshold(NativePtr, out ulong puht);
                    return puht;
                }
            }

            /// <summary>
            /// Return a copy of the plaintext upper half increment, i.e. coeffModulus
            /// minus plainModulus.
            /// </summary>
            /// <remarks>
            /// Return a copy of the plaintext upper half increment, i.e. coeffModulus
            /// minus plainModulus. The upper half increment is represented as an integer
            /// for the full product coeffModulus if UsingFastPlainLift is false and is
            /// otherwise represented modulo each of the CoeffModulus primes in order.
            /// </remarks>
            public ulong[] PlainUpperHalfIncrement
            {
                get
                {
                    ulong count = 0;
                    NativeMethods.ContextData_PlainUpperHalfIncrement(NativePtr, ref count, null);

                    ulong[] puhi = new ulong[count];
                    NativeMethods.ContextData_PlainUpperHalfIncrement(NativePtr, ref count, puhi);

                    return puhi;
                }
            }

            /// <summary>
            /// Return a copy of the upper half threshold with respect to the total
            /// coefficient modulus. This is needed in CKKS decryption.
            /// </summary>
            public ulong[] UpperHalfThreshold
            {
                get
                {
                    ulong count = 0;
                    NativeMethods.ContextData_UpperHalfThreshold(NativePtr, ref count, null);

                    if (count == 0)
                        return null;

                    ulong[] uht = new ulong[count];
                    NativeMethods.ContextData_UpperHalfThreshold(NativePtr, ref count, uht);

                    return uht;
                }
            }

            /// <summary>
            /// Return a copy of the upper half increment used for computing Delta*m
            /// and converting the coefficients to modulo CoeffModulus.
            /// </summary>
            /// <remarks>
            /// Return a copy of the upper half increment used for computing Delta*m
            /// and converting the coefficients to modulo CoeffModulus. For example,
            /// t-1 in plaintext should change into
            /// q - Delta = Delta*t + r_t(q) - Delta = Delta*(t-1) + r_t(q)
            /// so multiplying the message by Delta is not enough and requires also an
            /// addition of r_t(q). This is precisely the UpperHalfIncrement. Note that
            /// this operation is only done for negative message coefficients, i.e. those
            /// that exceed PlainUpperHalfThreshold.
            /// </remarks>
            public ulong[] UpperHalfIncrement
            {
                get
                {
                    ulong count = 0;
                    NativeMethods.ContextData_UpperHalfIncrement(NativePtr, ref count, null);

                    if (count == 0)
                        return null;

                    ulong[] uhi = new ulong[count];
                    NativeMethods.ContextData_UpperHalfIncrement(NativePtr, ref count, uhi);

                    return uhi;
                }
            }

            /// <summary>
            /// Returns the context data corresponding to the previous parameters in the
            /// modulus switching chain.
            /// </summary>
            /// <remarks>
            /// Returns the context data corresponding to the previous parameters in the
            /// modulus switching chain. If the current data is the first one in the chain,
            /// then the result is nullptr.
            /// </remarks>
            public ContextData PrevContextData
            {
                get
                {
                    NativeMethods.ContextData_PrevContextData(NativePtr, out IntPtr prev);

                    if (IntPtr.Zero.Equals(prev))
                        return null;

                    ContextData data = new ContextData(prev, owned: false);
                    return data;
                }
            }

            /// <summary>
            /// Returns the context data corresponding to the next parameters in the modulus
            /// switching chain.
            /// </summary>
            /// <remarks>
            /// Returns the context data corresponding to the next parameters in the modulus
            /// switching chain. If the current data is the last one in the chain, then the
            /// result is nullptr.
            /// </remarks>
            public ContextData NextContextData
            {
                get
                {
                    NativeMethods.ContextData_NextContextData(NativePtr, out IntPtr next);

                    if (IntPtr.Zero.Equals(next))
                        return null;

                    ContextData data = new ContextData(next, owned: false);
                    return data;
                }
            }

            /// <summary>
            /// Returns the index of the parameter set in a chain.
            /// </summary>
            /// <remarks>
            /// Returns the index of the parameter set in a chain. The initial parameters
            /// have index 0 and the index increases sequentially in the parameter chain.
            /// </remarks>
            public ulong ChainIndex
            {
                get
                {
                    NativeMethods.ContextData_ChainIndex(NativePtr, out ulong index);
                    return index;
                }
            }

            /// <summary>
            /// Destroy native object.
            /// </summary>
            protected override void DestroyNativeObject()
            {
                NativeMethods.ContextData_Destroy(NativePtr);
            }
        }
    }
}