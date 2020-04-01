// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

using System;
using System.Text;
using Microsoft.Research.SEAL.Tools;

namespace Microsoft.Research.SEAL
{
    /// <summary>
    /// Stores a set of attributes (qualifiers) of a set of encryption parameters.
    /// </summary>
    ///
    /// <remarks>
    /// Stores a set of attributes (qualifiers) of a set of encryption parameters.
    /// These parameters are mainly used internally in various parts of the library,
    /// e.g., to determine which algorithmic optimizations the current support.
    /// The qualifiers are automatically created by the <see cref="SEALContext" />
    /// class, silently passed on to classes such as <see cref="Encryptor" />,
    /// <see cref="Evaluator" />, and <see cref="Decryptor" />, and the only way
    /// to change them is by changing the encryption parameters themselves. In
    /// other words, a user will never have to create their own instance of this
    /// class, and in most cases never have to worry about it at all.
    /// </remarks>
    public class EncryptionParameterQualifiers : NativeObject
    {
        /// <summary>
        /// Create a copy of an existing instance of EncryptionParameterQualifiers
        /// </summary>
        /// <param name="copy">Original object to copy</param>
        public EncryptionParameterQualifiers(EncryptionParameterQualifiers copy)
        {
            if (null == copy)
                throw new ArgumentNullException(nameof(copy));

            NativeMethods.EPQ_Create(copy.NativePtr, out IntPtr ptr);
            NativePtr = ptr;
        }

        /// <summary>
        /// Create an instance of EncryptionParameterQualifiers through a pointer to
        /// a native object.
        /// </summary>
        /// <param name="ptr">Pointer to native EncryptionParameterQualifiers.</param>
        /// <param name="owned">Whether this instance owns the native pointer.</param>
        internal EncryptionParameterQualifiers(IntPtr ptr, bool owned = true)
            : base(ptr, owned)
        {
        }

        /// <summary>
        /// If the encryption parameters are set in a way that is considered valid by SEAL,
        /// the variable ParametersSet is set to true.
        /// </summary>
        public bool ParametersSet
        {
            get
            {
                NativeMethods.EPQ_ParametersSet(NativePtr, out bool result);
                return result;
            }
        }

        /// <summary>
        /// If the encryption parameters are set in a way that is considered valid by SEAL, return "success".
        /// If the encryption parameters are set but not validated yet, return "none".
        /// Otherwise, return a brief reason.
        /// </summary>
        public string ParametersErrorName()
        {
            NativeMethods.EPQ_ParameterErrorName(NativePtr, null, out ulong length);
            StringBuilder buffer = new StringBuilder(checked((int)length));
            NativeMethods.EPQ_ParameterErrorName(NativePtr, buffer, out length);
            return buffer.ToString();
        }

        /// <summary>
        /// If the encryption parameters are set in a way that is considered valid by SEAL, return "valid".
        /// Otherwise, return a comprehensive reason.
        /// </summary>
        public string ParametersErrorMessage()
        {
            NativeMethods.EPQ_ParameterErrorMessage(NativePtr, null, out ulong length);
            StringBuilder buffer = new StringBuilder(checked((int)length));
            NativeMethods.EPQ_ParameterErrorMessage(NativePtr, buffer, out length);
            return buffer.ToString();
        }

        /// <summary>
        /// Tells whether FFT can be used for polynomial multiplication.
        /// </summary>
        ///
        /// <remarks>
        /// Tells whether FFT can be used for polynomial multiplication. If the polynomial modulus
        /// is of the form X^N+1, where N is a power of two, then FFT can be used for fast
        /// multiplication of polynomials modulo the polynomial modulus. In this case the
        /// variable UsingFFT will be set to true. However, currently Microsoft SEAL requires this
        /// to be the case for the parameters to be valid. Therefore, ParametersSet can only
        /// be true if UsingFFT is true.
        /// </remarks>
        public bool UsingFFT
        {
            get
            {
                NativeMethods.EPQ_UsingFFT(NativePtr, out bool result);
                return result;
            }
        }

        /// <summary>
        /// Tells whether NTT can be used for polynomial multiplication.
        /// </summary>
        ///
        /// <remarks>
        /// Tells whether NTT can be used for polynomial multiplication. If the primes in the
        /// coefficient modulus are congruent to 1 modulo 2N, where X^N+1 is the polynomial
        /// modulus and N is a power of two, then the number-theoretic transform (NTT) can be
        /// used for fast multiplications of polynomials modulo the polynomial modulus and
        /// coefficient modulus.In this case the variable UsingNTT will be set to true. However,
        /// currently Microsoft SEAL requires this to be the case for the parameters to be valid.
        /// Therefore, ParametersSet can only be true if UsingNTT is true.
        /// </remarks>
        public bool UsingNTT
        {
            get
            {
                NativeMethods.EPQ_UsingNTT(NativePtr, out bool result);
                return result;
            }
        }

        /// <summary>
        /// Tells whether batching is supported by the encryption parameters.
        /// </summary>
        ///
        /// <remarks>
        /// Tells whether batching is supported by the encryption parameters. If the plaintext
        /// modulus is congruent to 1 modulo 2N, where X^N+1 is the polynomial modulus and N is
        /// a power of two, then it is possible to use the BatchEncoder class to view plaintext
        /// elements as 2-by-(N/2) matrices of integers modulo the plaintext modulus.This is
        /// called batching, and allows the user to operate on the matrix elements(slots) in
        /// a SIMD fashion, and rotate the matrix rows and columns.When the computation is
        /// easily vectorizable, using batching can yield a huge performance boost.If the
        /// encryption parameters support batching, the variable UsingBatching is set to true.
        /// </remarks>
        public bool UsingBatching
        {
            get
            {
                NativeMethods.EPQ_UsingBatching(NativePtr, out bool result);
                return result;
            }
        }

        /// <summary>
        /// Tells whether fast plain lift is supported by the encryption parameters.
        /// </summary>
        ///
        /// <remarks>
        /// Tells whether fast plain lift is supported by the encryption parameters. A certain
        /// performance optimization in multiplication of a ciphertext by a plaintext
        /// (Evaluator.MultiplyPlain) and in transforming a plaintext element to NTT domain
        /// (Evaluator.TransformToNTT) can be used when the plaintext modulus is smaller than
        /// each prime in the coefficient modulus. In this case the variable UsingFastPlainLift
        /// is set to true.
        /// </remarks>
        public bool UsingFastPlainLift
        {
            get
            {
                NativeMethods.EPQ_UsingFastPlainLift(NativePtr, out bool result);
                return result;
            }
        }

        /// <summary>
        /// Tells whether the coefficient modulus consists of a set of primes that are in
        /// decreasing order.
        /// </summary>
        ///
        /// <remarks>
        /// Tells whether the coefficient modulus consists of a set of primes that are in
        /// decreasing order. If this is true, certain modular reductions in base conversion
        /// can be omitted, improving performance.
        /// </remarks>
        public bool UsingDescendingModulusChain
        {
            get
            {
                NativeMethods.EPQ_UsingDescendingModulusChain(NativePtr, out bool result);
                return result;
            }
        }

        /// <summary>
        /// Tells whether the encryption parameters are secure based on the standard
        /// parameters from HomomorphicEncryption.org security standard.
        /// </summary>
        public SecLevelType SecLevel
        {
            get
            {
                NativeMethods.EPQ_SecLevel(NativePtr, out int result);
                return (SecLevelType)result;
            }
        }

        /// <summary>
        /// Destroy native object.
        /// </summary>
        protected override void DestroyNativeObject()
        {
            NativeMethods.EPQ_Destroy(NativePtr);
        }
    }
}