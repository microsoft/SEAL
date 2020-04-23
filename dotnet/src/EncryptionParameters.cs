// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

using Microsoft.Research.SEAL.Tools;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;

namespace Microsoft.Research.SEAL
{
    /// <summary>
    /// Describes the type of encryption scheme to be used.
    /// </summary>
    public enum SchemeType : byte
    {
        /// <summary>
        /// No scheme set; cannot be used for encryption
        /// </summary>
        None = 0x0,

        /// <summary>
        /// Brakerski/Fan-Vercauteren scheme
        /// </summary>
        BFV = 0x1,

        /// <summary>
        /// Cheon-Kim-Kim-Song scheme
        /// </summary>
        CKKS = 0x2
    }

    /// <summary>
    /// Represents the user-customizable encryption scheme settings.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Represents user-customizable encryption scheme settings. The parameters (most
    /// importantly PolyModulus, CoeffModulus, PlainModulus) significantly affect the
    /// performance, capabilities, and security of the encryption scheme. Once an
    /// instance of EncryptionParameters is populated with appropriate parameters, it
    /// can be used to create an instance of the <see cref="SEALContext" /> class,
    /// which verifies the validity of the parameters, and performs necessary
    /// pre-computations.
    /// </para>
    /// <para>
    /// Picking appropriate encryption parameters is essential to enable a particular
    /// application while balancing performance and security. Some encryption settings
    /// will not allow some inputs (e.g. attempting to encrypt a polynomial with more
    /// coefficients than PolyModulus or larger coefficients than PlainModulus) or
    /// support the desired computations (with noise growing too fast due to too large
    /// PlainModulus and too small CoeffModulus).
    /// </para>
    /// <para>
    /// The EncryptionParameters class maintains at all times a 256-bit hash of the
    /// currently set encryption parameters called the ParmsId. This hash acts as
    /// a unique identifier of the encryption parameters and is used by all further
    /// objects created for these encryption parameters. The ParmsId is not intended
    /// to be directly modified by the user but is used internally for pre-computation
    /// data lookup and input validity checks. In modulus switching the user can use
    /// the ParmsId to keep track of the chain of encryption parameters. The ParmsId is
    /// not exposed in the public API of EncryptionParameters, but can be accessed
    /// through the <see cref="SEALContext.ContextData" /> class once the SEALContext
    /// has been created.
    /// </para>
    /// <para>
    /// In general, reading from EncryptionParameters is thread-safe, while mutating
    /// is not.
    /// </para>
    /// <para>
    /// Choosing inappropriate encryption parameters may lead to an encryption scheme
    /// that is not secure, does not perform well, and/or does not support the input
    /// and computation of the desired application. We highly recommend consulting an
    /// expert in RLWE-based encryption when selecting parameters, as this is where
    /// inexperienced users seem to most often make critical mistakes.
    /// </para>
    /// </remarks>
    public class EncryptionParameters : NativeObject, IEquatable<EncryptionParameters>
    {
        /// <summary>
        /// Creates an empty set of encryption parameters.
        /// </summary>
        ///
        /// <param name="scheme">Scheme for the encryption parameters</param>
        public EncryptionParameters(SchemeType scheme = SchemeType.None)
        {
            NativeMethods.EncParams_Create((byte)scheme, out IntPtr ptr);
            NativePtr = ptr;
        }

        /// <summary>
        /// Creates an empty set of encryption parameters.
        /// </summary>
        /// <param name="scheme">Scheme for the encryption parameters</param>
        /// <exception cref="ArgumentException">if scheme is not supported</exception>
        public EncryptionParameters(byte scheme)
        {
            NativeMethods.EncParams_Create(scheme, out IntPtr ptr);
            NativePtr = ptr;
        }

        /// <summary>
        /// Creates a copy of a given instance of EncryptionParameters.
        /// </summary>
        /// <param name="copy">The EncryptionParameters to copy from</param>
        /// <exception cref="ArgumentNullException">if copy is null</exception>
        public EncryptionParameters(EncryptionParameters copy)
        {
            if (null == copy)
                throw new ArgumentNullException(nameof(copy));

            NativeMethods.EncParams_Create(copy.NativePtr, out IntPtr ptr);
            NativePtr = ptr;
        }

        /// <summary>
        /// Create an instance of Encryption Parameters through a pointer to a
        /// native object.
        /// </summary>
        /// <param name="ptr">Native encryption parameters</param>
        /// <param name="owned">Whether this instance owns the native pointer</param>
        internal EncryptionParameters(IntPtr ptr, bool owned = true)
            : base(ptr, owned)
        {
        }

        /// <summary>
        /// Overwrites the EncryptionParameters instance with a copy of a given
        /// instance.
        /// </summary>
        /// <param name="assign">The EncryptionParameters to copy from</param>
        /// <exception cref="ArgumentNullException">if assign is null</exception>
        public void Set(EncryptionParameters assign)
        {
            if (null == assign)
                throw new ArgumentNullException(nameof(assign));

            NativeMethods.EncParams_Set(NativePtr, assign.NativePtr);
        }

        /// <summary>
        /// Returns or Sets the degree of the polynomial modulus parameter.
        /// </summary>
        /// <remarks>
        /// Sets the degree of the polynomial modulus parameter to the specified value.
        /// The polynomial modulus directly affects the number of coefficients in plaintext
        /// polynomials, the size of ciphertext elements, the computational performance of
        /// the scheme (bigger is worse), and the security level(bigger is better). In SEAL
        /// the degree of the polynomial modulus must be a power of 2 (e.g. 1024, 2048, 4096,
        /// 8192, 16384, or 32768).
        /// </remarks>
        public ulong PolyModulusDegree
        {
            get
            {
                NativeMethods.EncParams_GetPolyModulusDegree(NativePtr, out ulong result);
                return result;
            }
            set
            {
                NativeMethods.EncParams_SetPolyModulusDegree(NativePtr, value);
            }
        }

        /// <summary>
        /// Get a copy of the currently set coefficient modulus parameter, or
        /// set the coefficient modulus parameter.
        /// </summary>
        /// <remarks>
        /// When setting:
        ///     Sets the coefficient modulus parameter. The coefficient modulus consists of a list
        ///     of distinct prime numbers, and is represented by a list of <see cref="Modulus" />
        ///     objects. The coefficient modulus directly affects the size of ciphertext elements,
        ///     the amount of computation that the scheme can perform (bigger is better), and the
        ///     security level (bigger is worse). In Microsoft SEAL each of the prime numbers in
        ///     the coefficient modulus must be at most 60 bits, and must be congruent to 1 modulo
        ///     2*PolyModulusDegree.
        /// </remarks>
        /// <exception cref="ArgumentNullException">if the value being set is null</exception>
        /// <exception cref="ArgumentException">if the value being set is invalid</exception>
        public IEnumerable<Modulus> CoeffModulus
        {
            get
            {
                ulong length = 0;
                NativeMethods.EncParams_GetCoeffModulus(NativePtr, ref length, null);

                IntPtr[] coeffArray = new IntPtr[length];
                NativeMethods.EncParams_GetCoeffModulus(NativePtr, ref length, coeffArray);

                List<Modulus> result = new List<Modulus>(checked((int)length));
                foreach(IntPtr sm in coeffArray)
                {
                    result.Add(new Modulus(sm));
                }

                return result;
            }

            set
            {
                if (null == value)
                    throw new ArgumentNullException(nameof(value));

                IntPtr[] coeffArray = value.Select(sm => sm.NativePtr).ToArray();
                NativeMethods.EncParams_SetCoeffModulus(NativePtr, (ulong)coeffArray.LongLength, coeffArray);
            }
        }

        /// <summary>
        /// Get a copy of the currently set plaintext modulus parameter, or
        /// set the plaintext modulus parameter.
        /// </summary>
        /// <remarks>
        /// When setting:
        ///     Sets the plaintext modulus parameter. The plaintext modulus is an integer modulus
        ///     represented by the <see cref="Modulus" /> class. The plaintext modulus determines
        ///     the largest coefficient that plaintext polynomials can represent. It also affects the
        ///     amount of computation that the scheme can perform (bigger is worse). In Microsoft SEAL
        ///     the plaintext modulus can be at most 60 bits long, but can otherwise be any integer.
        ///     Note, however, that some features (e.g. batching) require the plaintext modulus to be
        ///     of a particular form.
        /// </remarks>
        /// <exception cref="ArgumentNullException">if the value being set is null</exception>
        /// <exception cref="InvalidOperationException">if scheme is not SchemeType.BFV</exception>
        public Modulus PlainModulus
        {
            get
            {
                NativeMethods.EncParams_GetPlainModulus(NativePtr, out IntPtr ptr);
                Modulus sm = new Modulus(ptr, owned: false);
                return sm;
            }
            set
            {
                NativeMethods.EncParams_SetPlainModulus(NativePtr, value.NativePtr);
            }
        }

        /// <summary>
        /// Sets the plaintext modulus parameter.
        /// </summary>
        /// <remarks>
        /// Sets the plaintext modulus parameter. The plaintext modulus is an integer modulus
        /// represented by the <see cref="Modulus" /> class. This method instead takes
        /// a ulong and automatically creates the Modulus object. The plaintext modulus
        /// determines the largest coefficient that plaintext polynomials can represent. It also
        /// affects the amount of computation that the scheme can perform (bigger is worse). In
        /// Microsoft SEAL the plaintext modulus can be at most 60 bits long, but can otherwise
        /// be any integer. Note, however, that some features (e.g. batching) require the
        /// plaintext modulus to be of a particular form.
        /// </remarks>
        /// <param name="plainModulus">The new plaintext modulus</param>
        /// <exception cref="InvalidOperationException">if scheme is not CKKS</exception>
        public void SetPlainModulus(ulong plainModulus)
        {
            NativeMethods.EncParams_SetPlainModulus(NativePtr, plainModulus);
        }

        /// <summary>
        /// Returns the encryption scheme type.
        /// </summary>
        public SchemeType Scheme
        {
            get
            {
                NativeMethods.EncParams_GetScheme(NativePtr, out byte scheme);
                return (SchemeType)scheme;
            }
        }

        /// <summary>
        /// Returns an upper bound on the size of the EncryptionParameters, as if
        /// it was written to an output stream.
        /// </summary>
        /// <param name="comprMode">The compression mode</param>
        /// <exception cref="ArgumentException">if the compression mode is not
        /// supported</exception>
        /// <exception cref="InvalidOperationException">if the size does not fit in
        /// the return type</exception>
        public long SaveSize(ComprModeType? comprMode = null)
        {
            comprMode = comprMode ?? Serialization.ComprModeDefault;
            if (!Serialization.IsSupportedComprMode(comprMode.Value))
                throw new ArgumentException("Unsupported compression mode");

            ComprModeType comprModeValue = comprMode.Value;
            NativeMethods.EncParams_SaveSize(
                NativePtr, (byte)comprModeValue, out long outBytes);
            return outBytes;
        }

        /// <summary>Saves the EncryptionParameters to an output stream.</summary>
        /// <remarks>
        /// Saves the EncryptionParameters to an output stream. The output is in
        /// binary format and not human-readable.
        /// </remarks>
        /// <param name="stream">The stream to save the EncryptionParameters to</param>
        /// <param name="comprMode">The desired compression mode</param>
        /// <exception cref="ArgumentNullException">if stream is null</exception>
        /// <exception cref="ArgumentException">if the stream is closed or does not
        /// support writing, or if compression mode is not supported</exception>
        /// <exception cref="IOException">if I/O operations failed</exception>
        /// <exception cref="InvalidOperationException">if the data to be saved
        /// is invalid, or if compression failed</exception>
        public long Save(Stream stream, ComprModeType? comprMode = null)
        {
            comprMode = comprMode ?? Serialization.ComprModeDefault;
            if (!Serialization.IsSupportedComprMode(comprMode.Value))
                throw new ArgumentException("Unsupported compression mode");

            ComprModeType comprModeValue = comprMode.Value;
            return Serialization.Save(
                (byte[] outptr, ulong size, byte cm, out long outBytes) =>
                    NativeMethods.EncParams_Save(NativePtr, outptr, size,
                    cm, out outBytes),
                SaveSize(comprModeValue), comprModeValue, stream);
        }

        /// <summary>
        /// Loads an EncryptionParameters from an input stream overwriting the
        /// current EncryptionParameters.
        /// </summary>
        /// <param name="stream">The stream to load the EncryptionParameters from</param>
        /// <exception cref="ArgumentNullException">if stream is null</exception>
        /// <exception cref="ArgumentException">if the stream is closed or does not
        /// support reading</exception>
        /// <exception cref="EndOfStreamException">if the stream ended
        /// unexpectedly</exception>
        /// <exception cref="IOException">if I/O operations failed</exception>
        /// <exception cref="InvalidOperationException">if the data cannot be loaded
        /// by this version of Microsoft SEAL, if the loaded data is invalid, or if the
        /// loaded compression mode is not supported</exception>
        public long Load(Stream stream)
        {
            return Serialization.Load(
                (byte[] outptr, ulong size, out long outBytes) =>
                    NativeMethods.EncParams_Load(NativePtr, outptr, size,
                    out outBytes),
                stream);
        }

        /// <summary>
        /// Returns the ParmsId of the current parameters. This function is intended
        /// for internal use.
        /// </summary>
        internal ParmsId ParmsId
        {
            get
            {
                ParmsId id = new ParmsId();
                NativeMethods.EncParams_GetParmsId(NativePtr, id.Block);
                return id;
            }
        }

        /// <summary>
        /// Compares a given set of encryption parameters to the current set of
        /// encryption parameters.
        /// </summary>
        /// <remarks>
        /// Compares a given set of encryption parameters to the current set of encryption
        /// parameters. The comparison is performed by comparing hash blocks of the parameter
        /// sets rather than comparing the parameters individually.
        /// </remarks>
        /// <param name="obj">The EncryptionParameters to compare against</param>
        public override bool Equals(object obj)
        {
            EncryptionParameters encParams = obj as EncryptionParameters;
            return Equals(encParams);
        }

        /// <summary>
        /// Returns a hash-code based on the EncryptionParameters.
        /// </summary>
        public override int GetHashCode()
        {
            return Utilities.ComputeArrayHashCode(ParmsId.Block);
        }

        #region IEquatable<EncryptionParameters> methods

        /// <summary>
        /// Compares a given set of encryption parameters to the current set of
        /// encryption parameters.
        /// </summary>
        ///
        /// <remarks>
        /// Compares a given set of encryption parameters to the current set of encryption
        /// parameters. The comparison is performed by comparing hash blocks of the parameter
        /// sets rather than comparing the parameters individually.
        /// </remarks>
        /// <param name="other">The EncryptionParameters to compare against</param>
        public bool Equals(EncryptionParameters other)
        {
            if (null == other)
                return false;

            NativeMethods.EncParams_Equals(NativePtr, other.NativePtr, out bool result);
            return result;
        }

        #endregion

        /// <summary>
        /// Destroy native object.
        /// </summary>
        protected override void DestroyNativeObject()
        {
            NativeMethods.EncParams_Destroy(NativePtr);
        }
    }
}
