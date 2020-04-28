// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

using Microsoft.Research.SEAL.Tools;
using System;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;

namespace Microsoft.Research.SEAL
{
    /// <summary>
    /// Class to store a plaintext element.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Class to store a plaintext element. The data for the plaintext is
    /// a polynomial with coefficients modulo the plaintext modulus. The degree
    /// of the plaintext polynomial must be one less than the degree of the
    /// polynomial modulus. The backing array always allocates one 64-bit word
    /// per each coefficient of the polynomial.
    /// </para>
    /// <para>
    /// Memory Management
    /// The coefficient count of a plaintext refers to the number of word-size
    /// coefficients in the plaintext, whereas its capacity refers to the number
    /// of word-size coefficients that fit in the current memory allocation. In
    /// high-performance applications unnecessary re-allocations should be avoided
    /// by reserving enough memory for the plaintext to begin with either by
    /// providing the desired capacity to the constructor as an extra argument, or
    /// by calling the reserve function at any time.
    ///
    /// When the scheme is SchemeType.BFV each coefficient of a plaintext is
    /// a 64-bit word, but when the scheme is SchemeType.CKKS the plaintext is
    /// by default stored in an NTT transformed form with respect to each of the
    /// primes in the coefficient modulus. Thus, the size of the allocation that
    /// is needed is the size of the coefficient modulus (number of primes) times
    /// the degree of the polynomial modulus. In addition, a valid CKKS plaintext
    /// will also store the ParmsId for the corresponding encryption parameters.
    /// </para>
    /// <para>
    /// Thread Safety
    /// In general, reading from plaintext is thread-safe as long as no other
    /// thread is concurrently mutating it. This is due to the underlying data
    /// structure storing the plaintext not being thread-safe.
    /// </para>
    /// </remarks>
    /// <seealso cref="Ciphertext">See Ciphertext for the class that stores ciphertexts.</seealso>
    public class Plaintext : NativeObject, IEquatable<Plaintext>
    {
        /// <summary>
        /// Constructs an empty plaintext allocating no memory.
        /// </summary>
        /// <param name="pool">The MemoryPoolHandle pointing to a valid memory pool</param>
        /// <exception cref="ArgumentException">if pool is uninitialized</exception>
        public Plaintext(MemoryPoolHandle pool = null)
        {
            IntPtr poolPtr = pool?.NativePtr ?? IntPtr.Zero;

            NativeMethods.Plaintext_Create1(poolPtr, out IntPtr ptr);
            NativePtr = ptr;
        }

        /// <summary>
        /// Constructs a plaintext representing a constant polynomial 0. The
        /// coefficient count of the polynomial is set to the given value. The
        /// capacity is set to the same value.
        /// </summary>
        /// <param name="coeffCount">The number of (zeroed) coefficients in the
        /// plaintext polynomial</param>
        /// <param name="pool">The MemoryPoolHandle pointing to a valid memory pool</param>
        /// <exception cref="ArgumentException">if coeffCount is negative</exception>
        /// <exception cref="ArgumentException">if pool is uninitialized</exception>
        public Plaintext(ulong coeffCount, MemoryPoolHandle pool = null)
        {
            IntPtr poolPtr = pool?.NativePtr ?? IntPtr.Zero;

            NativeMethods.Plaintext_Create2(coeffCount, poolPtr, out IntPtr ptr);
            NativePtr = ptr;
        }

        /// <summary>
        /// Constructs a plaintext representing a constant polynomial 0. The
        /// coefficient count of the polynomial and the capacity are set to the
        /// given values.
        /// </summary>
        /// <param name="capacity">The capacity</param>
        /// <param name="coeffCount">The number of (zeroed) coefficients in the
        /// plaintext polynomial</param>
        /// <param name="pool">The MemoryPoolHandle pointing to a valid memory pool</param>
        /// <exception cref="ArgumentException">if capacity is less than coeffCount</exception>
        /// <exception cref="ArgumentException">if coeffCount is negative</exception>
        /// <exception cref="ArgumentException">if pool is uninitialized</exception>
        public Plaintext(ulong capacity, ulong coeffCount, MemoryPoolHandle pool = null)
        {
            IntPtr poolPtr = pool?.NativePtr ?? IntPtr.Zero;

            NativeMethods.Plaintext_Create3(capacity, coeffCount, poolPtr, out IntPtr ptr);
            NativePtr = ptr;
        }

        /// <summary>
        /// Constructs a plaintext from a given hexadecimal string describing the
        /// plaintext polynomial.
        /// </summary>
        /// <remarks>
        /// The string description of the polynomial must adhere to the format
        /// returned by ToString(), which is of the form "7FFx^3 + 1x^1 + 3"
        /// and summarized by the following
        /// rules:
        /// 1. Terms are listed in order of strictly decreasing exponent
        /// 2. Coefficient values are non-negative and in hexadecimal format (upper
        /// and lower case letters are both supported)
        /// 3. Exponents are positive and in decimal format
        /// 4. Zero coefficient terms (including the constant term) may be (but do
        /// not have to be) omitted
        /// 5. Term with the exponent value of one must be exactly written as x^1
        /// 6. Term with the exponent value of zero (the constant term) must be written
        /// as just a hexadecimal number without exponent
        /// 7. Terms must be separated by exactly [space]+[space] and minus is not
        /// allowed
        /// 8. Other than the +, no other terms should have whitespace
        /// </remarks>
        /// <param name="hexPoly">The formatted polynomial string specifying the plaintext
        /// polynomial</param>
        /// <param name="pool">The MemoryPoolHandle pointing to a valid memory pool</param>
        /// <exception cref="ArgumentNullException">if hexPoly is null</exception>
        /// <exception cref="ArgumentException">if hexPoly does not adhere to the expected
        /// format</exception>
        /// <exception cref="ArgumentException">if pool is uninitialized</exception>
        public Plaintext(string hexPoly, MemoryPoolHandle pool = null)
        {
            if (null == hexPoly)
                throw new ArgumentNullException(nameof(hexPoly));

            IntPtr poolPtr = pool?.NativePtr ?? IntPtr.Zero;

            NativeMethods.Plaintext_Create4(hexPoly, poolPtr, out IntPtr ptr);
            NativePtr = ptr;
        }

        /// <summary>
        /// Constructs a new plaintext by copying a given one.
        /// </summary>
        /// <param name="copy">The plaintext to copy from</param>
        /// <exception cref="ArgumentNullException">if copy is null</exception>
        public Plaintext(Plaintext copy)
        {
            if (null == copy)
                throw new ArgumentNullException(nameof(copy));

            NativeMethods.Plaintext_Create5(copy.NativePtr, out IntPtr ptr);
            NativePtr = ptr;
        }

        /// <summary>
        /// Constructs a new plaintext by copying a given one.
        /// </summary>
        /// <param name="copy">The plaintext to copy from</param>
        /// <param name="pool">The MemoryPoolHandle pointing to a valid memory pool</param>
        /// <exception cref="ArgumentNullException">if either copy or pool are null</exception>
        /// <exception cref="ArgumentException">if pool is uninitialized</exception>
        public Plaintext(Plaintext copy, MemoryPoolHandle pool) : this(pool)
        {
            if (null == copy)
                throw new ArgumentNullException(nameof(copy));

            Set(copy);
        }

        /// <summary>
        /// Constructs a plaintext by initializing it with a pointer to a native object.
        /// </summary>
        /// <param name="plaintextPtr">Pointer to native Plaintext object</param>
        /// <param name="owned">Whether this instance owns the native pointer</param>
        internal Plaintext(IntPtr plaintextPtr, bool owned = true)
            : base(plaintextPtr, owned)
        {
        }

        /// <summary>
        /// Allocates enough memory to accommodate the backing array of a plaintext
        /// with given capacity.
        /// </summary>
        /// <param name="capacity">The capacity</param>
        /// <exception cref="InvalidOperationException">if the plaintext is NTT transformed</exception>
        public void Reserve(ulong capacity)
        {
            NativeMethods.Plaintext_Reserve(NativePtr, capacity);
        }

        /// <summary>
        /// Allocates enough memory to accommodate the backing array of the current
        /// plaintext and copies it over to the new location. This function is meant
        /// to reduce the memory use of the plaintext to smallest possible and can be
        /// particularly important after modulus switching.
        /// </summary>
        public void ShrinkToFit()
        {
            NativeMethods.Plaintext_ShrinkToFit(NativePtr);
        }

        /// <summary>
        /// Resets the plaintext. This function releases any memory allocated by the
        /// plaintext, returning it to the memory pool.
        /// </summary>
        public void Release()
        {
            NativeMethods.Plaintext_Release(NativePtr);
        }

        /// <summary>
        /// Resizes the plaintext to have a given coefficient count. The plaintext
        /// is automatically reallocated if the new coefficient count does not fit in
        /// the current capacity.
        /// </summary>
        /// <param name="coeffCount">The number of coefficients in the plaintext
        /// polynomial</param>
        /// <exception cref="InvalidOperationException">if the plaintext is NTT transformed</exception>
        public void Resize(ulong coeffCount)
        {
            NativeMethods.Plaintext_Resize(NativePtr, coeffCount);
        }

        /// <summary>
        /// Copies a given plaintext to the current one.
        /// </summary>
        ///
        /// <param name="assign">The plaintext to copy from</param>
        /// <exception cref="ArgumentNullException">if assign is null</exception>
        public void Set(Plaintext assign)
        {
            if (null == assign)
                throw new ArgumentNullException(nameof(assign));

            NativeMethods.Plaintext_Set(NativePtr, assign.NativePtr);
        }

        /// <summary>
        /// Sets the value of the current plaintext to the polynomial represented by the a given hexadecimal string.
        /// </summary>
        ///
        /// <remarks>
        /// <para>
        /// Sets the value of the current plaintext to the polynomial represented by the a given hexadecimal string.
        /// </para>
        /// <para>
        /// The string description of the polynomial must adhere to the format returned by <see cref="ToString()"/>,
        /// which is of the form "7FFx^3 + 1x^1 + 3" and summarized by the following rules:
        /// <list type="number">
        /// <item><description>Terms are listed in order of strictly decreasing exponent</description></item>
        /// <item><description>Coefficient values are non-negative and in hexadecimal format (upper and lower case letters are both supported)</description></item>
        /// <item><description>Exponents are positive and in decimal format</description></item>
        /// <item><description>Zero coefficient terms (including the constant term) may be (but do not have to be) omitted</description></item>
        /// <item><description>Term with the exponent value of one is written as x^1</description></item>
        /// <item><description>Term with the exponent value of zero (the constant term) is written as just a hexadecimal number without x or exponent</description></item>
        /// <item><description>Terms are separated exactly by &lt;space&gt;+&lt;space&gt;</description></item>
        /// <item><description>Other than the +, no other terms have whitespace</description></item>
        /// </list>
        /// </para>
        /// </remarks>
        /// <param name="hexPoly">The formatted polynomial string specifying the plaintext polynomial</param>
        /// <exception cref="ArgumentException">if hexPoly does not adhere to the expected format</exception>
        /// <exception cref="ArgumentException">if the coefficients of hexPoly are too wide</exception>
        /// <exception cref="ArgumentNullException">if hexPoly is null</exception>
        public void Set(string hexPoly)
        {
            if (null == hexPoly)
                throw new ArgumentNullException(nameof(hexPoly));

            NativeMethods.Plaintext_Set(NativePtr, hexPoly);
        }

        /// <summary>
        /// Sets the value of the current plaintext to a given constant polynomial.
        /// </summary>
        ///
        /// <remarks>
        /// Sets the value of the current plaintext to a given constant polynomial. The coefficient count
        /// is set to one.
        /// </remarks>
        /// <param name="constCoeff">The constant coefficient</param>
        public void Set(ulong constCoeff)
        {
            NativeMethods.Plaintext_Set(NativePtr, constCoeff);
        }


        /// <summary>
        /// Sets a given range of coefficients of a plaintext polynomial to zero.
        /// </summary>
        ///
        /// <param name="startCoeff">The index of the first coefficient to set to zero</param>
        /// <param name="length">The number of coefficients to set to zero</param>
        /// <exception cref="ArgumentOutOfRangeException">if startCoeff is not within [0, CoeffCount)</exception>
        /// <exception cref="ArgumentOutOfRangeException">if startCoeff + length is not within [0, CoeffCount)</exception>
        /// */
        public void SetZero(ulong startCoeff, ulong length)
        {
            try
            {
                NativeMethods.Plaintext_SetZero(NativePtr, startCoeff, length);
            }
            catch(COMException e)
            {
                if ((uint)e.HResult == NativeMethods.Errors.HRInvalidIndex)
                    throw new ArgumentOutOfRangeException("startCoeff or length out of range", e);
                throw;
            }
        }

        /// <summary>
        /// Sets the plaintext polynomial coefficients to zero starting at a given
        /// index.
        /// </summary>
        /// <param name="startCoeff">The index of the first coefficient to set to zero</param>
        /// <exception cref="ArgumentOutOfRangeException">if startCoeff is not within [0, CoeffCount)</exception>
        public void SetZero(ulong startCoeff)
        {
            try
            {
                NativeMethods.Plaintext_SetZero(NativePtr, startCoeff);
            }
            catch (COMException e)
            {
                if ((uint)e.HResult == NativeMethods.Errors.HRInvalidIndex)
                    throw new ArgumentOutOfRangeException("startCoeff or length out of range", e);
                throw;
            }
        }

        /// <summary>
        /// Sets the plaintext polynomial to zero.
        /// </summary>
        public void SetZero()
        {
            NativeMethods.Plaintext_SetZero(NativePtr);
        }

        /// <summary>
        /// Gets/set the value of a given coefficient of the plaintext polynomial.
        /// </summary>
        /// <param name="coeffIndex">The index of the coefficient in the plaintext polynomial</param>
        /// <exception cref="ArgumentOutOfRangeException">if coeffIndex is not within [0, CoeffCount)</exception>
        public ulong this[ulong coeffIndex]
        {
            get
            {
                NativeMethods.Plaintext_CoeffAt(NativePtr, coeffIndex, out ulong result);
                return result;
            }
            set
            {
                NativeMethods.Plaintext_SetCoeffAt(NativePtr, coeffIndex, value);
            }
        }

        /// <summary>
        /// Returns whether the plaintext polynomial has all zero coefficients.
        /// </summary>
        public bool IsZero
        {
            get
            {
                NativeMethods.Plaintext_IsZero(NativePtr, out bool result);
                return result;
            }
        }

        /// <summary>
        /// Returns the capacity of the current allocation.
        /// </summary>
        public ulong Capacity
        {
            get
            {
                NativeMethods.Plaintext_Capacity(NativePtr, out ulong capacity);
                return capacity;
            }
        }

        /// <summary>
        /// Returns the coefficient count of the current plaintext polynomial.
        /// </summary>
        public ulong CoeffCount
        {
            get
            {
                NativeMethods.Plaintext_CoeffCount(NativePtr, out ulong result);
                return result;
            }
        }

        /// <summary>
        /// Returns the significant coefficient count of the current plaintext polynomial.
        /// </summary>
        public ulong SignificantCoeffCount
        {
            get
            {
                NativeMethods.Plaintext_SignificantCoeffCount(NativePtr, out ulong result);
                return result;
            }
        }

        /// <summary>
        /// Returns the non-zero coefficient count of the current plaintext polynomial.
        /// </summary>
        public ulong NonZeroCoeffCount
        {
            get
            {
                NativeMethods.Plaintext_NonZeroCoeffCount(NativePtr, out ulong result);
                return result;
            }
        }

        /// <summary>
        /// Returns a human-readable string description of the plaintext polynomial.
        /// </summary>
        /// <remarks>
        /// <para>
        /// Returns a human-readable string description of the plaintext polynomial.
        /// </para>
        /// <para>
        /// The returned string is of the form "7FFx^3 + 1x^1 + 3" with a format summarized by the following:
        /// <list type="number">
        /// <item><description>Terms are listed in order of strictly decreasing exponent</description></item>
        /// <item><description>Coefficient values are non-negative and in hexadecimal format (hexadecimal letters are in upper-case)</description></item>
        /// <item><description>Exponents are positive and in decimal format</description></item>
        /// <item><description>Zero coefficient terms (including the constant term) are omitted unless the polynomial is exactly 0 (see rule 9)</description></item>
        /// <item><description>Term with the exponent value of one is written as x^1</description></item>
        /// <item><description>Term with the exponent value of zero (the constant term) is written as just a hexadecimal number without x or exponent</description></item>
        /// <item><description>Terms are separated exactly by &lt;space&gt;+&lt;space&gt;</description></item>
        /// <item><description>Other than the +, no other terms have whitespace</description></item>
        /// <item><description>If the polynomial is exactly 0, the string "0" is returned</description></item>
        /// </list>
        /// </para>
        /// </remarks>
        /// <exception cref="InvalidOperationException">if the plaintext is in NTT transformed form</exception>
        public override string ToString()
        {
            NativeMethods.Plaintext_ToString(NativePtr, null, out ulong length);
            StringBuilder buffer = new StringBuilder(checked((int)length));
            NativeMethods.Plaintext_ToString(NativePtr, buffer, out length);
            return buffer.ToString();
        }

        /// <summary>
        /// Returns a hash-code based on the value of the plaintext polynomial.
        /// </summary>
        public override int GetHashCode()
        {
            ulong coeffCount = CoeffCount;
            ulong[] coeffs = new ulong[coeffCount];

            for (ulong i = 0; i < coeffCount; i++)
            {
                coeffs[i] = this[i];
            }

            return Utilities.ComputeArrayHashCode(coeffs);
        }

        /// <summary>
        /// Returns an upper bound on the size of the ciphertext, as if it was written
        /// to an output stream.
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
            NativeMethods.Plaintext_SaveSize(
                NativePtr, (byte)comprModeValue, out long outBytes);
            return outBytes;
        }

        /// <summary>Saves the Plaintext to an output stream.</summary>
        /// <remarks>
        /// Saves the Plaintext to an output stream. The output is in binary format
        /// and not human-readable.
        /// </remarks>
        /// <param name="stream">The stream to save the Plaintext to</param>
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
                    NativeMethods.Plaintext_Save(NativePtr, outptr, size,
                    cm, out outBytes),
                SaveSize(comprModeValue), comprModeValue, stream);
        }

        /// <summary>Loads a plaintext from an input stream overwriting the current
        /// plaintext.</summary>
        /// <remarks>
        /// Loads a plaintext from an input stream overwriting the current plaintext.
        /// No checking of the validity of the plaintext data against encryption
        /// parameters is performed. This function should not be used unless the
        /// plaintext comes from a fully trusted source.
        /// </remarks>
        /// <param name="context">The SEALContext</param>
        /// <param name="stream">The stream to load the plaintext from</param>
        /// <exception cref="ArgumentNullException">if context or stream is
        /// null</exception>
        /// <exception cref="ArgumentException">if the stream is closed or does not
        /// support reading</exception>
        /// <exception cref="ArgumentException">if context is not set or encryption
        /// parameters are not valid</exception>
        /// <exception cref="EndOfStreamException">if the stream ended
        /// unexpectedly</exception>
        /// <exception cref="IOException">if I/O operations failed</exception>
        /// <exception cref="InvalidOperationException">if the data cannot be loaded
        /// by this version of Microsoft SEAL, if the loaded data is invalid, or if the
        /// loaded compression mode is not supported</exception>
        public long UnsafeLoad(SEALContext context, Stream stream)
        {
            if (null == context)
                throw new ArgumentNullException(nameof(context));

            return Serialization.Load(
                (byte[] outptr, ulong size, out long outBytes) =>
                    NativeMethods.Plaintext_UnsafeLoad(context.NativePtr, NativePtr,
                    outptr, size, out outBytes),
                stream);
        }

        /// <summary>Loads a plaintext from an input stream overwriting the current
        /// plaintext.</summary>
        /// <remarks>
        /// Loads a plaintext from an input stream overwriting the current plaintext.
        /// The loaded plaintext is verified to be valid for the given SEALContext.
        /// </remarks>
        /// <param name="context">The SEALContext</param>
        /// <param name="stream">The stream to load the plaintext from</param>
        /// <exception cref="ArgumentNullException">if context or stream is
        /// null</exception>
        /// <exception cref="ArgumentException">if the stream is closed or does not
        /// support reading</exception>
        /// <exception cref="ArgumentException">if context is not set or encryption
        /// parameters are not valid</exception>
        /// <exception cref="EndOfStreamException">if the stream ended
        /// unexpectedly</exception>
        /// <exception cref="IOException">if I/O operations failed</exception>
        /// <exception cref="InvalidOperationException">if the data cannot be loaded
        /// by this version of Microsoft SEAL, if the loaded data is invalid, or if the
        /// loaded compression mode is not supported</exception>
        public long Load(SEALContext context, Stream stream)
        {
            if (null == context)
                throw new ArgumentNullException(nameof(context));

            return Serialization.Load(
                (byte[] outptr, ulong size, out long outBytes) =>
                    NativeMethods.Plaintext_Load(NativePtr, context.NativePtr,
                    outptr, size, out outBytes),
                stream);
        }

        /// <summary>
        /// Returns whether the plaintext is in NTT form.
        /// </summary>
        public bool IsNTTForm
        {
            get
            {
                NativeMethods.Plaintext_IsNTTForm(NativePtr, out bool result);
                return result;
            }
        }

        /// <summary>
        /// Returns a copy of ParmsId. The ParmsId must remain zero unless the
        /// plaintext polynomial is in NTT form.
        /// </summary>
        /// <seealso cref="EncryptionParameters">see EncryptionParameters for more
        /// information about parmsId.</seealso>
        public ParmsId ParmsId
        {
            get
            {
                ParmsId parms = new ParmsId();
                NativeMethods.Plaintext_GetParmsId(NativePtr, parms.Block);
                return parms;
            }

            private set
            {
                NativeMethods.Plaintext_SetParmsId(NativePtr, value.Block);
            }
        }

        /// <summary>
        /// Returns a reference to the scale. This is only needed when using the
        /// CKKS encryption scheme. The user should have little or no reason to ever
        /// change the scale by hand.
        /// </summary>
        public double Scale
        {
            get
            {
                NativeMethods.Plaintext_Scale(NativePtr, out double scale);
                return scale;
            }

            private set
            {
                NativeMethods.Plaintext_SetScale(NativePtr, value);
            }
        }

        /// <summary>
        /// Returns the currently used MemoryPoolHandle.
        /// </summary>
        public MemoryPoolHandle Pool
        {
            get
            {
                NativeMethods.Plaintext_Pool(NativePtr, out IntPtr pool);
                MemoryPoolHandle handle = new MemoryPoolHandle(pool);
                return handle;
            }
        }

        /// <summary>
        /// Returns whether or not the plaintext has the same semantic value as a given
        /// plaintext.
        /// </summary>
        /// <remarks>
        /// Returns whether or not the plaintext has the same semantic value as a given
        /// plaintext. Leading zero coefficients are ignored by the comparison.
        /// </remarks>
        /// <param name="obj">The object to compare against</param>
        public override bool Equals(object obj)
        {
            Plaintext pt = obj as Plaintext;
            return Equals(pt);
        }

        /// <summary>
        /// Returns whether or not the plaintext has the same semantic value as a given
        /// plaintext.
        /// </summary>
        /// <remarks>
        /// Returns whether or not the plaintext has the same semantic value as a given
        /// plaintext. Leading zero coefficients are ignored by the comparison.
        /// </remarks>
        /// <param name="other">The plaintext to compare against</param>
        public bool Equals(Plaintext other)
        {
            if (null == other)
                return false;

            NativeMethods.Plaintext_Equals(NativePtr, other.NativePtr, out bool equals);
            return equals;
        }

        /// <summary>
        /// Destroy native object.
        /// </summary>
        protected override void DestroyNativeObject()
        {
            NativeMethods.Plaintext_Destroy(NativePtr);
        }
    }
}
