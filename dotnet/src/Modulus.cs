// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

using Microsoft.Research.SEAL.Tools;
using System;
using System.IO;
using System.Collections.Generic;
using System.Linq;

namespace Microsoft.Research.SEAL
{
    /// <summary>Represent an integer modulus of up to 61 bits.</summary>
    /// <remarks>
    /// <para>
    /// Represent an integer modulus of up to 61 bits. An instance of the Modulus
    /// class represents a non-negative integer modulus up to 61 bits. In particular,
    /// the encryption parameter PlainModulus, and the primes in CoeffModulus, are
    /// represented by instances of Modulus. The purpose of this class is to
    /// perform and store the pre-computation required by Barrett reduction.
    /// </para>
    /// <para>
    /// In general, reading from Modulus is thread-safe as long as no other thread
    /// is  concurrently mutating it.
    /// </para>
    /// </remarks>
    /// <seealso cref="EncryptionParameters">See EncryptionParameters for a description
    /// of the encryption parameters.</seealso>
    public class Modulus : NativeObject,
        IEquatable<Modulus>, IEquatable<ulong>,
        IComparable<Modulus>, IComparable<ulong>
    {
        /// <summary>Creates a Modulus instance.</summary>
        /// <remarks>
        /// Creates a Modulus instance. The value of the Modulus is set to 0.
        /// </remarks>
        public Modulus()
        {
            NativeMethods.Modulus_Create(value: 0, smallModulus: out IntPtr ptr);
            NativePtr = ptr;
        }

        /// <summary>Creates a Modulus instance.</summary>
        /// <remarks>
        /// Creates a Modulus instance. The value of the Modulus is set to
        /// the given value.
        /// </remarks>
        /// <param name="value">The integer modulus</param>
        /// <exception cref="ArgumentException">if value is 1 or more than
        /// 61 bits</exception>
        public Modulus(ulong value)
        {
            NativeMethods.Modulus_Create(value, out IntPtr ptr);
            NativePtr = ptr;
        }

        /// <summary>Creates a new Modulus by copying a given one.</summary>
        /// <param name="copy">The Modulus to copy from</param>
        /// <exception cref="ArgumentNullException">if copy is null</exception>
        public Modulus(Modulus copy)
        {
            if (null == copy)
                throw new ArgumentNullException(nameof(copy));

            NativeMethods.Modulus_Create(copy.NativePtr, out IntPtr ptr);
            NativePtr = ptr;
        }

        /// <summary>
        /// Creates a Modulus from a native pointer
        /// </summary>
        /// <param name="sm">Pointer to the native Modulus</param>
        /// <param name="owned">Whether this instance owns the native pointer</param>
        internal Modulus(IntPtr sm, bool owned = true)
            : base(sm, owned)
        {
        }

        /// <summary>Copies a given Modulus to the current one.</summary>
        /// <param name="assign">The Modulus to copy from</param>
        /// <exception cref="ArgumentNullException">if assign is null</exception>
        public void Set(Modulus assign)
        {
            if (null == assign)
                throw new ArgumentNullException(nameof(assign));

            NativeMethods.Modulus_Set(NativePtr, assign.NativePtr);
        }

        /// <summary>Sets the value of the Modulus.</summary>
        /// <param name="value">The new integer modulus</param>
        /// <exception cref="ArgumentException">if value is 1 or more than
        /// 61 bits</exception>
        public void Set(ulong value)
        {
            NativeMethods.Modulus_Set(NativePtr, value);
        }

        /// <summary>
        /// Returns the significant bit count of the value of the current Modulus.
        /// </summary>
        public int BitCount
        {
            get
            {
                NativeMethods.Modulus_BitCount(NativePtr, out int result);
                return result;
            }
        }

        /// <summary>
        /// Returns the size (in 64-bit words) of the value of the current Modulus.
        /// </summary>
        public ulong UInt64Count
        {
            get
            {
                NativeMethods.Modulus_UInt64Count(NativePtr, out ulong result);
                return result;
            }
        }

        /// <summary>
        /// Returns the value of the current Modulus.
        /// </summary>
        public ulong Value
        {
            get
            {
                NativeMethods.Modulus_Value(NativePtr, out ulong result);
                return result;
            }
        }

        /// <summary>
        /// Returns the Barrett ratio computed for the value of the current Modulus.
        /// </summary>
        /// <remarks>
        /// Returns the Barrett ratio computed for the value of the current Modulus.
        /// The first two components of the Barrett ratio are the floor of 2^128/value,
        /// and the third component is the remainder.
        /// </remarks>
        public Tuple<ulong, ulong, ulong> ConstRatio
        {
            get
            {
                ulong[] ratio = new ulong[3];
                NativeMethods.Modulus_ConstRatio(NativePtr, length: (ulong)3, ratio: ratio);
                return new Tuple<ulong, ulong, ulong>(ratio[0], ratio[1], ratio[2]);
            }
        }

        /// <summary>
        /// Returns whether the value of the current Modulus is zero.
        /// </summary>
        public bool IsZero
        {
            get
            {
                NativeMethods.Modulus_IsZero(NativePtr, out bool result);
                return result;
            }
        }

        /// <summary>
        /// Returns whether the value of the current Modulus is a prime number.
        /// </summary>
        public bool IsPrime
        {
            get
            {
                NativeMethods.Modulus_IsPrime(NativePtr, out bool result);
                return result;
            }
        }

        /// <summary>
        /// Returns an upper bound on the size of the Modulus, as if it was
        /// written to an output stream.
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
            NativeMethods.Modulus_SaveSize(
                NativePtr, (byte)comprModeValue, out long outBytes);
            return outBytes;
        }

        /// <summary>Saves the Modulus to an output stream.</summary>
        /// <remarks>
        /// Saves the Modulus to an output stream. The output is in binary format
        /// and not human-readable.
        /// </remarks>
        /// <param name="stream">The stream to save the Modulus to</param>
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
                    NativeMethods.Modulus_Save(NativePtr, outptr, size,
                    cm, out outBytes),
                SaveSize(comprModeValue), comprModeValue, stream);
        }

        /// <summary>
        /// Loads a Modulus from an input stream overwriting the current
        /// Modulus.
        /// </summary>
        /// <param name="stream">The stream to load the Modulus from</param>
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
                    NativeMethods.Modulus_Load(NativePtr, outptr, size,
                    out outBytes),
                stream);
        }

        /// <summary>
        /// Returns a hash-code based on the value of the Modulus.
        /// </summary>
        public override int GetHashCode()
        {
            ulong[] arr = new ulong[1];
            arr[0] = Value;
            return Utilities.ComputeArrayHashCode(arr);
        }

        /// <summary>
        /// Compares two Modulus instances.
        /// </summary>
        /// <param name="obj">The value to compare against</param>
        public override bool Equals(object obj)
        {
            Modulus sm = obj as Modulus;
            return Equals(sm);
        }

        /// <summary>Creates a Modulus instance.</summary>
        /// <remarks>
        /// Creates a Modulus instance. The value of the Modulus is set to
        /// the given value.
        /// </remarks>
        /// <param name="value">The integer modulus</param>
        /// <exception cref="ArgumentException">if value is 1 or more than 61 bits</exception>
        public static explicit operator Modulus(ulong value)
        {
            Modulus sm = new Modulus(value);
            return sm;
        }

        #region IEquatable<Modulus> methods

        /// <summary>
        /// Determines whether this instance equals another Modulus instance
        /// </summary>
        /// <param name="other">Instance to compare against</param>
        public bool Equals(Modulus other)
        {
            if (null == other)
                return false;

            NativeMethods.Modulus_Equals(NativePtr, other.NativePtr, out bool result);
            return result;
        }

        #endregion

        #region IEquatable<ulong> methods

        /// <summary>
        /// Determines whether the value of this instance equals the given UInt64 value
        /// </summary>
        /// <param name="other">The value to compare against</param>
        public bool Equals(ulong other)
        {
            NativeMethods.Modulus_Equals(NativePtr, other, out bool result);
            return result;
        }

        #endregion

        #region IComparable<Modulus> methods

        /// <summary>
        /// Compares two Modulus instances.
        /// </summary>
        /// <param name="compare">The Modulus to compare against</param>
        public int CompareTo(Modulus compare)
        {
            if (null == compare)
                return 1;

            return Value.CompareTo(compare.Value);
        }

        #endregion

        #region IComparable<ulong> methods

        /// <summary>
        /// Compares a Modulus value to an unsigned integer.
        /// </summary>
        /// <param name="compare">The unsigned integer to compare against</param>
        public int CompareTo(ulong compare)
        {
            return Value.CompareTo(compare);
        }

        #endregion

        /// <summary>
        /// Destroy native object.
        /// </summary>
        protected override void DestroyNativeObject()
        {
            NativeMethods.Modulus_Destroy(NativePtr);
        }
    }

    /// <summary>
    /// Represents a standard security level according to the HomomorphicEncryption.org
    /// security standard.
    /// </summary>
    /// <remarks>
    /// Represents a standard security level according to the HomomorphicEncryption.org
    /// security standard. The value SecLevelType.None signals that no standard
    /// security level should be imposed. The value SecLevelType.TC128 provides
    /// a very high level of security and is the default security level enforced by
    /// Microsoft SEAL when constructing a SEALContext object. Normal users should not
    /// have to specify the security level explicitly anywhere.
    /// </remarks>
    public enum SecLevelType : int
    {
        /// <summary>
        /// No security level specified.
        /// </summary>
        None = 0,

        /// <summary>
        /// 128-bit security level according to HomomorphicEncryption.org standard.
        /// </summary>
        TC128 = 128,

        /// <summary>
        /// 192-bit security level according to HomomorphicEncryption.org standard.
        /// </summary>
        TC192 = 192,

        /// <summary>
        /// 256-bit security level according to HomomorphicEncryption.org standard.
        /// </summary>
        TC256 = 256
    }

    /// <summary>
    /// This class contains static methods for creating a coefficient modulus easily.
    /// </summary>
    /// <remarks>
    /// <para>
    /// This class contains static methods for creating a coefficient modulus easily.
    /// Note that while these functions take a SecLevelType argument, all security
    /// guarantees are lost if the output is used with encryption parameters with
    /// a mismatching value for the PolyModulusDegree.
    /// </para>
    /// <para>
    /// The default value SecLevelType.TC128 provides a very high level of security
    /// and is the default security level enforced by Microsoft SEAL when constructing
    /// a SEALContext object. Normal users should not have to specify the security
    /// level explicitly anywhere.
    /// </para>
    /// </remarks>
    public static class CoeffModulus
    {
        /// <summary>
        /// Returns the largest bit-length of the coefficient modulus, i.e., bit-length
        /// of the product of the primes in the coefficient modulus, that guarantees
        /// a given security level when using a given PolyModulusDegree, according
        /// to the HomomorphicEncryption.org security standard.
        /// </summary>
        /// <param name="polyModulusDegree">The value of the PolyModulusDegree
        /// encryption parameter</param>
        /// <param name="secLevel">The desired standard security level</param>
        static public int MaxBitCount(ulong polyModulusDegree, SecLevelType secLevel = SecLevelType.TC128)
        {
            NativeMethods.CoeffModulus_MaxBitCount(polyModulusDegree, (int)secLevel, out int result);
            return result;
        }

        /// <summary>
        /// Returns a default coefficient modulus for the BFV scheme that guarantees
        /// a given security level when using a given PolyModulusDegree, according
        /// to the HomomorphicEncryption.org security standard.
        /// </summary>
        /// <remarks>
        /// <para>
        /// Returns a default coefficient modulus for the BFV scheme that guarantees
        /// a given security level when using a given PolyModulusDegree, according
        /// to the HomomorphicEncryption.org security standard. Note that all security
        /// guarantees are lost if the output is used with encryption parameters with
        /// a mismatching value for the PolyModulusDegree.
        /// </para>
        /// <para>
        /// The coefficient modulus returned by this function will not perform well
        /// if used with the CKKS scheme.
        /// </para>
        /// </remarks>
        /// <param name="polyModulusDegree">The value of the PolyModulusDegree
        /// encryption parameter</param>
        /// <param name="secLevel">The desired standard security level</param>
        /// <exception cref="ArgumentException">if polyModulusDegree is not
        /// a power-of-two or is too large</exception>
        /// <exception cref="ArgumentException">if secLevel is SecLevelType.None</exception>
        static public IEnumerable<Modulus> BFVDefault(
            ulong polyModulusDegree, SecLevelType secLevel = SecLevelType.TC128)
        {
            List<Modulus> result = null;

            ulong length = 0;
            NativeMethods.CoeffModulus_BFVDefault(polyModulusDegree, (int)secLevel, ref length, null);

            IntPtr[] coeffArray = new IntPtr[length];
            NativeMethods.CoeffModulus_BFVDefault(polyModulusDegree, (int)secLevel, ref length, coeffArray);

            result = new List<Modulus>(checked((int)length));
            foreach (IntPtr sm in coeffArray)
            {
                result.Add(new Modulus(sm));
            }

            return result;
        }

        /// <summary>
        /// Returns a custom coefficient modulus suitable for use with the specified
        /// PolyModulusDegree.
        /// </summary>
        /// <remarks>
        /// Returns a custom coefficient modulus suitable for use with the specified
        /// PolyModulusDegree.The return value will be a vector consisting of
        /// Modulus elements representing distinct prime numbers of bit-lengths
        /// as given in the bitSizes parameter. The bit sizes of the prime numbers
        /// can be at most 60 bits.
        /// </remarks>
        /// <param name="polyModulusDegree">The value of the PolyModulusDegree
        /// encryption parameter</param>
        /// <param name="bitSizes">The bit-lengths of the primes to be generated</param>
        /// <exception cref="ArgumentException">if polyModulusDegree is not
        /// a power-of-two or is too large</exception>
        /// <exception cref="ArgumentException">if bitSizes is too large or if its
        /// elements are out of bounds</exception>
        /// <exception cref="InvalidOperationException">if not enough suitable primes could be found</exception>
        static public IEnumerable<Modulus> Create(
            ulong polyModulusDegree, IEnumerable<int> bitSizes)
        {
            if (null == bitSizes)
                throw new ArgumentNullException(nameof(bitSizes));

            List<Modulus> result = null;

            int[] bitSizesArr = bitSizes.ToArray();
            int length = bitSizesArr.Length;

            IntPtr[] coeffArray = new IntPtr[length];

            NativeMethods.CoeffModulus_Create(polyModulusDegree, (ulong)length, bitSizesArr, coeffArray);

            result = new List<Modulus>(length);
            foreach (IntPtr sm in coeffArray)
            {
                result.Add(new Modulus(sm));
            }

            return result;
        }
    }

    /// <summary>
    /// This class contains static methods for creating a plaintext modulus easily.
    /// </summary>
    public static class PlainModulus
    {
        /// <summary>
        /// Creates a prime number Modulus for use as PlainModulus encryption
        /// parameter that supports batching with a given PolyModulusDegree.
        /// </summary>
        /// <param name="polyModulusDegree">The value of the PolyModulusDegree
        /// encryption parameter</param>
        /// <param name="bitSize">The bit-length of the prime to be generated</param>
        /// <exception cref="ArgumentException">if polyModulusDegree is not
        /// a power-of-two or is too large</exception>
        /// <exception cref="ArgumentException">if bitSize is out of bounds</exception>
        /// <exception cref="InvalidOperationException">if a suitable prime could not be found</exception>
        static public Modulus Batching(ulong polyModulusDegree, int bitSize)
        {
            return CoeffModulus.Create(
                polyModulusDegree,
                new int[] { bitSize }).First();
        }

        /// <summary>
        /// Creates several prime number Modulus elements that can be used as
        /// PlainModulus encryption parameters, each supporting batching with a given
        /// PolyModulusDegree.
        /// </summary>
        /// <param name="polyModulusDegree">The value of the PolyModulusDegree
        /// encryption parameter</param>
        /// <param name="bitSizes">The bit-lengths of the primes to be generated</param>
        /// <exception cref="ArgumentException">if polyModulusDegree is not
        /// a power-of-two or is too large</exception>
        /// <exception cref="ArgumentException">if bitSizes is too large or if its
        /// elements are out of bounds</exception>
        /// <exception cref="InvalidOperationException">if not enough suitable primes could be found</exception>
        static public IEnumerable<Modulus> Batching(
            ulong polyModulusDegree, IEnumerable<int> bitSizes)
        {
            return CoeffModulus.Create(polyModulusDegree, bitSizes);
        }
    }
}
