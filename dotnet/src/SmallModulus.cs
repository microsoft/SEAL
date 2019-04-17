// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

using Microsoft.Research.SEAL.Tools;
using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using System.Runtime.InteropServices;

namespace Microsoft.Research.SEAL
{
    /// <summary>Represent an integer modulus of up to 62 bits.</summary>
    ///
    /// <remarks>
    /// <para>
    /// Represent an integer modulus of up to 62 bits. An instance of the SmallModulus
    /// class represents a non-negative integer modulus up to 62 bits. In particular,
    /// the encryption parameter PlainModulus, and the primes in CoeffModulus, are
    /// represented by instances of SmallModulus. The purpose of this class is to
    /// perform and store the pre-computation required by Barrett reduction.
    /// </para>
    /// <para>
    /// In general, reading from SmallModulus is thread-safe as long as no other thread
    /// is  concurrently mutating it.
    /// </para>
    /// </remarks>
    /// <seealso cref="EncryptionParameters">See EncryptionParameters for a description
    /// of the encryption parameters.</seealso>
    public class SmallModulus : NativeObject, IEquatable<SmallModulus>, IEquatable<ulong>
    {
        /// <summary>Creates a SmallModulus instance.</summary>
        ///
        /// <remarks>
        /// Creates a SmallModulus instance. The value of the SmallModulus is set to 0.
        /// </remarks>
        public SmallModulus()
        {
            NativeMethods.SmallModulus_Create(value: 0, smallModulus: out IntPtr ptr);
            NativePtr = ptr;
        }

        /// <summary>Creates a SmallModulus instance.</summary>
        ///
        /// <remarks>
        /// Creates a SmallModulus instance. The value of the SmallModulus is set to
        /// the given value.
        /// </remarks>
        /// <param name="value">The integer modulus</param>
        /// <exception cref="System.ArgumentException">if value is 1 or more than
        /// 62 bits</exception>
        public SmallModulus(ulong value)
        {
            NativeMethods.SmallModulus_Create(value, out IntPtr ptr);
            NativePtr = ptr;
        }

        /// <summary>Creates a new SmallModulus by copying a given one.</summary>
        ///
        /// <param name="copy">The SmallModulus to copy from</param>
        /// <exception cref="System.ArgumentNullException">if copy is null</exception>
        public SmallModulus(SmallModulus copy)
        {
            if (null == copy)
                throw new ArgumentNullException(nameof(copy));

            NativeMethods.SmallModulus_Create(copy.NativePtr, out IntPtr ptr);
            NativePtr = ptr;
        }

        /// <summary>
        /// Creates a SmallModulus from a native pointer
        /// </summary>
        /// <param name="sm">Pointer to the native SmallModulus</param>
        /// <param name="owned">Whether this instance owns the native pointer</param>
        internal SmallModulus(IntPtr sm, bool owned = true)
            : base(sm, owned)
        {
        }

        /// <summary>Copies a given SmallModulus to the current one.</summary>
        ///
        /// <param name="assign">The SmallModulus to copy from</param>
        /// <exception cref="System.ArgumentNullException">if assign is null</exception>
        public void Set(SmallModulus assign)
        {
            if (null == assign)
                throw new ArgumentNullException(nameof(assign));

            NativeMethods.SmallModulus_Set(NativePtr, assign.NativePtr);
        }

        /// <summary>Sets the value of the SmallModulus.</summary>
        ///
        /// <param name="value">The new integer modulus</param>
        /// <exception cref="System.ArgumentException">if value is 1 or more than
        /// 62 bits</exception>
        public void Set(ulong value)
        {
            NativeMethods.SmallModulus_Set(NativePtr, value);
        }

        /// <summary>
        /// Returns the significant bit count of the value of the current
        /// SmallModulus.
        /// </summary>
        public int BitCount
        {
            get
            {
                NativeMethods.SmallModulus_BitCount(NativePtr, out int result);
                return result;
            }
        }

        /// <summary>
        /// Returns the size (in 64-bit words) of the value of the current
        /// SmallModulus.
        /// </summary>
        public ulong UInt64Count
        {
            get
            {
                NativeMethods.SmallModulus_UInt64Count(NativePtr, out ulong result);
                return result;
            }
        }

        /// <summary>
        /// Returns the value of the current SmallModulus.
        /// </summary>
        public ulong Value
        {
            get
            {
                NativeMethods.SmallModulus_Value(NativePtr, out ulong result);
                return result;
            }
        }

        /// <summary>Returns the Barrett ratio computed for the value of the current
        /// SmallModulus.</summary>
        ///
        /// <remarks>
        /// Returns the Barrett ratio computed for the value of the current SmallModulus.
        /// The first two components of the Barrett ratio are the floor of 2^128/value,
        /// and the third component is the remainder.
        /// </remarks>
        public Tuple<ulong, ulong, ulong> ConstRatio
        {
            get
            {
                ulong[] ratio = new ulong[3];
                NativeMethods.SmallModulus_ConstRatio(NativePtr, length: (ulong)3, ratio: ratio);
                return new Tuple<ulong, ulong, ulong>(ratio[0], ratio[1], ratio[2]);
            }
        }

        /// <summary>
        /// Returns whether the value of the current SmallModulus is zero.
        /// </summary>
        public bool IsZero
        {
            get
            {
                NativeMethods.SmallModulus_IsZero(NativePtr, out bool result);
                return result;
            }
        }

        /// <summary>
        /// Returns whether the value of the current SmallModulus is a prime number.
        /// </summary>
        public bool IsPrime
        {
            get
            {
                NativeMethods.SmallModulus_IsPrime(NativePtr, out bool result);
                return result;
            }
        }

        /// <summary>Saves the SmallModulus to an output stream.</summary>
        ///
        /// <remarks>
        /// Saves the SmallModulus to an output stream. The output is in binary format and
        /// not human-readable. The output stream must have the "binary" flag set.
        /// </remarks>
        ///
        /// <param name="stream">The stream to save the SmallModulus to</param>
        /// <exception cref="System.ArgumentNullException">if stream is null</exception>
        public void Save(Stream stream)
        {
            if (null == stream)
                throw new ArgumentNullException(nameof(stream));

            using (BinaryWriter writer = new BinaryWriter(stream, Encoding.UTF8, leaveOpen: true))
            {
                writer.Write(BitCount);
                writer.Write(UInt64Count);
                writer.Write(Value);
            }
        }

        /// <summary>Loads a SmallModulus from an input stream overwriting the current
        /// SmallModulus.</summary>
        ///
        /// <param name="stream">The stream to load the SmallModulus from</param>
        /// <exception cref="System.ArgumentNullException">if stream is null</exception>
        public void Load(Stream stream)
        {
            if (null == stream)
                throw new ArgumentNullException(nameof(stream));

            try
            {
                using (BinaryReader reader = new BinaryReader(stream, Encoding.UTF8, leaveOpen: true))
                {
                    int bitCount = reader.ReadInt32();
                    ulong uint64Count = reader.ReadUInt64();
                    ulong value = reader.ReadUInt64();
                    Set(value);

                    if (bitCount != BitCount)
                        throw new InvalidOperationException("Expected bit count differs from actual bit count");
                    if (uint64Count != UInt64Count)
                        throw new InvalidOperationException("Expected uint64 count differs from actual uint64 count");
                }
            }
            catch (EndOfStreamException ex)
            {
                throw new ArgumentException("End of stream reached", ex);
            }
            catch (IOException ex)
            {
                throw new ArgumentException("Could not load SmallModulus", ex);
            }
        }

        /// <summary>
        /// Returns a hash-code based on the value of the SmallModulus.
        /// </summary>
        public override int GetHashCode()
        {
            ulong[] arr = new ulong[1];
            arr[0] = Value;
            return Utilities.ComputeArrayHashCode(arr);
        }

        /// <summary>
        /// Compares two SmallModulus instances.
        /// </summary>
        /// <param name="obj">The value to compare against</param>
        public override bool Equals(object obj)
        {
            SmallModulus sm = obj as SmallModulus;
            return Equals(sm);
        }

        /// <summary>Creates a SmallModulus instance.</summary>
        ///
        /// <remarks>
        /// Creates a SmallModulus instance. The value of the SmallModulus is set to
        /// the given value.
        /// </remarks>
        /// <param name="value">The integer modulus</param>
        /// <exception cref="System.ArgumentException">if value is 1 or more than
        /// 62 bits</exception>
        public static explicit operator SmallModulus(ulong value)
        {
            SmallModulus sm = new SmallModulus(value);
            return sm;
        }

        #region IEquatable<SmallModulus> methods

        /// <summary>
        /// Determines whether this instance equals another SmallModulus instance
        /// </summary>
        /// <param name="other">Instance to compare against</param>
        public bool Equals(SmallModulus other)
        {
            if (null == other)
                return false;

            NativeMethods.SmallModulus_Equals(NativePtr, other.NativePtr, out bool result);
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
            NativeMethods.SmallModulus_Equals(NativePtr, other, out bool result);
            return result;
        }

        #endregion

        /// <summary>
        /// Destroy native object.
        /// </summary>
        protected override void DestroyNativeObject()
        {
            NativeMethods.SmallModulus_Destroy(NativePtr);
        }

        /// <summary>
        /// Returns in decreasing order a vector of the largest prime numbers of a given
        /// length that all support NTTs of a given size.
        /// </summary>
        ///
        /// <remarks>
        /// Returns in decreasing order a vector of the largest prime numbers of a given
        /// length that all support NTTs of a given size. More precisely, the generated
        /// primes are all congruent to 1 modulo 2 * ntt_size.Typically, the user might
        /// call this function by passing poly_modulus_degree as ntt_size if the primes
        /// are to be used as a coefficient modulus primes for encryption parameters.
        /// </remarks>
        /// <param name="bitSize">the bit-size of primes to be generated, no less than 2 and
        /// no larger than 62</param>
        /// <param name="count">The total number of primes to be generated</param>
        /// <param name="nttSize">The size of NTT that should be supported</param>
        /// <exception cref="ArgumentException">if bitSize is less than 2</exception>
        /// <exception cref="ArgumentException">if count or nttSize is zero</exception>
        /// <exception cref="InvalidOperationException">if enough qualifying primes cannot be found</exception>
        public static IEnumerable<SmallModulus> GetPrimes(int bitSize, ulong count, ulong nttSize)
        {
            List<SmallModulus> result = new List<SmallModulus>((int)count);

            try
            {
                IntPtr[] primeArray = new IntPtr[count];
                NativeMethods.SmallModulus_GetPrimes(bitSize, count, nttSize, primeArray);
                foreach (IntPtr prime in primeArray)
                {
                    result.Add(new SmallModulus(prime));
                }
            }
            catch (COMException ex)
            {
                if ((uint)ex.HResult == NativeMethods.Errors.HRInvalidOperation)
                    throw new InvalidOperationException("Failed to find enough qualifying primes", ex);
                throw;
            }

            return result;
        }
    }
}
