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
    public class SmallModulus : NativeObject,
        IEquatable<SmallModulus>, IEquatable<ulong>,
        IComparable<SmallModulus>, IComparable<ulong>
    {
        /// <summary>Creates a SmallModulus instance.</summary>
        /// <remarks>
        /// Creates a SmallModulus instance. The value of the SmallModulus is set to 0.
        /// </remarks>
        public SmallModulus()
        {
            NativeMethods.SmallModulus_Create(value: 0, smallModulus: out IntPtr ptr);
            NativePtr = ptr;
        }

        /// <summary>Creates a SmallModulus instance.</summary>
        /// <remarks>
        /// Creates a SmallModulus instance. The value of the SmallModulus is set to
        /// the given value.
        /// </remarks>
        /// <param name="value">The integer modulus</param>
        /// <exception cref="ArgumentException">if value is 1 or more than
        /// 62 bits</exception>
        public SmallModulus(ulong value)
        {
            NativeMethods.SmallModulus_Create(value, out IntPtr ptr);
            NativePtr = ptr;
        }

        /// <summary>Creates a new SmallModulus by copying a given one.</summary>
        /// <param name="copy">The SmallModulus to copy from</param>
        /// <exception cref="ArgumentNullException">if copy is null</exception>
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
        /// <param name="assign">The SmallModulus to copy from</param>
        /// <exception cref="ArgumentNullException">if assign is null</exception>
        public void Set(SmallModulus assign)
        {
            if (null == assign)
                throw new ArgumentNullException(nameof(assign));

            NativeMethods.SmallModulus_Set(NativePtr, assign.NativePtr);
        }

        /// <summary>Sets the value of the SmallModulus.</summary>
        /// <param name="value">The new integer modulus</param>
        /// <exception cref="ArgumentException">if value is 1 or more than
        /// 62 bits</exception>
        public void Set(ulong value)
        {
            NativeMethods.SmallModulus_Set(NativePtr, value);
        }

        /// <summary>
        /// Returns the significant bit count of the value of the current SmallModulus.
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
        /// Returns the size (in 64-bit words) of the value of the current SmallModulus.
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

        /// <summary>
        /// Returns the Barrett ratio computed for the value of the current SmallModulus.
        /// </summary>
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

        /// <summary>
        /// Saves the SmallModulus to an output stream.
        /// </summary>
        /// <remarks>
        /// Saves the SmallModulus to an output stream. The output is in binary
        /// format and not human-readable. The output stream must have the "binary"
        /// flag set.
        /// </remarks>
        /// <param name="stream">The stream to save the SmallModulus to</param>
        /// <exception cref="ArgumentNullException">if stream is null</exception>
        /// <exception cref="ArgumentException">if the SmallModulus could not be
        /// written to stream</exception>
        public void Save(Stream stream)
        {
            if (null == stream)
                throw new ArgumentNullException(nameof(stream));

            try
            {
                using (BinaryWriter writer = new BinaryWriter(stream, Encoding.UTF8, leaveOpen: true))
                {
                    writer.Write(Value);
                }
            }
            catch (IOException ex)
            {
                throw new ArgumentException("Could not write SmallModulus", ex);
            }
        }

        /// <summary>
        /// Loads a SmallModulus from an input stream overwriting the current SmallModulus.
        /// </summary>
        /// <param name="stream">The stream to load the SmallModulus from</param>
        /// <exception cref="ArgumentNullException">if stream is null</exception>
        /// <exception cref="ArgumentException">if a valid SmallModulus could not be
        /// read from stream</exception>
        public void Load(Stream stream)
        {
            if (null == stream)
                throw new ArgumentNullException(nameof(stream));

            try
            {
                using (BinaryReader reader = new BinaryReader(stream, Encoding.UTF8, leaveOpen: true))
                {
                    ulong value = reader.ReadUInt64();
                    Set(value);
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
        /// <remarks>
        /// Creates a SmallModulus instance. The value of the SmallModulus is set to
        /// the given value.
        /// </remarks>
        /// <param name="value">The integer modulus</param>
        /// <exception cref="ArgumentException">if value is 1 or more than 62 bits</exception>
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

        #region IComparable<SmallModulus> methods

        /// <summary>
        /// Compares two SmallModulus instances.
        /// </summary>
        /// <param name="compare">The SmallModulus to compare against</param>
        public int CompareTo(SmallModulus compare)
        {
            if (null == compare)
                return 1;

            return Value.CompareTo(compare.Value);
        }

        #endregion

        #region IComparable<ulong> methods

        /// <summary>
        /// Compares a SmallModulus value to an unsigned integer.
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
            NativeMethods.SmallModulus_Destroy(NativePtr);
        }
    }
}