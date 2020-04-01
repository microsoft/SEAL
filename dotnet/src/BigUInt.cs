// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

using System;
using System.IO;
using System.Numerics;
using System.Text;
using Microsoft.Research.SEAL.Tools;
using System.Runtime.InteropServices;

namespace Microsoft.Research.SEAL
{
    /// <summary>
    /// Represents an unsigned integer with a specified bit width.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Represents an unsigned integer with a specified bit width. BigUInts are mutable
    /// and able to be resized. The bit count for a BigUInt (which can be read with
    /// <see cref="BitCount"/>) is set initially by the constructor and can be resized
    /// either explicitly with the <see cref="Resize(int)"/> function or implicitly
    /// with an assignment operation (e.g., one of the Set() functions). A rich set
    /// of unsigned integer operations are provided by the BigUInt class, including
    /// comparison, traditional arithmetic (addition, subtraction, multiplication,
    /// division), and modular arithmetic functions.
    /// </para>
    /// <para>
    /// The backing array for a BigUInt stores its unsigned integer value as a contiguous
    /// System.UInt64 array. Each System.UInt64 in the array sequentially represents
    /// 64-bits of the integer value, with the least significant quad-word storing the
    /// lower 64-bits and the order of the bits for each quad word dependent on the
    /// architecture's System.UInt64 representation. The size of the array equals the bit
    /// count of the BigUInt (which can be read with <see cref="BitCount"/>) rounded up
    /// to the next System.UInt64 boundary (i.e., rounded up to the next 64-bit boundary).
    /// The <see cref="UInt64Count"/> property returns the number of System.UInt64 in the
    /// backing array. The <see cref="Data(ulong)"/> method returns an element of the
    /// System.UInt64 array. Additionally, the index property allows accessing the
    /// individual bytes of the integer value in a platform-independent way - for example,
    /// reading the third byte will always return bits 16-24 of the BigUInt value
    /// regardless of the platform being little-endian or big-endian.
    /// </para>
    /// <para>
    /// Both the copy constructor and the Set function allocate more memory for the
    /// backing array when needed, i.e. when the source BigUInt has a larger backing
    /// array than the destination. Conversely, when the destination backing array is
    /// already large enough, the data is only copied and the unnecessary higher order
    /// bits are set to zero. When new memory has to be allocated, only the significant
    /// bits of the source BigUInt are taken into account. This is is important, because
    /// it avoids unnecessary zero bits to be included in the destination, which in some
    /// cases could accumulate and result in very large unnecessary allocations. However,
    /// sometimes it is necessary to preserve the original size, even if some of the
    /// leading bits are zero. For this purpose BigUInt contains functions
    /// <see cref="DuplicateFrom"/> and <see cref="DuplicateTo"/>, which create an exact
    /// copy of the source BigUInt.
    /// </para>
    /// <para>
    /// An aliased BigUInt (which can be determined with <see cref="IsAlias"/>) is
    /// a special type of BigUInt that does not manage its underlying System.UInt64
    /// pointer used to store the value. An aliased BigUInt supports most of the same
    /// operations as a non-aliased BigUInt, including reading and writing the value,
    /// however an aliased BigUInt does not internally allocate or deallocate its backing
    /// array and, therefore, does not support resizing. Any attempt, either explicitly
    /// or implicitly, to resize the BigUInt will result in an exception being thrown.
    /// Aliased BigUInt's are only created internally. Aliasing is useful in cases where
    /// it is desirable to not have each BigUInt manage its own memory allocation and/or
    /// to prevent unnecessary copying.
    /// </para>
    /// <para>
    /// In general, reading a BigUInt is thread-safe while mutating is not. Specifically,
    /// the backing array may be freed whenever a resize occurs or the BigUInt is
    /// destroyed. When it is known that a resize will not occur, concurrent reading and
    /// mutating will not inherently fail but it is possible for a read to see a partially
    /// updated value from a concurrent write. A non-aliased BigUInt allocates its backing
    /// array from the global (thread-safe) memory pool. Consequently, creating or
    /// resizing a large number of BigUInt can result in a performance loss due to thread
    /// contention.
    /// </para>
    /// </remarks>
    public class BigUInt : NativeObject, IEquatable<BigUInt>, IComparable<BigUInt>
    {
        /// <summary>Creates an empty BigUInt with zero bit width.</summary>
        /// <remarks>
        /// Creates an empty BigUInt with zero bit width. No memory is allocated by
        /// this constructor.
        /// </remarks>
        public BigUInt()
        {
            IntPtr ptr = IntPtr.Zero;
            NativeMethods.BigUInt_Create(out ptr);
            NativePtr = ptr;
        }

        /// <summary>Creates a zero-initialized BigUInt of the specified bit
        /// width.</summary>
        /// <param name="bitCount">The bit width</param>
        /// <exception cref="ArgumentException">if bitCount is negative</exception>
        public BigUInt(int bitCount)
        {
            if (bitCount < 0)
                throw new ArgumentException("bitCount cannot be negative");

            IntPtr ptr = IntPtr.Zero;
            NativeMethods.BigUInt_Create(bitCount, out ptr);
            NativePtr = ptr;
        }

        /// <summary>Creates a BigUInt of the specified bit width and initializes
        /// it with the unsigned hexadecimal integer specified by the string.</summary>
        /// <remarks>
        /// Creates a BigUInt of the specified bit width and initializes it with
        /// the unsigned hexadecimal integer specified by the string. The string
        /// must match the format returned by <see cref="ToString()"/> and must
        /// consist of only the characters 0-9, A-F, or a-f, most-significant nibble
        /// first.
        /// </remarks>
        ///
        /// <param name="bitCount">The bit width</param>
        /// <param name="hexString">The hexadecimal integer string specifying the
        /// initial value</param>
        /// <exception cref="ArgumentNullException">if hexString is null</exception>
        /// <exception cref="ArgumentException">if bitCount is negative</exception>
        /// <exception cref="ArgumentException">if hexString does not adhere to the
        /// expected format</exception>
        public BigUInt(int bitCount, string hexString)
        {
            if (null == hexString)
                throw new ArgumentNullException(nameof(hexString));
            if (bitCount < 0)
                throw new ArgumentException("bitCount cannot be negative");

            IntPtr ptr = IntPtr.Zero;
            NativeMethods.BigUInt_Create(bitCount, hexString, out ptr);
            NativePtr = ptr;
        }

        /// <summary>Creates a BigUInt of the specified bit width and initializes it
        /// to the specified unsigned integer value.</summary>
        ///
        /// <param name="bitCount"> The bit width</param>
        /// <param name="value"> The initial value to set the BigUInt</param>
        /// <exception cref="ArgumentException">if bitCount is negative</exception>
        public BigUInt(int bitCount, ulong value)
        {
            if (bitCount < 0)
                throw new ArgumentException("bitCount cannot be negative");

            IntPtr ptr = IntPtr.Zero;
            NativeMethods.BigUInt_Create(bitCount, value, out ptr);
            NativePtr = ptr;
        }

        /// <summary>Creates a BigUInt initialized and minimally sized to fit the
        /// unsigned hexadecimal integer specified by the string.</summary>
        /// <remarks>
        /// Creates a BigUInt initialized and minimally sized to fit the unsigned
        /// hexadecimal integer specified by the string. The string matches the format
        /// returned by<see cref= "ToString()" /> and must consist of only the characters
        /// 0-9, A-F, or a-f, most-significant nibble first.
        /// </remarks>
        /// <param name="hexString"> The hexadecimal integer string specifying the
        /// initial value</param>
        /// <exception cref="ArgumentNullException">if hexString is null</exception>
        /// <exception cref="ArgumentException">if hexString does not adhere to the
        /// expected format</exception>
        public BigUInt(string hexString)
        {
            if (null == hexString)
                throw new ArgumentNullException(nameof(hexString));

            IntPtr ptr = IntPtr.Zero;
            NativeMethods.BigUInt_Create(hexString, out ptr);
            NativePtr = ptr;
        }

        /// <summary>Creates a deep copy of a BigUInt.</summary>
        /// <remarks>
        /// Creates a deep copy of a BigUInt. The created BigUInt will have the same
        /// bit count and value as the original.
        /// </remarks>
        /// <param name="copy">The BigUInt to copy from</param>
        /// <exception cref="ArgumentNullException">if copy is null</exception>
        public BigUInt(BigUInt copy)
        {
            if (null == copy)
                throw new ArgumentNullException(nameof(copy));

            IntPtr ptr = IntPtr.Zero;
            NativeMethods.BigUInt_Create(copy.NativePtr, out ptr);
            NativePtr = ptr;
        }

        /// <summary>
        /// Creates a BigUInt initialized and minimally sized to fit the unsigned
        /// hexadecimal integer specified by the <see cref= "System.Numerics.BigInteger" />.
        /// </summary >
        /// <param name= "bigInteger"> The initial value of the BigUInt</param>
        /// <exception cref="ArgumentNullException">if bigInteger is null</exception>
        public BigUInt(BigInteger bigInteger)
        {
            if (null == bigInteger)
                throw new ArgumentNullException(nameof(bigInteger));

            string hex = bigInteger.ToString("X");
            IntPtr ptr = IntPtr.Zero;
            NativeMethods.BigUInt_Create(hex, out ptr);
            NativePtr = ptr;
        }

        /// <summary>
        /// Creates a BigUInt from an IntPtr.
        /// </summary>
        /// <param name="ptr">Native pointer</param>
        /// <param name="owned">Whether this BigUInt instance owns the native
        /// pointer</param>
        internal BigUInt(IntPtr ptr, bool owned = true)
            : base(ptr, owned)
        {
        }

        /// <summary>Returns whether or not the BigUInt is an alias.</summary>
        public bool IsAlias
        {
            get
            {
                NativeMethods.BigUInt_IsAlias(NativePtr, out bool isAlias);
                return isAlias;
            }
        }

        /// <summary>Returns the bit count for the BigUInt.</summary>
        public int BitCount
        {
            get
            {
                NativeMethods.BigUInt_BitCount(NativePtr, out int bitCount);
                return bitCount;
            }
        }

        /// <summary>Returns the number of bytes in the backing array used to store
        /// the BigUInt value.</summary>
        public ulong ByteCount
        {
            get
            {
                NativeMethods.BigUInt_ByteCount(NativePtr, out ulong byteCount);
                return byteCount;
            }
        }

        /// <summary>Returns the number of System.UInt64 in the backing array used
        /// to store the BigUInt value.</summary>
        public ulong UInt64Count
        {
            get
            {
                NativeMethods.BigUInt_UInt64Count(NativePtr, out ulong uint64Count);
                return uint64Count;
            }
        }

        /// <summary>Gets/sets the byte at the corresponding byte index of the BigUInt's
        /// integer value.</summary>
        /// <remarks>
        /// Gets/sets the byte at the corresponding byte index of the BigUInt's integer
        /// value. The bytes of the BigUInt are indexed least-significant byte first.
        /// </remarks>
        /// <param name="index"> The index of the byte to get/set</param>
        /// <exception cref="ArgumentOutOfRangeException">if index is not within
        /// [0, <see cref="ByteCount"/>)</exception>
        public byte this[ulong index]
        {
            get
            {
                if (index >= ByteCount)
                    throw new ArgumentOutOfRangeException(nameof(index));

                NativeMethods.BigUInt_Get(NativePtr, index, out byte result);
                return result;
            }
            set
            {
                if (index >= ByteCount)
                    throw new ArgumentOutOfRangeException(nameof(index));

                NativeMethods.BigUInt_Set(NativePtr, index, value);
            }
        }

        /// <summary>
        /// Returns the ulong value at a given position in the backing array storing
        /// the BigUInt value.
        /// </summary>
        /// <remarks>
        /// Returns the <see cref="ulong"/> value that is at position <paramref name="index"/>
        /// in the backing array storing the BigUInt value.
        /// </remarks>
        /// <param name="index"></param>
        /// <exception cref="ArgumentOutOfRangeException">if index is not within
        /// [0, <see cref="UInt64Count"/>)</exception>
        public ulong Data(ulong index)
        {
            if (index >= UInt64Count)
                throw new ArgumentOutOfRangeException(nameof(index));

            NativeMethods.BigUInt_GetU64(NativePtr, index, out ulong result);
            return result;
        }

        /// <summary>
        /// Returns whether or not the BigUInt has the value zero.
        /// </summary>
        public bool IsZero
        {
            get
            {
                NativeMethods.BigUInt_IsZero(NativePtr, out bool isZero);
                return isZero;
            }
        }

        /// <summary>
        /// Returns the number of significant bits for the BigUInt.
        /// </summary>
        public int GetSignificantBitCount()
        {
            NativeMethods.BigUInt_GetSignificantBitCount(NativePtr, out int result);
            return result;
        }

        /// <summary>
        /// Overwrites the BigUInt with the value of the specified BigUInt, enlarging
        /// if needed to fit the assigned value.
        /// </summary>
        /// <remarks>
        /// Overwrites the BigUInt with the value of the specified BigUInt, enlarging
        /// if needed to fit the assigned value. Only significant bits are used to size
        /// the BigUInt.
        /// </remarks>
        /// <param name="assign"> The BigUInt whose value should be assigned to the
        /// current BigUInt</param>
        /// <exception cref="ArgumentNullException">if assign is null</exception>
        /// <exception cref="InvalidOperationException">if BigUInt is an alias and
        /// the assigned BigUInt is too large to fit the current bit width</exception>
        public void Set(BigUInt assign)
        {
            if (null == assign)
                throw new ArgumentNullException(nameof(assign));
            if (IsAlias)
                throw new InvalidOperationException("Cannot assign to an alias");

            NativeMethods.BigUInt_Set(NativePtr, assign.NativePtr);
        }

        /// <summary>
        /// Overwrites the BigUInt with the unsigned hexadecimal value specified by
        /// the string, enlarging if needed to fit the assigned value.
        /// </summary>
        /// <remarks>
        /// Overwrites the BigUInt with the unsigned hexadecimal value specified by
        /// the string, enlarging if needed to fit the assigned value. The string must
        /// match the format returned by<see cref="ToString()"/> and must consist of
        /// only the characters 0-9, A-F, or a-f, most-significant nibble first.
        /// </remarks>
        /// <param name="assign"> The hexadecimal integer string specifying the value
        /// to assign</param>
        /// <exception cref="ArgumentNullException">if assign is null</exception>
        /// <exception cref="ArgumentException">if assign does not adhere to the
        /// expected format</exception>
        /// <exception cref="InvalidOperationException">if BigUInt is an alias and
        /// the assigned value is too large to fit the current bit width</exception>
        public void Set(string assign)
        {
            if (null == assign)
                throw new ArgumentNullException(nameof(assign));
            if (IsAlias)
                throw new InvalidOperationException("Cannot assign to an alias");

            NativeMethods.BigUInt_Set(NativePtr, assign);
        }

        /// <summary>Overwrites the BigUInt with the specified integer value, enlarging
        /// if needed to fit the value.</summary>
        ///
        /// <param name="assign"> The value to assign</param>
        /// <exception cref="InvalidOperationException">if BigUInt is an alias and
        /// the significant bit count of assign is too large to fit the current bit
        /// width</exception>
        public void Set(ulong assign)
        {
            NativeMethods.BigUInt_Set(NativePtr, assign);
        }

        /// <summary>Sets the BigUInt value to zero.</summary>
        /// <remarks>
        /// Sets the BigUInt value to zero. This does not resize the BigUInt.
        /// </remarks>
        public void SetZero()
        {
            NativeMethods.BigUInt_SetZero(NativePtr);
        }

        /// <summary>
        /// Returns an upper bound on the size of the BigUInt, as if it was written
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
            NativeMethods.BigUInt_SaveSize(
                NativePtr, (byte)comprModeValue, out long outBytes);
            return outBytes;
        }

        /// <summary>Saves the BigUInt to an output stream.</summary>
        /// <remarks>
        /// Saves the BigUInt to an output stream. The full state of the BigUInt is
        /// serialized, including insignificant bits. The output is in binary format
        /// and not human-readable.
        /// </remarks>
        /// <param name="stream">The stream to save the BigUInt to</param>
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
                    NativeMethods.BigUInt_Save(NativePtr, outptr, size,
                    cm, out outBytes),
                SaveSize(comprModeValue), comprModeValue, stream);
        }

        /// <summary>
        /// Loads a BigUInt from an input stream overwriting the current BigUInt.
        /// </summary>
        /// <param name="stream">The stream to load the BigUInt from</param>
        /// <exception cref="ArgumentNullException">if stream is null</exception>
        /// <exception cref="ArgumentException">if the stream is closed or does not
        /// support reading</exception>
        /// <exception cref="EndOfStreamException">if the stream ended
        /// unexpectedly</exception>
        /// <exception cref="IOException">if I/O operations failed</exception>
        /// <exception cref="InvalidOperationException">if the data cannot be loaded
        /// by this version of Microsoft SEAL, if the loaded data is invalid, if the
        /// loaded compression mode is not supported, or if the loaded BigUInt is too
        /// large for an aliased BigUInt</exception>
        public long Load(Stream stream)
        {
            return Serialization.Load(
                (byte[] outptr, ulong size, out long outBytes) =>
                    NativeMethods.BigUInt_Load(NativePtr, outptr, size, out outBytes),
                stream);
        }

        /// <summary>
        /// Resizes the BigUInt to the specified bit width, copying over the old
        /// value as much as will fit.
        /// </summary>
        /// <param name="bitCount">The bit width</param>
        /// <exception cref="ArgumentException">if bitCount is negative</exception>
        /// <exception cref="InvalidOperationException">if the BigUInt is an
        /// alias</exception>
        public void Resize(int bitCount)
        {
            if (bitCount < 0)
                throw new ArgumentException("bitCount cannot be negative");
            if (IsAlias)
                throw new InvalidOperationException("Cannot resize an alias");

            NativeMethods.BigUInt_Resize(NativePtr, bitCount);
        }

        /// <summary>
        /// Returns the BigUInt value as a <see cref="System.Numerics.BigInteger"/>.
        /// </summary>
        public BigInteger ToBigInteger()
        {
            ulong byteCount = ByteCount;
            byte[] bytes = new byte[byteCount + 1];
            for (ulong i = 0; i < byteCount; i++)
            {
                bytes[i] = this[i];
            }
            bytes[byteCount] = 0;

            BigInteger result = new BigInteger(bytes);
            return result;
        }

        /// <summary>
        /// Returns the BigUInt value as a decimal string.
        /// </summary>
        public string ToDecimalString()
        {
            NativeMethods.BigUInt_ToDecimalString(NativePtr, null, length: out ulong length);
            StringBuilder buffer = new StringBuilder(checked((int)length));
            NativeMethods.BigUInt_ToDecimalString(NativePtr, buffer, out length);
            return buffer.ToString();
        }

        /// <summary>
        /// Compares a BigUInt and an unsigned integer and returns -1, 0, or 1 if
        /// the BigUInt is less-than, equal-to, or greater-than the second operand
        /// respectively. The input operands are not modified.
        /// </summary>
        /// <param name="compare">The value to compare against</param>
        public int CompareTo(ulong compare)
        {
            NativeMethods.BigUInt_CompareTo(NativePtr, compare, out int result);
            return result;
        }

        /// <summary>Divides two BigUInts and returns the quotient and sets the
        /// remainder parameter to the remainder.</summary>
        /// <remarks>
        /// Divides two BigUInts and returns the quotient and sets the remainder
        /// parameter to the remainder. The bit count of the quotient is set to be
        /// the significant bit count of the BigUInt. The remainder is resized if
        /// and only if it is smaller than the bit count of the BigUInt.
        /// </remarks>
        /// <param name="operand2">The second operand to divide</param>
        /// <param name="remainder">The BigUInt to store the remainder</param>
        /// <exception cref="ArgumentNullException">if operand2 or remainder is
        /// null</exception>
        /// <exception cref="ArgumentException">if operand2 is zero</exception>
        /// <exception cref="InvalidOperationException">if the remainder is an alias
        /// and the operator attempts to enlarge the BigUInt to fit the result</exception>
        public BigUInt DivideRemainder(BigUInt operand2, BigUInt remainder)
        {
            if (null == operand2)
                throw new ArgumentNullException(nameof(operand2));
            if (null == remainder)
                throw new ArgumentNullException(nameof(remainder));
            if (operand2.IsZero)
                throw new ArgumentException("operand2 is zero");
            if (remainder.IsAlias)
                throw new InvalidOperationException("remainder is an alias");

            NativeMethods.BigUInt_DivideRemainder(NativePtr, operand2.NativePtr,
                remainder.NativePtr, out IntPtr resultptr);
            BigUInt result = new BigUInt(resultptr);
            return result;
        }

        /// <summary>Divides a BigUInt and an unsigned integer and returns the quotient
        /// and sets the remainder parameter to the remainder.</summary>
        ///
        /// <remarks>
        /// Divides a BigUInt and an unsigned integer and returns the quotient and
        /// sets the remainder parameter to the remainder. The bit count of the quotient
        /// is set to be the significant bit count of the BigUInt. The remainder is
        /// resized if and only if it is smaller than the bit count of the BigUInt.
        /// </remarks>
        /// <param name="operand2">The second operand to divide</param>
        /// <param name="remainder">The BigUInt to store the remainder</param>
        /// <exception cref="ArgumentNullException">if remainder is null</exception>
        /// <exception cref="ArgumentException">if operand2 is zero</exception>
        /// <exception cref="InvalidOperationException">if the remainder is an alias
        /// which the function attempts to enlarge to fit the result</exception>
        public BigUInt DivideRemainder(ulong operand2, BigUInt remainder)
        {
            if (null == remainder)
                throw new ArgumentNullException(nameof(remainder));
            if (operand2 == 0)
                throw new ArgumentException("operand2 is zero");
            if (remainder.IsAlias)
                throw new InvalidOperationException("remainder is an alias");

            NativeMethods.BigUInt_DivideRemainder(NativePtr, operand2,
                remainder.NativePtr, out IntPtr resultptr);
            BigUInt result = new BigUInt(resultptr);
            return result;
        }

        /// <summary>Returns the inverse of a BigUInt with respect to the specified
        /// modulus.</summary>
        /// <remarks>
        /// Returns the inverse of a BigUInt with respect to the specified modulus.
        /// The original BigUInt is not modified. The bit count of the inverse is
        /// set to be the significant bit count of the modulus.
        /// </remarks>
        /// <param name="modulus">The modulus to calculate the inverse with respect
        /// to</param>
        /// <exception cref="ArgumentNullException">if modulus is null</exception>
        /// <exception cref="ArgumentException">if modulus is zero</exception>
        /// <exception cref="ArgumentException">if modulus is not greater than the
        /// BigUInt value</exception>
        /// <exception cref="ArgumentException">if the BigUInt value and modulus
        /// are not co-prime</exception>
        /// <exception cref="InvalidOperationException">if the BigUInt value is
        /// zero</exception>
        public BigUInt ModuloInvert(BigUInt modulus)
        {
            if (null == modulus)
                throw new ArgumentNullException(nameof(modulus));

            BigUInt result = null;
            NativeMethods.BigUInt_ModuloInvert(NativePtr, modulus.NativePtr,
                out IntPtr resultptr);
            result = new BigUInt(resultptr);
            return result;
        }

        /// <summary>Returns the inverse of a BigUInt with respect to the specified
        /// modulus.</summary>
        /// <remarks>
        /// Returns the inverse of a BigUInt with respect to the specified modulus.
        /// The original BigUInt is not modified. The bit count of the inverse is set
        /// to be the significant bit count of the modulus.
        /// </remarks>
        /// <param name="modulus">The modulus to calculate the inverse with respect
        /// to</param>
        /// <exception cref="ArgumentException">if modulus is zero</exception>
        /// <exception cref="ArgumentException">if modulus is not greater than the
        /// BigUInt value</exception>
        /// <exception cref="ArgumentException">if the BigUInt value and modulus
        /// are not co-prime</exception>
        public BigUInt ModuloInvert(ulong modulus)
        {
            NativeMethods.BigUInt_ModuloInvert(NativePtr, modulus, out IntPtr resultptr);
            BigUInt result = new BigUInt(resultptr);
            return result;
        }

        /// <summary>Attempts to calculate the inverse of a BigUInt with respect to
        /// the specified modulus, returning whether or not the inverse was successful
        /// and setting the inverse parameter to the inverse.</summary>
        /// <remarks>
        /// Attempts to calculate the inverse of a BigUInt with respect to the specified
        /// modulus, returning whether or not the inverse was successful and setting
        /// the inverse parameter to the inverse. The original BigUInt is not modified.
        /// The inverse parameter is resized if and only if its bit count is smaller
        /// than the significant bit count of the modulus.
        /// </remarks>
        /// <param name="modulus">The modulus to calculate the inverse with respect
        /// to</param>
        /// <param name="inverse">Stores the inverse if the inverse operation was
        /// successful</param>
        /// <exception cref="ArgumentNullException">if modulus or inverse is null</exception>
        /// <exception cref="ArgumentException">if modulus is zero</exception>
        /// <exception cref="ArgumentException">if modulus is not greater than the
        /// BigUInt value</exception>
        /// <exception cref="InvalidOperationException">if the inverse is an alias
        /// which the function attempts to enlarge to fit the result</exception>
        public bool TryModuloInvert(BigUInt modulus, BigUInt inverse)
        {
            if (null == modulus)
                throw new ArgumentNullException(nameof(modulus));
            if (null == inverse)
                throw new ArgumentNullException(nameof(inverse));
            if (inverse.IsAlias)
                throw new InvalidOperationException("inverse is an alias");

            NativeMethods.BigUInt_TryModuloInvert(NativePtr, modulus.NativePtr,
                inverse.NativePtr, out bool result);
            return result;
        }

        /// <summary>Attempts to calculate the inverse of a BigUInt with respect to
        /// the specified modulus, returning whether or not the inverse was successful
        /// and setting the inverse parameter to the inverse.</summary>
        /// <remarks>
        /// Attempts to calculate the inverse of a BigUInt with respect to the
        /// specified modulus, returning whether or not the inverse was successful
        /// and setting the inverse parameter to the inverse. The original BigUInt
        /// is not modified. The inverse parameter is resized if and only if its bit
        /// count is smaller than the significant bit count of the modulus.
        /// </remarks>
        /// <param name="modulus">The modulus to calculate the inverse with respect
        /// to</param>
        /// <param name="inverse">Stores the inverse if the inverse operation was
        /// successful</param>
        /// <exception cref="ArgumentNullException">if inverse is null</exception>
        /// <exception cref="ArgumentException">if modulus is zero</exception>
        /// <exception cref="ArgumentException">if modulus is not greater than the
        /// BigUInt value</exception>
        /// <exception cref="InvalidOperationException">if the inverse is an alias
        /// which the function attempts to enlarge to fit the result</exception>
        public bool TryModuloInvert(ulong modulus, BigUInt inverse)
        {
            if (null == inverse)
                throw new ArgumentNullException(nameof(inverse));
            if (inverse.IsAlias)
                throw new InvalidOperationException("inverse is an alias");

            NativeMethods.BigUInt_TryModuloInvert(NativePtr, modulus,
                inverse.NativePtr, out bool result);
            return result;
        }

        /// <summary>Duplicates the current BigUInt.</summary>
        /// <remarks>
        /// Duplicates the current BigUInt. The bit count and the value of the given
        /// BigUInt are set to be exactly the same as in the current one.
        /// </remarks>
        /// <param name="destination">The BigUInt to overwrite with the duplicate</param>
        /// <exception cref="ArgumentNullException">if destination is null</exception>
        /// <exception cref="InvalidOperationException">if the destination BigUInt
        /// is an alias</exception>
        public void DuplicateTo(BigUInt destination)
        {
            if (null == destination)
                throw new ArgumentNullException(nameof(destination));
            if (destination.IsAlias)
                throw new InvalidOperationException("destination is an alias");

            NativeMethods.BigUInt_DuplicateTo(NativePtr, destination.NativePtr);
        }

        /// <summary>Duplicates a given BigUInt.</summary>
        /// <remarks>
        /// Duplicates a given BigUInt. The bit count and the value of the current
        /// BigUInt are set to be exactly the same as in the given one.
        /// </remarks>
        /// <param name="value">The BigUInt to duplicate</param>
        /// <exception cref="ArgumentNullException">if value is null</exception>
        /// <exception cref="InvalidOperationException">if the current BigUInt is
        /// an alias</exception>
        public void DuplicateFrom(BigUInt value)
        {
            if (null == value)
                throw new ArgumentNullException(nameof(value));

            NativeMethods.BigUInt_DuplicateFrom(NativePtr, value.NativePtr);
        }

        #region Operators

        /// <summary>Returns a copy of the BigUInt value resized to the significant bit count.</summary>
        ///
        /// <param name="operand">The operand to copy</param>
        /// <exception cref="ArgumentNullException">if operand is null</exception>
        public static BigUInt operator +(BigUInt operand)
        {
            if (null == operand)
                throw new ArgumentNullException(nameof(operand));

            return new BigUInt(operand);
        }

        /// <summary>Returns a negated copy of the BigUInt value.</summary>
        ///
        /// <remarks>
        /// Returns a negated copy of the BigUInt value. The bit count does not change.
        /// </remarks>
        /// <param name="operand">The operand to negate</param>
        /// <exception cref="ArgumentNullException">if operand is null</exception>
        public static BigUInt operator -(BigUInt operand)
        {
            if (null == operand)
                throw new ArgumentNullException(nameof(operand));

            NativeMethods.BigUInt_OperatorNeg(operand.NativePtr, out IntPtr resultptr);
            BigUInt result = new BigUInt(resultptr);
            return result;
        }

        /// <summary>Returns an inverted copy of the BigUInt value.</summary>
        ///
        /// <remarks>
        /// Returns an inverted copy of the BigUInt value. The bit count does not change.
        /// </remarks>
        /// <param name="operand">The operand to invert</param>
        /// <exception cref="ArgumentNullException">if operand is null</exception>
        public static BigUInt operator ~(BigUInt operand)
        {
            if (null == operand)
                throw new ArgumentNullException(nameof(operand));

            NativeMethods.BigUInt_OperatorTilde(operand.NativePtr, out IntPtr resultptr);
            BigUInt result = new BigUInt(resultptr);
            return result;
        }

        /// <summary>Increments the BigUInt and returns the incremented value.</summary>
        ///
        /// <remarks>
        /// Increments the BigUInt and returns the incremented value. The BigUInt will increment the bit count if needed to fit the
        /// carry.
        /// </remarks>
        /// <param name="operand">The operand to increment</param>
        /// <exception cref="ArgumentNullException">if operand is null</exception>
        /// <exception cref="InvalidOperationException">if BigUInt is an alias and a carry occurs requiring the BigUInt to
        /// be resized</exception>
        public static BigUInt operator ++(BigUInt operand)
        {
            if (null == operand)
                throw new ArgumentNullException(nameof(operand));

            NativeMethods.BigUInt_OperatorPlus(operand.NativePtr, operand: 1ul, result: out IntPtr resultptr);
            BigUInt result = new BigUInt(resultptr);
            return result;
        }

        /// <summary>Decrements the BigUInt and returns the decremented value.</summary>
        ///
        /// <remarks>
        /// Decrements the BigUInt and returns the decremented value. The bit count does not change.
        /// </remarks>
        /// <param name="operand">The operand to decrement</param>
        /// <exception cref="ArgumentNullException">if operand is null</exception>
        public static BigUInt operator --(BigUInt operand)
        {
            if (null == operand)
                throw new ArgumentNullException(nameof(operand));

            NativeMethods.BigUInt_OperatorMinus(operand.NativePtr, operand: 1ul, result: out IntPtr resultptr);
            BigUInt result = new BigUInt(resultptr);
            return result;
        }

        /// <summary>Adds two BigUInts and returns the sum.</summary>
        ///
        /// <remarks>
        /// Adds two BigUInts and returns the sum. The input operands are not modified. The bit count of the sum is set to be one
        /// greater than the significant bit count of the larger of the two input operands.
        /// </remarks>
        /// <param name="operand1">The first operand to add</param>
        /// <param name="operand2">The second operand to add</param>
        /// <exception cref="ArgumentNullException">if operand1 or operand2 is null</exception>
        public static BigUInt operator +(BigUInt operand1, BigUInt operand2)
        {
            if (null == operand1)
                throw new ArgumentNullException(nameof(operand1));
            if (null == operand2)
                throw new ArgumentNullException(nameof(operand2));

            NativeMethods.BigUInt_OperatorPlus(operand1.NativePtr, operand2.NativePtr, out IntPtr resultptr);
            BigUInt result = new BigUInt(resultptr);
            return result;
        }

        /// <summary>Adds a BigUInt and an unsigned integer and returns the sum.</summary>
        ///
        /// <remarks>
        /// Adds a BigUInt and an unsigned integer and returns the sum. The input operands are not modified. The bit count of the
        /// sum is set to be one greater than the significant bit count of the larger of the two operands.
        /// </remarks>
        /// <param name="operand1">The first operand to add</param>
        /// <param name="operand2">The second operand to add</param>
        /// <exception cref="ArgumentNullException">if operand1 is null</exception>
        public static BigUInt operator +(BigUInt operand1, ulong operand2)
        {
            if (null == operand1)
                throw new ArgumentNullException(nameof(operand1));

            NativeMethods.BigUInt_OperatorPlus(operand1.NativePtr, operand2, out IntPtr resultptr);
            BigUInt result = new BigUInt(resultptr);
            return result;
        }

        /// <summary>Subtracts two BigUInts and returns the difference.</summary>
        ///
        /// <remarks>
        /// Subtracts two BigUInts and returns the difference. The input operands are not modified. The bit count of the difference
        /// is set to be the significant bit count of the larger of the two input operands.
        /// </remarks>
        /// <param name="operand1">The first operand to subtract</param>
        /// <param name="operand2">The second operand to subtract</param>
        /// <exception cref="ArgumentNullException">if operand1 or operand2 is null</exception>
        public static BigUInt operator -(BigUInt operand1, BigUInt operand2)
        {
            if (null == operand1)
                throw new ArgumentNullException(nameof(operand1));
            if (null == operand2)
                throw new ArgumentNullException(nameof(operand2));

            NativeMethods.BigUInt_OperatorMinus(operand1.NativePtr, operand2.NativePtr, out IntPtr resultptr);
            BigUInt result = new BigUInt(resultptr);
            return result;
        }

        /// <summary>Subtracts a BigUInt and an unsigned integer and returns the difference.</summary>
        ///
        /// <remarks>
        /// Subtracts a BigUInt and an unsigned integer and returns the difference. The input operands are not modified. The bit
        /// count of the difference is set to be the significant bit count of the larger of the two operands.
        /// </remarks>
        /// <param name="operand1">The first operand to subtract</param>
        /// <param name="operand2">The second operand to subtract</param>
        /// <exception cref="ArgumentNullException">if operand1 is null</exception>
        public static BigUInt operator -(BigUInt operand1, ulong operand2)
        {
            if (null == operand1)
                throw new ArgumentNullException(nameof(operand1));

            NativeMethods.BigUInt_OperatorMinus(operand1.NativePtr, operand2, out IntPtr resultptr);
            BigUInt result = new BigUInt(resultptr);
            return result;
        }

        /// <summary>Multiplies two BigUInts and returns the product.</summary>
        ///
        /// <remarks>
        /// Multiplies two BigUInts and returns the product. The input operands are not modified. The bit count of the product is
        /// set to be the sum of the significant bit counts of the two input operands.
        /// </remarks>
        /// <param name="operand1">The first operand to multiply</param>
        /// <param name="operand2">The second operand to multiply</param>
        /// <exception cref="ArgumentNullException">if operand1 or operand2 is null</exception>
        public static BigUInt operator *(BigUInt operand1, BigUInt operand2)
        {
            if (null == operand1)
                throw new ArgumentNullException(nameof(operand1));
            if (null == operand2)
                throw new ArgumentNullException(nameof(operand2));

            NativeMethods.BigUInt_OperatorMult(operand1.NativePtr, operand2.NativePtr, out IntPtr resultptr);
            BigUInt result = new BigUInt(resultptr);
            return result;
        }

        /// <summary>Multiplies a BigUInt and an unsigned integer and returns the product.</summary>
        ///
        /// <remarks>
        /// Multiplies a BigUInt and an unsigned integer and returns the product. The input operands are not modified. The bit
        /// count of the product is set to be the sum of the significant bit counts of the two input operands.
        /// </remarks>
        /// <param name="operand1">The first operand to multiply</param>
        /// <param name="operand2">The second operand to multiply</param>
        /// <exception cref="ArgumentNullException">if operand1 is null</exception>
        public static BigUInt operator *(BigUInt operand1, ulong operand2)
        {
            if (null == operand1)
                throw new ArgumentNullException(nameof(operand1));

            NativeMethods.BigUInt_OperatorMult(operand1.NativePtr, operand2, out IntPtr resultptr);
            BigUInt result = new BigUInt(resultptr);
            return result;
        }

        /// <summary>Divides two BigUInts and returns the quotient.</summary>
        ///
        /// <remarks>
        /// Divides two BigUInts and returns the quotient. The input operands are not modified. The bit count of the quotient is
        /// set to be the significant bit count of the first input operand.
        /// </remarks>
        /// <param name="operand1">The first operand to divide</param>
        /// <param name="operand2">The second operand to divide</param>
        /// <exception cref="ArgumentNullException">if operand1 or operand2 is null</exception>
        /// <exception cref="ArgumentException">if operand2 is zero</exception>
        public static BigUInt operator /(BigUInt operand1, BigUInt operand2)
        {
            if (null == operand1)
                throw new ArgumentNullException(nameof(operand1));
            if (null == operand2)
                throw new ArgumentNullException(nameof(operand2));
            if (operand2.IsZero)
                throw new ArgumentException("operand2 is zero");

            NativeMethods.BigUInt_OperatorDiv(operand1.NativePtr, operand2.NativePtr, out IntPtr resultptr);
            BigUInt result = new BigUInt(resultptr);
            return result;
        }

        /// <summary>Divides a BigUInt and an unsigned integer and returns the quotient.</summary>
        ///
        /// <remarks>
        /// Divides a BigUInt and an unsigned integer and returns the quotient. The input operands are not modified. The bit count
        /// of the quotient is set to be the significant bit count of the first input operand.
        /// </remarks>
        /// <param name="operand1">The first operand to divide</param>
        /// <param name="operand2">The second operand to divide</param>
        /// <exception cref="ArgumentNullException">if operand1 is null</exception>
        /// <exception cref="ArgumentException">if operand2 is zero</exception>
        public static BigUInt operator /(BigUInt operand1, ulong operand2)
        {
            if (null == operand1)
                throw new ArgumentNullException(nameof(operand1));
            if (0 == operand2)
                throw new ArgumentException("operand2 is zero");

            NativeMethods.BigUInt_OperatorDiv(operand1.NativePtr, operand2, out IntPtr resultptr);
            BigUInt result = new BigUInt(resultptr);
            return result;
        }

        /// <summary>Performs a bit-wise XOR operation between two BigUInts and returns the result.</summary>
        ///
        /// <remarks>
        /// Performs a bit-wise XOR operation between two BigUInts and returns the result. The input operands are not modified. The
        /// bit count of the result is set to the maximum of the two input operand bit counts.
        /// </remarks>
        /// <param name="operand1">The first operand to XOR</param>
        /// <param name="operand2">The second operand to XOR</param>
        /// <exception cref="ArgumentNullException">if operand1 or operand2 is null</exception>
        public static BigUInt operator ^(BigUInt operand1, BigUInt operand2)
        {
            if (null == operand1)
                throw new ArgumentNullException(nameof(operand1));
            if (null == operand2)
                throw new ArgumentNullException(nameof(operand2));

            NativeMethods.BigUInt_OperatorXor(operand1.NativePtr, operand2.NativePtr, out IntPtr resultptr);
            BigUInt result = new BigUInt(resultptr);
            return result;
        }

        /// <summary>Performs a bit-wise XOR operation between a BigUInt and an unsigned integer and returns the result.</summary>
        ///
        /// <remarks>
        /// Performs a bit-wise XOR operation between a BigUInt and an unsigned integer and returns the result. The input operands
        /// are not modified. The bit count of the result is set to the maximum of the two input operand bit counts.
        /// </remarks>
        /// <param name="operand1">The first operand to XOR</param>
        /// <param name="operand2">The second operand to XOR</param>
        /// <exception cref="ArgumentNullException">if operand1 is null</exception>
        public static BigUInt operator ^(BigUInt operand1, ulong operand2)
        {
            if (null == operand1)
                throw new ArgumentNullException(nameof(operand1));

            NativeMethods.BigUInt_OperatorXor(operand1.NativePtr, operand2, out IntPtr resultptr);
            BigUInt result = new BigUInt(resultptr);
            return result;
        }

        /// <summary>Performs a bit-wise AND operation between two BigUInts and returns the result.</summary>
        ///
        /// <remarks>
        /// Performs a bit-wise AND operation between two BigUInts and returns the result. The input operands are not modified. The
        /// bit count of the result is set to the maximum of the two input operand bit counts.
        /// </remarks>
        /// <param name="operand1">The first operand to AND</param>
        /// <param name="operand2">The second operand to AND</param>
        /// <exception cref="ArgumentNullException">if operand1 or operand2 is null</exception>
        public static BigUInt operator &(BigUInt operand1, BigUInt operand2)
        {
            if (null == operand1)
                throw new ArgumentNullException(nameof(operand1));
            if (null == operand2)
                throw new ArgumentNullException(nameof(operand2));

            NativeMethods.BigUInt_OperatorAnd(operand1.NativePtr, operand2.NativePtr, out IntPtr resultptr);
            BigUInt result = new BigUInt(resultptr);
            return result;
        }

        ///  <summary>Performs a bit-wise AND operation between a BigUInt and an unsigned integer and returns the result.</summary>
        ///
        ///  <remarks>
        ///  Performs a bit-wise AND operation between a BigUInt and an unsigned integer and returns the result. The input operands
        ///  are not modified. The bit count of the result is set to the maximum of the two input operand bit counts.
        ///  </remarks>
        ///  <param name="operand1">The first operand to AND</param>
        ///  <param name="operand2">The second operand to AND</param>
        ///  <exception cref="ArgumentNullException">if operand1 is null</exception>
        public static BigUInt operator &(BigUInt operand1, ulong operand2)
        {
            if (null == operand1)
                throw new ArgumentNullException(nameof(operand1));

            NativeMethods.BigUInt_OperatorAnd(operand1.NativePtr, operand2, out IntPtr resultptr);
            BigUInt result = new BigUInt(resultptr);
            return result;
        }

        /// <summary>Performs a bit-wise OR operation between two BigUInts and returns the result.</summary>
        ///
        /// <remarks>
        /// Performs a bit-wise OR operation between two BigUInts and returns the result. The input operands are not modified. The
        /// bit count of the result is set to the maximum of the two input operand bit counts.
        /// </remarks>
        /// <param name="operand1">The first operand to OR</param>
        /// <param name="operand2">The second operand to OR</param>
        /// <exception cref="ArgumentNullException">if operand1 or operand2 is null</exception>
        public static BigUInt operator |(BigUInt operand1, BigUInt operand2)
        {
            if (null == operand1)
                throw new ArgumentNullException(nameof(operand1));
            if (null == operand2)
                throw new ArgumentNullException(nameof(operand2));

            NativeMethods.BigUInt_OperatorOr(operand1.NativePtr, operand2.NativePtr, out IntPtr resultptr);
            BigUInt result = new BigUInt(resultptr);
            return result;
        }

        /// <summary>Performs a bit-wise OR operation between a BigUInt and an unsigned integer and returns the result.</summary>
        ///
        /// <remarks>
        /// Performs a bit-wise OR operation between a BigUInt and an unsigned integer and returns the result. The input operands
        /// are not modified. The bit count of the result is set to the maximum of the two input operand bit counts.
        /// </remarks>
        /// <param name="operand1">The first operand to OR</param>
        /// <param name="operand2">The second operand to OR</param>
        /// <exception cref="ArgumentNullException">if operand1 is null</exception>
        public static BigUInt operator |(BigUInt operand1, ulong operand2)
        {
            if (null == operand1)
                throw new ArgumentNullException(nameof(operand1));

            NativeMethods.BigUInt_OperatorOr(operand1.NativePtr, operand2, out IntPtr resultptr);
            BigUInt result = new BigUInt(resultptr);
            return result;
        }

        /// <summary>Returns a left-shifted copy of the BigUInt.</summary>
        ///
        /// <remarks>
        /// Returns a left-shifted copy of the BigUInt. The bit count of the returned value is the sum of the original significant
        /// bit count and the shift amount.
        /// </remarks>
        /// <param name="operand1">The operand to left-shift</param>
        /// <param name="shift">The number of bits to shift by</param>
        /// <exception cref="ArgumentNullException">if operand1 is null</exception>
        /// <exception cref="ArgumentException">if shift is negative</exception>
        public static BigUInt operator <<(BigUInt operand1, int shift)
        {
            if (null == operand1)
                throw new ArgumentNullException(nameof(operand1));
            if (shift < 0)
                throw new ArgumentException("shift is negative");

            NativeMethods.BigUInt_OperatorShiftLeft(operand1.NativePtr, shift, out IntPtr resultptr);
            BigUInt result = new BigUInt(resultptr);
            return result;
        }

        /// <summary>Returns a right-shifted copy of the BigUInt.</summary>
        ///
        /// <remarks>
        /// Returns a right-shifted copy of the BigUInt. The bit count of the returned value is the original significant bit count
        /// subtracted by the shift amount (clipped to zero if negative).
        /// </remarks>
        /// <param name="operand1">The operand to right-shift</param>
        /// <param name="shift">The number of bits to shift by</param>
        /// <exception cref="ArgumentNullException">if operand1 is null</exception>
        /// <exception cref="ArgumentException">if shift is negative</exception>
        public static BigUInt operator >>(BigUInt operand1, int shift)
        {
            if (null == operand1)
                throw new ArgumentNullException(nameof(operand1));
            if (shift < 0)
                throw new ArgumentException("shift is negative");

            NativeMethods.BigUInt_OperatorShiftRight(operand1.NativePtr, shift, out IntPtr resultptr);
            BigUInt result = new BigUInt(resultptr);
            return result;
        }

        /// <summary>Returns the BigUInt value as a double.</summary>
        /// <remarks>
        /// Returns the BigUInt value as a double. Note that precision may be lost during the conversion.
        /// </remarks>
        /// <param name="value">The value to convert</param>
        /// <exception cref="ArgumentNullException">if value is null</exception>
        public static explicit operator double(BigUInt value)
        {
            if (null == value)
                throw new ArgumentNullException(nameof(value));

            NativeMethods.BigUInt_ToDouble(value.NativePtr, out double result);
            return result;
        }

        /// <summary>Returns the BigUInt value as a float.</summary>
        /// <remarks>
        /// Returns the BigUInt value as a float. Note that precision may be lost during the conversion.
        /// </remarks>
        /// <param name="value">The value to convert</param>
        /// <exception cref="ArgumentNullException">if value is null</exception>
        public static explicit operator float(BigUInt value)
        {
            if (null == value)
                throw new ArgumentNullException(nameof(value));

            double dblvalue = (double)value;
            return unchecked((float)dblvalue);
        }

        /// <summary>Returns the lower 64-bits of a BigUInt value.</summary>
        /// <remarks>
        /// Returns the lower 64-bits of a BigUInt value. Note that if the value is greater than 64-bits,
        /// the higher bits are dropped.
        /// </remarks>
        /// <param name="value">The value to convert</param>
        /// <exception cref="ArgumentNullException">if value is null</exception>
        public static explicit operator ulong(BigUInt value)
        {
            if (null == value)
                throw new ArgumentNullException(nameof(value));

            if (value.BitCount == 0)
                return 0;

            return value.Data(0);
        }

        /// <summary>Returns the lower 64-bits of a BigUInt value as a signed-integer.</summary>
        /// <remarks>
        /// Returns the lower 64-bits of a BigUInt value as a signed-integer. Note that if the value is greater than
        /// 64-bits, the result may be negative and the higher bits are dropped.
        /// </remarks>
        /// <param name="value">The value to convert</param>
        /// <exception cref="ArgumentNullException">if value is null</exception>
        public static explicit operator long(BigUInt value)
        {
            if (null == value)
                throw new ArgumentNullException(nameof(value));

            ulong ulvalue = (ulong)value;
            return unchecked((long)ulvalue);
        }

        /// <summary>Returns the lower 32-bits of a BigUInt value.</summary>
        /// <remarks>
        /// Returns the lower 32-bits of a BigUInt value. Note that if the value is greater than 32-bits,
        /// the higher bits are dropped.
        /// </remarks>
        /// <param name="value">The value to convert</param>
        /// <exception cref="ArgumentNullException">if value is null</exception>
        public static explicit operator uint(BigUInt value)
        {
            if (null == value)
                throw new ArgumentNullException(nameof(value));

            ulong ulvalue = (ulong)value;
            return unchecked((uint)ulvalue);
        }

        /// <summary>Returns the lower 32-bits of a BigUInt value as a signed-integer.</summary>
        /// <remarks>
        /// Returns the lower 32-bits of a BigUInt value as a signed-integer. Note that if the value is greater than
        /// 32-bits, the result may be negative and the higher bits are dropped.
        /// </remarks>
        /// <param name="value">The value to convert</param>
        /// <exception cref="ArgumentNullException">if value is null</exception>
        public static explicit operator int(BigUInt value)
        {
            if (null == value)
                throw new ArgumentNullException(nameof(value));

            ulong ulvalue = (ulong)value;
            return unchecked((int)ulvalue);
        }

        #endregion // Operators

        #region IComparable methods

        /// <summary>Compares two BigUInts and returns -1, 0, or 1 if the BigUInt is less-than, equal-to, or greater-than the
        /// second operand respectively.</summary>
        ///
        /// <remarks>
        /// Compares two BigUInts and returns -1, 0, or 1 if the BigUInt is less-than, equal-to, or greater-than the second
        /// operand respectively. The input operands are not modified.
        /// </remarks>
        /// <param name="compare">The value to compare against</param>
        public int CompareTo(BigUInt compare)
        {
            if (null == compare)
                return 1;

            NativeMethods.BigUInt_CompareTo(NativePtr, compare.NativePtr, out int result);
            return result;
        }

        #endregion

        #region IEquatable methods

        /// <summary>Returns whether or not a BigUInt is equal to a second BigUInt.</summary>
        /// <remarks>
        /// Returns whether or not a BigUInt is equal to a second BigUInt. The input operands are not modified.
        /// </remarks>
        ///
        /// <param name="compare">The value to compare against</param>
        public bool Equals(BigUInt compare)
        {
            if (null == compare)
                return false;

            NativeMethods.BigUInt_Equals(NativePtr, compare.NativePtr, out bool result);
            return result;
        }

        #endregion

        #region Object overrides

        /// <summary>Returns whether or not a BigUInt is equal to a second BigUInt.</summary>
        /// <remarks>
        /// Returns whether or not a BigUInt is equal to a second BigUInt. The input operands are not modified.
        /// </remarks>
        ///
        /// <param name="compare">The value to compare against</param>
        public override bool Equals(object compare)
        {
            BigUInt other = compare as BigUInt;
            return Equals(other);
        }

        /// <summary>
        /// Returns the BigUInt value as a hexadecimal string.
        /// </summary>
        public override string ToString()
        {
            NativeMethods.BigUInt_ToString(NativePtr, null, length: out ulong length);
            StringBuilder buffer = new StringBuilder(checked((int)length));
            NativeMethods.BigUInt_ToString(NativePtr, buffer, out length);
            return buffer.ToString();
        }

        /// <summary>
        /// Returns a hash-code based on the value of the BigUInt.
        /// </summary>
        public override int GetHashCode()
        {
            ulong[] data = new ulong[UInt64Count];
            for (long i = 0; i < data.LongLength; i++)
            {
                data[i] = Data((ulong)i);
            }

            return Utilities.ComputeArrayHashCode(data);
        }

        #endregion

        /// <summary>
        /// Destroy native object.
        /// </summary>
        protected override void DestroyNativeObject()
        {
            NativeMethods.BigUInt_Destroy(NativePtr);
        }
    }
}
