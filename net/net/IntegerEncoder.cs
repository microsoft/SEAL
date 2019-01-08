using Microsoft.Research.SEAL.Tools;
using System;
using System.Collections.Generic;
using System.Text;

namespace Microsoft.Research.SEAL
{
    /// <summary>
    /// Encodes integers into plaintext polynomials that Encryptor can encrypt. An instance of
    /// the IntegerEncoder class converts an integer into a plaintext polynomial by placing its
    /// digits in balanced base-b representation as the coefficients of the polynomial. The base
    /// b must be a positive integer at least 2 (which is the default value). When b is odd,
    /// digits in such a balanced representation are integers in the range -(b-1)/2,...,(b-1)/2.
    /// When b is even, digits are integers in the range -b/2,...,b/2-1. When b is 2, the 
    /// coefficients are either all non-negative (0 and 1), or all non-positive (0 and -1). A larger 
    /// base allows for more compact representation at the cost of having larger coefficients in 
    /// freshly encoded plaintext polynomials. Decoding the integer amounts to evaluating the 
    /// plaintext polynomial at X=b.
    /// 
    /// Addition and multiplication on the integer side translate into addition and multiplication
    /// on the encoded plaintext polynomial side, provided that the length of the polynomial
    /// never grows to be of the size of the polynomial modulus (poly_modulus), and that the
    /// coefficients of the plaintext polynomials appearing throughout the computations never
    /// experience coefficients larger than the plaintext modulus (plain_modulus).
    /// </summary>
    /// 
    /// <remarks>
    /// <para>
    /// Negative Integers
    /// Negative integers in the base-b encoding are represented the same way as positive integers, 
    /// namely, both positive and negative integers can have both positive and negative digits in their 
    /// base-b representation. Negative coefficients are stored in the plaintext polynomials as unsigned 
    /// integers that represent them modulo the plaintext modulus. Thus, for example, a coefficient of -1 
    /// would be stored as a polynomial coefficient plain_modulus-1.
    /// </para>
    /// <para>
    /// BinaryEncoder and BalancedEncoder
    /// Under the hood IntegerEncoder uses either the BinaryEncoder or the BalancedEncoder classes
    /// to do the encoding. The first one is used when the base is 2, and the second one when the
    /// base is at least 3. Currently the BinaryEncoder and BalancedEncoder classes can also be used 
    /// directly, but this might change in future releases.
    /// </para>
    /// </remarks>
    public class IntegerEncoder : NativeObject
    {
        /// <summary>
        /// Creates an IntegerEncoder object. The constructor takes as input a reference
        /// to the plaintext modulus (represented by SmallModulus), and optionally an integer,
        /// at least 2, that is used as a base in the encoding.
        /// </summary>
        /// <param name="plainModulus">The plaintext modulus (represented by SmallModulus)</param>
        /// <param name="baseVal">The base to be used for encoding (default value is 2)</param>
        /// <exception cref="ArgumentNullException">if plainModulus is null</exception>
        /// <exception cref="ArgumentException">if base is not an integer and at least 2</exception>
        /// <exception cref="ArgumentException">if plain_modulus is not at least base</exception>
        public IntegerEncoder(SmallModulus plainModulus, ulong baseVal = 2)
        {
            if (null == plainModulus)
                throw new ArgumentNullException(nameof(plainModulus));

            NativeMethods.IntegerEncoder_Create(plainModulus.NativePtr, baseVal, out IntPtr encoderPtr);
            NativePtr = encoderPtr;
        }

        /// <summary>
        /// Creates a copy of a IntegerEncoder.
        /// </summary>
        /// <param name="copy">The IntegerEncoder to copy from</param>
        /// <exception cref="ArgumentNullException">if copy is null</exception>
        public IntegerEncoder(IntegerEncoder copy)
        {
            if (null == copy)
                throw new ArgumentNullException(nameof(copy));

            NativeMethods.IntegerEncoder_Create(copy.NativePtr, out IntPtr ptr);
            NativePtr = ptr;
        }

        /// <summary>
        /// Encodes an unsigned integer (represented by ulong) into a plaintext polynomial.
        /// </summary>
        /// <param name="value">The unsigned integer to encode</param>
        public Plaintext Encode(ulong value)
        {
            Plaintext plain = new Plaintext();
            NativeMethods.IntegerEncoder_Encode(NativePtr, value, plain.NativePtr);
            return plain;
        }

        /// <summary>
        /// Encodes an unsigned integer(represented by ulong) into a plaintext polynomial.
        /// </summary>
        /// <param name="value">The unsigned integer to encode</param>
        /// <param name="destination">The plaintext to overwrite with the encoding</param>
        /// <exception cref="ArgumentNullException">if destination is null</exception>
        public void Encode(ulong value, Plaintext destination)
        {
            if (null == destination)
                throw new ArgumentNullException(nameof(destination));

            NativeMethods.IntegerEncoder_Encode(NativePtr, value, destination.NativePtr);
        }

        /// <summary>
        /// Decodes a plaintext polynomial and returns the result as uint.
        /// Mathematically this amounts to evaluating the input polynomial at X = base.
        /// </summary>
        /// <param name="plain">The plaintext to be decoded</param>
        /// <exception cref="ArgumentNullException">if plain is null</exception>
        /// <exception cref="ArgumentException">if plain does not represent a valid plaintext polynomial</exception>
        /// <exception cref="ArgumentException">if the output does not fit in uint</exception>
        public uint DecodeUInt32(Plaintext plain)
        {
            if (null == plain)
                throw new ArgumentNullException(nameof(plain));

            NativeMethods.IntegerEncoder_DecodeUInt32(NativePtr, plain.NativePtr, out uint result);
            return result;
        }

        /// <summary>
        /// Decodes a plaintext polynomial and returns the result as std::uint64_t.
        /// Mathematically this amounts to evaluating the input polynomial at X=base.
        /// </summary>
        /// <param name="plain">The plaintext to be decoded</param>
        /// <exception cref="ArgumentNullException">if plain is null</exception>
        /// <exception cref="ArgumentException">if plain does not represent a valid plaintext polynomial</exception>
        /// <exception cref="ArgumentException">if the output does not fit in ulong</exception>
        public ulong DecodeUInt64(Plaintext plain)
        {
            if (null == plain)
                throw new ArgumentNullException(nameof(plain));

            NativeMethods.IntegerEncoder_DecodeUInt64(NativePtr, plain.NativePtr, out ulong result);
            return result;
        }

        /// <summary>
        /// Encodes a signed integer (represented by long) into a plaintext polynomial.
        /// </summary>
        /// <remarks>
        /// <para>
        /// Negative Integers
        /// Negative integers in the base-b encoding are represented the same way as positive integers,
        /// namely, both positive and negative integers can have both positive and negative digits in their
        /// base-b representation. Negative coefficients are stored in the plaintext polynomials as unsigned
        /// integers that represent them modulo the plaintext modulus. Thus, for example, a coefficient of -1
        /// would be stored as a polynomial coefficient plain_modulus-1.
        /// </para>
        /// </remarks>
        /// <param name="value">The signed integer to encode</param>
        public Plaintext Encode(long value)
        {
            Plaintext plain = new Plaintext();
            NativeMethods.IntegerEncoder_Encode(NativePtr, value, plain.NativePtr);
            return plain;
        }

        /// <summary>
        /// Encodes a signed integer(represented by long) into a plaintext polynomial.
        /// </summary>
        /// <remarks>
        /// <para>
        /// Negative Integers
        /// Negative integers in the base-b encoding are represented the same way as positive integers,
        /// namely, both positive and negative integers can have both positive and negative digits in their
        /// base-b representation. Negative coefficients are stored in the plaintext polynomials as unsigned
        /// integers that represent them modulo the plaintext modulus.Thus, for example, a coefficient of -1
        /// would be stored as a polynomial coefficient plain_modulus-1.
        /// </para>
        /// </remarks>
        /// <param name="value">The signed integer to encode</param>
        /// <param name="destination">The plaintext to overwrite with the encoding</param>
        public void Encode(long value, Plaintext destination)
        {
            if (null == destination)
                throw new ArgumentNullException(nameof(destination));

            NativeMethods.IntegerEncoder_Encode(NativePtr, value, destination.NativePtr);
        }

        /// <summary>
        /// Encodes an unsigned integer(represented by BigUInt) into a plaintext polynomial.
        /// </summary>
        /// <param name="value">The unsigned integer to encode</param>
        /// <exception cref="ArgumentNullException">if value is null</exception>
        public Plaintext Encode(BigUInt value)
        {
            if (null == value)
                throw new ArgumentNullException(nameof(value));

            Plaintext plain = new Plaintext();
            NativeMethods.IntegerEncoder_Encode(NativePtr, value.NativePtr, plain.NativePtr);
            return plain;
        }

        /// <summary>
        /// Encodes an unsigned integer(represented by BigUInt) into a plaintext polynomial.
        /// </summary>
        /// <param name="value">The unsigned integer to encode</param>
        /// <param name="destination">The plaintext to overwrite with the encoding</param>
        /// <exception cref="ArgumentNullException">if either value or destination are null</exception>
        public void Encode(BigUInt value, Plaintext destination)
        {
            if (null == value)
                throw new ArgumentNullException(nameof(value));
            if (null == destination)
                throw new ArgumentNullException(nameof(destination));

            NativeMethods.IntegerEncoder_Encode(NativePtr, value.NativePtr, destination.NativePtr);
        }

        /// <summary>
        /// Decodes a plaintext polynomial and returns the result as std::int32_t.
        /// Mathematically this amounts to evaluating the input polynomial at X = base.
        /// </summary>
        /// <param name="plain">The plaintext to be decoded</param>
        /// <exception cref="ArgumentNullException">if plain is null</exception>
        /// <exception cref="ArgumentException">if plain does not represent a valid plaintext polynomial</exception>
        /// <exception cref="ArgumentException">if the output does not fit in int</exception>
        public int DecodeInt32(Plaintext plain)
        {
            if (null == plain)
                throw new ArgumentNullException(nameof(plain));

            NativeMethods.IntegerEncoder_DecodeInt32(NativePtr, plain.NativePtr, out int result);
            return result;
        }

        /// <summary>
        /// Decodes a plaintext polynomial and returns the result as std::int64_t.
        /// Mathematically this amounts to evaluating the input polynomial at X = base.
        /// </summary>
        /// <param name="plain">The plaintext to be decoded</param>
        /// <exception cref="ArgumentNullException">if plain is null</exception>
        /// <exception cref="ArgumentException">if plain does not represent a valid plaintext polynomial</exception>
        /// <exception cref="ArgumentException">if the output does not fit in long</exception>
        public long DecodeInt64(Plaintext plain)
        {
            if (null == plain)
                throw new ArgumentNullException(nameof(plain));

            NativeMethods.IntegerEncoder_DecodeInt64(NativePtr, plain.NativePtr, out long result);
            return result;
        }

        /// <summary>
        /// Decodes a plaintext polynomial and returns the result as BigUInt.
        /// Mathematically this amounts to evaluating the input polynomial at X = base.
        /// </summary>
        /// <param name="plain">The plaintext to be decoded</param>
        /// <exception cref="ArgumentNullException">if plain is null</exception>
        /// <exception cref="ArgumentException">if plain does not represent a valid plaintext polynomial</exception>
        /// <exception cref="ArgumentException">if the output is negative</exception>
        public BigUInt DecodeBigUInt(Plaintext plain)
        {
            if (null == plain)
                throw new ArgumentNullException(nameof(plain));

            int resultUInt64Count = 1;
            int bitsPerUInt64 = 64;
            int resultBitCapacity = resultUInt64Count * bitsPerUInt64;

            BigUInt bui = new BigUInt(resultBitCapacity);
            NativeMethods.IntegerEncoder_DecodeBigUInt(NativePtr, plain.NativePtr, bui.NativePtr);
            return bui;
        }

        /// <summary>
        /// Decodes a plaintext polynomial and stores the result in a given BigUInt.
        /// Mathematically this amounts to evaluating the input polynomial at X = base.
        /// </summary>
        /// <param name="plain">The plaintext to be decoded</param>
        /// <param name="destination">The BigUInt to overwrite with the decoding</param>
        /// <exception cref="ArgumentNullException">if either plain or destination are null</exception>
        /// <exception cref="ArgumentException">if plain does not represent a valid plaintext polynomial</exception>
        /// <exception cref="ArgumentException">if the output does not fit in destination</exception>
        /// <exception cref="ArgumentException">if the output is negative</exception>
        public void DecodeBigUInt(Plaintext plain, BigUInt destination)
        {
            if (null == plain)
                throw new ArgumentNullException(nameof(plain));
            if (null == destination)
                throw new ArgumentNullException(nameof(destination));

            NativeMethods.IntegerEncoder_DecodeBigUInt(NativePtr, plain.NativePtr, destination.NativePtr);
        }

        /// <summary>
        /// Encodes a signed integer(represented by int) into a plaintext polynomial.
        /// </summary>
        /// <remarks>
        /// <para>
        /// Negative Integers
        /// Negative integers in the base-b encoding are represented the same way as positive integers,
        /// namely, both positive and negative integers can have both positive and negative digits in their
        /// base-b representation. Negative coefficients are stored in the plaintext polynomials as unsigned
        /// integers that represent them modulo the plaintext modulus.Thus, for example, a coefficient of -1
        /// would be stored as a polynomial coefficient plain_modulus-1.
        /// </para>
        /// </remarks>
        /// <param name="value">The signed integer to encode</param>
        public Plaintext Encode(int value)
        {
            Plaintext plain = new Plaintext();
            NativeMethods.IntegerEncoder_Encode(NativePtr, value, plain.NativePtr);
            return plain;
        }

        /// <summary>
        /// Encodes an unsigned integer(represented by std::uint32_t) into a plaintext polynomial.
        /// </summary>
        /// <param name="value">The unsigned integer to encode</param>
        public Plaintext Encode(uint value)
        {
            Plaintext plain = new Plaintext();
            NativeMethods.IntegerEncoder_Encode(NativePtr, value, plain.NativePtr);
            return plain;
        }

        /// <summary>
        /// Encodes a signed integer(represented by int) into a plaintext polynomial.
        /// </summary>
        /// <remarks>
        /// <para>
        /// Negative Integers
        /// Negative integers in the base-b encoding are represented the same way as positive integers,
        /// namely, both positive and negative integers can have both positive and negative digits in their
        ///  base-b representation. Negative coefficients are stored in the plaintext polynomials as unsigned
        /// integers that represent them modulo the plaintext modulus.Thus, for example, a coefficient of -1
        /// would be stored as a polynomial coefficient plain_modulus-1.
        /// </para>
        /// </remarks>
        /// <param name="value">The signed integer to encode</param>
        /// <param name="destination">The plaintext to overwrite with the encoding</param>
        /// <exception cref="ArgumentNullException">if destination is null</exception>
        public void Encode(int value, Plaintext destination)
        {
            if (null == destination)
                throw new ArgumentNullException(nameof(destination));

            NativeMethods.IntegerEncoder_Encode(NativePtr, value, destination.NativePtr);
        }

        /// <summary>
        /// Encodes an unsigned integer(represented by std::uint32_t) into a plaintext polynomial.
        /// </summary>
        /// <param name="value">The unsigned integer to encode</param>
        /// <param name="destination">The plaintext to overwrite with the encoding</param>
        /// <exception cref="ArgumentNullException">if destination is null</exception>
        public void Encode(uint value, Plaintext destination)
        {
            if (null == destination)
                throw new ArgumentNullException(nameof(destination));

            NativeMethods.IntegerEncoder_Encode(NativePtr, value, destination.NativePtr);
        }

        /// <summary>
        /// Get a copy of the plaintext modulus.
        /// </summary>
        public SmallModulus PlainModulus
        {
            get
            {
                NativeMethods.IntegerEncoder_PlainModulus(NativePtr, out IntPtr sm);
                SmallModulus result = new SmallModulus(sm);
                return result;
            }
        }

        /// <summary>
        /// Get the base used for encoding
        /// </summary>
        public ulong Base
        {
            get
            {
                NativeMethods.IntegerEncoder_Base(NativePtr, out ulong result);
                return result;
            }
        }

        /// <summary>
        /// Destroy the native object
        /// </summary>
        protected override void DestroyNativeObject()
        {
            NativeMethods.IntegerEncoder_Destroy(NativePtr);
        }
    }
}
