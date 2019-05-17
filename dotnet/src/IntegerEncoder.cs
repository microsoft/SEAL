// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

using Microsoft.Research.SEAL.Tools;
using System;

namespace Microsoft.Research.SEAL
{
    /// <summary>
    /// Encodes integers into plaintext polynomials that Encryptor can encrypt. An instance of
    /// the IntegerEncoder class converts an integer into a plaintext polynomial by placing its
    /// binary digits as the coefficients of the polynomial. Decoding the integer amounts to
    /// evaluating the plaintext polynomial at x=2.
    ///
    /// Addition and multiplication on the integer side translate into addition and multiplication
    /// on the encoded plaintext polynomial side, provided that the length of the polynomial
    /// never grows to be of the size of the polynomial modulus (PolyModulus), and that the
    /// coefficients of the plaintext polynomials appearing throughout the computations never
    /// experience coefficients larger than the plaintext modulus (PlainModulus).
    /// </summary>
    /// <remarks>
    /// <para>
    /// Negative Integers
    /// Negative integers are represented by using -1 instead of 1 in the binary representation,
    /// and the negative coefficients are stored in the plaintext polynomials as unsigned integers
    /// that represent them modulo the plaintext modulus. Thus, for example, a coefficient of -1
    /// would be stored as a polynomial coefficient PlainModulus-1.
    /// </para>
    /// </remarks>
    public class IntegerEncoder : NativeObject
    {
        /// <summary>
        /// Creates a IntegerEncoder object. The constructor takes as input a pointer to
        /// a SEALContext object which contains the plaintext modulus.
        /// </summary>
        /// <param name="context">The SEALContext</param>
        /// <exception cref="ArgumentNullException">if context is null</exception>
        /// <exception cref="ArgumentException">if the context is not set</exception>
        /// <exception cref="ArgumentException">if the PlainModulus set in context is not
        /// at least 2</exception>
        public IntegerEncoder(SEALContext context)
        {
            if (null == context)
                throw new ArgumentNullException(nameof(context));
            if (!context.ParametersSet)
                throw new ArgumentException("Encryption parameters are not set correctly");

            SEALContext.ContextData contextData = context.FirstContextData;
            if (contextData.Parms.Scheme != SchemeType.BFV)
                throw new ArgumentException("Unsupported scheme");

            NativeMethods.IntegerEncoder_Create(context.NativePtr, out IntPtr encoderPtr);
            NativePtr = encoderPtr;
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
        /// Decodes a plaintext polynomial and returns the result as uint. Mathematically
        /// this amounts to evaluating the input polynomial at X = 2.
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
        /// Decodes a plaintext polynomial and returns the result as ulong. Mathematically
        /// this amounts to evaluating the input polynomial at X=2.
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
        /// Negative integers are represented by using -1 instead of 1 in the binary representation,
        /// and the negative coefficients are stored in the plaintext polynomials as unsigned integers
        /// that represent them modulo the plaintext modulus. Thus, for example, a coefficient of -1
        /// would be stored as a polynomial coefficient PlainModulus-1.
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
        /// Negative integers are represented by using -1 instead of 1 in the binary representation,
        /// and the negative coefficients are stored in the plaintext polynomials as unsigned integers
        /// that represent them modulo the plaintext modulus. Thus, for example, a coefficient of -1
        /// would be stored as a polynomial coefficient PlainModulus-1.
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
        /// Decodes a plaintext polynomial and returns the result as int. Mathematically
        /// this amounts to evaluating the input polynomial at X = 2.
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
        /// Decodes a plaintext polynomial and returns the result as long. Mathematically
        /// this amounts to evaluating the input polynomial at X = 2.
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
        /// Mathematically this amounts to evaluating the input polynomial at X = 2.
        /// </summary>
        /// <param name="plain">The plaintext to be decoded</param>
        /// <exception cref="ArgumentNullException">if plain is null</exception>
        /// <exception cref="ArgumentException">if plain does not represent a valid plaintext polynomial</exception>
        /// <exception cref="ArgumentException">if the output is negative</exception>
        public BigUInt DecodeBigUInt(Plaintext plain)
        {
            if (null == plain)
                throw new ArgumentNullException(nameof(plain));

            NativeMethods.IntegerEncoder_DecodeBigUInt(NativePtr, plain.NativePtr, out IntPtr buiPtr);
            BigUInt bui = new BigUInt(buiPtr);
            return bui;
        }

        /// <summary>
        /// Encodes a signed integer(represented by int) into a plaintext polynomial.
        /// </summary>
        /// <remarks>
        /// <para>
        /// Negative Integers
        /// Negative integers are represented by using -1 instead of 1 in the binary representation,
        /// and the negative coefficients are stored in the plaintext polynomials as unsigned integers
        /// that represent them modulo the plaintext modulus. Thus, for example, a coefficient of -1
        /// would be stored as a polynomial coefficient PlainModulus-1.
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
        /// Encodes an unsigned integer(represented by uint) into a plaintext polynomial.
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
        /// Negative integers are represented by using -1 instead of 1 in the binary representation,
        /// and the negative coefficients are stored in the plaintext polynomials as unsigned integers
        /// that represent them modulo the plaintext modulus. Thus, for example, a coefficient of -1
        /// would be stored as a polynomial coefficient PlainModulus-1.
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
        /// Encodes an unsigned integer(represented by uint) into a plaintext polynomial.
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
        /// Destroy the native object
        /// </summary>
        protected override void DestroyNativeObject()
        {
            NativeMethods.IntegerEncoder_Destroy(NativePtr);
        }
    }
}
