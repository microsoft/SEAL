// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

using Microsoft.Research.SEAL.Tools;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Numerics;

namespace Microsoft.Research.SEAL
{
    /// <summary>
    /// Provides functionality for encoding vectors of complex or real numbers into plaintext
    /// polynomials to be encrypted and computed on using the CKKS scheme. If the polynomial
    /// modulus degree is N, then CKKSEncoder converts vectors of N/2 complex numbers into
    /// plaintext elements. Homomorphic operations performed on such encrypted vectors are
    /// applied coefficient (slot-)wise, enabling powerful SIMD functionality for computations
    /// that are vectorizable. This functionality is often called "batching" in the homomorphic
    /// encryption literature.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Mathematical Background
    /// Mathematically speaking, if the polynomial modulus is X^N+1, N is a power of two, the
    /// CKKSEncoder implements an approximation of the canonical embedding of the ring of
    /// integers Z[X]/(X^N+1) into C^(N/2), where C denotes the complex numbers. The Galois
    /// group of the extension is (Z/2NZ)* ~= Z/2Z x Z/(N/2) whose action on the primitive roots
    /// of unity modulo CoeffModulus is easy to describe. Since the batching slots correspond
    /// 1-to-1 to the primitive roots of unity, applying Galois automorphisms on the plaintext
    /// acts by permuting the slots. By applying generators of the two cyclic subgroups of the
    /// Galois group, we can effectively enable cyclic rotations and complex conjugations of
    /// the encrypted complex vectors.
    /// </para>
    /// </remarks>
    public class CKKSEncoder : NativeObject
    {
        /// <summary>
        /// Creates a CKKSEncoder instance initialized with the specified SEALContext.
        /// </summary>
        /// <param name="context">The SEALContext</param>
        /// <exception cref="ArgumentNullException">if context is null</exception>
        /// <exception cref="ArgumentException">if the context is not set or encryption parameters
        /// are not valid</exception>
        /// <exception cref="ArgumentException">if scheme is not SchemeType.CKKS</exception>
        public CKKSEncoder(SEALContext context)
        {
            if (null == context)
                throw new ArgumentNullException(nameof(context));
            if (!context.ParametersSet)
                throw new ArgumentException("Encryption parameters are not set correctly");

            SEALContext.ContextData contextData = context.FirstContextData;
            if (contextData.Parms.Scheme != SchemeType.CKKS)
                throw new ArgumentException("Unsupported scheme");

            NativeMethods.CKKSEncoder_Create(context.NativePtr, out IntPtr ptr);
            NativePtr = ptr;

            context_ = context;
        }

        /// <summary>
        /// Encodes double-precision floating-point real numbers into a plaintext
        /// polynomial. Dynamic memory allocations in the process are allocated from the
        /// memory pool pointed to by the given MemoryPoolHandle.
        /// </summary>
        /// <param name="values">The enumeration of double-precision floating-point numbers
        /// to encode</param>
        /// <param name="parmsId">parmsId determining the encryption parameters to be used
        /// by the result plaintext</param>
        /// <param name="scale">Scaling parameter defining encoding precision</param>
        /// <param name="destination">The plaintext polynomial to overwrite with the result</param>
        /// <param name="pool">The MemoryPoolHandle pointing to a valid memory pool</param>
        /// <exception cref="ArgumentNullException">if either values, parmsId or destionation are null.</exception>
        /// <exception cref="ArgumentException">if values has invalid size</exception>
        /// <exception cref="ArgumentException">if parmsId is not valid for the encryption
        /// parameters </exception>
        /// <exception cref="ArgumentException">if scale is not strictly positive</exception>
        /// <exception cref="ArgumentException">if encoding is too large for the encryption
        /// parameters</exception>
        /// <exception cref="ArgumentException">if pool is uninitialized</exception>
        public void Encode(IEnumerable<double> values, ParmsId parmsId,
            double scale, Plaintext destination, MemoryPoolHandle pool = null)
        {
            if (null == values)
                throw new ArgumentNullException(nameof(values));
            if (null == parmsId)
                throw new ArgumentNullException(nameof(parmsId));
            if (null == destination)
                throw new ArgumentNullException(nameof(destination));

            IntPtr poolPtr = pool?.NativePtr ?? IntPtr.Zero;
            double[] valuearray = values.ToArray();
            NativeMethods.CKKSEncoder_EncodeDouble(NativePtr, (ulong)valuearray.LongLength, valuearray,
                parmsId.Block, scale, destination.NativePtr, poolPtr);
        }

        /// <summary>
        /// Encodes double-precision floating-point complex numbers into a plaintext
        /// polynomial. Dynamic memory allocations in the process are allocated from the
        /// memory pool pointed to by the given MemoryPoolHandle.
        /// </summary>
        /// <param name="values">The enumeration of double-precision complex numbers
        /// to encode</param>
        /// <param name="parmsId">parmsId determining the encryption parameters to be used
        /// by the result plaintext</param>
        /// <param name="scale">Scaling parameter defining encoding precision</param>
        /// <param name="destination">The plaintext polynomial to overwrite with the result</param>
        /// <param name="pool">The MemoryPoolHandle pointing to a valid memory pool</param>
        /// <exception cref="ArgumentNullException">if either values, parmsId or destionation are null.</exception>
        /// <exception cref="ArgumentException">if values has invalid size</exception>
        /// <exception cref="ArgumentException">if parmsId is not valid for the encryption
        /// parameters </exception>
        /// <exception cref="ArgumentException">if scale is not strictly positive</exception>
        /// <exception cref="ArgumentException">if encoding is too large for the encryption
        /// parameters</exception>
        /// <exception cref="ArgumentException">if pool is uninitialized</exception>
        public void Encode(IEnumerable<Complex> values, ParmsId parmsId,
            double scale, Plaintext destination, MemoryPoolHandle pool = null)
        {
            if (null == values)
                throw new ArgumentNullException(nameof(values));
            if (null == parmsId)
                throw new ArgumentNullException(nameof(parmsId));
            if (null == destination)
                throw new ArgumentNullException(nameof(destination));

            IntPtr poolPtr = pool?.NativePtr ?? IntPtr.Zero;
            double[] valuearray = new double[values.LongCount() * 2];
            ulong idx = 0;
            foreach(Complex complex in values)
            {
                valuearray[idx++] = complex.Real;
                valuearray[idx++] = complex.Imaginary;
            }

            // Note that we should pass values.Count as the length instead of valuearray.Length,
            // since we are using two doubles in the array per element.
            NativeMethods.CKKSEncoder_EncodeComplex(NativePtr, (ulong)values.LongCount(), valuearray,
                parmsId.Block, scale, destination.NativePtr, poolPtr);
        }

        /// <summary>
        /// Encodes double-precision floating-point real numbers into
        /// a plaintext polynomial. The encryption parameters used are the top level
        /// parameters for the given context. Dynamic memory allocations in the process
        /// are allocated from the memory pool pointed to by the given MemoryPoolHandle.
        /// </summary>
        /// <param name="values">The enumeration of double-precision floating-point numbers
        /// to encode</param>
        /// <param name="scale">Scaling parameter defining encoding precision</param>
        /// <param name="destination">The plaintext polynomial to overwrite with the result</param>
        /// <param name="pool">The MemoryPoolHandle pointing to a valid memory pool</param>
        /// <exception cref="ArgumentNullException">if either values or destionation are null.</exception>
        /// <exception cref="ArgumentException">if values has invalid size</exception>
        /// <exception cref="ArgumentException">if scale is not strictly positive</exception>
        /// <exception cref="ArgumentException">if encoding is too large for the encryption
        /// parameters</exception>
        /// <exception cref="ArgumentException">if pool is uninitialized</exception>
        public void Encode(IEnumerable<double> values, double scale,
            Plaintext destination, MemoryPoolHandle pool = null)
        {
            Encode(values, context_.FirstParmsId, scale, destination, pool);
        }

        /// <summary>
        /// Encodes double-precision floating-point complex numbers into
        /// a plaintext polynomial. The encryption parameters used are the top level
        /// parameters for the given context. Dynamic memory allocations in the process
        /// are allocated from the memory pool pointed to by the given MemoryPoolHandle.
        /// </summary>
        /// <param name="values">The enumeration of double-precision floating-point numbers
        /// to encode</param>
        /// <param name="scale">Scaling parameter defining encoding precision</param>
        /// <param name="destination">The plaintext polynomial to overwrite with the result</param>
        /// <param name="pool">The MemoryPoolHandle pointing to a valid memory pool</param>
        /// <exception cref="ArgumentNullException">if either values or destionation are null.</exception>
        /// <exception cref="ArgumentException">if values has invalid size</exception>
        /// <exception cref="ArgumentException">if scale is not strictly positive</exception>
        /// <exception cref="ArgumentException">if encoding is too large for the encryption
        /// parameters</exception>
        /// <exception cref="ArgumentException">if pool is uninitialized</exception>
        public void Encode(IEnumerable<Complex> values, double scale,
            Plaintext destination, MemoryPoolHandle pool = null)
        {
            Encode(values, context_.FirstParmsId, scale, destination, pool);
        }

        /// <summary>
        /// Encodes a double-precision floating-point number into a plaintext polynomial.
        /// Dynamic memory allocations in the process are allocated from the memory pool
        /// pointed to by the given MemoryPoolHandle.
        /// </summary>
        /// <param name="value">The double-precision floating-point number to encode</param>
        /// <param name="parmsId">parmsId determining the encryption parameters to be used
        /// by the result plaintext</param>
        /// <param name="scale">Scaling parameter defining encoding precision</param>
        /// <param name="destination">The plaintext polynomial to overwrite with the result</param>
        /// <param name="pool">The MemoryPoolHandle pointing to a valid memory pool</param>
        /// <exception cref="ArgumentNullException">if either parmsId or destination are null</exception>
        /// <exception cref="ArgumentException">if parmsId is not valid for the encryption
        /// parameters </exception>
        /// <exception cref="ArgumentException">if scale is not strictly positive</exception>
        /// <exception cref="ArgumentException">if encoding is too large for the encryption
        /// parameters</exception>
        /// <exception cref="ArgumentException">if pool is uninitialized</exception>
        public void Encode(double value, ParmsId parmsId,
            double scale, Plaintext destination,
            MemoryPoolHandle pool = null)
        {
            if (null == parmsId)
                throw new ArgumentNullException(nameof(parmsId));
            if (null == destination)
                throw new ArgumentNullException(nameof(destination));

            IntPtr poolPtr = pool?.NativePtr ?? IntPtr.Zero;
            NativeMethods.CKKSEncoder_Encode(NativePtr, value, parmsId.Block, scale, destination.NativePtr, poolPtr);
        }

        /// <summary>
        /// Encodes a double-precision floating-point number into a plaintext polynomial.
        /// The encryption parameters used are the top level parameters for the given context.
        /// Dynamic memory allocations in the process are allocated from the memory pool
        /// pointed to by the given MemoryPoolHandle.
        /// </summary>
        /// <param name="value">The double-precision floating-point number to encode</param>
        /// <param name="scale">Scaling parameter defining encoding precision</param>
        /// <param name="destination">The plaintext polynomial to overwrite with the result</param>
        /// <param name="pool">The MemoryPoolHandle pointing to a valid memory pool</param>
        /// <exception cref="ArgumentNullException">if destination is null</exception>
        /// <exception cref="ArgumentException">if scale is not strictly positive</exception>
        /// <exception cref="ArgumentException">if encoding is too large for the encryption
        /// parameters</exception>
        /// <exception cref="ArgumentException">if pool is uninitialized</exception>
        public void Encode(double value, double scale, Plaintext destination,
            MemoryPoolHandle pool = null)
        {
            Encode(value, context_.FirstParmsId, scale, destination, pool);
        }

        /// <summary>
        /// Encodes a double-precision complex number into a plaintext polynomial. Dynamic
        /// memory allocations in the process are allocated from the memory pool pointed to
        /// by the given MemoryPoolHandle.
        /// </summary>
        /// <param name="value">The double-precision complex number to encode</param>
        /// <param name="parmsId">parmsId determining the encryption parameters to be used
        /// by the result plaintext</param>
        /// <param name="scale">Scaling parameter defining encoding precision</param>
        /// <param name="destination">The plaintext polynomial to overwrite with the result</param>
        /// <param name="pool">The MemoryPoolHandle pointing to a valid memory pool</param>
        /// <exception cref="ArgumentNullException">if either parmsId or destination are null</exception>
        /// <exception cref="ArgumentException">if parmsId is not valid for the encryption
        /// parameters </exception>
        /// <exception cref="ArgumentException">if scale is not strictly positive</exception>
        /// <exception cref="ArgumentException">if encoding is too large for the encryption
        /// parameters</exception>
        /// <exception cref="ArgumentException">if pool is uninitialized</exception>
        public void Encode(Complex value, ParmsId parmsId, double scale,
            Plaintext destination, MemoryPoolHandle pool = null)
        {
            if (null == parmsId)
                throw new ArgumentNullException(nameof(parmsId));
            if (null == destination)
                throw new ArgumentNullException(nameof(destination));

            IntPtr poolPtr = pool?.NativePtr ?? IntPtr.Zero;
            NativeMethods.CKKSEncoder_Encode(NativePtr, value.Real, value.Imaginary, parmsId.Block, scale, destination.NativePtr, poolPtr);
        }

        /// <summary>
        /// Encodes a double-precision complex number into a plaintext polynomial. The
        /// encryption parameters used are the top level parameters for the given context.
        /// Dynamic memory allocations in the process are allocated from the memory pool
        /// pointed to by the given MemoryPoolHandle.
        /// </summary>
        /// <param name="value">The double-precision complex number to encode</param>
        /// <param name="scale">Scaling parameter defining encoding precision</param>
        /// <param name="destination">The plaintext polynomial to overwrite with the result</param>
        /// <param name="pool">The MemoryPoolHandle pointing to a valid memory pool</param>
        /// <exception cref="ArgumentNullException">if destination is null</exception>
        /// <exception cref="ArgumentException">if scale is not strictly positive</exception>
        /// <exception cref="ArgumentException">if encoding is too large for the encryption
        /// parameters</exception>
        /// <exception cref="ArgumentException">if pool is uninitialized</exception>
        public void Encode(Complex value, double scale, Plaintext destination,
            MemoryPoolHandle pool = null)
        {
            Encode(value, context_.FirstParmsId, scale, destination, pool);
        }

        /// <summary>
        /// Encodes an integer number into a plaintext polynomial without any scaling.
        /// </summary>
        /// <param name="value">The integer number to encode</param>
        /// <param name="parmsId">parmsId determining the encryption parameters to be used
        /// by the result plaintext</param>
        /// <param name="destination">The plaintext polynomial to overwrite with the result</param>
        /// <exception cref="ArgumentNullException">if either parmsId or destionation are null</exception>
        /// <exception cref="ArgumentException">if parmsId is not valid for the encryption
        /// parameters </exception>
        public void Encode(long value, ParmsId parmsId, Plaintext destination)
        {
            if (null == parmsId)
                throw new ArgumentNullException(nameof(parmsId));
            if (null == destination)
                throw new ArgumentNullException(nameof(destination));

            NativeMethods.CKKSEncoder_Encode(NativePtr, value, parmsId.Block, destination.NativePtr);
        }

        /// <summary>
        /// Encodes an integer number into a plaintext polynomial without any scaling. The
        /// encryption parameters used are the top level parameters for the given context.
        /// </summary>
        /// <param name="value">The integer number to encode</param>
        /// <param name="destination">The plaintext polynomial to overwrite with the result</param>
        /// <exception cref="ArgumentNullException">if destination is null</exception>
        public void Encode(long value, Plaintext destination)
        {
            Encode(value, context_.FirstParmsId, destination);
        }

        /// <summary>
        /// Decodes a plaintext polynomial into double-precision floating-point real
        /// numbers. Dynamic memory allocations in the process are allocated from
        /// the memory pool pointed to by the given MemoryPoolHandle.
        /// </summary>
        /// <param name="plain">plain The plaintext to decode</param>
        /// <param name="destination">The collection to be overwritten with the values in the slots</param>
        /// <param name="pool">The MemoryPoolHandle pointing to a valid memory pool</param>
        /// <exception cref="ArgumentNullException">if either plain or destination are null</exception>
        /// <exception cref="ArgumentException">if plain is not in NTT form or is invalid for the
        /// encryption parameters</exception>
        /// <exception cref="ArgumentException">if pool is uninitialized</exception>
        public void Decode(Plaintext plain, ICollection<double> destination,
                MemoryPoolHandle pool = null)
        {
            if (null == plain)
                throw new ArgumentNullException(nameof(plain));
            if (null == destination)
                throw new ArgumentNullException(nameof(destination));

            IntPtr poolPtr = pool?.NativePtr ?? IntPtr.Zero;
            ulong destCount = 0;

            // Find out what is the actual result size
            NativeMethods.CKKSEncoder_DecodeDouble(NativePtr, plain.NativePtr, ref destCount, null, poolPtr);

            // Now get the result
            double[] destarray = new double[destCount];
            NativeMethods.CKKSEncoder_DecodeDouble(NativePtr, plain.NativePtr, ref destCount, destarray, poolPtr);

            // Transfer result to actual destination
            destination.Clear();
            foreach (double value in destarray)
            {
                destination.Add(value);
            }
        }

        /// <summary>
        /// Decodes a plaintext polynomial into double-precision floating-point complex
        /// numbers. Dynamic memory allocations in the process are allocated from
        /// the memory pool pointed to by the given MemoryPoolHandle.
        /// </summary>
        /// <param name="plain">plain The plaintext to decode</param>
        /// <param name="destination">The collection to be overwritten with the values in the slots</param>
        /// <param name="pool">The MemoryPoolHandle pointing to a valid memory pool</param>
        /// <exception cref="ArgumentNullException">if either plain or destination are null</exception>
        /// <exception cref="ArgumentException">if plain is not in NTT form or is invalid for the
        /// encryption parameters</exception>
        /// <exception cref="ArgumentException">if pool is uninitialized</exception>
        public void Decode(Plaintext plain, ICollection<Complex> destination,
                MemoryPoolHandle pool = null)
        {
            if (null == plain)
                throw new ArgumentNullException(nameof(plain));
            if (null == destination)
                throw new ArgumentNullException(nameof(destination));

            IntPtr poolPtr = pool?.NativePtr ?? IntPtr.Zero;
            ulong destCount = 0;

            // Find out what is the actual result size
            NativeMethods.CKKSEncoder_DecodeComplex(NativePtr, plain.NativePtr, ref destCount, null, poolPtr);

            // Now get the result
            double[] destarray = new double[destCount * 2];
            NativeMethods.CKKSEncoder_DecodeComplex(NativePtr, plain.NativePtr, ref destCount, destarray, poolPtr);

            // Transfer result to actual destination
            destination.Clear();
            for (ulong i = 0; i < destCount; i++)
            {
                destination.Add(new Complex(destarray[i * 2], destarray[i * 2 + 1]));
            }
        }

        /// <summary>
        /// Returns the number of complex numbers encoded.
        /// </summary>
        public ulong SlotCount
        {
            get
            {
                NativeMethods.CKKSEncoder_SlotCount(NativePtr, out ulong slotCount);
                return slotCount;
            }
        }

        /// <summary>
        /// SEALContext for this encoder
        /// </summary>
        private readonly SEALContext context_ = null;

        /// <summary>
        /// Destroy native object
        /// </summary>
        protected override void DestroyNativeObject()
        {
            NativeMethods.CKKSEncoder_Destroy(NativePtr);
        }
    }
}
