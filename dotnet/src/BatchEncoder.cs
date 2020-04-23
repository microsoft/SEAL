// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

using Microsoft.Research.SEAL.Tools;
using System;
using System.Collections.Generic;
using System.Linq;

namespace Microsoft.Research.SEAL
{
    /// <summary>
    /// Provides functionality for CRT batching. If the polynomial modulus degree is N, and
    /// the plaintext modulus is a prime number T such that T is congruent to 1 modulo 2N,
    /// then BatchEncoder allows the plaintext elements to be viewed as 2-by-(N/2)
    /// matrices of integers modulo T. Homomorphic operations performed on such encrypted
    /// matrices are applied coefficient (slot) wise, enabling powerful SIMD functionality
    /// for computations that are vectorizable. This functionality is often called "batching"
    /// in the homomorphic encryption literature.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Mathematical Background
    /// Mathematically speaking, if the polynomial modulus is X^N+1, N is a power of two, and
    /// PlainModulus is a prime number T such that 2N divides T-1, then integers modulo T
    /// contain a primitive 2N-th root of unity and the polynomial X^N+1 splits into n distinct
    /// linear factors as X^N+1 = (X-a_1)*...*(X-a_N) mod T, where the constants a_1, ..., a_n
    /// are all the distinct primitive 2N-th roots of unity in integers modulo T. The Chinese
    /// Remainder Theorem (CRT) states that the plaintext space Z_T[X]/(X^N+1) in this case is
    /// isomorphic (as an algebra) to the N-fold direct product of fields Z_T. The isomorphism
    /// is easy to compute explicitly in both directions, which is what this class does.
    /// Furthermore, the Galois group of the extension is (Z/2NZ)* ~= Z/2Z x Z/(N/2) whose
    /// action on the primitive roots of unity is easy to describe. Since the batching slots
    /// correspond 1-to-1 to the primitive roots of unity, applying Galois automorphisms on the
    /// plaintext act by permuting the slots. By applying generators of the two cyclic
    /// subgroups of the Galois group, we can effectively view the plaintext as a 2-by-(N/2)
    /// matrix, and enable cyclic row rotations, and column rotations (row swaps).
    /// </para>
    /// <para>
    /// Valid Parameters
    /// Whether batching can be used depends on whether the plaintext modulus has been chosen
    /// appropriately. Thus, to construct a BatchEncoder the user must provide an instance
    /// of SEALContext such that its associated EncryptionParameterQualifiers object has the
    /// flags ParametersSet and EnableBatching set to true.
    /// </para>
    /// </remarks>
    /// <see cref="EncryptionParameters">see EncryptionParameters for more information about encryption parameters.</see>
    /// <see cref="EncryptionParameterQualifiers">see EncryptionParameterQualifiers for more information about parameter qualifiers.</see>
    /// <see cref="Evaluator">see Evaluator for rotating rows and columns of encrypted matrices.</see>
    public class BatchEncoder : NativeObject
    {
        /// <summary>
        /// Creates a BatchEncoder. It is necessary that the encryption parameters
        /// given through the SEALContext object support batching.
        /// </summary>
        /// <param name="context">The SEALContext</param>
        /// @param[in] context
        /// <exception cref="ArgumentNullException">if context is null.</exception>
        /// <exception cref="ArgumentException">if the context is not set or encryption
        /// parameters are not valid for batching</exception>
        /// <exception cref="ArgumentException">if scheme is not SchemeType.BFV</exception>
        public BatchEncoder(SEALContext context)
        {
            if (null == context)
                throw new ArgumentNullException(nameof(context));
            if (!context.ParametersSet)
                throw new ArgumentException("Encryption parameters are not set correctly");

            SEALContext.ContextData contextData = context.FirstContextData;
            if (contextData.Parms.Scheme != SchemeType.BFV)
                throw new ArgumentException("Unsupported scheme");
            if (!contextData.Qualifiers.UsingBatching)
                throw new ArgumentException("Encryption parameters are not valid for batching");

            NativeMethods.BatchEncoder_Create(context.NativePtr, out IntPtr ptr);
            NativePtr = ptr;
        }

        /// <summary>
        /// Creates a plaintext from a given matrix. This function "batches" a given matrix
        /// of integers modulo the plaintext modulus into a plaintext element, and stores
        /// the result in the destination parameter. The input vector must have size at most equal
        /// to the degree of the polynomial modulus. The first half of the elements represent the
        /// first row of the matrix, and the second half represent the second row. The numbers
        /// in the matrix can be at most equal to the plaintext modulus for it to represent
        /// a valid plaintext.
        ///
        /// If the destination plaintext overlaps the input values in memory, the behavior of
        /// this function is undefined.
        /// </summary>
        /// <param name="values">The matrix of integers modulo plaintext modulus to batch</param>
        /// <param name="destination">The plaintext polynomial to overwrite with the result</param>
        /// <exception cref="ArgumentNullException">if either values or destination are null</exception>
        /// <exception cref="ArgumentException">if values is too large</exception>
        public void Encode(IEnumerable<ulong> values, Plaintext destination)
        {
            if (null == values)
                throw new ArgumentNullException(nameof(values));
            if (null == destination)
                throw new ArgumentNullException(nameof(destination));

            ulong[] valarray = values.ToArray();
            NativeMethods.BatchEncoder_Encode(NativePtr, (ulong)valarray.LongLength, valarray, destination.NativePtr);
        }

        /// <summary>
        /// Creates a plaintext from a given matrix. This function "batches" a given matrix
        /// of integers modulo the plaintext modulus into a plaintext element, and stores
        /// the result in the destination parameter. The input vector must have size at most equal
        /// to the degree of the polynomial modulus. The first half of the elements represent the
        /// first row of the matrix, and the second half represent the second row. The numbers
        /// in the matrix can be at most equal to the plaintext modulus for it to represent
        /// a valid plaintext.
        ///
        /// If the destination plaintext overlaps the input values in memory, the behavior of
        /// this function is undefined.
        /// </summary>
        /// <param name="values">The matrix of integers modulo plaintext modulus to batch</param>
        /// <param name="destination">The plaintext polynomial to overwrite with the result</param>
        /// <exception cref="ArgumentNullException">if either values or destionation are null</exception>
        /// <exception cref="ArgumentException">if values is too large</exception>
        public void Encode(IEnumerable<long> values, Plaintext destination)
        {
            if (null == values)
                throw new ArgumentNullException(nameof(values));
            if (null == destination)
                throw new ArgumentNullException(nameof(destination));

            long[] valarray = values.ToArray();
            NativeMethods.BatchEncoder_Encode(NativePtr, (ulong)valarray.LongLength, valarray, destination.NativePtr);
        }

        /// <summary>
        /// Creates a plaintext from a given matrix. This function "batches" a given matrix
        /// of integers modulo the plaintext modulus in-place into a plaintext ready to be
        /// encrypted. The matrix is given as a plaintext element whose first N/2 coefficients
        /// represent the first row of the matrix, and the second N/2 coefficients represent the
        /// second row, where N denotes the degree of the polynomial modulus. The input plaintext
        /// must have degress less than the polynomial modulus, and coefficients less than the
        /// plaintext modulus, i.e. it must be a valid plaintext for the encryption parameters.
        /// Dynamic memory allocations in the process are allocated from the memory pool pointed
        /// to by the given MemoryPoolHandle.
        /// </summary>
        /// <param name="plain">The matrix of integers modulo plaintext modulus to batch</param>
        /// <param name="pool"></param>
        /// <exception cref="ArgumentNullException">if plain is null.</exception>
        /// <exception cref="ArgumentException">if plain is not valid for the encryption parameters</exception>
        /// <exception cref="ArgumentException">if plain is in NTT form</exception>
        /// <exception cref="ArgumentException">if pool is uninitialized</exception>
        public void Encode(Plaintext plain, MemoryPoolHandle pool = null)
        {
            if (null == plain)
                throw new ArgumentNullException(nameof(plain));

            IntPtr poolPtr = pool?.NativePtr ?? IntPtr.Zero;
            NativeMethods.BatchEncoder_Encode(NativePtr, plain.NativePtr, poolPtr);
        }

        /// <summary>
        /// Inverse of encode. This function "unbatches" a given plaintext into a matrix
        /// of integers modulo the plaintext modulus, and stores the result in the destination
        /// parameter. The input plaintext must have degress less than the polynomial modulus,
        /// and coefficients less than the plaintext modulus, i.e. it must be a valid plaintext
        /// for the encryption parameters. Dynamic memory allocations in the process are
        /// allocated from the memory pool pointed to by the given MemoryPoolHandle.
        /// </summary>
        /// <param name="plain">The plaintext polynomial to unbatch</param>
        /// <param name="destination">The matrix to be overwritten with the values in the slots</param>
        /// <param name="pool">The MemoryPoolHandle pointing to a valid memory pool</param>
        /// <exception cref="ArgumentNullException">if either plain or destionation are null</exception>
        /// <exception cref="ArgumentException">if plain is not valid for the encryption parameters</exception>
        /// <exception cref="ArgumentException">if plain is in NTT form</exception>
        /// <exception cref="ArgumentException">if pool is uninitialized</exception>
        public void Decode(Plaintext plain, ICollection<ulong> destination, MemoryPoolHandle pool = null)
        {
            if (null == plain)
                throw new ArgumentNullException(nameof(plain));
            if (null == destination)
                throw new ArgumentNullException(nameof(destination));

            IntPtr poolPtr = pool?.NativePtr ?? IntPtr.Zero;
            ulong destCount = 0;

            // Allocate a big enough array to hold the result
            ulong[] destArray = new ulong[SlotCount];
            NativeMethods.BatchEncoder_Decode(NativePtr, plain.NativePtr, ref destCount, destArray, poolPtr);

            // Transfer result to actual destination
            destination.Clear();
            for (ulong i = 0; i < destCount; i++)
            {
                destination.Add(destArray[i]);
            }
        }

        /// <summary>
        /// Inverse of encode. This function "unbatches" a given plaintext into a matrix
        /// of integers modulo the plaintext modulus, and stores the result in the destination
        /// parameter. The input plaintext must have degress less than the polynomial modulus,
        /// and coefficients less than the plaintext modulus, i.e. it must be a valid plaintext
        /// for the encryption parameters. Dynamic memory allocations in the process are
        /// allocated from the memory pool pointed to by the given MemoryPoolHandle.
        /// </summary>
        /// <param name="plain">The plaintext polynomial to unbatch</param>
        /// <param name="destination">The matrix to be overwritten with the values in the slots</param>
        /// <param name="pool">The MemoryPoolHandle pointing to a valid memory pool</param>
        /// <exception cref="ArgumentNullException">if either plain or destination are null</exception>
        /// <exception cref="ArgumentException">if plain is not valid for the encryption parameters</exception>
        /// <exception cref="ArgumentException">if plain is in NTT form</exception>
        /// <exception cref="ArgumentException">if pool is uninitialized</exception>
        public void Decode(Plaintext plain, ICollection<long> destination, MemoryPoolHandle pool = null)
        {
            if (null == plain)
                throw new ArgumentNullException(nameof(plain));
            if (null == destination)
                throw new ArgumentNullException(nameof(destination));

            IntPtr poolPtr = pool?.NativePtr ?? IntPtr.Zero;
            ulong destCount = 0;

            // Allocate a big enough array to hold the result
            long[] destArray = new long[SlotCount];
            NativeMethods.BatchEncoder_Decode(NativePtr, plain.NativePtr, ref destCount, destArray, poolPtr);

            // Transfer result to actual destination
            destination.Clear();
            for (ulong i = 0; i < destCount; i++)
            {
                destination.Add(destArray[i]);
            }
        }

        /// <summary>
        /// Inverse of encode. This function "unbatches" a given plaintext in-place into
        /// a matrix of integers modulo the plaintext modulus. The input plaintext must have
        /// degress less than the polynomial modulus, and coefficients less than the plaintext
        /// modulus, i.e. it must be a valid plaintext for the encryption parameters. Dynamic
        /// memory allocations in the process are allocated from the memory pool pointed to by
        /// the given MemoryPoolHandle.
        /// </summary>
        /// <param name="plain">The plaintext polynomial to unbatch</param>
        /// <param name="pool">The MemoryPoolHandle pointing to a valid memory pool</param>
        /// <exception cref="ArgumentNullException">if plain is null</exception>
        /// <exception cref="ArgumentException">if plain is not valid for the encryption parameters</exception>
        /// <exception cref="ArgumentException">if plain is in NTT form</exception>
        /// <exception cref="ArgumentException">if pool is uninitialized</exception>
        public void Decode(Plaintext plain, MemoryPoolHandle pool = null)
        {
            if (null == plain)
                throw new ArgumentNullException(nameof(plain));

            IntPtr poolPtr = pool?.NativePtr ?? IntPtr.Zero;

            NativeMethods.BatchEncoder_Decode(NativePtr, plain.NativePtr, poolPtr);
        }

        /// <summary>
        /// Returns the number of slots.
        /// </summary>
        public ulong SlotCount
        {
            get
            {
                NativeMethods.BatchEncoder_GetSlotCount(NativePtr, out ulong slotCount);
                return slotCount;
            }
        }

        /// <summary>
        /// Destroy native object
        /// </summary>
        protected override void DestroyNativeObject()
        {
            NativeMethods.BatchEncoder_Destroy(NativePtr);
        }
    }
}
