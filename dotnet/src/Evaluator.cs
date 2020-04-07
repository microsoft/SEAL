// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

using Microsoft.Research.SEAL.Tools;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;

namespace Microsoft.Research.SEAL
{
    /// <summary>
    /// Provides operations on ciphertexts.
    /// </summary>
    ///
    /// <remarks>
    /// <para>
    /// Provides operations on ciphertexts. Due to the properties of the encryption scheme,
    /// the arithmetic operations pass through the encryption layer to the underlying plaintext,
    /// changing it according to the type of the operation. Since the plaintext elements are
    /// fundamentally polynomials in the polynomial quotient ring Z_T[x]/(X^N+1), where T is
    /// the plaintext modulus and X^N+1 is the polynomial modulus, this is the ring where the
    /// arithmetic operations will take place. BatchEncoder (batching) provider an alternative
    /// possibly more convenient view of the plaintext elements as 2-by-(N2/2) matrices of
    /// integers modulo the plaintext modulus. In the batching view the arithmetic operations
    /// act on the matrices element-wise. Some of the operations only apply in the batching
    /// view, such as matrix row and column rotations. Other operations such as relinearization
    /// have no semantic meaning but are necessary for performance reasons.
    /// </para>
    /// <para>
    /// Arithmetic Operations
    /// The core operations are arithmetic operations, in particular multiplication and addition
    /// of ciphertexts. In addition to these, we also provide negation, subtraction, squaring,
    /// exponentiation, and multiplication and addition of several ciphertexts for convenience.
    /// in many cases some of the inputs to a computation are plaintext elements rather than
    /// ciphertexts. For this we provide fast "plain" operations: plain addition, plain subtraction,
    /// and plain multiplication.
    /// </para>
    /// <para>
    /// Relinearization
    /// One of the most important non-arithmetic operations is relinearization, which takes
    /// as input a ciphertext of size K+1 and relinearization keys (at least K-1 keys are needed),
    /// and changes the size of the ciphertext down to 2 (minimum size). For most use-cases only
    /// one relinearization key suffices, in which case relinearization should be performed after
    /// every multiplication. Homomorphic multiplication of ciphertexts of size K+1 and L+1
    /// outputs a ciphertext of size K+L+1, and the computational cost of multiplication is
    /// proportional to K*L. Plain multiplication and addition operations of any type do not
    /// change the size. Relinearization requires relinearization keys to have been generated.
    /// </para>
    /// <para>
    /// Rotations
    /// When batching is enabled, we provide operations for rotating the plaintext matrix rows
    /// cyclically left or right, and for rotating the columns (swapping the rows). Rotations
    /// require Galois keys to have been generated.
    /// </para>
    /// <para>
    /// Other Operations
    /// We also provide operations for transforming ciphertexts to NTT form and back, and for
    /// transforming plaintext polynomials to NTT form. These can be used in a very fast plain
    /// multiplication variant, that assumes the inputs to be in NTT form. Since the NTT has to
    /// be done in any case in plain multiplication, this function can be used when e.g. one
    /// plaintext input is used in several plain multiplication, and transforming it several
    /// times would not make sense.
    /// </para>
    /// <para>
    /// NTT form
    /// When using the BFV scheme (SchemeType.BFV), all plaintexts and ciphertexts should
    /// remain by default in the usual coefficient representation, i.e., not in NTT form.
    /// When using the CKKS scheme (SchemeType.CKKS), all plaintexts and ciphertexts
    /// should remain by default in NTT form. We call these scheme-specific NTT states the
    /// "default NTT form". Some functions, such as add, work even if the inputs are not in
    /// the default state, but others, such as multiply, will throw an exception. The output
    /// of all evaluation functions will be in the same state as the input(s), with the
    /// exception of the TransformToNTT and TransformFromNTT functions, which change the
    /// state. Ideally, unless these two functions are called, all other functions should
    /// "just work".
    /// </para>
    /// </remarks>
    /// <see cref="EncryptionParameters"/> for more details on encryption parameters.
    /// <see cref="BatchEncoder"/> for more details on batching
    /// <see cref="RelinKeys"/> for more details on relinearization keys.
    /// <see cref="GaloisKeys"/> for more details on Galois keys.
    public class Evaluator : NativeObject
    {
        /// <summary>
        /// Creates an Evaluator instance initialized with the specified SEALContext.
        /// </summary>
        ///
        /// <param name="context">The SEALContext</param>
        /// <exception cref="ArgumentNullException">if context is null</exception>
        /// <exception cref="ArgumentException">if the context is not set or encryption
        /// parameters are not valid</exception>
        public Evaluator(SEALContext context)
        {
            if (null == context)
                throw new ArgumentNullException(nameof(context));
            if (!context.ParametersSet)
                throw new ArgumentException("Encryption parameters are not set correctly");

            NativeMethods.Evaluator_Create(context.NativePtr, out IntPtr ptr);
            NativePtr = ptr;
        }

        /// <summary>
        /// Negates a ciphertext.
        /// </summary>
        ///
        /// <param name="encrypted">The ciphertext to negate</param>
        /// <exception cref="ArgumentNullException">if encrypted is null</exception>
        /// <exception cref="ArgumentException">if encrypted is not valid for the encryption parameters</exception>
        /// <exception cref="InvalidOperationException">if result ciphertext is transparent</exception>
        public void NegateInplace(Ciphertext encrypted)
        {
            Negate(encrypted, destination: encrypted);
        }

        /// <summary>
        /// Negates a ciphertext and stores the result in the destination parameter.
        /// </summary>
        /// <param name="encrypted">The ciphertext to negate</param>
        /// <param name="destination">The ciphertext to overwrite with the negated result</param>
        /// <exception cref="ArgumentNullException">if either encrypted or destionation are null</exception>
        /// <exception cref="ArgumentException">if encrypted is not valid for the encryption parameters</exception>
        /// <exception cref="InvalidOperationException">if result ciphertext is transparent</exception>
        public void Negate(Ciphertext encrypted, Ciphertext destination)
        {
            if (null == encrypted)
                throw new ArgumentNullException(nameof(encrypted));
            if (null == destination)
                throw new ArgumentNullException(nameof(destination));

            NativeMethods.Evaluator_Negate(NativePtr, encrypted.NativePtr, destination.NativePtr);
        }

        /// <summary>
        /// Adds two ciphertexts.
        /// </summary>
        /// <remarks>
        /// This function adds together encrypted1 and encrypted2 and stores the result in encrypted1.
        /// </remarks>
        /// <param name="encrypted1">The first ciphertext to add</param>
        /// <param name="encrypted2">The second ciphertext to add</param>
        /// <exception cref="ArgumentNullException">if either encrypted1 or encrypted2 are null</exception>
        /// <exception cref="ArgumentException">if encrypted1 or encrypted2 is not valid for
        /// the encryption parameters</exception>
        /// <exception cref="ArgumentException">if encrypted1 and encrypted2 are in different
        /// NTT forms</exception>
        /// <exception cref="ArgumentException">if encrypted1 and encrypted2 have different scale</exception>
        /// <exception cref="InvalidOperationException">if result ciphertext is transparent</exception>
        public void AddInplace(Ciphertext encrypted1, Ciphertext encrypted2)
        {
            Add(encrypted1, encrypted2, destination: encrypted1);
        }

        /// <summary>
        /// Adds two ciphertexts.
        /// </summary>
        /// <remarks>
        /// This function adds together encrypted1 and encrypted2 and stores the result in the destination
        /// parameter.
        /// </remarks>
        /// <param name="encrypted1">The first ciphertext to add</param>
        /// <param name="encrypted2">The second ciphertext to add</param>
        /// <param name="destination">The ciphertext to overwrite with the addition result</param>
        /// <exception cref="ArgumentNullException">if either encrypted1, encrypted2 or destination are null</exception>
        /// <exception cref="ArgumentException">if encrypted1 or encrypted2 is not valid for
        /// the encryption parameters</exception>
        /// <exception cref="ArgumentException">if encrypted1 and encrypted2 are in different
        /// NTT forms</exception>
        /// <exception cref="ArgumentException">if encrypted1 and encrypted2 have different scale</exception>
        /// <exception cref="InvalidOperationException">if result ciphertext is transparent</exception>
        public void Add(Ciphertext encrypted1, Ciphertext encrypted2, Ciphertext destination)
        {
            if (null == encrypted1)
                throw new ArgumentNullException(nameof(encrypted1));
            if (null == encrypted2)
                throw new ArgumentNullException(nameof(encrypted2));
            if (null == destination)
                throw new ArgumentNullException(nameof(destination));

            NativeMethods.Evaluator_Add(NativePtr, encrypted1.NativePtr, encrypted2.NativePtr, destination.NativePtr);
        }

        /// <summary>
        /// Adds together a vector of ciphertexts and stores the result in the destination
        /// parameter.
        /// </summary>
        /// <param name="encrypteds">The ciphertexts to add</param>
        /// <param name="destination">The ciphertext to overwrite with the addition result</param>
        /// <exception cref="ArgumentNullException">if either encrypteds or destination are null</exception>
        /// <exception cref="ArgumentException">if encrypteds is empty</exception>
        /// <exception cref="ArgumentException">if the encrypteds are not valid for the encryption
        /// parameters</exception>
        /// <exception cref="ArgumentException">if encrypteds are in different NTT forms</exception>
        /// <exception cref="ArgumentException">if encrypteds have different scale</exception>
        /// <exception cref="InvalidOperationException">if result ciphertext is transparent</exception>
        public void AddMany(IEnumerable<Ciphertext> encrypteds, Ciphertext destination)
        {
            if (null == encrypteds)
                throw new ArgumentNullException(nameof(encrypteds));
            if (null == destination)
                throw new ArgumentNullException(nameof(destination));

            IntPtr[] encarray = encrypteds.Select(c => c.NativePtr).ToArray();
            NativeMethods.Evaluator_AddMany(NativePtr, (ulong)encarray.Length, encarray, destination.NativePtr);
        }

        /// <summary>
        /// Subtracts two ciphertexts.
        /// </summary>
        /// <remarks>
        /// This function computes the difference of encrypted1 and encrypted2, and stores the result in encrypted1.
        /// </remarks>
        /// <param name="encrypted1">The ciphertext to subtract from</param>
        /// <param name="encrypted2">The ciphertext to subtract</param>
        /// <exception cref="ArgumentNullException">if either encrypted1 or encrypted2 are null</exception>
        /// <exception cref="ArgumentException">if encrypted1 or encrypted2 is not valid for the
        /// encryption parameters</exception>
        /// <exception cref="ArgumentException">if encrypted1 and encrypted2 are in different
        /// NTT forms</exception>
        /// <exception cref="ArgumentException">if encrypted1 and encrypted2 have different scale</exception>
        /// <exception cref="InvalidOperationException">if result ciphertext is transparent</exception>
        public void SubInplace(Ciphertext encrypted1, Ciphertext encrypted2)
        {
            Sub(encrypted1, encrypted2, destination: encrypted1);
        }

        /// <summary>
        /// Subtracts two ciphertexts.
        /// </summary>
        /// <remarks>This function computes the difference of encrypted1 and encrypted2 and stores the result
        /// in the destination parameter.
        /// </remarks>
        /// <param name="encrypted1">The ciphertext to subtract from</param>
        /// <param name="encrypted2">The ciphertext to subtract</param>
        /// <param name="destination">The ciphertext to overwrite with the subtraction result</param>
        /// <exception cref="ArgumentNullException">if either encrypted1, encrypted2 or destination are null</exception>
        /// <exception cref="ArgumentException">if encrypted1 or encrypted2 is not valid for the
        /// encryption parameters</exception>
        /// <exception cref="ArgumentException">if encrypted1 and encrypted2 are in different
        /// NTT forms</exception>
        /// <exception cref="ArgumentException">if encrypted1 and encrypted2 have different scale</exception>
        /// <exception cref="InvalidOperationException">if result ciphertext is transparent</exception>
        public void Sub(Ciphertext encrypted1, Ciphertext encrypted2, Ciphertext destination)
        {
            if (null == encrypted1)
                throw new ArgumentNullException(nameof(encrypted1));
            if (null == encrypted2)
                throw new ArgumentNullException(nameof(encrypted2));
            if (null == destination)
                throw new ArgumentNullException(nameof(destination));

            NativeMethods.Evaluator_Sub(NativePtr, encrypted1.NativePtr, encrypted2.NativePtr, destination.NativePtr);
        }

        /// <summary>
        /// Multiplies two ciphertexts.
        /// </summary>
        /// <remarks>This functions computes the product of encrypted1 and encrypted2 and stores the
        /// result in encrypted1. Dynamic memory allocations in the process are allocated from the
        /// memory pool pointed to by the given MemoryPoolHandle.
        /// </remarks>
        /// <param name="encrypted1">The first ciphertext to multiply</param>
        /// <param name="encrypted2">The second ciphertext to multiply</param>
        /// <param name="pool">The MemoryPoolHandle pointing to a valid memory pool</param>
        /// <exception cref="ArgumentNullException">if either encrypted1, encrypted2 are null</exception>
        /// <exception cref="ArgumentException">if encrypted1 or encrypted2 is not valid for the
        /// encryption parameters</exception>
        /// <exception cref="ArgumentException">if encrypted1 or encrypted2 is not in the default
        /// NTT form</exception>
        /// <exception cref="ArgumentException">if, when using SchemeType.CKKS, the output scale
        /// is too large for the encryption parameters</exception>
        /// <exception cref="ArgumentException">if pool is uninitialized</exception>
        /// <exception cref="InvalidOperationException">if result ciphertext is transparent</exception>
        public void MultiplyInplace(Ciphertext encrypted1, Ciphertext encrypted2,
            MemoryPoolHandle pool = null)
        {
            Multiply(encrypted1, encrypted2, destination: encrypted1, pool: pool);
        }

        /// <summary>
        /// Multiplies two ciphertexts.
        /// </summary>
        /// <remarks>
        /// This functions computes the product of encrypted1 and encrypted2 and stores the result
        /// in the destination parameter. Dynamic memory allocations in the process are allocated
        /// from the memory pool pointed to by the given MemoryPoolHandle.
        /// </remarks>
        /// <param name="encrypted1">The first ciphertext to multiply</param>
        /// <param name="encrypted2">The second ciphertext to multiply</param>
        /// <param name="destination">The ciphertext to overwrite with the multiplication result</param>
        /// <param name="pool">The MemoryPoolHandle pointing to a valid memory pool</param>
        /// <exception cref="ArgumentNullException">if either encrypted1, encrypted2, destination are null</exception>
        /// <exception cref="ArgumentException">if encrypted1 or encrypted2 is not valid for the
        /// encryption parameters</exception>
        /// <exception cref="ArgumentException">if encrypted1 or encrypted2 is not in the default
        /// NTT form</exception>
        /// <exception cref="ArgumentException">if, when using SchemeType.CKKS, the output scale
        /// is too large for the encryption parameters</exception>
        /// <exception cref="ArgumentException">if pool is uninitialized</exception>
        /// <exception cref="InvalidOperationException">if result ciphertext is transparent</exception>
        public void Multiply(Ciphertext encrypted1, Ciphertext encrypted2,
            Ciphertext destination, MemoryPoolHandle pool = null)
        {
            if (null == encrypted1)
                throw new ArgumentNullException(nameof(encrypted1));
            if (null == encrypted2)
                throw new ArgumentNullException(nameof(encrypted2));
            if (null == destination)
                throw new ArgumentNullException(nameof(destination));

            IntPtr poolPtr = pool?.NativePtr ?? IntPtr.Zero;
            NativeMethods.Evaluator_Multiply(NativePtr, encrypted1.NativePtr, encrypted2.NativePtr, destination.NativePtr, poolPtr);
        }

        /// <summary>
        /// Squares a ciphertext.
        /// </summary>
        /// <remarks>
        /// This functions computes the square of encrypted. Dynamic memory allocations in the process
        /// are allocated from the memory pool pointed to by the given MemoryPoolHandle.
        /// </remarks>
        /// <param name="encrypted">The ciphertext to square</param>
        /// <param name="pool">The MemoryPoolHandle pointing to a valid memory pool</param>
        /// <exception cref="ArgumentNullException">if either encrypted are null</exception>
        /// <exception cref="ArgumentException">if encrypted is not valid for the encryption
        /// parameters</exception>
        /// <exception cref="ArgumentException">if encrypted is not in the default NTT form</exception>
        /// <exception cref="ArgumentException">if, when using SchemeType.CKKS, the output scale
        /// is too large for the encryption parameters</exception>
        /// <exception cref="ArgumentException">if pool is uninitialized</exception>
        /// <exception cref="InvalidOperationException">if result ciphertext is transparent</exception>
        public void SquareInplace(Ciphertext encrypted, MemoryPoolHandle pool = null)
        {
            Square(encrypted, destination: encrypted, pool: pool);
        }

        /// <summary>
        /// Squares a ciphertext.
        /// </summary>
        /// <remarks>
        /// This functions computes the square of encrypted and stores the result in the destination
        /// parameter. Dynamic memory allocations in the process are allocated from the memory pool
        /// pointed to by the given MemoryPoolHandle.
        /// </remarks>
        /// <param name="encrypted">The ciphertext to square</param>
        /// <param name="destination">The ciphertext to overwrite with the square</param>
        /// <param name="pool">The MemoryPoolHandle pointing to a valid memory pool</param>
        /// <exception cref="ArgumentNullException">if either encrypted, destination are null</exception>
        /// <exception cref="ArgumentException">if encrypted is not valid for the encryption
        /// parameters</exception>
        /// <exception cref="ArgumentException">if encrypted is not in the default NTT form</exception>
        /// <exception cref="ArgumentException">if, when using SchemeType.CKKS, the output scale
        /// is too large for the encryption parameters</exception>
        /// <exception cref="ArgumentException">if pool is uninitialized</exception>
        /// <exception cref="InvalidOperationException">if result ciphertext is transparent</exception>
        public void Square(Ciphertext encrypted, Ciphertext destination, MemoryPoolHandle pool = null)
        {
            if (null == encrypted)
                throw new ArgumentNullException(nameof(encrypted));
            if (null == destination)
                throw new ArgumentNullException(nameof(destination));

            IntPtr poolPtr = pool?.NativePtr ?? IntPtr.Zero;
            NativeMethods.Evaluator_Square(NativePtr, encrypted.NativePtr, destination.NativePtr, poolPtr);
        }

        /// <summary>
        /// Relinearizes a ciphertext.
        /// </summary>
        /// <remarks>
        /// This functions relinearizes encrypted, reducing its size down to 2. If the size
        /// of encrypted is K+1, the given relinearization keys need to have size at least K-1.
        /// Dynamic memory allocations in the process are allocated from the memory pool pointed
        /// to by the given MemoryPoolHandle.
        /// </remarks>
        /// <param name="encrypted">The ciphertext to relinearize</param>
        /// <param name="relinKeys">The relinearization keys</param>
        /// <param name="pool">The MemoryPoolHandle pointing to a valid memory pool</param>
        /// <exception cref="ArgumentNullException">if either encrypted, relinKeys are null</exception>
        /// <exception cref="ArgumentException">if encrypted or relinKeys is not valid for the
        /// encryption parameters</exception>
        /// <exception cref="ArgumentException">if encrypted is not in the default NTT form</exception>
        /// <exception cref="ArgumentException">if relinKeys do not correspond to the top level
        /// parameters in the current context</exception>
        /// <exception cref="ArgumentException">if the size of relinKeys is too small</exception>
        /// <exception cref="ArgumentException">if pool is uninitialized</exception>
        /// <exception cref="InvalidOperationException">if keyswitching is not supported by the context</exception>
        /// <exception cref="InvalidOperationException">if result ciphertext is transparent</exception>
        public void RelinearizeInplace(Ciphertext encrypted, RelinKeys relinKeys,
            MemoryPoolHandle pool = null)
        {
            Relinearize(encrypted, relinKeys, destination: encrypted, pool: pool);
        }

        /// <summary>
        /// Relinearizes a ciphertext.
        /// </summary>
        /// <remarks>
        /// This functions relinearizes encrypted, reducing its size down to 2, and stores the
        /// result in the destination parameter. If the size of encrypted is K+1, the given
        /// relinearization keys need to have size at least K-1. Dynamic memory allocations in the
        /// process are allocated from the memory pool pointed to by the given MemoryPoolHandle.
        /// </remarks>
        /// <param name="encrypted">The ciphertext to relinearize</param>
        /// <param name="relinKeys">The relinearization keys</param>
        /// <param name="destination">The ciphertext to overwrite with the relinearized result</param>
        /// <param name="pool">The MemoryPoolHandle pointing to a valid memory pool</param>
        /// <exception cref="ArgumentNullException">if either encrypted, relinKeys or destination are null</exception>
        /// <exception cref="ArgumentException">if encrypted or relinKeys is not valid for the
        /// encryption parameters</exception>
        /// <exception cref="ArgumentException">if encrypted is not in the default NTT form</exception>
        /// <exception cref="ArgumentException">if relinKeys do not correspond to the top level
        /// parameters in the current context</exception>
        /// <exception cref="ArgumentException">if the size of relinKeys is too small</exception>
        /// <exception cref="ArgumentException">if pool is uninitialized</exception>
        /// <exception cref="InvalidOperationException">if keyswitching is not supported by the context</exception>
        /// <exception cref="InvalidOperationException">if result ciphertext is transparent</exception>
        public void Relinearize(Ciphertext encrypted, RelinKeys relinKeys,
            Ciphertext destination, MemoryPoolHandle pool = null)
        {
            if (null == encrypted)
                throw new ArgumentNullException(nameof(encrypted));
            if (null == relinKeys)
                throw new ArgumentNullException(nameof(relinKeys));
            if (null == destination)
                throw new ArgumentNullException(nameof(destination));
            if (!ContextUsingKeyswitching)
                throw new InvalidOperationException("Keyswitching is not supported by the context");

            IntPtr poolPtr = pool?.NativePtr ?? IntPtr.Zero;
            NativeMethods.Evaluator_Relinearize(
                NativePtr, encrypted.NativePtr, relinKeys.NativePtr, destination.NativePtr, poolPtr);
        }

        /// <summary>
        /// Given a ciphertext encrypted modulo q_1...q_k, this function switches the modulus
        /// down to q_1...q_{k-1} and stores the result in the destination parameter.
        /// </summary>
        /// <remarks>
        /// Given a ciphertext encrypted modulo q_1...q_k, this function switches the modulus
        /// down to q_1...q_{k-1} and stores the result in the destination parameter. Dynamic
        /// memory allocations in the process are allocated from the memory pool pointed to by
        /// the given MemoryPoolHandle.
        /// </remarks>
        /// <param name="encrypted">The ciphertext to be switched to a smaller modulus</param>
        /// <param name="destination">The ciphertext to overwrite with the modulus switched result</param>
        /// <param name="pool">The MemoryPoolHandle pointing to a valid memory pool</param>
        /// <exception cref="ArgumentNullException">if either encrypted or destination are null</exception>
        /// <exception cref="ArgumentException">if encrypted is not valid for the encryption parameters</exception>
        /// <exception cref="ArgumentException">if encrypted is not in the default NTT form</exception>
        /// <exception cref="ArgumentException">if encrypted is already at lowest level</exception>
        /// <exception cref="ArgumentException">if, when using SchemeType.CKKS, the scale is too
        /// large for the new encryption parameters</exception>
        /// <exception cref="ArgumentException">if pool is uninitialized</exception>
        /// <exception cref="InvalidOperationException">if result ciphertext is transparent</exception>
        public void ModSwitchToNext(Ciphertext encrypted, Ciphertext destination, MemoryPoolHandle pool = null)
        {
            if (null == encrypted)
                throw new ArgumentNullException(nameof(encrypted));
            if (null == destination)
                throw new ArgumentNullException(nameof(destination));

            IntPtr poolPtr = pool?.NativePtr ?? IntPtr.Zero;
            NativeMethods.Evaluator_ModSwitchToNext(
                NativePtr, encrypted.NativePtr, destination.NativePtr, poolPtr);
        }

        /// <summary>
        /// Given a ciphertext encrypted modulo q_1...q_k, this function switches the modulus
        /// down to q_1...q_{k-1}.
        /// </summary>
        /// <remarks>
        /// Given a ciphertext encrypted modulo q_1...q_k, this function switches the modulus
        /// down to q_1...q_{k-1}. Dynamic memory allocations in the process are allocated from
        /// the memory pool pointed to by the given MemoryPoolHandle.
        /// </remarks>
        /// <param name="encrypted">The ciphertext to be switched to a smaller modulus</param>
        /// <param name="pool">The MemoryPoolHandle pointing to a valid memory pool</param>
        /// <exception cref="ArgumentNullException">if encrypted is null</exception>
        /// <exception cref="ArgumentException">if encrypted is not valid for the encryption parameters</exception>
        /// <exception cref="ArgumentException">if encrypted is not in the default NTT form</exception>
        /// <exception cref="ArgumentException">if encrypted is already at lowest level</exception>
        /// <exception cref="ArgumentException">if, when using SchemeType.CKKS, the scale is too
        /// large for the new encryption parameters</exception>
        /// <exception cref="ArgumentException">if pool is uninitialized</exception>
        /// <exception cref="InvalidOperationException">if result ciphertext is transparent</exception>
        public void ModSwitchToNextInplace(Ciphertext encrypted, MemoryPoolHandle pool = null)
        {
            ModSwitchToNext(encrypted, destination: encrypted, pool: pool);
        }

        /// <summary>
        /// Modulus switches an NTT transformed plaintext from modulo q_1...q_k down to modulo
        /// q_1...q_{k-1}.
        /// </summary>
        /// <param name="plain">The plaintext to be switched to a smaller modulus</param>
        /// <exception cref="ArgumentNullException">if plain is null</exception>
        /// <exception cref="ArgumentException">if plain is not in NTT form</exception>
        /// <exception cref="ArgumentException">if plain is not valid for the encryption parameters</exception>
        /// <exception cref="ArgumentException">if plain is already at lowest level</exception>
        /// <exception cref="ArgumentException">if, when using SchemeType.CKKS, the scale is too
        /// large for the new encryption parameters</exception>
        public void ModSwitchToNextInplace(Plaintext plain)
        {
            ModSwitchToNext(plain, destination: plain);
        }

        /// <summary>
        /// Modulus switches an NTT transformed plaintext from modulo q_1...q_k down to modulo
        /// q_1...q_{k-1} and stores the result in the destination parameter.
        /// </summary>
        /// <param name="plain">The plaintext to be switched to a smaller modulus</param>
        /// <param name="destination">destination The plaintext to overwrite with the modulus switched result</param>
        /// <exception cref="ArgumentNullException">if either plain or destination are null</exception>
        /// <exception cref="ArgumentException">if plain is not in NTT form</exception>
        /// <exception cref="ArgumentException">if plain is not valid for the encryption parameters</exception>
        /// <exception cref="ArgumentException">if plain is already at lowest level</exception>
        /// <exception cref="ArgumentException">if, when using SchemeType.CKKS, the scale is too
        /// large for the new encryption parameters</exception>
        /// <exception cref="ArgumentException">if pool is uninitialized</exception>
        public void ModSwitchToNext(Plaintext plain, Plaintext destination)
        {
            if (null == plain)
                throw new ArgumentNullException(nameof(plain));
            if (null == destination)
                throw new ArgumentNullException(nameof(destination));

            NativeMethods.Evaluator_ModSwitchToNext(NativePtr, plain.NativePtr, destination.NativePtr);
        }

        /// <summary>
        /// Given a ciphertext encrypted modulo q_1...q_k, this function switches the modulus
        /// down until the parameters reach the given ParmsId.
        /// </summary>
        /// <remarks>
        /// Given a ciphertext encrypted modulo q_1...q_k, this function switches the modulus
        /// down until the parameters reach the given ParmsId. Dynamic memory allocations in
        /// the process are allocated from the memory pool pointed to by the given
        /// MemoryPoolHandle.
        /// </remarks>
        /// <param name="encrypted">The ciphertext to be switched to a smaller modulus</param>
        /// <param name="parmsId">The target parmsId</param>
        /// <param name="pool">The MemoryPoolHandle pointing to a valid memory pool</param>
        /// <exception cref="ArgumentNullException">if either encrypted or parmsId are null</exception>
        /// <exception cref="ArgumentException">if encrypted is not valid for the encryption parameters</exception>
        /// <exception cref="ArgumentException">if encrypted is not in the default NTT form</exception>
        /// <exception cref="ArgumentException">if parmsId is not valid for the encryption parameters</exception>
        /// <exception cref="ArgumentException">if encrypted is already at lower level in modulus chain
        /// than the parameters corresponding to parmsId</exception>
        /// <exception cref="ArgumentException">if, when using SchemeType.CKKS, the scale is too
        /// large for the new encryption parameters</exception>
        /// <exception cref="ArgumentException">if pool is uninitialized</exception>
        /// <exception cref="InvalidOperationException">if result ciphertext is transparent</exception>
        public void ModSwitchToInplace(Ciphertext encrypted, ParmsId parmsId, MemoryPoolHandle pool = null)
        {
            ModSwitchTo(encrypted, parmsId, destination: encrypted, pool: pool);
        }

        /// <summary>
        /// Given a ciphertext encrypted modulo q_1...q_k, this function switches the modulus
        /// down until the parameters reach the given ParmsId and stores the result in the
        /// destination parameter.
        /// </summary>
        /// <remarks>
        /// Given a ciphertext encrypted modulo q_1...q_k, this function switches the modulus
        /// down until the parameters reach the given ParmsId and stores the result in the
        /// destination parameter. Dynamic memory allocations in the process are allocated
        /// from the memory pool pointed to by the given MemoryPoolHandle.
        /// </remarks>
        /// <param name="encrypted">The ciphertext to be switched to a smaller modulus</param>
        /// <param name="parmsId">The target parmsId</param>
        /// <param name="destination">The ciphertext to overwrite with the modulus switched result</param>
        /// <param name="pool">The MemoryPoolHandle pointing to a valid memory pool</param>
        /// <exception cref="ArgumentNullException">if either encrypted, parmsId or destination are null</exception>
        /// <exception cref="ArgumentException">if encrypted is not valid for the encryption parameters</exception>
        /// <exception cref="ArgumentException">if encrypted is not in the default NTT form</exception>
        /// <exception cref="ArgumentException">if parmsId is not valid for the encryption parameters</exception>
        /// <exception cref="ArgumentException">if encrypted is already at lower level in modulus chain
        /// than the parameters corresponding to parmsId</exception>
        /// <exception cref="ArgumentException">if, when using SchemeType.CKKS, the scale is too
        /// large for the new encryption parameters</exception>
        /// <exception cref="ArgumentException">if pool is uninitialized</exception>
        /// <exception cref="InvalidOperationException">if result ciphertext is transparent</exception>
        public void ModSwitchTo(Ciphertext encrypted, ParmsId parmsId, Ciphertext destination, MemoryPoolHandle pool = null)
        {
            if (null == encrypted)
                throw new ArgumentNullException(nameof(encrypted));
            if (null == parmsId)
                throw new ArgumentNullException(nameof(parmsId));
            if (null == destination)
                throw new ArgumentNullException(nameof(destination));

            IntPtr poolPtr = pool?.NativePtr ?? IntPtr.Zero;
            NativeMethods.Evaluator_ModSwitchTo(
                NativePtr, encrypted.NativePtr, parmsId.Block, destination.NativePtr, poolPtr);
        }

        /// <summary>
        /// Given an NTT transformed plaintext modulo q_1...q_k, this function switches the
        /// modulus down until the parameters reach the given ParmsId.
        /// </summary>
        /// <param name="plain">The plaintext to be switched to a smaller modulus</param>
        /// <param name="parmsId">The target parmsId</param>
        /// <exception cref="ArgumentNullException">if either plain or parmsId is null</exception>
        /// <exception cref="ArgumentException">if plain is not in NTT form</exception>
        /// <exception cref="ArgumentException">if plain is not valid for the encryption parameters</exception>
        /// <exception cref="ArgumentException">if parmsId is not valid for the encryption parameters</exception>
        /// <exception cref="ArgumentException">if plain is already at lower level in modulus chain
        /// than the parameters corresponding to parmsId</exception>
        /// <exception cref="ArgumentException">if, when using SchemeType.CKKS, the scale is too
        /// large for the new encryption parameters</exception>
        public void ModSwitchToInplace(Plaintext plain, ParmsId parmsId)
        {
            ModSwitchTo(plain, parmsId, destination: plain);
        }

        /// <summary>
        /// Given an NTT transformed plaintext modulo q_1...q_k, this function switches the
        /// modulus down until the parameters reach the given ParmsId and stores the result in
        /// the destination parameter.
        /// </summary>
        /// <param name="plain">The plaintext to be switched to a smaller modulus</param>
        /// <param name="parmsId">The target parmsId</param>
        /// <param name="destination">The plaintext to overwrite with the modulus switched result</param>
        /// <exception cref="ArgumentNullException">if either plain, parmsId or destination are null</exception>
        /// <exception cref="ArgumentException">if plain is not in NTT form</exception>
        /// <exception cref="ArgumentException">if plain is not valid for the encryption parameters</exception>
        /// <exception cref="ArgumentException">if parmsId is not valid for the encryption parameters</exception>
        /// <exception cref="ArgumentException">if plain is already at lower level in modulus chain
        /// than the parameters corresponding to parmsId</exception>
        /// <exception cref="ArgumentException">if, when using SchemeType.CKKS, the scale is too
        /// large for the new encryption parameters</exception>
        public void ModSwitchTo(Plaintext plain, ParmsId parmsId,
            Plaintext destination)
        {
            if (null == plain)
                throw new ArgumentNullException(nameof(plain));
            if (null == parmsId)
                throw new ArgumentNullException(nameof(parmsId));
            if (null == destination)
                throw new ArgumentNullException(nameof(destination));

            NativeMethods.Evaluator_ModSwitchTo(NativePtr, plain.NativePtr, parmsId.Block, destination.NativePtr);
        }

        /// <summary>
        /// Given a ciphertext encrypted modulo q_1...q_k, this function switches the modulus
        /// down to q_1...q_{k-1}, scales the message down accordingly, and stores the
        /// result in the destination parameter.
        /// </summary>
        /// <remarks>
        /// Given a ciphertext encrypted modulo q_1...q_k, this function switches the modulus
        /// down to q_1...q_{k-1}, scales the message down accordingly, and stores the
        /// result in the destination parameter. Dynamic memory allocations in the process
        /// are allocated from the memory pool pointed to by the given MemoryPoolHandle.
        /// </remarks>
        /// <param name="encrypted">The ciphertext to be switched to a smaller modulus</param>
        /// <param name="destination">The ciphertext to overwrite with the modulus switched result</param>
        /// <param name="pool">The MemoryPoolHandle pointing to a valid memory pool</param>
        /// <exception cref="ArgumentNullException">if either encrypted or destination are null</exception>
        /// <exception cref="ArgumentException">if the scheme is invalid for rescaling</exception>
        /// <exception cref="ArgumentException">if encrypted is not valid for the encryption parameters</exception>
        /// <exception cref="ArgumentException">if encrypted is not in the default NTT form</exception>
        /// <exception cref="ArgumentException">if encrypted is already at lowest level</exception>
        /// <exception cref="ArgumentException">if pool is uninitialized</exception>
        /// <exception cref="InvalidOperationException">if result ciphertext is transparent</exception>
        public void RescaleToNext(Ciphertext encrypted, Ciphertext destination, MemoryPoolHandle pool = null)
        {
            if (null == encrypted)
                throw new ArgumentNullException(nameof(encrypted));
            if (null == destination)
                throw new ArgumentNullException(nameof(destination));

            IntPtr poolPtr = pool?.NativePtr ?? IntPtr.Zero;
            NativeMethods.Evaluator_RescaleToNext(
                NativePtr, encrypted.NativePtr, destination.NativePtr, poolPtr);
        }

        /// <summary>
        /// Given a ciphertext encrypted modulo q_1...q_k, this function switches the modulus
        /// down to q_1...q_{k-1} and scales the message down accordingly.
        /// </summary>
        /// <remarks>
        /// Given a ciphertext encrypted modulo q_1...q_k, this function switches the modulus
        /// down to q_1...q_{k-1} and scales the message down accordingly. Dynamic memory
        /// allocations in the process are allocated from the memory pool pointed to by the
        /// given MemoryPoolHandle.
        /// </remarks>
        /// <param name="encrypted">The ciphertext to be switched to a smaller modulus</param>
        /// <param name="pool">The MemoryPoolHandle pointing to a valid memory pool</param>
        /// <exception cref="ArgumentNullException">if encrypted is null</exception>
        /// <exception cref="ArgumentException">if the scheme is invalid for rescaling</exception>
        /// <exception cref="ArgumentException">if encrypted is not valid for the encryption parameters</exception>
        /// <exception cref="ArgumentException">if encrypted is not in the default NTT form
        /// guaranteed to be</exception>
        /// <exception cref="ArgumentException">if encrypted is already at lowest level</exception>
        /// <exception cref="ArgumentException">if pool is uninitialized</exception>
        /// <exception cref="InvalidOperationException">if result ciphertext is transparent</exception>
        public void RescaleToNextInplace(Ciphertext encrypted, MemoryPoolHandle pool = null)
        {
            RescaleToNext(encrypted, destination: encrypted, pool: pool);
        }

        /// <summary>
        /// Given a ciphertext encrypted modulo q_1...q_k, this function switches the modulus
        /// down until the parameters reach the given ParmsId and scales the message down
        /// accordingly.
        /// </summary>
        /// <remarks>
        /// Given a ciphertext encrypted modulo q_1...q_k, this function switches the modulus
        /// down until the parameters reach the given ParmsId and scales the message down
        /// accordingly. Dynamic memory allocations in the process are allocated from the
        /// memory pool pointed to by the given MemoryPoolHandle.
        /// </remarks>
        /// <param name="encrypted">The ciphertext to be switched to a smaller modulus</param>
        /// <param name="parmsId">The target parmsId</param>
        /// <param name="pool">The MemoryPoolHandle pointing to a valid memory pool</param>
        /// <exception cref="ArgumentNullException">if either encrypted or parmsId are null</exception>
        /// <exception cref="ArgumentException">if the scheme is invalid for rescaling</exception>
        /// <exception cref="ArgumentException">if encrypted is not valid for the encryption parameters</exception>
        /// <exception cref="ArgumentException">if encrypted is not in the default NTT form</exception>
        /// <exception cref="ArgumentException">if parmsId is not valid for the encryption parameters</exception>
        /// <exception cref="ArgumentException">if encrypted is already at lower level in modulus chain
        /// than the parameters corresponding to parmsId</exception>
        /// <exception cref="ArgumentException">if pool is uninitialized</exception>
        /// <exception cref="InvalidOperationException">if result ciphertext is transparent</exception>
        public void RescaleToInplace(Ciphertext encrypted, ParmsId parmsId, MemoryPoolHandle pool = null)
        {
            RescaleTo(encrypted, parmsId, destination: encrypted, pool: pool);
        }

        /// <summary>
        /// Given a ciphertext encrypted modulo q_1...q_k, this function switches the modulus
        /// down until the parameters reach the given ParmsId, scales the message down
        /// accordingly, and stores the result in the destination parameter.
        /// </summary>
        /// <remarks>
        /// Given a ciphertext encrypted modulo q_1...q_k, this function switches the modulus
        /// down until the parameters reach the given ParmsId, scales the message down
        /// accordingly, and stores the result in the destination parameter. Dynamic memory
        /// allocations in the process are allocated from the memory pool pointed to by the
        /// given MemoryPoolHandle.
        /// </remarks>
        /// <param name="encrypted">The ciphertext to be switched to a smaller modulus</param>
        /// <param name="parmsId">The target parmsId</param>
        /// <param name="destination">The ciphertext to overwrite with the modulus switched result</param>
        /// <param name="pool">The MemoryPoolHandle pointing to a valid memory pool</param>
        /// <exception cref="ArgumentNullException">if either encrypted, parmsId or destination are null.</exception>
        /// <exception cref="ArgumentException">if the scheme is invalid for rescaling</exception>
        /// <exception cref="ArgumentException">if encrypted is not valid for the encryption parameters</exception>
        /// <exception cref="ArgumentException">if encrypted is not in the default NTT form</exception>
        /// <exception cref="ArgumentException">if parmsId is not valid for the encryption parameters</exception>
        /// <exception cref="ArgumentException">if encrypted is already at lower level in modulus chain
        /// than the parameters corresponding to parmsId</exception>
        /// <exception cref="ArgumentException">if pool is uninitialized</exception>
        /// <exception cref="InvalidOperationException">if result ciphertext is transparent</exception>
        public void RescaleTo(Ciphertext encrypted, ParmsId parmsId, Ciphertext destination, MemoryPoolHandle pool = null)
        {
            if (null == encrypted)
                throw new ArgumentNullException(nameof(encrypted));
            if (null == parmsId)
                throw new ArgumentNullException(nameof(parmsId));
            if (null == destination)
                throw new ArgumentNullException(nameof(destination));

            IntPtr poolPtr = pool?.NativePtr ?? IntPtr.Zero;
            NativeMethods.Evaluator_RescaleTo(
                NativePtr, encrypted.NativePtr, parmsId.Block, destination.NativePtr, poolPtr);
        }

        /// <summary>
        /// Multiplies several ciphertexts together. This function computes the product of several
        /// ciphertext given as an IEnumerable and stores the result in the destination parameter.
        /// </summary>
        /// <remarks>
        /// Multiplies several ciphertexts together. This function computes the product of several
        /// ciphertext given as an IEnumerable and stores the result in the destination parameter.
        /// The multiplication is done in a depth-optimal order, and relinearization is performed
        /// automatically after every multiplication in the process. In relinearization the given
        /// relinearization keys are used. Dynamic memory allocations in the process are allocated
        /// from the memory pool pointed to by the given MemoryPoolHandle.
        /// </remarks>
        /// <param name="encrypteds">The ciphertexts to multiply</param>
        /// <param name="relinKeys">The relinearization keys</param>
        /// <param name="destination">The ciphertext to overwrite with the multiplication result</param>
        /// <param name="pool">The MemoryPoolHandle pointing to a valid memory pool</param>
        /// <exception cref="ArgumentNullException">if either encrypteds, relinKeys or destination are null</exception>
        /// <exception cref="InvalidOperationException">if scheme is not SchemeType.BFV</exception>
        /// <exception cref="ArgumentException">if encrypteds is empty</exception>
        /// <exception cref="ArgumentException">if the ciphertexts or relinKeys are not valid for
        /// the encryption parameters</exception>
        /// <exception cref="ArgumentException">if encrypteds are not in the default NTT form</exception>
        /// <exception cref="ArgumentException">if, when using SchemeType.CKKS, the output scale
        /// is too large for the encryption parameters</exception>
        /// <exception cref="ArgumentException">if the size of relinKeys is too small</exception>
        /// <exception cref="ArgumentException">if pool is uninitialized</exception>
        /// <exception cref="InvalidOperationException">if keyswitching is not supported by the context</exception>
        /// <exception cref="InvalidOperationException">if result ciphertext is transparent</exception>
        public void MultiplyMany(IEnumerable<Ciphertext> encrypteds, RelinKeys relinKeys,
            Ciphertext destination, MemoryPoolHandle pool = null)
        {
            if (null == encrypteds)
                throw new ArgumentNullException(nameof(encrypteds));
            if (null == relinKeys)
                throw new ArgumentNullException(nameof(relinKeys));
            if (null == destination)
                throw new ArgumentNullException(nameof(destination));
            if (!ContextUsingKeyswitching)
                throw new InvalidOperationException("Keyswitching is not supported by the context");

            IntPtr[] encarray = encrypteds.Select(c => c.NativePtr).ToArray();
            IntPtr poolPtr = pool?.NativePtr ?? IntPtr.Zero;
            NativeMethods.Evaluator_MultiplyMany(
                NativePtr, (ulong)encarray.Length, encarray, relinKeys.NativePtr,
                destination.NativePtr, poolPtr);
        }

        /// <summary>
        /// Exponentiates a ciphertext.
        /// </summary>
        /// <remarks>
        /// This functions raises encrypted to a power. Dynamic memory allocations in the process
        /// are allocated from the memory pool pointed to by the given MemoryPoolHandle. The
        /// exponentiation is done in a depth-optimal order, and relinearization is performed
        /// automatically after every multiplication in the process. In relinearization the given
        /// relinearization keys are used.
        /// </remarks>
        /// <param name="encrypted">The ciphertext to exponentiate</param>
        /// <param name="exponent">The power to raise the ciphertext to</param>
        /// <param name="relinKeys">The relinearization keys</param>
        /// <param name="pool">The MemoryPoolHandle pointing to a valid memory pool</param>
        /// <exception cref="ArgumentNullException">if either encrypted or relinKeys are null</exception>
        /// <exception cref="InvalidOperationException">if scheme is not SchemeType.BFV</exception>
        /// <exception cref="ArgumentException">if encrypted or relinKeys is not valid for the
        /// encryption parameters</exception>
        /// <exception cref="ArgumentException">if encrypted is not in the default NTT form</exception>
        /// <exception cref="ArgumentException">if, when using SchemeType.CKKS, the output scale
        /// is too large for the encryption parameters</exception>
        /// <exception cref="ArgumentException">if exponent is zero</exception>
        /// <exception cref="ArgumentException">if the size of relinKeys is too small</exception>
        /// <exception cref="ArgumentException">if pool is uninitialized</exception>
        /// <exception cref="InvalidOperationException">if keyswitching is not supported by the context</exception>
        /// <exception cref="InvalidOperationException">if result ciphertext is transparent</exception>
        public void ExponentiateInplace(Ciphertext encrypted, ulong exponent,
            RelinKeys relinKeys, MemoryPoolHandle pool = null)
        {
            Exponentiate(encrypted, exponent, relinKeys, destination: encrypted, pool: pool);
        }

        /// <summary>
        /// Exponentiates a ciphertext.
        /// </summary>
        /// <remarks>
        /// This functions raises encrypted to a power and stores the result in the destination
        /// parameter. Dynamic memory allocations in the process are allocated from the memory pool
        /// pointed to by the given MemoryPoolHandle. The exponentiation is done in a depth-optimal
        /// order, and relinearization is performed automatically after every multiplication in the
        /// process. In relinearization the given relinearization keys are used.
        /// </remarks>
        /// <param name="encrypted">The ciphertext to exponentiate</param>
        /// <param name="exponent">The power to raise the ciphertext to</param>
        /// <param name="relinKeys">The relinearization keys</param>
        /// <param name="destination">The ciphertext to overwrite with the power</param>
        /// <param name="pool">The MemoryPoolHandle pointing to a valid memory pool</param>
        /// <exception cref="InvalidOperationException">if scheme is not SchemeType.BFV</exception>
        /// <exception cref="ArgumentException">if encrypted or relinKeys is not valid for the
        /// encryption parameters</exception>
        /// <exception cref="ArgumentException">if encrypted is not in the default NTT form</exception>
        /// <exception cref="ArgumentException">if, when using SchemeType.CKKS, the output scale
        /// is too large for the encryption parameters</exception>
        /// <exception cref="ArgumentException">if exponent is zero</exception>
        /// <exception cref="ArgumentException">if the size of relinKeys is too small</exception>
        /// <exception cref="ArgumentException">if pool is uninitialized</exception>
        /// <exception cref="InvalidOperationException">if keyswitching is not supported by the context</exception>
        /// <exception cref="InvalidOperationException">if result ciphertext is transparent</exception>
        public void Exponentiate(Ciphertext encrypted, ulong exponent, RelinKeys relinKeys,
            Ciphertext destination, MemoryPoolHandle pool = null)
        {
            if (null == encrypted)
                throw new ArgumentNullException(nameof(encrypted));
            if (null == relinKeys)
                throw new ArgumentNullException(nameof(relinKeys));
            if (null == destination)
                throw new ArgumentNullException(nameof(destination));
            if (!ContextUsingKeyswitching)
                throw new InvalidOperationException("Keyswitching is not supported by the context");

            IntPtr poolPtr = pool?.NativePtr ?? IntPtr.Zero;
            NativeMethods.Evaluator_Exponentiate(
                NativePtr, encrypted.NativePtr, exponent, relinKeys.NativePtr,
                destination.NativePtr, poolPtr);
        }

        /// <summary>
        /// Adds a ciphertext and a plaintext.
        /// </summary>
        /// <remarks>
        /// Adds a ciphertext and a plaintext. The plaintext must be valid for the current
        /// encryption parameters.
        /// </remarks>
        /// <param name="encrypted">The ciphertext to add</param>
        /// <param name="plain">The plaintext to add</param>
        /// <exception cref="ArgumentNullException">if either encrypted or plain are null</exception>
        /// <exception cref="ArgumentException">if encrypted or plain is not valid for the encryption
        /// parameters</exception>
        /// <exception cref="ArgumentException">if encrypted or plain is in NTT form</exception>
        /// <exception cref="InvalidOperationException">if result ciphertext is transparent</exception>
        public void AddPlainInplace(Ciphertext encrypted, Plaintext plain)
        {
            AddPlain(encrypted, plain, destination: encrypted);
        }

        /// <summary>
        /// Adds a ciphertext and a plaintext.
        /// </summary>
        /// <remarks>
        /// Adds a ciphertext and a plaintext. This function adds a ciphertext and a plaintext
        /// and stores the result in the destination parameter. The plaintext must be valid for
        /// the current encryption parameters.
        /// </remarks>
        /// <param name="encrypted">The ciphertext to add</param>
        /// <param name="plain">The plaintext to add</param>
        /// <param name="destination">The ciphertext to overwrite with the addition result</param>
        /// <exception cref="ArgumentNullException">if either encrypted, plain or destination are null</exception>
        /// <exception cref="ArgumentException">if encrypted or plain is not valid for the encryption
        /// parameters</exception>
        /// <exception cref="ArgumentException">if encrypted or plain is in NTT form</exception>
        /// <exception cref="InvalidOperationException">if result ciphertext is transparent</exception>
        public void AddPlain(Ciphertext encrypted, Plaintext plain, Ciphertext destination)
        {
            if (null == encrypted)
                throw new ArgumentNullException(nameof(encrypted));
            if (null == plain)
                throw new ArgumentNullException(nameof(plain));
            if (null == destination)
                throw new ArgumentNullException(nameof(destination));

            NativeMethods.Evaluator_AddPlain(
                NativePtr, encrypted.NativePtr, plain.NativePtr, destination.NativePtr);
        }

        /// <summary>
        /// Subtracts a plaintext from a ciphertext.
        /// </summary>
        /// <remarks>
        /// Subtracts a plaintext from a ciphertext. The plaintext must be valid for the current
        /// encryption parameters.
        /// </remarks>
        /// <param name="encrypted">The ciphertext to subtract from</param>
        /// <param name="plain">The plaintext to subtract</param>
        /// <exception cref="ArgumentNullException">if either encrypted or plain are null</exception>
        /// <exception cref="ArgumentException">if encrypted or plain is not valid for the encryption
        /// parameters</exception>
        /// <exception cref="ArgumentException">if encrypted or plain is in NTT form</exception>
        /// <exception cref="InvalidOperationException">if result ciphertext is transparent</exception>
        public void SubPlainInplace(Ciphertext encrypted, Plaintext plain)
        {
            SubPlain(encrypted, plain, destination: encrypted);
        }

        /// <summary>
        /// Subtracts a plaintext from a ciphertext.
        /// </summary>
        /// <remarks>This function subtracts a plaintext from a ciphertext and stores the result in the
        /// destination parameter. The plaintext must be valid for the current encryption parameters.
        /// </remarks>
        /// <param name="encrypted">The ciphertext to subtract from</param>
        /// <param name="plain">The plaintext to subtract</param>
        /// <param name="destination">The ciphertext to overwrite with the subtraction result</param>
        /// <exception cref="ArgumentNullException">if either encrypted, plain or destination are null</exception>
        /// <exception cref="ArgumentException">if encrypted or plain is not valid for the encryption
        /// parameters</exception>
        /// <exception cref="ArgumentException">if encrypted or plain is in NTT form</exception>
        /// <exception cref="InvalidOperationException">if result ciphertext is transparent</exception>
        public void SubPlain(Ciphertext encrypted, Plaintext plain, Ciphertext destination)
        {
            if (null == encrypted)
                throw new ArgumentNullException(nameof(encrypted));
            if (null == plain)
                throw new ArgumentNullException(nameof(plain));
            if (null == destination)
                throw new ArgumentNullException(nameof(destination));

                NativeMethods.Evaluator_SubPlain(
                    NativePtr, encrypted.NativePtr, plain.NativePtr, destination.NativePtr);
        }

        /// <summary>
        /// Multiplies a ciphertext with a plaintext.
        /// </summary>
        /// <remarks>Multiplies a ciphertext with a plaintext. The plaintext must be valid for the
        /// current encryption parameters, and cannot be identially 0. Dynamic memory allocations in
        /// the process are allocated from the memory pool pointed to by the given MemoryPoolHandle.
        /// </remarks>
        /// <param name="encrypted">The ciphertext to multiply</param>
        /// <param name="plain">The plaintext to multiply</param>
        /// <param name="pool">The MemoryPoolHandle pointing to a valid memory pool</param>
        /// <exception cref="ArgumentNullException">if either encrypted or plain are null.</exception>
        /// <exception cref="ArgumentException">if the encrypted or plain is not valid for the encryption
        /// parameters</exception>
        /// <exception cref="ArgumentException">if encrypted and plain are in different NTT forms</exception>
        /// <exception cref="ArgumentException">if plain is zero</exception>
        /// <exception cref="ArgumentException">if, when using SchemeType.CKKS, the output scale
        /// is too large for the encryption parameters</exception>
        /// <exception cref="ArgumentException">if pool is uninitialized</exception>
        /// <exception cref="InvalidOperationException">if result ciphertext is transparent</exception>
        public void MultiplyPlainInplace(Ciphertext encrypted, Plaintext plain, MemoryPoolHandle pool = null)
        {
            MultiplyPlain(encrypted, plain, destination: encrypted, pool: pool);
        }

        /// <summary>
        /// Multiplies a ciphertext with a plaintext.
        /// </summary>
        /// <remarks>
        /// This function multiplies a ciphertext with a plaintext and stores the result in the
        /// destination parameter. The plaintext must be valid for the current encryption parameters,
        /// and cannot be identially 0. Dynamic memory allocations in the process are allocated from
        /// the memory pool pointed to by the given MemoryPoolHandle.
        /// </remarks>
        /// <param name="encrypted">The ciphertext to multiply</param>
        /// <param name="plain">The plaintext to multiply</param>
        /// <param name="destination">The ciphertext to overwrite with the multiplication result</param>
        /// <param name="pool">The MemoryPoolHandle pointing to a valid memory pool</param>
        /// <exception cref="ArgumentNullException">if either encrypted, plain or destination are null</exception>
        /// <exception cref="ArgumentException">if the encrypted or plain is not valid for the
        /// encryption parameters</exception>
        /// <exception cref="ArgumentException">if encrypted and plain are in different NTT forms</exception>
        /// <exception cref="ArgumentException">if plain is zero</exception>
        /// <exception cref="ArgumentException">if, when using SchemeType.CKKS, the output scale
        /// is too large for the encryption parameters</exception>
        /// <exception cref="ArgumentException">if pool is uninitialized</exception>
        /// <exception cref="InvalidOperationException">if result ciphertext is transparent</exception>
        public void MultiplyPlain(Ciphertext encrypted, Plaintext plain,
            Ciphertext destination, MemoryPoolHandle pool = null)
        {
            if (null == encrypted)
                throw new ArgumentNullException(nameof(encrypted));
            if (null == plain)
                throw new ArgumentNullException(nameof(plain));
            if (null == destination)
                throw new ArgumentNullException(nameof(destination));

            IntPtr poolPtr = pool?.NativePtr ?? IntPtr.Zero;
            NativeMethods.Evaluator_MultiplyPlain(
                NativePtr, encrypted.NativePtr, plain.NativePtr, destination.NativePtr, poolPtr);
        }

        /// <summary>
        /// Transforms a plaintext to NTT domain.
        /// </summary>
        /// <remarks>This functions applies the Number Theoretic Transform to a plaintext by first
        /// embedding integers modulo the plaintext modulus to integers modulo the coefficient
        /// modulus and then performing David Harvey's NTT on the resulting polynomial. The
        /// transformation is done with respect to encryption parameters corresponding to a given
        /// parmsId. For the operation to be valid, the plaintext must have degree less than
        /// PolyModulusDegree and each coefficient must be less than the plaintext modulus, i.e.,
        /// the plaintext must be a valid plaintext under the current encryption parameters.
        /// Dynamic memory allocations in the process are allocated from the memory pool pointed
        /// to by the given MemoryPoolHandle.
        /// </remarks>
        /// <param name="plain">The plaintext to transform</param>
        /// <param name="parmsId">The ParmsId with respect to which the NTT is done</param>
        /// <param name="pool">The MemoryPoolHandle pointing to a valid memory pool</param>
        /// <exception cref="ArgumentNullException">if either plain or parmsId are null</exception>
        /// <exception cref="ArgumentException">if plain is already in NTT form</exception>
        /// <exception cref="ArgumentException">if plain or parmsId is not valid for the encryption
        /// parameters</exception>
        /// <exception cref="ArgumentException">if pool is uninitialized</exception>
        public void TransformToNTTInplace(Plaintext plain, ParmsId parmsId, MemoryPoolHandle pool = null)
        {
            TransformToNTT(plain, parmsId, destinationNTT: plain, pool: pool);
        }

        /// <summary>
        /// Transforms a plaintext to NTT domain.
        /// </summary>
        /// <remarks>
        /// This functions applies the Number Theoretic Transform to a plaintext by first
        /// embedding integers modulo the plaintext modulus to integers modulo the coefficient
        /// modulus and then performing David Harvey's NTT on the resulting polynomial. The
        /// transformation is done with respect to encryption parameters corresponding to
        /// a given ParmsId. The result is stored in the destinationNTT parameter. For the
        /// operation to be valid, the plaintext must have degree less than PolyModulusDegree
        /// and each coefficient must be less than the plaintext modulus, i.e., the plaintext
        /// must be a valid plaintext under the current encryption parameters. Dynamic memory
        /// allocations in the process are allocated from the memory pool pointed to by the
        /// given MemoryPoolHandle.
        /// </remarks>
        /// <param name="plain">The plaintext to transform</param>
        /// <param name="parmsId">The ParmsId with respect to which the NTT is done</param>
        /// <param name="destinationNTT">The plaintext to overwrite with the transformed result</param>
        /// <param name="pool">The MemoryPoolHandle pointing to a valid memory pool</param>
        /// <exception cref="ArgumentNullException">if either plain, parmsId or destinationNTT are null</exception>
        /// <exception cref="ArgumentException">if plain is already in NTT form</exception>
        /// <exception cref="ArgumentException">if plain or parmsId is not valid for the encryption
        /// parameters</exception>
        /// <exception cref="ArgumentException">if pool is uninitialized</exception>
        public void TransformToNTT(Plaintext plain, ParmsId parmsId,
            Plaintext destinationNTT, MemoryPoolHandle pool = null)
        {
            if (null == plain)
                throw new ArgumentNullException(nameof(plain));
            if (null == parmsId)
                throw new ArgumentNullException(nameof(parmsId));
            if (null == destinationNTT)
                throw new ArgumentNullException(nameof(destinationNTT));

            IntPtr poolPtr = pool?.NativePtr ?? IntPtr.Zero;
            NativeMethods.Evaluator_TransformToNTT(NativePtr, plain.NativePtr, parmsId.Block, destinationNTT.NativePtr, poolPtr);
        }

        /// <summary>
        /// Transforms a ciphertext to NTT domain.
        /// </summary>
        /// <remarks>
        /// Transforms a ciphertext to NTT domain. This functions applies David Harvey's Number
        /// Theoretic Transform separately to each polynomial of a ciphertext.
        /// </remarks>
        /// <param name="encrypted">The ciphertext to transform</param>
        /// <exception cref="ArgumentNullException">if encrypted is null</exception>
        /// <exception cref="ArgumentException">if encrypted is not valid for the encryption parameters</exception>
        /// <exception cref="ArgumentException">if encrypted is already in NTT form</exception>
        /// <exception cref="InvalidOperationException">if result ciphertext is transparent</exception>
        public void TransformToNTTInplace(Ciphertext encrypted)
        {
            TransformToNTT(encrypted, destinationNTT: encrypted);
        }

        /// <summary>
        /// Transforms a ciphertext to NTT domain.
        /// </summary>
        /// <remarks>
        /// Transforms a ciphertext to NTT domain. This functions applies David Harvey's Number
        /// Theoretic Transform separately to each polynomial of a ciphertext. The result is
        /// stored in the DestinationNTT parameter.
        /// </remarks>
        /// <param name="encrypted">The ciphertext to transform</param>
        /// <param name="destinationNTT">The ciphertext to overwrite with the transformed result</param>
        /// <exception cref="ArgumentNullException">if either encrypted or destinationNTT are null</exception>
        /// <exception cref="ArgumentException">if encrypted is not valid for the encryption parameters</exception>
        /// <exception cref="ArgumentException">if encrypted is already in NTT form</exception>
        /// <exception cref="InvalidOperationException">if result ciphertext is transparent</exception>
        public void TransformToNTT(Ciphertext encrypted,
                    Ciphertext destinationNTT)
        {
            if (null == encrypted)
                throw new ArgumentNullException(nameof(encrypted));
            if (null == destinationNTT)
                throw new ArgumentNullException(nameof(destinationNTT));

            NativeMethods.Evaluator_TransformToNTT(
                NativePtr, encrypted.NativePtr, destinationNTT.NativePtr);
        }

        /// <summary>
        /// Transforms a ciphertext back from NTT domain.
        /// </summary>
        /// <remarks>
        /// Transforms a ciphertext back from NTT domain. This functions applies the inverse of
        /// David Harvey's Number Theoretic Transform separately to each polynomial of a ciphertext.
        /// </remarks>
        /// <param name="encryptedNTT">The ciphertext to transform</param>
        /// <exception cref="ArgumentNullException">if encryptedNTT is null</exception>
        /// <exception cref="ArgumentException">if encryptedNTT is not valid for the encryption parameters</exception>
        /// <exception cref="ArgumentException">if encryptedNTT is not in NTT form</exception>
        /// <exception cref="InvalidOperationException">if result ciphertext is transparent</exception>
        public void TransformFromNTTInplace(Ciphertext encryptedNTT)
        {
            TransformFromNTT(encryptedNTT, destination: encryptedNTT);
        }

        /// <summary>
        /// Transforms a ciphertext back from NTT domain.
        /// </summary>
        /// <remarks>
        /// Transforms a ciphertext back from NTT domain. This functions applies the inverse of
        /// David Harvey's Number Theoretic Transform separately to each polynomial of a ciphertext.
        /// The result is stored in the destination parameter.
        /// </remarks>
        /// <param name="encryptedNTT">The ciphertext to transform</param>
        /// <param name="destination">The ciphertext to overwrite with the transformed result</param>
        /// <exception cref="ArgumentNullException">if either encryptedNTT or destination are null</exception>
        /// <exception cref="ArgumentException">if encryptedNTT is not valid for the encryption parameters</exception>
        /// <exception cref="ArgumentException">if encryptedNTT is not in NTT form</exception>
        /// <exception cref="InvalidOperationException">if result ciphertext is transparent</exception>
        public void TransformFromNTT(Ciphertext encryptedNTT, Ciphertext destination)
        {
            if (null == encryptedNTT)
                throw new ArgumentNullException(nameof(encryptedNTT));
            if (null == destination)
                throw new ArgumentNullException(nameof(destination));

            NativeMethods.Evaluator_TransformFromNTT(
                NativePtr, encryptedNTT.NativePtr, destination.NativePtr);
        }

        /// <summary>
        /// Applies a Galois automorphism to a ciphertext.
        /// </summary>
        /// <remarks>
        /// <para>
        /// Applies a Galois automorphism to a ciphertext. To evaluate the Galois automorphism,
        /// an appropriate set of Galois keys must also be provided. Dynamic memory allocations
        /// in the process are allocated from the memory pool pointed to by the given
        /// MemoryPoolHandle.
        /// </para>
        /// <para>
        /// The desired Galois automorphism is given as a Galois element, and must be an odd
        /// integer in the interval [1, M-1], where M = 2*N, and N = PolyModulusDegree. Used
        /// with batching, a Galois element 3^i % M corresponds to a cyclic row rotation i steps
        /// to the left, and a Galois element 3^(N/2-i) % M corresponds to a cyclic row rotation
        /// i steps to the right. The Galois element M-1 corresponds to a column rotation (row
        /// swap) in BFV, and complex conjugation in CKKS. In the polynomial view (not batching),
        /// a Galois automorphism by a Galois element p changes Enc(plain(x)) to Enc(plain(x^p)).
        /// </para>
        /// </remarks>
        /// <param name="encrypted">The ciphertext to apply the Galois automorphism to</param>
        /// <param name="galoisElt">The Galois element</param>
        /// <param name="galoisKeys">The Galois keys</param>
        /// <param name="pool">The MemoryPoolHandle pointing to a valid memory pool</param>
        /// <exception cref="ArgumentNullException">if either encrypted or galoisKeys are null</exception>
        /// <exception cref="ArgumentException">if encrypted or galoisKeys is not valid for the
        /// encryption parameters</exception>
        /// <exception cref="ArgumentException">if galoisKeys do not correspond to the top level
        /// parameters in the current context</exception>
        /// <exception cref="ArgumentException">if encrypted is not in the default NTT form</exception>
        /// <exception cref="ArgumentException">if encrypted has size larger than 2</exception>
        /// <exception cref="ArgumentException">if the Galois element is not valid</exception>
        /// <exception cref="ArgumentException">if necessary Galois keys are not present</exception>
        /// <exception cref="ArgumentException">if pool is uninitialized</exception>
        /// <exception cref="InvalidOperationException">if keyswitching is not supported by the context</exception>
        /// <exception cref="InvalidOperationException">if result ciphertext is transparent</exception>
        public void ApplyGaloisInplace(Ciphertext encrypted, uint galoisElt,
            GaloisKeys galoisKeys, MemoryPoolHandle pool = null)
        {
            ApplyGalois(encrypted, galoisElt, galoisKeys, destination: encrypted, pool: pool);
        }

        /// <summary>
        /// Applies a Galois automorphism to a ciphertext and writes the result to the
        /// destination parameter.
        /// </summary>
        /// <remarks>
        /// <para>
        /// Applies a Galois automorphism to a ciphertext and writes the result to the
        /// destination parameter. To evaluate the Galois automorphism, an appropriate set of
        /// Galois keys must also be provided. Dynamic memory allocations in the process are
        /// allocated from the memory pool pointed to by the given MemoryPoolHandle.
        /// </para>
        /// <para>
        /// The desired Galois automorphism is given as a Galois element, and must be an odd
        /// integer in the interval [1, M-1], where M = 2*N, and N = PolyModulusDegree. Used
        /// with batching, a Galois element 3^i % M corresponds to a cyclic row rotation i steps
        /// to the left, and a Galois element 3^(N/2-i) % M corresponds to a cyclic row rotation
        /// i steps to the right. The Galois element M-1 corresponds to a column rotation (row
        /// swap) in BFV, and complex conjugation in CKKS. In the polynomial view (not batching),
        /// a Galois automorphism by a Galois element p changes Enc(plain(x)) to Enc(plain(x^p)).
        /// </para>
        /// </remarks>
        /// <param name="encrypted">The ciphertext to apply the Galois automorphism to</param>
        /// <param name="galoisElt">The Galois element</param>
        /// <param name="galoisKeys">The Galois keys</param>
        /// <param name="destination">The ciphertext to overwrite with the result</param>
        /// <param name="pool">The MemoryPoolHandle pointing to a valid memory pool</param>
        /// <exception cref="ArgumentNullException">if either encrypted, galoisKeys or destination are null</exception>
        /// <exception cref="ArgumentException">if encrypted or galoisKeys is not valid for the
        /// encryption parameters</exception>
        /// <exception cref="ArgumentException">if galoisKeys do not correspond to the top level
        /// parameters in the current context</exception>
        /// <exception cref="ArgumentException">if encrypted is not in the default NTT form</exception>
        /// <exception cref="ArgumentException">if encrypted has size larger than 2</exception>
        /// <exception cref="ArgumentException">if the Galois element is not valid</exception>
        /// <exception cref="ArgumentException">if necessary Galois keys are not present</exception>
        /// <exception cref="ArgumentException">if pool is uninitialized</exception>
        /// <exception cref="InvalidOperationException">if keyswitching is not supported by the context</exception>
        /// <exception cref="InvalidOperationException">if result ciphertext is transparent</exception>
        public void ApplyGalois(Ciphertext encrypted, uint galoisElt, GaloisKeys galoisKeys,
            Ciphertext destination, MemoryPoolHandle pool = null)
        {
            if (null == encrypted)
                throw new ArgumentNullException(nameof(encrypted));
            if (null == galoisKeys)
                throw new ArgumentNullException(nameof(galoisKeys));
            if (null == destination)
                throw new ArgumentNullException(nameof(destination));
            if (!ContextUsingKeyswitching)
                throw new InvalidOperationException("Keyswitching is not supported by the context");

            IntPtr poolPtr = pool?.NativePtr ?? IntPtr.Zero;
            NativeMethods.Evaluator_ApplyGalois(
                NativePtr, encrypted.NativePtr, galoisElt,
                galoisKeys.NativePtr, destination.NativePtr, poolPtr);
        }

        /// <summary>
        /// Rotates plaintext matrix rows cyclically.
        /// </summary>
        /// <remarks>
        /// When batching is used with the BFV scheme, this function rotates the encrypted plaintext
        /// matrix rows cyclically to the left (steps &gt; 0) or to the right (steps &lt; 0). Since
        /// the size of the batched matrix is 2-by-(N/2), where N is the degree of the polynomial
        /// modulus, the number of steps to rotate must have absolute value at most N/2-1. Dynamic
        /// memory allocations in the process are allocated from the memory pool pointed to by the
        /// given MemoryPoolHandle.
        /// </remarks>
        /// <param name="encrypted">The ciphertext to rotate</param>
        /// <param name="steps">The number of steps to rotate (negative left, positive right)</param>
        /// <param name="galoisKeys">The Galois keys</param>
        /// <param name="pool">The MemoryPoolHandle pointing to a valid memory pool</param>
        /// <exception cref="ArgumentNullException">if either encrypted or galoisKeys are null</exception>
        /// <exception cref="InvalidOperationException">if the encryption parameters do not support batching</exception>
        /// <exception cref="InvalidOperationException">if scheme is not SchemeType.BFV</exception>
        /// <exception cref="ArgumentException">if encrypted or galoisKeys is not valid for the
        /// encryption parameters</exception>
        /// <exception cref="ArgumentException">if galoisKeys do not correspond to the top level
        /// parameters in the current context</exception>
        /// <exception cref="ArgumentException">if encrypted is not in the default NTT form</exception>
        /// <exception cref="ArgumentException">if encrypted has size larger than 2</exception>
        /// <exception cref="ArgumentException">if steps has too big absolute value</exception>
        /// <exception cref="ArgumentException">if necessary Galois keys are not present</exception>
        /// <exception cref="ArgumentException">if pool is uninitialized</exception>
        /// <exception cref="InvalidOperationException">if keyswitching is not supported by the context</exception>
        /// <exception cref="InvalidOperationException">if result ciphertext is transparent</exception>
        public void RotateRowsInplace(Ciphertext encrypted,
            int steps, GaloisKeys galoisKeys, MemoryPoolHandle pool = null)
        {
            RotateRows(encrypted, steps, galoisKeys, destination: encrypted, pool: pool);
        }

        /// <summary>
        /// Rotates plaintext matrix rows cyclically.
        /// </summary>
        /// <remarks>
        /// When batching is used with the BFV scheme, this function rotates the encrypted plaintext
        /// matrix rows cyclically to the left (steps &gt; 0) or to the right (steps &lt; 0) and writes
        /// the result to the destination parameter. Since the size of the batched matrix is 2-by-(N/2),
        /// where N is the degree of the polynomial modulus, the number of steps to rotate must have
        /// absolute value at most N/2-1. Dynamic memory allocations in the process are allocated from
        /// the memory pool pointed to by the given MemoryPoolHandle.
        /// </remarks>
        /// <param name="encrypted">The ciphertext to rotate</param>
        /// <param name="steps">The number of steps to rotate (negative left, positive right)</param>
        /// <param name="galoisKeys">The Galois keys</param>
        /// <param name="destination">The ciphertext to overwrite with the rotated result</param>
        /// <param name="pool">The MemoryPoolHandle pointing to a valid memory pool</param>
        /// <exception cref="ArgumentNullException">if either encrypted, galoisKeys or destination are null</exception>
        /// <exception cref="InvalidOperationException">if the encryption parameters do not support batching</exception>
        /// <exception cref="InvalidOperationException">if scheme is not SchemeType.BFV</exception>
        /// <exception cref="ArgumentException">if encrypted or galoisKeys is not valid for the
        /// encryption parameters</exception>
        /// <exception cref="ArgumentException">if galoisKeys do not correspond to the top level
        /// parameters in the current context</exception>
        /// <exception cref="ArgumentException">if encrypted is in NTT form</exception>
        /// <exception cref="ArgumentException">if encrypted has size larger than 2</exception>
        /// <exception cref="ArgumentException">if steps has too big absolute value</exception>
        /// <exception cref="ArgumentException">if necessary Galois keys are not present</exception>
        /// <exception cref="ArgumentException">if pool is uninitialized</exception>
        /// <exception cref="InvalidOperationException">if keyswitching is not supported by the context</exception>
        /// <exception cref="InvalidOperationException">if result ciphertext is transparent</exception>
        public void RotateRows(Ciphertext encrypted, int steps, GaloisKeys galoisKeys,
            Ciphertext destination, MemoryPoolHandle pool = null)
        {
            if (null == encrypted)
                throw new ArgumentNullException(nameof(encrypted));
            if (null == galoisKeys)
                throw new ArgumentNullException(nameof(galoisKeys));
            if (null == destination)
                throw new ArgumentNullException(nameof(destination));
            if (!ContextUsingKeyswitching)
                throw new InvalidOperationException("Keyswitching is not supported by the context");

            IntPtr poolPtr = pool?.NativePtr ?? IntPtr.Zero;
            NativeMethods.Evaluator_RotateRows(
                NativePtr, encrypted.NativePtr, steps, galoisKeys.NativePtr,
                destination.NativePtr, poolPtr);
        }

        /// <summary>
        /// Rotates plaintext matrix columns cyclically.
        /// </summary>
        /// <remarks>
        /// When batching is used with the BFV scheme, this function rotates the encrypted
        /// plaintext matrix columns cyclically. Since the size of the batched matrix is 2-by-(N/2),
        /// where N is the degree of the polynomial modulus, this means simply swapping the two
        /// rows. Dynamic memory allocations in the process are allocated from the memory pool
        /// pointed to by the given MemoryPoolHandle.
        /// </remarks>
        /// <param name="encrypted">The ciphertext to rotate</param>
        /// <param name="galoisKeys">The Galois keys</param>
        /// <param name="pool">The MemoryPoolHandle pointing to a valid memory pool</param>
        /// <exception cref="ArgumentNullException">if either encrypted or galoisKeys are null</exception>
        /// <exception cref="InvalidOperationException">if the encryption parameters do not support batching</exception>
        /// <exception cref="InvalidOperationException">if scheme is not SchemeType.BFV</exception>
        /// <exception cref="ArgumentException">if encrypted or galoisKeys is not valid for the
        /// encryption parameters</exception>
        /// <exception cref="ArgumentException">if galoisKeys do not correspond to the top level
        /// parameters in the current context</exception>
        /// <exception cref="ArgumentException">if encrypted is in NTT form</exception>
        /// <exception cref="ArgumentException">if encrypted has size larger than 2</exception>
        /// <exception cref="ArgumentException">if necessary Galois keys are not present</exception>
        /// <exception cref="ArgumentException">if pool is uninitialized</exception>
        /// <exception cref="InvalidOperationException">if keyswitching is not supported by the context</exception>
        /// <exception cref="InvalidOperationException">if result ciphertext is transparent</exception>
        public void RotateColumnsInplace(Ciphertext encrypted, GaloisKeys galoisKeys, MemoryPoolHandle pool = null)
        {
            RotateColumns(encrypted, galoisKeys, destination: encrypted, pool: pool);
        }

        /// <summary>
        /// Rotates plaintext matrix columns cyclically.
        /// </summary>
        /// <remarks>
        /// When batching is used with the BFV scheme, this function rotates the encrypted plaintext
        /// matrix columns cyclically, and writes the result to the destination parameter. Since the
        /// size of the batched matrix is 2-by-(N/2), where N is the degree of the polynomial modulus,
        /// this means simply swapping the two rows. Dynamic memory allocations in the process are
        /// allocated from the memory pool pointed to by the given MemoryPoolHandle.
        /// </remarks>
        /// <param name="encrypted">The ciphertext to rotate</param>
        /// <param name="galoisKeys">The Galois keys</param>
        /// <param name="destination">The ciphertext to overwrite with the rotated result</param>
        /// <param name="pool">The MemoryPoolHandle pointing to a valid memory pool</param>
        /// <exception cref="ArgumentNullException">if either encrypted, galoisKeys or destination are null</exception>
        /// <exception cref="InvalidOperationException">if the encryption parameters do not support batching</exception>
        /// <exception cref="InvalidOperationException">if scheme is not SchemeType.BFV</exception>
        /// <exception cref="ArgumentException">if encrypted or galoisKeys is not valid for the
        /// encryption parameters</exception>
        /// <exception cref="ArgumentException">if galoisKeys do not correspond to the top level
        /// parameters in the current context</exception>
        /// <exception cref="ArgumentException">if encrypted is in NTT form</exception>
        /// <exception cref="ArgumentException">if encrypted has size larger than 2</exception>
        /// <exception cref="ArgumentException">if necessary Galois keys are not present</exception>
        /// <exception cref="ArgumentException">if pool is uninitialized</exception>
        /// <exception cref="InvalidOperationException">if keyswitching is not supported by the context</exception>
        /// <exception cref="InvalidOperationException">if result ciphertext is transparent</exception>
        public void RotateColumns(Ciphertext encrypted, GaloisKeys galoisKeys,
            Ciphertext destination, MemoryPoolHandle pool = null)
        {
            if (null == encrypted)
                throw new ArgumentNullException(nameof(encrypted));
            if (null == galoisKeys)
                throw new ArgumentNullException(nameof(galoisKeys));
            if (null == destination)
                throw new ArgumentNullException(nameof(destination));
            if (!ContextUsingKeyswitching)
                throw new InvalidOperationException("Keyswitching is not supported by the context");

            IntPtr poolPtr = pool?.NativePtr ?? IntPtr.Zero;
            NativeMethods.Evaluator_RotateColumns(
                NativePtr, encrypted.NativePtr, galoisKeys.NativePtr,
                destination.NativePtr, poolPtr);
        }

        /// <summary>
        /// Rotates plaintext vector cyclically.
        /// </summary>
        /// <remarks>
        /// When using the CKKS scheme, this function rotates the encrypted plaintext vector
        /// cyclically to the left (steps &gt; 0) or to the right (steps &lt; 0). Since the size
        /// of the batched matrix is 2-by-(N/2), where N is the degree of the polynomial modulus,
        /// the number of steps to rotate must have absolute value at most N/2-1. Dynamic memory
        /// allocations in the process are allocated from the memory pool pointed to by the given
        /// MemoryPoolHandle.
        /// </remarks>
        /// <param name="encrypted">The ciphertext to rotate</param>
        /// <param name="steps">The number of steps to rotate (negative left, positive right)</param>
        /// <param name="galoisKeys">The Galois keys</param>
        /// <param name="pool">The MemoryPoolHandle pointing to a valid memory pool</param>
        /// <exception cref="ArgumentNullException">if either encrypted or galoisKeys are null</exception>
        /// <exception cref="InvalidOperationException">if the encryption parameters do not support batching</exception>
        /// <exception cref="InvalidOperationException">if scheme is not SchemeType.CKKS</exception>
        /// <exception cref="ArgumentException">if encrypted or galoisKeys is not valid for the
        /// encryption parameters</exception>
        /// <exception cref="ArgumentException">if galoisKeys do not correspond to the top level
        /// parameters in the current context</exception>
        /// <exception cref="ArgumentException">if encrypted is in NTT form</exception>
        /// <exception cref="ArgumentException">if encrypted has size larger than 2</exception>
        /// <exception cref="ArgumentException">if steps has too big absolute value</exception>
        /// <exception cref="ArgumentException">if necessary Galois keys are not present</exception>
        /// <exception cref="ArgumentException">if pool is uninitialized</exception>
        /// <exception cref="InvalidOperationException">if keyswitching is not supported by the context</exception>
        /// <exception cref="InvalidOperationException">if result ciphertext is transparent</exception>
        public void RotateVectorInplace(Ciphertext encrypted, int steps,
            GaloisKeys galoisKeys, MemoryPoolHandle pool = null)
        {
            RotateVector(encrypted, steps, galoisKeys, destination: encrypted, pool: pool);
        }

        /// <summary>
        /// Rotates plaintext vector cyclically.
        /// </summary>
        /// <remarks>
        /// When using the CKKS scheme, this function rotates the encrypted plaintext vector
        /// cyclically to the left (steps &gt; 0) or to the right (steps &lt; 0) and writes
        /// the result to the destination parameter. Since the size of the batched matrix is
        /// 2-by-(N/2), where N is the degree of the polynomial modulus, the number of steps
        /// to rotate must have absolute value at most N/2-1. Dynamic memory allocations in the
        /// process are allocated from the memory pool pointed to by the given MemoryPoolHandle.
        /// </remarks>
        /// <param name="encrypted">The ciphertext to rotate</param>
        /// <param name="steps">The number of steps to rotate (negative left, positive right)</param>
        /// <param name="galoisKeys">The Galois keys</param>
        /// <param name="destination">The ciphertext to overwrite with the rotated result</param>
        /// <param name="pool">The MemoryPoolHandle pointing to a valid memory pool</param>
        /// <exception cref="ArgumentNullException">if either encrypted, galoisKeys or destination are null</exception>
        /// <exception cref="InvalidOperationException">if the encryption parameters do not support batching</exception>
        /// <exception cref="InvalidOperationException">if scheme is not SchemeType.CKKS</exception>
        /// <exception cref="ArgumentException">if encrypted or galoisKeys is not valid for the
        /// encryption parameters</exception>
        /// <exception cref="ArgumentException">if galoisKeys do not correspond to the top level
        /// parameters in the current context</exception>
        /// <exception cref="ArgumentException">if encrypted is in NTT form</exception>
        /// <exception cref="ArgumentException">if encrypted has size larger than 2</exception>
        /// <exception cref="ArgumentException">if steps has too big absolute value</exception>
        /// <exception cref="ArgumentException">if necessary Galois keys are not present</exception>
        /// <exception cref="ArgumentException">if pool is uninitialized</exception>
        /// <exception cref="InvalidOperationException">if keyswitching is not supported by the context</exception>
        /// <exception cref="InvalidOperationException">if result ciphertext is transparent</exception>
        public void RotateVector(Ciphertext encrypted, int steps, GaloisKeys galoisKeys,
            Ciphertext destination, MemoryPoolHandle pool = null)
        {
            if (null == encrypted)
                throw new ArgumentNullException(nameof(encrypted));
            if (null == galoisKeys)
                throw new ArgumentNullException(nameof(galoisKeys));
            if (null == destination)
                throw new ArgumentNullException(nameof(destination));
            if (!ContextUsingKeyswitching)
                throw new InvalidOperationException("Keyswitching is not supported by the context");

            IntPtr poolPtr = pool?.NativePtr ?? IntPtr.Zero;
            NativeMethods.Evaluator_RotateVector(
                NativePtr, encrypted.NativePtr, steps, galoisKeys.NativePtr,
                destination.NativePtr, poolPtr);
        }

        /// <summary>
        /// Complex conjugates plaintext slot values.
        /// </summary>
        /// <remarks>
        /// When using the CKKS scheme, this function complex conjugates all values in the
        /// underlying plaintext. Dynamic memory allocations in the process are allocated from
        /// the memory pool pointed to by the given MemoryPoolHandle.
        /// </remarks>
        /// <param name="encrypted">The ciphertext to rotate</param>
        /// <param name="galoisKeys">The Galois keys</param>
        /// <param name="pool">The MemoryPoolHandle pointing to a valid memory pool</param>
        /// <exception cref="ArgumentNullException">if either encrypted or galoisKeys are null</exception>
        /// <exception cref="InvalidOperationException">if the encryption parameters do not support batching</exception>
        /// <exception cref="InvalidOperationException">if scheme is not SchemeType.CKKS</exception>
        /// <exception cref="ArgumentException">if encrypted or galoisKeys is not valid for the
        /// encryption parameters</exception>
        /// <exception cref="ArgumentException">if galoisKeys do not correspond to the top level
        /// parameters in the current context</exception>
        /// <exception cref="ArgumentException">if encrypted is in NTT form</exception>
        /// <exception cref="ArgumentException">if encrypted has size larger than 2</exception>
        /// <exception cref="ArgumentException">if necessary Galois keys are not present</exception>
        /// <exception cref="ArgumentException">if pool is uninitialized</exception>
        /// <exception cref="InvalidOperationException">if keyswitching is not supported by the context</exception>
        /// <exception cref="InvalidOperationException">if result ciphertext is transparent</exception>
        public void ComplexConjugateInplace(Ciphertext encrypted, GaloisKeys galoisKeys, MemoryPoolHandle pool = null)
        {
            ComplexConjugate(encrypted, galoisKeys, destination: encrypted, pool: pool);
        }

        /// <summary>
        /// Complex conjugates plaintext slot values.
        /// </summary>
        /// <remarks>
        /// When using the CKKS scheme, this function complex conjugates all values in the
        /// underlying plaintext, and writes the result to the destination parameter. Dynamic
        /// memory allocations in the process are allocated from the memory pool pointed to
        /// by the given MemoryPoolHandle.
        /// </remarks>
        /// <param name="encrypted">The ciphertext to rotate</param>
        /// <param name="galoisKeys">The Galois keys</param>
        /// <param name="destination">The ciphertext to overwrite with the rotated result</param>
        /// <param name="pool">The MemoryPoolHandle pointing to a valid memory pool</param>
        /// <exception cref="InvalidOperationException">if the encryption parameters do not support batching</exception>
        /// <exception cref="InvalidOperationException">if scheme is not SchemeType.CKKS</exception>
        /// <exception cref="ArgumentException">if encrypted or galoisKeys is not valid for the
        /// encryption parameters</exception>
        /// <exception cref="ArgumentException">if galoisKeys do not correspond to the top level
        /// parameters in the current context</exception>
        /// <exception cref="ArgumentException">if encrypted is in NTT form</exception>
        /// <exception cref="ArgumentException">if encrypted has size larger than 2</exception>
        /// <exception cref="ArgumentException">if necessary Galois keys are not present</exception>
        /// <exception cref="ArgumentException">if pool is uninitialized</exception>
        /// <exception cref="InvalidOperationException">if keyswitching is not supported by the context</exception>
        /// <exception cref="InvalidOperationException">if result ciphertext is transparent</exception>
        public void ComplexConjugate(Ciphertext encrypted, GaloisKeys galoisKeys,
            Ciphertext destination, MemoryPoolHandle pool = null)
        {
            if (null == encrypted)
                throw new ArgumentNullException(nameof(encrypted));
            if (null == galoisKeys)
                throw new ArgumentNullException(nameof(galoisKeys));
            if (null == destination)
                throw new ArgumentNullException(nameof(destination));
            if (!ContextUsingKeyswitching)
                throw new InvalidOperationException("Keyswitching is not supported by the context");

            IntPtr poolPtr = pool?.NativePtr ?? IntPtr.Zero;
            NativeMethods.Evaluator_ComplexConjugate(
                NativePtr, encrypted.NativePtr, galoisKeys.NativePtr,
                destination.NativePtr, poolPtr);
        }

        /// <summary>
        /// Destroy native object.
        /// </summary>
        protected override void DestroyNativeObject()
        {
            NativeMethods.Evaluator_Destroy(NativePtr);
        }

        internal bool ContextUsingKeyswitching
        {
            get
            {
                NativeMethods.Evaluator_ContextUsingKeyswitching(NativePtr, out bool result);
                return result;
            }
        }
    }
}