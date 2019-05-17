// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

using Microsoft.Research.SEAL.Tools;
using System;

namespace Microsoft.Research.SEAL
{
    /// <summary>
    /// Decrypts Ciphertext objects into Plaintext objects. Constructing a Decryptor requires
    /// a SEALContext with valid encryption parameters, and the secret key. The Decryptor is
    /// also used to compute the invariant noise budget in a given ciphertext.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Overloads
    /// For the decrypt function we provide two overloads concerning the memory pool used in
    /// allocations needed during the operation. In one overload the global memory pool is used
    /// for this purpose, and in another overload the user can supply a MemoryPoolHandle
    /// to to be used instead. This is to allow one single Decryptor to be used concurrently by
    /// several threads without running into thread contention in allocations taking place during
    /// operations. For example, one can share one single Decryptor across any number of threads,
    /// but in each thread call the decrypt function by giving it a thread-local MemoryPoolHandle
    /// to use. It is important for a developer to understand how this works to avoid unnecessary
    /// performance bottlenecks.
    /// </para>
    /// <para>
    /// NTT form
    /// When using the BFV scheme (SchemeType.BFV), all plaintext and ciphertexts should
    /// remain by default in the usual coefficient representation, i.e. not in NTT form.
    /// When using the CKKS scheme (SchemeType.CKKS), all plaintexts and ciphertexts
    /// should remain by default in NTT form. We call these scheme-specific NTT states the
    /// "default NTT form". Decryption requires the input ciphertexts to be in the default
    /// NTT form, and will throw an exception if this is not the case.
    /// </para>
    /// </remarks>
    public class Decryptor : NativeObject
    {
        /// <summary>
        /// Creates a Decryptor instance initialized with the specified SEALContext
        /// and secret key.
        /// </summary>
        /// <param name="context">The SEALContext</param>
        /// <param name="secretKey">The secret key</param>
        /// <exception cref="ArgumentNullException">if either context or secretKey are null</exception>
        /// <exception cref="ArgumentException">if the context is not set or encryption
        /// parameters are not valid</exception>
        /// <exception cref="ArgumentException">if secretKey is not valid</exception>
        public Decryptor(SEALContext context, SecretKey secretKey)
        {
            if (null == context)
                throw new ArgumentNullException(nameof(context));
            if (null == secretKey)
                throw new ArgumentNullException(nameof(secretKey));
            if (!context.ParametersSet)
                throw new ArgumentException("Encryption parameters are not set correctly");
            if (!ValCheck.IsValidFor(secretKey, context))
                throw new ArgumentException("Secret key is not valid for encryption parameters");

            NativeMethods.Decryptor_Create(context.NativePtr, secretKey.NativePtr, out IntPtr ptr);
            NativePtr = ptr;
        }

        /// <summary>
        /// Decrypts a Ciphertext and stores the result in the destination parameter. Dynamic
        /// memory allocations in the process are allocated from the memory pool pointed to by
        /// the given MemoryPoolHandle.
        /// </summary>
        /// <param name="encrypted">The ciphertext to decrypt</param>
        /// <param name="destination">The plaintext to overwrite with the decrypted ciphertext</param>
        /// <exception cref="ArgumentNullException">if either encrypted or destination are null</exception>
        /// <exception cref="ArgumentException">if encrypted is not valid for the encryption parameters</exception>
        /// <exception cref="ArgumentException">if encrypted is not in the default NTT form</exception>
        /// <exception cref="ArgumentException">if pool is uninitialized</exception>
        public void Decrypt(Ciphertext encrypted, Plaintext destination)
        {
            if (null == encrypted)
                throw new ArgumentNullException(nameof(encrypted));
            if (null == destination)
                throw new ArgumentNullException(nameof(destination));

            NativeMethods.Decryptor_Decrypt(NativePtr, encrypted.NativePtr, destination.NativePtr);
        }

        /// <summary>
        /// Computes the invariant noise budget (in bits) of a ciphertext. The invariant noise
        /// budget measures the amount of room there is for the noise to grow while ensuring
        /// correct decryptions. Dynamic memory allocations in the process are allocated from
        /// the memory pool pointed to by the given MemoryPoolHandle. This function works only
        /// with the BFV scheme.
        /// </summary>
        /// <remarks>
        /// <para>
        /// Invariant Noise Budget
        /// The invariant noise polynomial of a ciphertext is a rational coefficient polynomial,
        /// such that a ciphertext decrypts correctly as long as the coefficients of the invariant
        /// noise polynomial are of absolute value less than 1/2. Thus, we call the infinity-norm
        /// of the invariant noise polynomial the invariant noise, and for correct decryption require
        /// it to be less than 1/2. If v denotes the invariant noise, we define the invariant noise
        /// budget as -log2(2v). Thus, the invariant noise budget starts from some initial value,
        /// which depends on the encryption parameters, and decreases when computations are performed.
        /// When the budget reaches zero, the ciphertext becomes too noisy to decrypt correctly.
        /// </para>
        /// </remarks>
        /// <param name="encrypted">The ciphertext</param>
        /// <exception cref="ArgumentNullException">if encrypted is null</exception>
        /// <exception cref="ArgumentException">if the scheme is not BFV</exception>
        /// <exception cref="ArgumentException">if encrypted is not valid for the encryption parameters</exception>
        /// <exception cref="ArgumentException">if encrypted is in NTT form</exception>
        /// <exception cref="ArgumentException">if pool is uninitialized</exception>
        public int InvariantNoiseBudget(Ciphertext encrypted)
        {
            if (null == encrypted)
                throw new ArgumentNullException(nameof(encrypted));

            NativeMethods.Decryptor_InvariantNoiseBudget(NativePtr, encrypted.NativePtr, out int result);
            return result;
        }

        /// <summary>
        /// Destroy native object
        /// </summary>
        protected override void DestroyNativeObject()
        {
            NativeMethods.Decryptor_Destroy(NativePtr);
        }
    }
}
