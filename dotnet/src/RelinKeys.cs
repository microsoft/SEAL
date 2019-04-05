// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

using Microsoft.Research.SEAL.Tools;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;

namespace Microsoft.Research.SEAL
{
    /// <summary>
    /// Class to store relinearization keys.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Relinearization
    /// Concretely, a relinearization key corresponding to a power K of the secret key can be used
    /// in the relinearization operation to change a ciphertext of size K+1 to size K. Recall
    /// that the smallest possible size for a ciphertext is 2, so the first relinearization key is
    /// corresponds to the square of the secret key. The second relinearization key corresponds to
    /// the cube of the secret key, and so on. For example, to relinearize a ciphertext of size
    /// 7 back to size 2, one would need 5 relinearization keys, although it is hard to imagine
    /// a situation where it makes sense to have size 7 ciphertexts, as operating on such objects
    /// would be very slow. Most commonly only one relinearization key is needed, and relinearization
    /// is performed after every multiplication.
    /// </para>
    /// <para>
    /// Thread Safety
    /// In general, reading from RelinKeys is thread-safe as long as no other thread is
    /// concurrently mutating it. This is due to the underlying data structure storing the
    /// relinearization keys not being thread-safe.
    /// </para>
    /// </remarks>
    /// <see cref="SecretKey">see SecretKey for the class that stores the secret key.</see>
    /// <see cref="PublicKey">see PublicKey for the class that stores the public key.</see>
    /// <see cref="GaloisKeys">see GaloisKeys for the class that stores the Galois keys.</see>
    /// <see cref="KeyGenerator">see KeyGenerator for the class that generates the relinearization keys.</see>
    public class RelinKeys : KSwitchKeys
    {
        /// <summary>
        /// Creates an empty set of relinearization keys.
        /// </summary>
        public RelinKeys()
        {
            NativeMethods.RelinKeys_Create(out IntPtr ptr);
            NativePtr = ptr;
        }

        /// <summary>
        /// Creates a new RelinKeys instance by copying a given instance.
        /// </summary>
        /// <param name="copy">The RelinKeys to copy from</param>
        /// <exception cref="ArgumentNullException">if copy is null</exception>
        public RelinKeys(RelinKeys copy)
        {
            if (null == copy)
                throw new ArgumentNullException(nameof(copy));

            NativeMethods.RelinKeys_Create(copy.NativePtr, out IntPtr ptr);
            NativePtr = ptr;
        }

        /// <summary>
        /// Creates a new RelinKeys instance initialized with a pointer to a
        /// native RelinKeys object
        /// </summary>
        /// <param name="relinKeys">Pointer to native RelinKeys object</param>
        internal RelinKeys(IntPtr relinKeys)
        {
            NativePtr = relinKeys;
        }

        /// <summary>
        /// Copies a given RelinKeys instance to the current one.
        /// </summary>
        /// <param name="copy">The RelinKeys to copy from</param>
        /// <exception cref="ArgumentNullException">if copy is null</exception>
        public void Set(RelinKeys copy)
        {
            if (null == copy)
                throw new ArgumentNullException(nameof(copy));

            NativeMethods.RelinKeys_Set(NativePtr, copy.NativePtr);
        }

        /// <summary>
        /// Returns whether a relinearizaton key corresponding to a given power of the secret key
        /// exists.
        /// </summary>
        ///
        /// <param name="keyPower">The power of the secret key</param>
        public bool HasKey(ulong keyPower)
        {
            NativeMethods.RelinKeys_HasKey(NativePtr, keyPower, out bool hasKey);
            return hasKey;
        }
    }
}
