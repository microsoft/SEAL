// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

using System;
using System.Collections.Generic;
using System.Linq;

namespace Microsoft.Research.SEAL
{
    /// <summary>
    /// Class to store Galois keys.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Slot Rotations
    /// Galois keys are used together with batching (<see cref="BatchEncoder"/>). If the
    /// polynomial modulus is a polynomial of degree N, in batching the idea is to view
    /// a plaintext polynomial as a 2-by-(N/2) matrix of integers modulo plaintext modulus.
    /// Normal homomorphic computations operate on such encrypted matrices element (slot)
    /// wise. However, special rotation operations allow us to also rotate the matrix rows
    /// cyclically in either direction, and rotate the columns (swap the rows). These
    /// operations require the Galois keys.
    /// </para>
    /// <para>
    /// Thread Safety
    /// In general, reading from GaloisKeys is thread-safe as long as no other thread is
    /// concurrently mutating it. This is due to the underlying data structure storing
    /// the Galois keys not being thread-safe.
    /// </para>
    /// </remarks>
    /// <see cref="SecretKey">see SecretKey for the class that stores the secret key.</see>
    /// <see cref="PublicKey">see PublicKey for the class that stores the public key.</see>
    /// <see cref="RelinKeys">see RelinKeys for the class that stores the relinearization keys.</see>
    /// <see cref="KeyGenerator">see KeyGenerator for the class that generates the Galois keys.</see>
    public class GaloisKeys : KSwitchKeys
    {
        /// <summary>
        /// Creates an empty set of Galois keys.
        /// </summary>
        public GaloisKeys() : base()
        {
        }

        /// <summary>
        /// Creates a new GaloisKeys instance initialized with a pointer to a native
        /// KSwitchKeys object.
        /// </summary>
        /// <param name="kswitchKeys">Pointer to native KSwitchKeys object</param>
        /// <param name="owned">Whether this instance owns the native pointer</param>
        internal GaloisKeys(IntPtr kswitchKeys, bool owned = true)
            : base(kswitchKeys, owned)
        {
        }

        /// <summary>
        /// Creates a new GaloisKeys instance by copying a given instance.
        /// </summary>
        /// <param name="copy">The GaloisKeys to copy from</param>
        /// <exception cref="ArgumentNullException">if copy is null</exception>
        public GaloisKeys(GaloisKeys copy)
            : base(copy)
        {
        }

        /// <summary>
        /// Returns the index of a Galois key in the backing KSwitchKeys instance that
        /// corresponds to the given Galois element, assuming that it exists in the
        /// backing KSwitchKeys.
        /// </summary>
        /// <param name="galoisElt">The Galois element</param>
        /// <exception cref="ArgumentException">if Galois element is not valid</exception>
        public static ulong GetIndex(ulong galoisElt)
        {
            NativeMethods.GaloisKeys_GetIndex(galoisElt, out ulong index);
            return index;
        }

        /// <summary>
        /// Returns whether a Galois key corresponding to a given Galois key element
        /// exists.
        /// </summary>
        /// <param name="galoisElt">The Galois element</param>
        /// <exception cref="ArgumentException">if Galois element is not valid</exception>
        public bool HasKey(ulong galoisElt)
        {
            ulong index = GetIndex(galoisElt);
            return (ulong)Data.LongCount() > index &&
                Data.ElementAt(checked((int)index)).Count() != 0;
        }

        /// <summary>
        /// Returns a specified Galois key.
        /// </summary>
        /// <remarks>
        /// Returns a specified Galois key. The returned Galois key corresponds to the
        /// given Galois element and is valid only as long as the GaloisKeys is valid.
        /// </remarks>
        /// <param name="galoisElt">The Galois element</param>
        /// <exception cref="ArgumentException">if the key corresponding to galoisElt does
        /// not exist</exception>
        public IEnumerable<PublicKey> Key(ulong galoisElt)
        {
            return Data.ElementAt(checked((int)GetIndex(galoisElt)));
        }
    }
}