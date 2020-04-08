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
    /// Slot rotations
    /// Galois keys are certain types of public keys that are needed to perform encrypted
    /// vector rotation operations on batched ciphertexts. Batched ciphertexts encrypt
    /// a 2-by-(N/2) matrix of modular integers in the BFV scheme, or an N/2-dimensional
    /// vector of complex numbers in the CKKS scheme, where N denotes the degree of the
    /// polynomial modulus. In the BFV scheme Galois keys can enable both cyclic rotations
    /// of the encrypted matrix rows, as well as row swaps (column rotations). In the CKKS
    /// scheme Galois keys can enable cyclic vector rotations, as well as a complex
    /// conjugation operation.
    /// </para>
    /// <para>
    /// Thread Safety
    /// In general, reading from GaloisKeys is thread-safe as long as no other thread is
    /// concurrently mutating it. This is due to the underlying data structure storing
    /// the Galois keys not being thread-safe.
    /// </para>
    /// </remarks>
    public class GaloisKeys :
        KSwitchKeys,
        ISettable<GaloisKeys>
    {
        /// <summary>
        /// Creates an empty set of Galois keys.
        /// </summary>
        public GaloisKeys() : base()
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
        /// Copies a given GaloisKeys instance to the current one.
        /// </summary>
        ///
        /// <param name="assign">The GaloisKeys to copy from</param>
        /// <exception cref="ArgumentNullException">if assign is null</exception>
        public void Set(GaloisKeys assign)
        {
            base.Set(assign);
        }

        /// <summary>
        /// Returns the index of a Galois key in the backing KSwitchKeys instance that
        /// corresponds to the given Galois element, assuming that it exists in the
        /// backing KSwitchKeys.
        /// </summary>
        /// <param name="galoisElt">The Galois element</param>
        /// <exception cref="ArgumentException">if Galois element is not valid</exception>
        public static ulong GetIndex(uint galoisElt)
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
        public bool HasKey(uint galoisElt)
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
        /// <exception cref="ArgumentException">if the key corresponding to galoisElt
        /// does not exist</exception>
        public IEnumerable<PublicKey> Key(uint galoisElt)
        {
            return Data.ElementAt(checked((int)GetIndex(galoisElt)));
        }
    }
}
