// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

using System;
using System.Collections.Generic;
using System.Linq;

namespace Microsoft.Research.SEAL
{
    /// <summary>
    /// Class to store relinearization keys.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Relinearization
    /// Concretely, a relinearization key corresponding to a power K of the secret
    /// key can be used in the relinearization operation to change a ciphertext of
    /// size K+1 to size K. Recall that the smallest possible size for a ciphertext
    /// is 2, so the first relinearization key is corresponds to the square of the
    /// secret key. The second relinearization key corresponds to the cube of the
    /// secret key, and so on. For example, to relinearize a ciphertext of size 7
    /// back to size 2, one would need 5 relinearization keys, although it is hard
    /// to imagine a situation where it makes sense to have size 7 ciphertexts, as
    /// operating on such objects would be very slow. Most commonly only one
    /// relinearization key is needed, and relinearization is performed after every
    /// multiplication.
    /// </para>
    /// <para>
    /// Thread Safety
    /// In general, reading from RelinKeys is thread-safe as long as no other thread
    /// is concurrently mutating it. This is due to the underlying data structure
    /// storing the relinearization keys not being thread-safe.
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
        public RelinKeys() : base()
        {
        }

        /// <summary>
        /// Creates a new RelinKeys instance by copying a given instance.
        /// </summary>
        /// <param name="copy">The RelinKeys to copy from</param>
        /// <exception cref="ArgumentNullException">if copy is null</exception>
        public RelinKeys(RelinKeys copy)
            : base(copy)
        {
        }

        /// <summary>
        /// Creates a new RelinKeys instance initialized with a pointer to a native
        /// KSwitchKeys object.
        /// </summary>
        /// <param name="kswitchKeys">Pointer to native KSwitchKeys object</param>
        /// <param name="owned">Whether this instance owns the native pointer</param>
        internal RelinKeys(IntPtr kswitchKeys, bool owned = true)
            : base(kswitchKeys, owned)
        {
        }

        /// <summary>
        /// Returns the index of a relinearization key in the backing KSwitchKeys instance
        /// that corresponds to the given secret key power, assuming that it exists in the
        /// backing KSwitchKeys.
        /// </summary>
        /// <param name="keyPower">The power of the secret key</param>
        /// <exception cref="ArgumentException">if keyPower is less than 2</exception>
        public static ulong GetIndex(ulong keyPower)
        {
            NativeMethods.RelinKeys_GetIndex(keyPower, out ulong index);
            return index;
        }

        /// <summary>
        /// Returns whether a relinearization key corresponding to a given Galois key
        /// element exists.
        /// </summary>
        /// <param name="keyPower">The power of the secret key</param>
        /// <exception cref="ArgumentException">if keyPower is less than 2</exception>
        public bool HasKey(ulong keyPower)
        {
            ulong index = GetIndex(keyPower);
            return (ulong)Data.LongCount() > index && 
                Data.ElementAt(checked((int)index)).Count() != 0;
        }

        /// <summary>
        /// Returns a specified relinearization key.
        /// </summary>
        /// <remarks>
        /// Returns a specified relinearization key. The returned relinearization key
        /// corresponds to the given power of the secret key and is valid only as long
        /// as the RelinKeys is valid.
        /// </remarks>
        /// <param name="keyPower">The power of the secret key</param>
        /// <exception cref="ArgumentException">if the key corresponding to keyPower
        /// does not exist</exception>
        public IEnumerable<PublicKey> Key(ulong keyPower)
        {
            return Data.ElementAt(checked((int)GetIndex(keyPower)));
        }
    }
}