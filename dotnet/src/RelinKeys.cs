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
    /// Freshly encrypted ciphertexts have a size of 2, and multiplying ciphertexts
    /// of sizes K and L results in a ciphertext of size K+L-1. Unfortunately, this
    /// growth in size slows down further multiplications and increases noise growth.
    /// Relinearization is an operation that has no semantic meaning, but it reduces
    /// the size of ciphertexts back to 2. Microsoft SEAL can only relinearize size 3
    /// ciphertexts back to size 2, so if the ciphertexts grow larger than size 3,
    /// there is no way to reduce their size. Relinearization requires an instance of
    /// RelinKeys to be created by the secret key owner and to be shared with the
    /// evaluator. Note that plain multiplication is fundamentally different from
    /// normal multiplication and does not result in ciphertext size growth.
    /// </para>
    /// <para>
    /// When to Relinearize
    /// Typically, one should always relinearize after each multiplications. However,
    /// in some cases relinearization should be postponed as late as possible due to
    /// its computational cost.For example, suppose the computation involves several
    /// homomorphic multiplications followed by a sum of the results. In this case it
    /// makes sense to not relinearize each product, but instead add them first and
    /// only then relinearize the sum. This is particularly important when using the
    /// CKKS scheme, where relinearization is much more computationally costly than
    /// multiplications and additions.
    /// </para>
    /// <para>
    /// Thread Safety
    /// In general, reading from RelinKeys is thread-safe as long as no other thread
    /// is concurrently mutating it. This is due to the underlying data structure
    /// storing the relinearization keys not being thread-safe.
    /// </para>
    /// </remarks>
    public class RelinKeys :
        KSwitchKeys,
        ISerializableObject,
        ISettable<RelinKeys>
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
        /// Copies a given RelinKeys instance to the current one.
        /// </summary>
        ///
        /// <param name="assign">The RelinKeys to copy from</param>
        /// <exception cref="ArgumentNullException">if assign is null</exception>
        public void Set(RelinKeys assign)
        {
            base.Set(assign);
        }

        /// <summary>
        /// Returns the index of a relinearization key in the backing KSwitchKeys
        /// instance that corresponds to the given secret key power, assuming that
        /// it exists in the backing KSwitchKeys.
        /// </summary>
        /// <param name="keyPower">The power of the secret key</param>
        /// <exception cref="ArgumentException">if keyPower is less than 2</exception>
        public static ulong GetIndex(ulong keyPower)
        {
            NativeMethods.RelinKeys_GetIndex(keyPower, out ulong index);
            return index;
        }

        /// <summary>
        /// Returns whether a relinearization key corresponding to a given secret
        /// key power exists.
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
        /// Returns a specified relinearization key. The returned relinearization
        /// key corresponds to the given power of the secret key and is valid only
        /// as long as the RelinKeys is valid.
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
