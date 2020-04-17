// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

using Microsoft.Research.SEAL.Tools;
using System;
using System.Collections.Generic;
using System.Linq;

namespace Microsoft.Research.SEAL
{
    /// <summary>
    /// Generates matching secret key and public key.
    /// </summary>
    /// <remarks>
    /// Generates matching secret key and public key. An existing KeyGenerator can
    /// also at any time be used to generate relinearization keys and Galois keys.
    /// Constructing a KeyGenerator requires only a SEALContext.
    /// </remarks>
    public class KeyGenerator : NativeObject
    {
        /// <summary>
        /// Creates a KeyGenerator initialized with the specified SEALContext.
        /// </summary>
        /// <remarks>
        /// Creates a KeyGenerator initialized with the specified <see cref="SEALContext" />.
        /// Dynamically allocated member variables are allocated from the global memory pool.
        /// </remarks>
        /// <param name="context">The SEALContext</param>
        /// <exception cref="ArgumentException">if encryption parameters are not
        /// valid</exception>
        /// <exception cref="ArgumentNullException">if context is null</exception>
        public KeyGenerator(SEALContext context)
        {
            if (null == context)
                throw new ArgumentNullException(nameof(context));
            if (!context.ParametersSet)
                throw new ArgumentException("Encryption parameters are not set correctly");

            NativeMethods.KeyGenerator_Create(context.NativePtr, out IntPtr ptr);
            NativePtr = ptr;
        }

        /// <summary>
        /// Creates an KeyGenerator instance initialized with the specified
        /// SEALContext and specified previously secret key.
        /// </summary>
        /// <remarks>
        /// Creates an KeyGenerator instance initialized with the specified
        /// SEALContext and specified previously secret key. This can e.g. be used
        /// to increase the number of relinearization keys from what had earlier
        /// been generated, or to generate Galois keys in case they had not been
        /// generated earlier.
        /// </remarks>
        /// <param name="context">The SEALContext</param>
        /// <param name="secretKey">A previously generated secret key</param>
        /// <exception cref="ArgumentNullException">if either context or secretKey
        /// are null</exception>
        /// <exception cref="ArgumentException">if encryption parameters are not
        /// valid</exception>
        /// <exception cref="ArgumentException">if secretKey or publicKey is not
        /// valid for encryption parameters</exception>
        public KeyGenerator(SEALContext context, SecretKey secretKey)
        {
            if (null == context)
                throw new ArgumentNullException(nameof(context));
            if (null == secretKey)
                throw new ArgumentNullException(nameof(secretKey));
            if (!context.ParametersSet)
                throw new ArgumentException("Encryption parameters are not set correctly");
            if (!ValCheck.IsValidFor(secretKey, context))
                throw new ArgumentException("Secret key is not valid for encryption parameters");

            NativeMethods.KeyGenerator_Create(context.NativePtr,
                secretKey.NativePtr, out IntPtr ptr);
            NativePtr = ptr;
        }

        /// <summary>
        /// Generates and returns a public key. Every time this function is called,
        /// a new public key will be generated.
        /// </summary>
        public PublicKey PublicKey
        {
            get
            {
                NativeMethods.KeyGenerator_PublicKey(NativePtr, out IntPtr pubKeyPtr);
                PublicKey pubKey = new PublicKey(pubKeyPtr);
                return pubKey;
            }
        }

        /// <summary>
        /// Returns a copy of the secret key.
        /// </summary>
        public SecretKey SecretKey
        {
            get
            {
                NativeMethods.KeyGenerator_SecretKey(NativePtr, out IntPtr secretKeyPtr);
                SecretKey secretKey = new SecretKey(secretKeyPtr);
                return secretKey;
            }
        }

        /// <summary>
        /// Generates and returns relinearization keys.
        /// </summary>
        /// <remarks>
        /// Generates and returns relinearization keys. This function returns
        /// relinearization keys in a fully expanded form and is meant to be used
        /// primarily for demo, testing, and debugging purposes.
        /// </remarks>
        /// <exception cref="InvalidOperationException">if the encryption
        /// parameters do not support keyswitching</exception>
        public RelinKeys RelinKeysLocal()
        {
            if (!UsingKeyswitching())
                throw new InvalidOperationException("Encryption parameters do not support keyswitching");

            NativeMethods.KeyGenerator_RelinKeys(NativePtr, false, out IntPtr relinKeysPtr);
            return new RelinKeys(relinKeysPtr);
        }

        /// <summary>
        /// Generates and returns relinearization keys as a serializable object.
        /// </summary>
        /// <remarks>
        /// <para>
        /// Generates and returns relinearization keys as a serializable object.
        /// </para>
        /// <para>
        /// Half of the key data is pseudo-randomly generated from a seed to reduce
        /// the object size. The resulting serializable object cannot be used
        /// directly and is meant to be serialized for the size reduction to have an
        /// impact.
        /// </para>
        /// </remarks>
        /// <exception cref="InvalidOperationException">if the encryption
        /// parameters do not support keyswitching</exception>
        public Serializable<RelinKeys> RelinKeys()
        {
            if (!UsingKeyswitching())
                throw new InvalidOperationException("Encryption parameters do not support keyswitching");

            NativeMethods.KeyGenerator_RelinKeys(NativePtr, true, out IntPtr relinKeysPtr);
            RelinKeys relinKeys = new RelinKeys(relinKeysPtr);
            return new Serializable<RelinKeys>(relinKeys);
        }

        /// <summary>
        /// Generates and returns Galois keys.
        /// </summary>
        /// <remarks>
        /// <para>
        /// Generates and returns Galois keys. This function returns Galois keys in
        /// a fully expanded form and is meant to be used primarily for demo, testing,
        /// and debugging purposes. This function creates specific Galois keys that
        /// can be used to apply specific Galois automorphisms on encrypted data. The
        /// user needs to give as input a vector of Galois elements corresponding to
        /// the keys that are to be created.
        /// </para>
        /// <para>
        /// The Galois elements are odd integers in the interval [1, M-1], where
        /// M = 2*N, and N = PolyModulusDegree. Used with batching, a Galois element
        /// 3^i % M corresponds to a cyclic row rotation i steps to the left, and
        /// a Galois element 3^(N/2-i) % M corresponds to a cyclic row rotation i
        /// steps to the right. The Galois element M-1 corresponds to a column rotation
        /// (row swap). In the polynomial view (not batching), a Galois automorphism by
        /// a Galois element p changes Enc(plain(x)) to Enc(plain(x^p)).
        /// </para>
        /// </remarks>
        /// <param name="galoisElts">The Galois elements for which to generate keys</param>
        /// <exception cref="InvalidOperationException">if the encryption parameters
        /// do not support batching and scheme is SchemeType.BFV</exception>
        /// <exception cref="InvalidOperationException">if the encryption
        /// parameters do not support keyswitching</exception>
        /// <exception cref="ArgumentException">if the Galois elements are not valid</exception>
        public GaloisKeys GaloisKeysLocal(IEnumerable<uint> galoisElts)
        {
            if (null == galoisElts)
                throw new ArgumentNullException(nameof(galoisElts));
            if (!UsingKeyswitching())
                throw new InvalidOperationException("Encryption parameters do not support keyswitching");

            uint[] galoisEltsArr = galoisElts.ToArray();
            NativeMethods.KeyGenerator_GaloisKeysFromElts(NativePtr,
                (ulong)galoisEltsArr.Length, galoisEltsArr, false, out IntPtr galoisKeysPtr);
            return new GaloisKeys(galoisKeysPtr);
        }

        /// <summary>
        /// Generates and returns Galois keys as a serializable object.
        /// </summary>
        /// <remarks>
        /// <para>
        /// Generates and returns Galois keys as a serializable object. This function
        /// creates specific Galois keys that can be used to apply specific Galois
        /// automorphisms on encrypted data. The user needs to give as input a vector
        /// of Galois elements corresponding to the keys that are to be created.
        /// </para>
        /// <para>
        /// The Galois elements are odd integers in the interval [1, M-1], where
        /// M = 2*N, and N = PolyModulusDegree. Used with batching, a Galois element
        /// 3^i % M corresponds to a cyclic row rotation i steps to the left, and
        /// a Galois element 3^(N/2-i) % M corresponds to a cyclic row rotation i
        /// steps to the right. The Galois element M-1 corresponds to a column rotation
        /// (row swap). In the polynomial view (not batching), a Galois automorphism by
        /// a Galois element p changes Enc(plain(x)) to Enc(plain(x^p)).
        /// </para>
        /// <para>
        /// Half of the key data is pseudo-randomly generated from a seed to reduce
        /// the object size. The resulting serializable object cannot be used
        /// directly and is meant to be serialized for the size reduction to have an
        /// impact.
        /// </para>
        /// </remarks>
        /// <param name="galoisElts">The Galois elements for which to generate keys</param>
        /// <exception cref="ArgumentNullException">if galoisElts is null</exception>
        /// <exception cref="InvalidOperationException">if the encryption parameters
        /// do not support batching and scheme is SchemeType.BFV</exception>
        /// <exception cref="InvalidOperationException">if the encryption
        /// parameters do not support keyswitching</exception>
        /// <exception cref="ArgumentException">if the Galois elements are not valid</exception>
        public Serializable<GaloisKeys> GaloisKeys(IEnumerable<uint> galoisElts)
        {
            if (null == galoisElts)
                throw new ArgumentNullException(nameof(galoisElts));
            if (!UsingKeyswitching())
                throw new InvalidOperationException("Encryption parameters do not support keyswitching");

            uint[] galoisEltsArr = galoisElts.ToArray();
            NativeMethods.KeyGenerator_GaloisKeysFromElts(NativePtr,
                (ulong)galoisEltsArr.Length, galoisEltsArr, true, out IntPtr galoisKeysPtr);
            GaloisKeys galoisKeys = new GaloisKeys(galoisKeysPtr);
            return new Serializable<GaloisKeys>(galoisKeys);
        }

        /// <summary>
        /// Generates and returns Galois keys.
        /// </summary>
        /// <remarks>
        /// Generates and returns Galois keys. This function returns Galois keys in
        /// a fully expanded form and is meant to be used primarily for demo, testing,
        /// and debugging purposes. The user needs to give as input a vector of desired
        /// Galois rotation step counts, where negative step counts correspond to
        /// rotations to the right and positive step counts correspond to rotations to
        /// the left. A step count of zero can be used to indicate a column rotation
        /// in the BFV scheme complex conjugation in the CKKS scheme.
        /// </remarks>
        /// <param name="steps">The rotation step counts for which to generate keys</param>
        /// <exception cref="ArgumentNullException">if steps is null</exception>
        /// <exception cref="InvalidOperationException">if the encryption parameters
        /// do not support batching and scheme is SchemeType.BFV</exception>
        /// <exception cref="InvalidOperationException">if the encryption
        /// parameters do not support keyswitching</exception>
        /// <exception cref="ArgumentException">if the step counts are not valid</exception>
        public GaloisKeys GaloisKeysLocal(IEnumerable<int> steps)
        {
            if (null == steps)
                throw new ArgumentNullException(nameof(steps));
            if (!UsingKeyswitching())
                throw new InvalidOperationException("Encryption parameters do not support keyswitching");

            int[] stepsArr = steps.ToArray();
            NativeMethods.KeyGenerator_GaloisKeysFromSteps(NativePtr,
                (ulong)stepsArr.Length, stepsArr, false, out IntPtr galoisKeysPtr);
            return new GaloisKeys(galoisKeysPtr);
        }

        /// <summary>
        /// Generates and returns Galois keys as a serializable object.
        /// </summary>
        /// <remarks>
        /// <para>
        /// Generates and returns Galois keys as a serializable object. This function
        /// creates specific Galois keys that can be used to apply specific Galois
        /// automorphisms on encrypted data. The user needs to give as input a vector
        /// of desired Galois rotation step counts, where negative step counts
        /// correspond to rotations to the right and positive step counts correspond
        /// to rotations to the left. A step count of zero can be used to indicate
        /// a column rotation in the BFV scheme complex conjugation in the CKKS scheme.
        /// </para>
        /// <para>
        /// Half of the key data is pseudo-randomly generated from a seed to reduce
        /// the object size. The resulting serializable object cannot be used
        /// directly and is meant to be serialized for the size reduction to have an
        /// impact.
        /// </para>
        /// </remarks>
        /// <param name="steps">The rotation step counts for which to generate keys</param>
        /// <exception cref="ArgumentNullException">if steps is null</exception>
        /// <exception cref="InvalidOperationException">if the encryption parameters
        /// do not support batching and scheme is SchemeType.BFV</exception>
        /// <exception cref="InvalidOperationException">if the encryption
        /// parameters do not support keyswitching</exception>
        /// <exception cref="ArgumentException">if the step counts are not valid</exception>
        public Serializable<GaloisKeys> GaloisKeys(IEnumerable<int> steps)
        {
            if (null == steps)
                throw new ArgumentNullException(nameof(steps));
            if (!UsingKeyswitching())
                throw new InvalidOperationException("Encryption parameters do not support keyswitching");

            int[] stepsArr = steps.ToArray();
            NativeMethods.KeyGenerator_GaloisKeysFromSteps(NativePtr,
                (ulong)stepsArr.Length, stepsArr, true, out IntPtr galoisKeysPtr);
            GaloisKeys galoisKeys = new GaloisKeys(galoisKeysPtr);
            return new Serializable<GaloisKeys>(galoisKeys);
        }

        /// <summary>
        /// Generates and returns Galois keys.
        /// </summary>
        /// <remarks>
        /// Generates and returns Galois keys. This function returns Galois keys in
        /// a fully expanded form and is meant to be used primarily for demo, testing,
        /// and debugging purposes. This function creates logarithmically many (in
        /// degree of the polynomial modulus) Galois keys that is sufficient to apply
        /// any Galois automorphism (e.g. rotations) on encrypted data. Most users
        /// will want to use this overload of the function.
        /// </remarks>
        /// <exception cref="InvalidOperationException">if the encryption parameters
        /// do not support batching and scheme is SchemeType.BFV</exception>
        /// <exception cref="InvalidOperationException">if the encryption
        /// parameters do not support keyswitching</exception>
        public GaloisKeys GaloisKeysLocal()
        {
            if (!UsingKeyswitching())
                throw new InvalidOperationException("Encryption parameters do not support keyswitching");

            NativeMethods.KeyGenerator_GaloisKeysAll(NativePtr, false, out IntPtr galoisKeysPtr);
            return new GaloisKeys(galoisKeysPtr);
        }

        /// <summary>
        /// Generates and returns Galois keys as a serializable object.
        /// </summary>
        /// <remarks>
        /// <para>
        /// Generates and returns Galois keys as a serializable object. This function
        /// creates logarithmically many (in degree of the polynomial modulus) Galois
        /// keys that is sufficient to apply any Galois automorphism (e.g. rotations)
        /// on encrypted data. Most users will want to use this overload of the function.
        /// </para>
        /// <para>
        /// Half of the key data is pseudo-randomly generated from a seed to reduce
        /// the object size. The resulting serializable object cannot be used
        /// directly and is meant to be serialized for the size reduction to have an
        /// impact.
        /// </para>
        /// </remarks>
        /// <exception cref="InvalidOperationException">if the encryption parameters
        /// do not support batching and scheme is SchemeType.BFV</exception>
        /// <exception cref="InvalidOperationException">if the encryption
        /// parameters do not support keyswitching</exception>
        public Serializable<GaloisKeys> GaloisKeys()
        {
            if (!UsingKeyswitching())
                throw new InvalidOperationException("Encryption parameters do not support keyswitching");

            NativeMethods.KeyGenerator_GaloisKeysAll(NativePtr, true, out IntPtr galoisKeysPtr);
            GaloisKeys galoisKeys = new GaloisKeys(galoisKeysPtr);
            return new Serializable<GaloisKeys>(galoisKeys);
        }

        /// <summary>
        /// Destroy native object.
        /// </summary>
        protected override void DestroyNativeObject()
        {
            NativeMethods.KeyGenerator_Destroy(NativePtr);
        }

        internal bool UsingKeyswitching()
        {
            NativeMethods.KeyGenerator_ContextUsingKeyswitching(NativePtr, out bool result);
            return result;
        }
    }
}
