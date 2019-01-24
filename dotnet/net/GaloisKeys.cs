// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

using Microsoft.Research.SEAL.Tools;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;

namespace Microsoft.Research.SEAL
{
    /// <summary>
    /// Class to store Galois keys.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Slot Rotations
    /// Galois keys are used together with batching (<see cref="BatchEncoder"/>). If the polynomial modulus
    /// is a polynomial of degree N, in batching the idea is to view a plaintext polynomial as
    /// a 2-by-(N/2) matrix of integers modulo plaintext modulus. Normal homomorphic computations
    /// operate on such encrypted matrices element (slot) wise. However, special rotation
    /// operations allow us to also rotate the matrix rows cyclically in either direction, and 
    /// rotate the columns (swap the rows). These operations require the Galois keys.
    /// </para>
    /// <para>
    /// Decomposition Bit Count
    /// Decomposition bit count (dbc) is a parameter that describes a performance trade-off in
    /// the rotation operation. Its function is exactly the same as in relinearization. Namely, 
    /// the polynomials in the ciphertexts (with large coefficients) get decomposed into a smaller
    /// base 2^dbc, coefficient-wise. Each of the decomposition factors corresponds to a piece of 
    /// data in the Galois keys, so the smaller the dbc is, the larger the Galois keys are. 
    /// Moreover, a smaller dbc results in less invariant noise budget being consumed in the
    /// rotation operation. However, using a large dbc is much faster, and often one would want 
    /// to optimize the dbc to be as large as possible for performance. The dbc is upper-bounded 
    /// by the value of 60, and lower-bounded by the value of 1.
    /// </para>
    /// <para>
    /// Thread Safety
    /// In general, reading from GaloisKeys is thread-safe as long as no other thread is 
    /// concurrently mutating it. This is due to the underlying data structure storing the
    /// Galois keys not being thread-safe.
    /// </para>
    /// </remarks>
    /// <see cref="SecretKey">see SecretKey for the class that stores the secret key.</see>
    /// <see cref="PublicKey">see PublicKey for the class that stores the public key.</see>
    /// <see cref="RelinKeys">see RelinKeys for the class that stores the relinearization keys.</see>
    /// <see cref="KeyGenerator">see KeyGenerator for the class that generates the Galois keys.</see>
    public class GaloisKeys : NativeObject
    {
        /// <summary>
        /// Creates an empty set of Galois keys.
        /// </summary>
        public GaloisKeys()
        {
            NativeMethods.GaloisKeys_Create(out IntPtr ptr);
            NativePtr = ptr;
        }

        /// <summary>
        /// Creates a new GaloisKeys instance by copying a given instance.
        /// </summary>
        /// <param name="copy">The GaloisKeys to copy from</param>
        /// <exception cref="ArgumentNullException">if copy is null</exception>
        public GaloisKeys(GaloisKeys copy)
        {
            if (null == copy)
                throw new ArgumentNullException(nameof(copy));

            NativeMethods.GaloisKeys_Create(copy.NativePtr, out IntPtr ptr);
            NativePtr = ptr;
        }

        /// <summary>
        /// Creates a new GaloisKeys instance initialized with a pointer to a
        /// native GaloisKeys object.
        /// </summary>
        /// <param name="galoisKeys">Pointer to native GaloisKeys object</param>
        /// <param name="owned">Whether this instance owns the native pointer</param>
        internal GaloisKeys(IntPtr galoisKeys, bool owned = true)
            : base(galoisKeys, owned)
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
            if (null == assign)
                throw new ArgumentNullException(nameof(assign));

            NativeMethods.GaloisKeys_Set(NativePtr, assign.NativePtr);
        }

        /// <summary>
        /// Returns the current number of Galois keys.
        /// </summary>
        public ulong Size
        {
            get
            {
                NativeMethods.GaloisKeys_Size(NativePtr, out ulong size);
                return size;
            }
        }

        /// <summary>
        /// Returns the decomposition bit count.
        /// </summary>
        public int DecompositionBitCount
        {
            get
            {
                NativeMethods.GaloisKeys_DBC(NativePtr, out int dbc);
                return dbc;
            }
            private set
            {
                NativeMethods.GaloisKeys_SetDBC(NativePtr, value);
            }
        }

        /// <summary>
        /// Returns a copy of the Galois keys data.
        /// </summary>
        public IEnumerable<IEnumerable<Ciphertext>> Data
        {
            get
            {
                List<List<Ciphertext>> result = new List<List<Ciphertext>>();
                NativeMethods.GaloisKeys_GetKeyCount(NativePtr, out ulong size);

                for (ulong i = 0; i < size; i++)
                {
                    ulong count = 0;
                    NativeMethods.GaloisKeys_GetKeyList(NativePtr, i, ref count, null);

                    IntPtr[] pointers = new IntPtr[count];
                    NativeMethods.GaloisKeys_GetKeyList(NativePtr, i, ref count, pointers);

                    List<Ciphertext> ciphers = new List<Ciphertext>((int)count);
                    foreach(IntPtr ptr in pointers)
                    {
                        ciphers.Add(new Ciphertext(ptr));
                    }

                    result.Add(ciphers);
                }

                return result;
            }
        }

        /// <summary>
        /// Returns a copy of a Galois key.
        /// </summary>
        /// 
        /// <remarks>
        /// Returns a copy of a Galois key. The returned Galois key corresponds to the given 
        /// Galois element.
        /// </remarks>
        /// <param name="galoisElt">The Galois element</param>
        /// <exception cref="ArgumentException">if the key corresponding to galoisElt does 
        /// not exist</exception>
        public IEnumerable<Ciphertext> Key(ulong galoisElt)
        {
            ulong count = 0;
            NativeMethods.GaloisKeys_GetKey(NativePtr, galoisElt, ref count, null);

            IntPtr[] ciphers = new IntPtr[count];
            NativeMethods.GaloisKeys_GetKey(NativePtr, galoisElt, ref count, ciphers);

            List<Ciphertext> result = new List<Ciphertext>((int)count);
            foreach (IntPtr ptr in ciphers)
            {
                result.Add(new Ciphertext(ptr));
            }

            return result;
        }

        /// <summary>
        /// Returns whether a Galois key corresponding to a given Galois key element
        /// exists.
        /// </summary>
        /// 
        /// <param name="galoisElt">The Galois element</param>
        /// <exception cref="ArgumentException">if Galois element is not valid</exception>
        public bool HasKey(ulong galoisElt)
        {
            NativeMethods.GaloisKeys_HasKey(NativePtr, galoisElt, out bool hasKey);
            return hasKey;
        }

        /// <summary>
        /// Returns a reference to parmsId.
        /// </summary>
        /// <see cref="EncryptionParameters">see EncryptionParameters for more information about parmsId.</see>
        public ParmsId ParmsId
        {
            get
            {
                ParmsId parms = new ParmsId();
                NativeMethods.GaloisKeys_GetParmsId(NativePtr, parms.Block);
                return parms;
            }
            private set
            {
                NativeMethods.GaloisKeys_SetParmsId(NativePtr, value.Block);
            }
        }

        /// <summary>
        /// Check whether the current GaloisKeys is valid for a given SEALContext. If 
        /// the given SEALContext is not set, the encryption parameters are invalid, 
        /// or the GaloisKeys data does not match the SEALContext, this function returns 
        /// false. Otherwise, returns true.
        /// </summary>
        /// <param name="context">The SEALContext</param>
        /// <exception cref="ArgumentNullException">if context is null</exception>
        public bool IsValidFor(SEALContext context)
        {
            if (null == context)
                throw new ArgumentNullException(nameof(context));

            NativeMethods.GaloisKeys_IsValidFor(NativePtr, context.NativePtr, out bool result);
            return result;
        }

        /// <summary>
        /// Check whether the current GaloisKeys is valid for a given SEALContext.If
        /// the given SEALContext is not set, the encryption parameters are invalid,
        /// or the GaloisKeys data does not match the SEALContext, this function returns 
        /// false. Otherwise, returns true. This function only checks the metadata
        /// and not the Galois key data itself.
        /// </summary>
        /// <param name="context">The SEALContext</param>
        /// <exception cref="ArgumentNullException">if context is null</exception>
        public bool IsMetadataValidFor(SEALContext context)
        {
            if (null == context)
                throw new ArgumentNullException(nameof(context));

            NativeMethods.GaloisKeys_IsMetadataValidFor(NativePtr, context.NativePtr, out bool result);
            return result;
        }

        /// <summary>
        /// Saves the GaloisKeys instance to an output stream.
        /// </summary>
        /// 
        /// <remarks>
        /// Saves the GaloisKeys instance to an output stream. The output is in binary format 
        /// and not human-readable. The output stream must have the "binary" flag set.
        /// </remarks>
        /// <param name="stream">The stream to save the GaloisKeys to</param>
        /// <exception cref="ArgumentNullException">if stream is null</exception>
        /// <seealso cref="Load(SEALContext, Stream)">See Load() to load a saved GaloisKeys instance.</seealso>
        public void Save(Stream stream)
        {
            if (null == stream)
                throw new ArgumentNullException(nameof(stream));

            using (BinaryWriter writer = new BinaryWriter(stream, Encoding.UTF8, leaveOpen: true))
            {
                // Save the ParmsId
                ParmsId.Save(writer.BaseStream);

                // Save the Decomposition Bit Count
                writer.Write(DecompositionBitCount);

                // Save the size of Keys
                IEnumerable<IEnumerable<Ciphertext>> data = Data;
                writer.Write((ulong)data.LongCount());

                // Loop over entries in the first list
                foreach (IEnumerable<Ciphertext> keyList in data)
                {
                    writer.Write((ulong)keyList.LongCount());

                    // Loop over ciphertexts and save all
                    foreach(Ciphertext cipher in keyList)
                    {
                        cipher.Save(writer.BaseStream);
                    }
                }
            }
        }

        /// <summary>
        /// Loads a GaloisKeys from an input stream overwriting the current GaloisKeys.
        /// No checking of the validity of the GaloisKeys data against encryption
        /// parameters is performed. This function should not be used unless the 
        /// GaloisKeys comes from a fully trusted source.
        /// </summary>
        /// <param name="stream">The stream to load the GaloisKeys from</param>
        /// <exception cref="ArgumentNullException">if stream is null</exception>
        /// <exception cref="ArgumentException">if a valid GaloisKeys could not be read from stream</exception>
        public void UnsafeLoad(Stream stream)
        {
            if (null == stream)
                throw new ArgumentNullException(nameof(stream));

            try
            {
                // Read the ParmsId
                ParmsId parmsId = new ParmsId();
                parmsId.Load(stream);
                ParmsId = parmsId;

                using (BinaryReader reader = new BinaryReader(stream, Encoding.UTF8, leaveOpen: true))
                {
                    // Read the decomposition bit count
                    int dbc = reader.ReadInt32();
                    DecompositionBitCount = dbc;

                    // Read the size
                    ulong size = reader.ReadUInt64();

                    // Clear current data and reserve new size
                    NativeMethods.GaloisKeys_ClearDataAndReserve(NativePtr, size);

                    // Read all lists
                    for (ulong i = 0; i < size; i++)
                    {
                        // Read size of second list
                        ulong keySize = reader.ReadUInt64();
                        List<Ciphertext> ciphers = new List<Ciphertext>((int)keySize);

                        // Load all ciphertexts
                        for (ulong j = 0; j < keySize; j++)
                        {
                            Ciphertext cipher = new Ciphertext();
                            cipher.UnsafeLoad(reader.BaseStream);
                            ciphers.Add(cipher);
                        }

                        IntPtr[] pointers = ciphers.Select(c =>
                        {
                            return c.NativePtr;
                        }).ToArray();

                        NativeMethods.GaloisKeys_AddKeyList(NativePtr, (ulong)pointers.LongLength, pointers);
                    }
                }
            }
            catch (EndOfStreamException ex)
            {
                throw new ArgumentException("Stream ended unexpectedly", ex);
            }
            catch (IOException ex)
            {
                throw new ArgumentException("Error reading keys", ex);
            }
        }

        /// <summary>
        /// Loads a GaloisKeys from an input stream overwriting the current GaloisKeys.
        /// The loaded GaloisKeys is verified to be valid for the given SEALContext.
        /// </summary>
        /// 
        /// <param name="context">The SEALContext</param>
        /// <param name="stream">The stream to load the GaloisKeys instance from</param>
        /// <exception cref="ArgumentNullException">if either stream or context are null</exception>
        /// <exception cref="ArgumentException">if the context is not set or encryption
        /// parameters are not valid</exception>
        /// <exception cref="ArgumentException">if the loaded data is invalid or is not
        /// valid for the context</exception>
        /// <seealso cref="Save(Stream)">See Save() to save an GaloisKeys instance.</seealso>
        public void Load(SEALContext context, Stream stream)
        {
            if (null == context)
                throw new ArgumentNullException(nameof(context));
            if (null == stream)
                throw new ArgumentNullException(nameof(stream));

            UnsafeLoad(stream);

            if (!IsValidFor(context))
            {
                throw new ArgumentException("GaloisKeys data is invalid for the context");
            }
        }

        /// <summary>
        /// Returns the currently used MemoryPoolHandle.
        /// </summary>
        public MemoryPoolHandle Pool
        {
            get
            {
                NativeMethods.GaloisKeys_Pool(NativePtr, out IntPtr pool);
                MemoryPoolHandle handle = new MemoryPoolHandle(pool);
                return handle;
            }
        }

        /// <summary>
        /// Destroy native object.
        /// </summary>
        protected override void DestroyNativeObject()
        {
            NativeMethods.GaloisKeys_Destroy(NativePtr);
        }
    }
}
