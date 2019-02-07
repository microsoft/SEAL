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
    /// Concretely, an relinearization key corresponding to a power K of the secret key can be used
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
    /// Decomposition Bit Count
    /// Decomposition bit count (dbc) is a parameter that describes a performance trade-off in
    /// the relinearization process. Namely, in the relinearization process the polynomials in 
    /// the ciphertexts (with large coefficients) get decomposed into a smaller base 2^dbc,
    /// coefficient-wise. Each of the decomposition factors corresponds to a piece of data in
    /// the relinearization key, so the smaller the dbc is, the larger the relinearization keys are.
    /// Moreover, a smaller dbc results in less invariant noise budget being consumed in the
    /// relinearization process. However, using a large dbc is much faster, and often one 
    /// would want to optimize the dbc to be as large as possible for performance. The dbc is 
    /// upper-bounded by the value of 60, and lower-bounded by the value of 1.
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
    public class RelinKeys : NativeObject
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
        /// Returns the current number of evaluation keys.
        /// </summary>
        public ulong Size
        {
            get
            {
                NativeMethods.RelinKeys_Size(NativePtr, out ulong size);
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
                NativeMethods.RelinKeys_DBC(NativePtr, out int dbc);
                return dbc;
            }
            private set
            {
                NativeMethods.RelinKeys_SetDBC(NativePtr, value);
            }
        }

        /// <summary>
        /// Returns a copy of the relinearization keys data.
        /// </summary>
        public IEnumerable<IEnumerable<Ciphertext>> Data
        {
            get
            {
                List<List<Ciphertext>> result = new List<List<Ciphertext>>();
                ulong size = Size;

                for (ulong i = 0; i < size; i++)
                {
                    ulong count = 0;
                    NativeMethods.RelinKeys_GetKeyList(NativePtr, i, ref count, null);

                    IntPtr[] pointers = new IntPtr[count];
                    NativeMethods.RelinKeys_GetKeyList(NativePtr, i, ref count, pointers);

                    List<Ciphertext> ciphers = new List<Ciphertext>((int)count);
                    foreach (IntPtr ptr in pointers)
                    {
                        ciphers.Add(new Ciphertext(ptr));
                    }

                    result.Add(ciphers);
                }

                return result;
            }
        }

        /// <summary>
        /// Returns a copy of an evaluation key.
        /// </summary>
        /// 
        /// <remarks>
        /// Returns a copy of a relinearization key. The returned evaluation key corresponds to the 
        /// given power of the secret key.
        /// </remarks>
        /// <param name="keyPower">The power of the secret key</param>
        /// <exception cref="ArgumentOutOfRangeException">if the key corresponding to keyPower does not 
        /// exist</exception>
        public IEnumerable<Ciphertext> Key(ulong keyPower)
        {
            try
            {
                ulong count = 0;
                NativeMethods.RelinKeys_GetKey(NativePtr, keyPower, ref count, null);

                IntPtr[] ciphers = new IntPtr[count];
                NativeMethods.RelinKeys_GetKey(NativePtr, keyPower, ref count, ciphers);

                List<Ciphertext> result = new List<Ciphertext>((int)count);
                foreach(IntPtr cipherptr in ciphers)
                {
                    result.Add(new Ciphertext(cipherptr));
                }

                return result;
            }
            catch (COMException ex)
            {
                if ((uint)ex.HResult == NativeMethods.Errors.HRInvalidIndex)
                    throw new ArgumentOutOfRangeException(nameof(keyPower), ex);
                throw;
            }
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

        /// <summary>
        /// Returns a copy of parmsId.
        /// </summary>
        /// <see cref="EncryptionParameters">see EncryptionParameters for more information about parmsId.</see>
        public ParmsId ParmsId
        {
            get
            {
                ParmsId parms = new ParmsId();
                NativeMethods.RelinKeys_GetParmsId(NativePtr, parms.Block);
                return parms;
            }
            private set
            {
                NativeMethods.RelinKeys_SetParmsId(NativePtr, value.Block);
            }
        }

        /// <summary>
        /// Check whether the current RelinKeys is valid for a given SEALContext. If 
        /// the given SEALContext is not set, the encryption parameters are invalid, 
        /// or the RelinKeys data does not match the SEALContext, this function returns 
        /// false. Otherwise, returns true.
        /// </summary>
        /// <param name="context">The SEALContext</param>
        /// <exception cref="ArgumentNullException">if context is null</exception>
        public bool IsValidFor(SEALContext context)
        {
            if (null == context)
                throw new ArgumentNullException(nameof(context));

            NativeMethods.RelinKeys_IsValidFor(NativePtr, context.NativePtr, out bool result);
            return result;
        }

        /// <summary>
        /// Check whether the current RelinKeys is valid for a given SEALContext. If
        /// the given SEALContext is not set, the encryption parameters are invalid,
        /// or the RelinKeys data does not match the SEALContext, this function returns 
        /// false. Otherwise, returns true. This function only checks the metadata
        /// and not the relinearization key data itself.
        /// </summary>
        /// <param name="context">The SEALContext</param>
        /// <exception cref="ArgumentNullException">if context is null</exception>
        public bool IsMetadataValidFor(SEALContext context)
        {
            if (null == context)
                throw new ArgumentNullException(nameof(context));

            NativeMethods.RelinKeys_IsMetadataValidFor(NativePtr, context.NativePtr, out bool result);
            return result;
        }

        /// <summary>
        /// Saves the RelinKeys instance to an output stream.
        /// </summary>
        /// 
        /// <remarks>
        /// Saves the RelinKeys instance to an output stream. The output is in binary format 
        /// and not human-readable. The output stream must have the "binary" flag set.
        /// </remarks>
        /// <param name="stream">The stream to save the RelinKeys to</param>
        /// <exception cref="ArgumentNullException">if stream is null</exception>
        /// <seealso cref="Load(SEALContext, Stream)">See Load() to load a saved RelinKeys instance.</seealso>
        public void Save(Stream stream)
        {
            if (null == stream)
                throw new ArgumentNullException(nameof(stream));

            using (BinaryWriter writer = new BinaryWriter(stream, Encoding.UTF8, leaveOpen: true))
            {
                // Save ParmsId
                ParmsId.Save(writer.BaseStream);

                // Save the decomposition bit count
                writer.Write(DecompositionBitCount);

                // Save the size of Keys
                IEnumerable<IEnumerable<Ciphertext>> data = Data;
                writer.Write((ulong)data.LongCount());

                // Loop over entries in the first list
                foreach (IEnumerable<Ciphertext> keyList in data)
                {
                    writer.Write((ulong)keyList.LongCount());

                    // Loop over ciphertexts and save all
                    foreach (Ciphertext cipher in keyList)
                    {
                        cipher.Save(writer.BaseStream);
                    }
                }
            }
        }

        /// <summary>
        /// Loads a RelinKeys from an input stream overwriting the current RelinKeys.
        /// No checking of the validity of the RelinKeys data against encryption
        /// parameters is performed. This function should not be used unless the 
        /// RelinKeys comes from a fully trusted source.
        /// </summary>
        /// <param name="stream">The stream to load the RelinKeys from</param>
        /// <exception cref="ArgumentNullException">if stream is null</exception>
        /// <exception cref="ArgumentException">if valid RelinKeys could not be read
        /// from stream</exception>
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
                    NativeMethods.RelinKeys_ClearDataAndReserve(NativePtr, size);

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

                        NativeMethods.RelinKeys_AddKeyList(NativePtr, (ulong)pointers.LongLength, pointers);
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
        /// Loads a RelinKeys from an input stream overwriting the current RelinKeys.
        /// The loaded RelinKeys is verified to be valid for the given SEALContext.
        /// </summary>
        /// 
        /// <param name="context">The SEALContext</param>
        /// <param name="stream">The stream to load the RelinKeys instance from</param>
        /// <exception cref="ArgumentNullException">if either stream or context are null</exception>
        /// <exception cref="ArgumentException">if the context is not set or encryption
        /// parameters are not valid</exception>
        /// <exception cref="ArgumentException">If the stream data is invalid or is not
        /// valid for the context</exception>
        /// <seealso cref="Save(Stream)">See Save() to save an RelinKeys instance.</seealso>
        public void Load(SEALContext context, Stream stream)
        {
            if (null == context)
                throw new ArgumentNullException(nameof(context));
            if (null == stream)
                throw new ArgumentNullException(nameof(stream));

            UnsafeLoad(stream);

            if (!IsValidFor(context))
            {
                throw new ArgumentException("RelinKeys data is invalid for the context");
            }
        }

        /// <summary>
        /// Returns the currently used MemoryPoolHandle.
        /// </summary>
        public MemoryPoolHandle Pool
        {
            get
            {
                NativeMethods.RelinKeys_Pool(NativePtr, out IntPtr pool);
                MemoryPoolHandle handle = new MemoryPoolHandle(pool);
                return handle;
            }
        }

        /// <summary>
        /// Destroy native object.
        /// </summary>
        protected override void DestroyNativeObject()
        {
            NativeMethods.RelinKeys_Destroy(NativePtr);
        }
    }
}
