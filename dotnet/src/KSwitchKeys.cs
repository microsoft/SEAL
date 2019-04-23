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
    /// Class to store keyswitching keys.
    /// </summary>
    ///
    /// <remarks>
    /// <para>
    /// Class to store keyswitching keys. It should never be necessary for normal
    /// users to create an instance of KSwitchKeys. This class is used strictly as
    /// a base class for RelinKeys and GaloisKeys classes.
    /// </para>
    /// <para>
    /// Concretely, keyswitching is used to change a ciphertext encrypted with one
    /// key to be encrypted with another key.It is a general technique and is used
    /// in relinearization and Galois rotations. A keyswitching key contains a sequence
    /// (vector) of keys.In RelinKeys, each key is an encryption of a power of the
    /// secret key.In GaloisKeys, each key corresponds to a type of rotation.
    /// </para>
    /// <para>
    /// In general, reading from KSwitchKeys is thread-safe as long as no
    /// other thread is concurrently mutating it.This is due to the underlying
    /// data structure storing the keyswitching keys not being thread-safe.
    /// </para>
    /// </remarks>
    /// <see cref="RelinKeys">see RelinKeys for the class that stores the relinearization keys.</see>
    /// <see cref="GaloisKeys">see GaloisKeys for the class that stores the Galois keys.</see>
    public class KSwitchKeys : NativeObject
    {
        /// <summary>
        /// Creates an empty KSwitchKeys.
        /// </summary>
        public KSwitchKeys()
        {
            NativeMethods.KSwitchKeys_Create(out IntPtr ptr);
            NativePtr = ptr;
        }

        /// <summary>
        /// Creates a new KSwitchKeys instance by copying a given instance.
        /// </summary>
        /// <param name="copy">The KSwitchKeys to copy from</param>
        /// <exception cref="ArgumentNullException">if copy is null</exception>
        public KSwitchKeys(KSwitchKeys copy)
        {
            if (null == copy)
                throw new ArgumentNullException(nameof(copy));

            NativeMethods.KSwitchKeys_Create(copy.NativePtr, out IntPtr ptr);
            NativePtr = ptr;
        }

        /// <summary>
        /// Creates a new KSwitchKeys instance initialized with a pointer to a native
        /// KSwitchKeys object.
        /// </summary>
        /// <param name="kswitchKeys">Pointer to native KSwitchKeys object</param>
        /// <param name="owned">Whether this instance owns the native pointer</param>
        internal KSwitchKeys(IntPtr kswitchKeys, bool owned = true)
            : base(kswitchKeys, owned)
        {
        }

        /// <summary>
        /// Copies a given KSwitchKeys instance to the current one.
        /// </summary>
        ///
        /// <param name="assign">The KSwitchKeys to copy from</param>
        /// <exception cref="ArgumentNullException">if assign is null</exception>
        public void Set(KSwitchKeys assign)
        {
            if (null == assign)
                throw new ArgumentNullException(nameof(assign));

            NativeMethods.KSwitchKeys_Set(NativePtr, assign.NativePtr);
        }

        /// <summary>
        /// Returns the current number of keyswitching keys. Only keys that are non-empty
        /// are counted.
        /// </summary>
        public ulong Size
        {
            get
            {
                NativeMethods.KSwitchKeys_Size(NativePtr, out ulong size);
                return size;
            }
        }

        /// <summary>
        /// Returns the KSwitchKeys data.
        /// </summary>
        /// <remarks>
        /// Returns the KSwitchKeys data. The returned object is valid only as long as
        /// the KSwitchKeys is valid and not changed.
        /// </remarks>
        public IEnumerable<IEnumerable<PublicKey>> Data
        {
            get
            {
                List<List<PublicKey>> result = new List<List<PublicKey>>();
                NativeMethods.KSwitchKeys_RawSize(NativePtr, out ulong size);

                for (ulong i = 0; i < size; i++)
                {
                    ulong count = 0;
                    NativeMethods.KSwitchKeys_GetKeyList(NativePtr, i, ref count, null);

                    IntPtr[] pointers = new IntPtr[count];
                    NativeMethods.KSwitchKeys_GetKeyList(NativePtr, i, ref count, pointers);

                    List<PublicKey> key = new List<PublicKey>(checked((int)count));
                    foreach (IntPtr ptr in pointers)
                    {
                        key.Add(new PublicKey(ptr, owned: false));
                    }

                    result.Add(key);
                }

                return result;
            }
        }

        /// <summary>
        /// Returns a copy of ParmsId.
        /// </summary>
        /// <see cref="EncryptionParameters">see EncryptionParameters for more information about parmsId.</see>
        public ParmsId ParmsId
        {
            get
            {
                ParmsId parms = new ParmsId();
                NativeMethods.KSwitchKeys_GetParmsId(NativePtr, parms.Block);
                return parms;
            }
            private set
            {
                NativeMethods.KSwitchKeys_SetParmsId(NativePtr, value.Block);
            }
        }

        /// <summary>
        /// Saves the KSwitchKeys instance to an output stream.
        /// </summary>
        /// <remarks>
        /// Saves the KSwitchKeys instance to an output stream. The output is in binary
        /// format and not human-readable. The output stream must have the "binary" flag set.
        /// </remarks>
        /// <param name="stream">The stream to save the KSwitchKeys to</param>
        /// <exception cref="ArgumentNullException">if stream is null</exception>
        /// <exception cref="ArgumentException">if the KSwitchKeys could not be written to stream</exception>
        public void Save(Stream stream)
        {
            if (null == stream)
                throw new ArgumentNullException(nameof(stream));

            try
            {
                using (BinaryWriter writer = new BinaryWriter(stream, Encoding.UTF8, leaveOpen: true))
                {
                    // Save the ParmsId
                    ParmsId.Save(writer.BaseStream);

                    // Save the size of Keys
                    IEnumerable<IEnumerable<PublicKey>> data = Data;
                    writer.Write((ulong)data.LongCount());

                    // Loop over entries in the first list
                    foreach (IEnumerable<PublicKey> key in data)
                    {
                        writer.Write((ulong)key.LongCount());

                        // Loop over keys and save all
                        foreach (PublicKey pkey in key)
                        {
                            pkey.Save(writer.BaseStream);
                        }
                    }
                }
            }
            catch (IOException ex)
            {
                throw new ArgumentException("Could not write KSwitchKeys", ex);
            }
        }

        /// <summary>
        /// Loads a KSwitchKeys from an input stream overwriting the current KSwitchKeys.
        /// </summary>
        /// <remarks>
        /// Loads a KSwitchKeys from an input stream overwriting the current KSwitchKeys.
        /// No checking of the validity of the KSwitchKeys data against encryption
        /// parameters is performed. This function should not be used unless the
        /// KSwitchKeys comes from a fully trusted source.
        /// </remarks>
        /// <param name="stream">The stream to load the KSwitchKeys from</param>
        /// <exception cref="ArgumentNullException">if stream is null</exception>
        /// <exception cref="ArgumentException">if KSwitchKeys could not be read from
        /// stream</exception>
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
                    // Read the size
                    ulong size = reader.ReadUInt64();

                    // Clear current data and reserve new size
                    NativeMethods.KSwitchKeys_ClearDataAndReserve(NativePtr, size);

                    // Read all lists
                    for (ulong i = 0; i < size; i++)
                    {
                        // Read size of second list
                        ulong keySize = reader.ReadUInt64();
                        List<PublicKey> key = new List<PublicKey>(checked((int)keySize));

                        // Load all ciphertexts
                        for (ulong j = 0; j < keySize; j++)
                        {
                            PublicKey pkey = new PublicKey();
                            pkey.UnsafeLoad(reader.BaseStream);
                            key.Add(pkey);
                        }

                        IntPtr[] pointers = key.Select(c =>
                        {
                            return c.NativePtr;
                        }).ToArray();

                        NativeMethods.KSwitchKeys_AddKeyList(NativePtr, (ulong)pointers.LongLength, pointers);
                    }
                }
            }
            catch (EndOfStreamException ex)
            {
                throw new ArgumentException("Stream ended unexpectedly", ex);
            }
            catch (IOException ex)
            {
                throw new ArgumentException("Could not load KSwitchKeys", ex);
            }
        }

        /// <summary>
        /// Loads a KSwitchKeys from an input stream overwriting the current KSwitchKeys.
        /// </summary>
        /// <remarks>
        /// Loads a KSwitchKeys from an input stream overwriting the current KSwitchKeys.
        /// The loaded GaloisKeys is verified to be valid for the given SEALContext.
        /// </remarks>
        /// <param name="context">The SEALContext</param>
        /// <param name="stream">The stream to load the KSwitchKeys instance from</param>
        /// <exception cref="ArgumentNullException">if either stream or context are null</exception>
        /// <exception cref="ArgumentException">if the context is not set or encryption
        /// parameters are not valid</exception>
        /// <exception cref="ArgumentException">if KSwitchKeys could not be read from
        /// stream or is invalid for the context</exception>
        public void Load(SEALContext context, Stream stream)
        {
            if (null == context)
                throw new ArgumentNullException(nameof(context));
            if (null == stream)
                throw new ArgumentNullException(nameof(stream));

            UnsafeLoad(stream);
            if (!ValCheck.IsValidFor(this, context))
            {
                throw new ArgumentException("KSwitchKeys data is invalid for the context");
            }
        }

        /// <summary>
        /// Returns the currently used MemoryPoolHandle.
        /// </summary>
        public MemoryPoolHandle Pool
        {
            get
            {
                NativeMethods.KSwitchKeys_Pool(NativePtr, out IntPtr pool);
                MemoryPoolHandle handle = new MemoryPoolHandle(pool);
                return handle;
            }
        }

        /// <summary>
        /// Destroy native object.
        /// </summary>
        protected override void DestroyNativeObject()
        {
            NativeMethods.KSwitchKeys_Destroy(NativePtr);
        }
    }
}