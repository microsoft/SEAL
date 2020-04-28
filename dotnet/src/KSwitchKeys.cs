// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

using Microsoft.Research.SEAL.Tools;
using System;
using System.Collections.Generic;
using System.IO;
using System.Runtime.InteropServices;

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
    public class KSwitchKeys :
        NativeObject,
        ISerializableObject,
        ISettable<KSwitchKeys>
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
        /// Returns an upper bound on the size of the KSwitchKeys, as if it was written
        /// to an output stream.
        /// </summary>
        /// <param name="comprMode">The compression mode</param>
        /// <exception cref="ArgumentException">if the compression mode is not
        /// supported</exception>
        /// <exception cref="InvalidOperationException">if the size does not fit in
        /// the return type</exception>
        public long SaveSize(ComprModeType? comprMode = null)
        {
            comprMode = comprMode ?? Serialization.ComprModeDefault;
            if (!Serialization.IsSupportedComprMode(comprMode.Value))
                throw new ArgumentException("Unsupported compression mode");

            ComprModeType comprModeValue = comprMode.Value;
            NativeMethods.KSwitchKeys_SaveSize(
                NativePtr, (byte)comprModeValue, out long outBytes);
            return outBytes;
        }

        /// <summary>Saves the KSwitchKeys to an output stream.</summary>
        /// <remarks>
        /// Saves the KSwitchKeys to an output stream. The output is in binary format
        /// and not human-readable.
        /// </remarks>
        /// <param name="stream">The stream to save the KSwitchKeys to</param>
        /// <param name="comprMode">The desired compression mode</param>
        /// <exception cref="ArgumentNullException">if stream is null</exception>
        /// <exception cref="ArgumentException">if the stream is closed or does not
        /// support writing, or if compression mode is not supported</exception>
        /// <exception cref="IOException">if I/O operations failed</exception>
        /// <exception cref="InvalidOperationException">if the data to be saved
        /// is invalid, or if compression failed</exception>
        public long Save(Stream stream, ComprModeType? comprMode = null)
        {
            comprMode = comprMode ?? Serialization.ComprModeDefault;
            if (!Serialization.IsSupportedComprMode(comprMode.Value))
                throw new ArgumentException("Unsupported compression mode");

            ComprModeType comprModeValue = comprMode.Value;
            return Serialization.Save(
                (byte[] outptr, ulong size, byte cm, out long outBytes) =>
                    NativeMethods.KSwitchKeys_Save(NativePtr, outptr, size,
                    cm, out outBytes),
                SaveSize(comprModeValue), comprModeValue, stream);
        }

        /// <summary>Loads a KSwitchKeys from an input stream overwriting the current
        /// KSwitchKeys.</summary>
        /// <remarks>
        /// Loads a KSwitchKeys from an input stream overwriting the current
        /// KSwitchKeys. No checking of the validity of the KSwitchKeys data against
        /// encryption parameters is performed. This function should not be used
        /// unless the KSwitchKeys comes from a fully trusted source.
        /// </remarks>
        /// <param name="context">The SEALContext</param>
        /// <param name="stream">The stream to load the KSwitchKeys from</param>
        /// <exception cref="ArgumentNullException">if context or stream is
        /// null</exception>
        /// <exception cref="ArgumentException">if the stream is closed or does not
        /// support reading</exception>
        /// <exception cref="ArgumentException">if context is not set or encryption
        /// parameters are not valid</exception>
        /// <exception cref="EndOfStreamException">if the stream ended
        /// unexpectedly</exception>
        /// <exception cref="IOException">if I/O operations failed</exception>
        /// <exception cref="InvalidOperationException">if the data cannot be loaded
        /// by this version of Microsoft SEAL, if the loaded data is invalid, or if the
        /// loaded compression mode is not supported</exception>
        public long UnsafeLoad(SEALContext context, Stream stream)
        {
            if (null == context)
                throw new ArgumentNullException(nameof(context));

            return Serialization.Load(
                (byte[] outptr, ulong size, out long outBytes) =>
                    NativeMethods.KSwitchKeys_UnsafeLoad(NativePtr, context.NativePtr,
                    outptr, size, out outBytes),
                stream);
        }

        /// <summary>Loads a KSwitchKeys from an input stream overwriting the current
        /// KSwitchKeys.</summary>
        /// <remarks>
        /// Loads a KSwitchKeys from an input stream overwriting the current
        /// KSwitchKeys. The loaded KSwitchKeys is verified to be valid for the given
        /// SEALContext.
        /// </remarks>
        /// <param name="context">The SEALContext</param>
        /// <param name="stream">The stream to load the KSwitchKeys from</param>
        /// <exception cref="ArgumentNullException">if context or stream is
        /// null</exception>
        /// <exception cref="ArgumentException">if the stream is closed or does not
        /// support reading</exception>
        /// <exception cref="ArgumentException">if context is not set or encryption
        /// parameters are not valid</exception>
        /// <exception cref="EndOfStreamException">if the stream ended
        /// unexpectedly</exception>
        /// <exception cref="IOException">if I/O operations failed</exception>
        /// <exception cref="InvalidOperationException">if the data cannot be loaded
        /// by this version of Microsoft SEAL, if the loaded data is invalid, or if the
        /// loaded compression mode is not supported</exception>
        public long Load(SEALContext context, Stream stream)
        {
            if (null == context)
                throw new ArgumentNullException(nameof(context));

            return Serialization.Load(
                (byte[] outptr, ulong size, out long outBytes) =>
                    NativeMethods.KSwitchKeys_Load(NativePtr, context.NativePtr,
                    outptr, size, out outBytes),
                stream);
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
