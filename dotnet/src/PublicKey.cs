// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

using Microsoft.Research.SEAL.Tools;
using System;
using System.IO;
using System.Runtime.InteropServices;

namespace Microsoft.Research.SEAL
{
    /// <summary>
    /// Class to store a public key.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Thread Safety
    /// In general, reading from PublicKey is thread-safe as long as no other thread
    /// is concurrently mutating it. This is due to the underlying data structure
    /// storing the public key not being thread-safe.
    /// </para>
    /// </remarks>
    public class PublicKey : NativeObject
    {
        /// <summary>
        /// Creates an empty public key.
        /// </summary>
        public PublicKey()
        {
            NativeMethods.PublicKey_Create(out IntPtr ptr);
            NativePtr = ptr;
        }

        /// <summary>
        /// Creates a new PublicKey by copying an old one.
        /// </summary>
        /// <param name="copy">The PublicKey to copy from</param>
        /// <exception cref="ArgumentNullException">if copy is null</exception>
        public PublicKey(PublicKey copy)
        {
            if (null == copy)
                throw new ArgumentNullException(nameof(copy));

            NativeMethods.PublicKey_Create(copy.NativePtr, out IntPtr ptr);
            NativePtr = ptr;
        }

        /// <summary>
        /// Creates a new PublicKey by initializing with a pointer to a native object.
        /// </summary>
        /// <param name="publicKeyPtr">Pointer to native PublicKey</param>
        /// <param name="owned">Whether this instance owns the native pointer</param>
        internal PublicKey(IntPtr publicKeyPtr, bool owned = true)
            : base(publicKeyPtr, owned)
        {
        }

        /// <summary>
        /// Copies an old PublicKey to the current one.
        /// </summary>
        /// <param name="assign">The PublicKey to copy from</param>
        /// <exception cref="ArgumentNullException">if assign is null</exception>
        public void Set(PublicKey assign)
        {
            if (null == assign)
                throw new ArgumentNullException(nameof(assign));

            NativeMethods.PublicKey_Set(NativePtr, assign.NativePtr);
        }

        /// <summary>
        /// Returns the underlying Ciphertext.
        /// </summary>
        /// <remarks>
        /// Returns the underlying Ciphertext. The returned Ciphertext is valid
        /// only as long as the PublicKey is valid and not changed.
        /// </remarks>
        public Ciphertext Data
        {
            get
            {
                NativeMethods.PublicKey_Data(NativePtr, out IntPtr cipherPtr);
                Ciphertext cipher = new Ciphertext(cipherPtr, owned: false);
                return cipher;
            }
        }

        /// <summary>
        /// Returns an upper bound on the size of the PublicKey, as if it was written
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
            NativeMethods.PublicKey_SaveSize(
                NativePtr, (byte)comprModeValue, out long outBytes);
            return outBytes;
        }

        /// <summary>Saves the PublicKey to an output stream.</summary>
        /// <remarks>
        /// Saves the PublicKey to an output stream. The output is in binary format
        /// and not human-readable.
        /// </remarks>
        /// <param name="stream">The stream to save the PublicKey to</param>
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
                    NativeMethods.PublicKey_Save(NativePtr, outptr, size,
                    cm, out outBytes),
                SaveSize(comprModeValue), comprModeValue, stream);
        }

        /// <summary>Loads a PublicKey from an input stream overwriting the current
        /// PublicKey.</summary>
        /// <remarks>
        /// Loads a PublicKey from an input stream overwriting the current PublicKey.
        /// No checking of the validity of the PublicKey data against encryption
        /// parameters is performed. This function should not be used unless the
        /// PublicKey comes from a fully trusted source.
        /// </remarks>
        /// <param name="context">The SEALContext</param>
        /// <param name="stream">The stream to load the PublicKey from</param>
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
                    NativeMethods.PublicKey_UnsafeLoad(NativePtr, context.NativePtr,
                    outptr, size, out outBytes),
                stream);
        }

        /// <summary>Loads a PublicKey from an input stream overwriting the current
        /// PublicKey.</summary>
        /// <remarks>
        /// Loads a PublicKey from an input stream overwriting the current PublicKey.
        /// The loaded PublicKey is verified to be valid for the given SEALContext.
        /// </remarks>
        /// <param name="context">The SEALContext</param>
        /// <param name="stream">The stream to load the PublicKey from</param>
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
                    NativeMethods.PublicKey_Load(NativePtr, context.NativePtr,
                    outptr, size, out outBytes),
                stream);
        }

        /// <summary>
        /// Returns a copy of ParmsId.
        /// </summary>
        public ParmsId ParmsId
        {
            get
            {
                ParmsId parmsId = new ParmsId();
                NativeMethods.PublicKey_ParmsId(NativePtr, parmsId.Block);
                return parmsId;
            }
        }

        /// <summary>
        /// Returns the currently used MemoryPoolHandle.
        /// </summary>
        public MemoryPoolHandle Pool
        {
            get
            {
                NativeMethods.PublicKey_Pool(NativePtr, out IntPtr pool);
                MemoryPoolHandle handle = new MemoryPoolHandle(pool);
                return handle;
            }
        }

        /// <summary>
        /// Destroy native object.
        /// </summary>
        protected override void DestroyNativeObject()
        {
            NativeMethods.PublicKey_Destroy(NativePtr);
        }
    }
}
