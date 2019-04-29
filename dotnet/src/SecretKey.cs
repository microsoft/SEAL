// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

using Microsoft.Research.SEAL.Tools;
using System;
using System.IO;

namespace Microsoft.Research.SEAL
{
    /// <summary>
    /// Class to store a secret key.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Thread Safety
    /// In general, reading from SecretKey is thread-safe as long as no other
    /// thread is concurrently mutating it. This is due to the underlying data
    /// structure storing the secret key not being thread-safe.
    /// </para>
    /// </remarks>
    /// <see cref="KeyGenerator">see KeyGenerator for the class that generates the secret key.</see>
    /// <see cref="PublicKey">see PublicKey for the class that stores the public key.</see>
    /// <see cref="RelinKeys">see RelinKeys for the class that stores the relinearization keys.</see>
    /// <see cref="GaloisKeys">see GaloisKeys for the class that stores the Galois keys.</see>
    public class SecretKey : NativeObject
    {
        /// <summary>
        /// Creates an empty secret key.
        /// </summary>
        public SecretKey()
        {
            NativeMethods.SecretKey_Create(out IntPtr ptr);
            NativePtr = ptr;
        }

        /// <summary>
        /// Creates a new SecretKey by initializing it with a pointer to a native object.
        /// </summary>
        /// <param name="secretKeyPtr">The native SecretKey pointer</param>
        /// <param name="owned">Whether this instance owns the native pointer</param>
        internal SecretKey(IntPtr secretKeyPtr, bool owned = true)
            : base(secretKeyPtr, owned)
        {
        }

        /// <summary>
        /// Creates a new SecretKey by copying an old one.
        /// </summary>
        /// <param name="copy">The SecretKey to copy from</param>
        /// <exception cref="ArgumentNullException">if copy is null</exception>
        public SecretKey(SecretKey copy)
        {
            if (null == copy)
                throw new ArgumentNullException(nameof(copy));

            NativeMethods.SecretKey_Create(copy.NativePtr, out IntPtr ptr);
            NativePtr = ptr;
        }

        /// <summary>
        /// Copies an old SecretKey to the current one.
        /// </summary>
        /// <param name="assign">The SecretKey to copy from</param>
        /// <exception cref="ArgumentNullException">if assign is null</exception>
        public void Set(SecretKey assign)
        {
            if (null == assign)
                throw new ArgumentNullException(nameof(assign));

            NativeMethods.SecretKey_Set(NativePtr, assign.NativePtr);
        }

        /// <summary>
        /// Returns the underlying Plaintext.
        /// </summary>
        /// <remarks>
        /// Returns the underlying Plaintext. The returned Plaintext is valid
        /// only as long as the SecretKey is valid and not changed.
        /// </remarks>
        public Plaintext Data
        {
            get
            {
                NativeMethods.SecretKey_Data(NativePtr, out IntPtr plaintextPtr);
                Plaintext plaintext = new Plaintext(plaintextPtr, owned: false);
                return plaintext;
            }
        }

        /// <summary>
        /// Saves the SecretKey to an output stream.
        /// </summary>
        /// <remarks>
        /// Saves the SecretKey to an output stream. The output is in binary format and
        /// not human-readable. The output stream must have the "binary" flag set.
        /// </remarks>
        /// <param name="stream">The stream to save the SecretKey to</param>
        /// <exception cref="ArgumentNullException">if stream is null</exception>
        /// <exception cref="ArgumentException">if the SecretKey could not be written
        /// to stream</exception>
        public void Save(Stream stream)
        {
            if (null == stream)
                throw new ArgumentNullException(nameof(stream));

            Data.Save(stream);
        }

        /// <summary>
        /// Loads a SecretKey from an input stream overwriting the current SecretKey.
        /// No checking of the validity of the SecretKey data against encryption
        /// parameters is performed. This function should not be used unless the
        /// SecretKey comes from a fully trusted source.
        /// </summary>
        /// <param name="stream">The stream to load the SecretKey from</param>
        /// <exception cref="ArgumentNullException">if stream is null</exception>
        /// <exception cref="ArgumentException">if SecretKey could not be read from
        /// stream</exception>
        public void UnsafeLoad(Stream stream)
        {
            if (null == stream)
                throw new ArgumentNullException(nameof(stream));

            Data.UnsafeLoad(stream);
        }

        /// <summary>
        /// Loads a SecretKey from an input stream overwriting the current SecretKey.
        /// The loaded SecretKey is verified to be valid for the given SEALContext.
        /// </summary>
        /// <param name="context">The SEALContext</param>
        /// <param name="stream">The stream to load the SecretKey from</param>
        /// <exception cref="ArgumentNullException">if stream is null</exception>
        /// <exception cref="ArgumentException">if the context is not set or encryption
        /// parameters are not valid</exception>
        /// <exception cref="ArgumentException">if SecretKey could not be read from
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
                throw new ArgumentException("SecretKey data is invalid for context");
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
                NativeMethods.SecretKey_ParmsId(NativePtr, parms.Block);
                return parms;
            }
        }

        /// <summary>
        /// Returns the currently used MemoryPoolHandle.
        /// </summary>
        public MemoryPoolHandle Pool
        {
            get
            {
                NativeMethods.SecretKey_Pool(NativePtr, out IntPtr pool);
                MemoryPoolHandle handle = new MemoryPoolHandle(pool);
                return handle;
            }
        }

        /// <summary>
        /// Destroy native object.
        /// </summary>
        protected override void DestroyNativeObject()
        {
            NativeMethods.SecretKey_Destroy(NativePtr);
        }
    }
}
