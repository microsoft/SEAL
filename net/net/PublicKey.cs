using Microsoft.Research.SEAL.Tools;
using System;
using System.Collections.Generic;
using System.IO;
using System.Text;

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
    /// <see cref="KeyGenerator">see KeyGenerator for the class that generates the public key.</see>
    /// <see cref="SecretKey">see SecretKey for the class that stores the secret key.</see>
    /// <see cref="RelinKeys">see RelinKeys for the class that stores the relinearization keys.</see>
    /// <see cref="GaloisKeys">see GaloisKeys for the class that stores the Galois keys.</see>
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
        /// Returns a copy of the underlying Ciphertext
        /// </summary>
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
        /// Saves the PublicKey to an output stream.
        /// </summary>
        /// 
        /// <remarks>
        /// Saves the PublicKey to an output stream. The output is in binary format and 
        /// not human-readable. The output stream must have the "binary" flag set.
        /// </remarks>
        /// <param name="stream">The stream to save the PublicKey to</param>
        /// <exception cref="ArgumentNullException">if stream is null</exception>
        public void Save(Stream stream)
        {
            // TODO: implement
            throw new NotImplementedException();
        }

        /// <summary>
        /// Loads a PublicKey from an input stream overwriting the current 
        /// PublicKey.
        /// </summary>
        /// <param name="stream">The stream to load the PublicKey from</param>
        /// <exception cref="ArgumentNullException">if stream is null</exception>
        public void Load(Stream stream)
        {
            // TODO: implement
            throw new NotImplementedException();
        }

        /// <summary>
        /// Returns a reference to parmsId.
        /// </summary>
        public ParmsId ParmsId
        {
            get
            {
                // TODO: implement
                throw new NotImplementedException();
            }
        }

        /// <summary>
        /// Returns the currently used MemoryPoolHandle.
        /// </summary>
        public MemoryPoolHandle Pool
        {
            get
            {
                // TODO: implement
                throw new NotImplementedException();
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
