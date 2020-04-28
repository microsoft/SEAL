// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

using Microsoft.Research.SEAL.Tools;
using System;
using System.IO;

namespace Microsoft.Research.SEAL
{
    /// <summary>Interface for classes with a Set function.</summary>
    public interface ISettable<T> where T : class
    {
        /// <summary>
        /// Copies a given object to the current one.
        /// </summary>
        /// <param name="assign">The object to copy from</param>
        /// <exception cref="ArgumentNullException">if assign is null</exception>
        void Set(T assign);
    }

    /// <summary>Interface for classes that are serializable.</summary>
    public interface ISerializableObject
    {
        /// <summary>
        /// Returns an upper bound on the size of the object, as if it was written
        /// to an output stream.
        /// </summary>
        /// <param name="comprMode">The compression mode</param>
        /// <exception cref="ArgumentException">if the compression mode is not
        /// supported</exception>
        /// <exception cref="InvalidOperationException">if the size does not fit in
        /// the return type</exception>
        long SaveSize(ComprModeType? comprMode);

        /// <summary>Saves the object to an output stream.</summary>
        /// <remarks>
        /// Saves the object to an output stream. The output is in binary format
        /// and not human-readable.
        /// </remarks>
        /// <param name="stream">The stream to save the object to</param>
        /// <param name="comprMode">The desired compression mode</param>
        /// <exception cref="ArgumentNullException">if stream is null</exception>
        /// <exception cref="ArgumentException">if the stream is closed or does not
        /// support writing, or if compression mode is not supported</exception>
        /// <exception cref="IOException">if I/O operations failed</exception>
        /// <exception cref="InvalidOperationException">if the data to be saved
        /// is invalid, or if compression failed</exception>
        long Save(Stream stream, ComprModeType? comprMode);
    }

    /// <summary>Class to represent a serializable object.</summary>
    /// <remarks>
    /// <para>
    /// Some functions return serializable objects rather than normal objects. For
    /// example, Encryptor can be used in symmetric-key mode to create symmetric-key
    /// ciphertexts, where half of the ciphertext data is pseudo-random and can be
    /// generated from a seed, reducing the size of the newly created ciphertext
    /// object by nearly 50%. However, the compression only has an effect when the
    /// object is serialized with compression mode ComprModeType.Deflate due to an
    /// implementation detail. This makes sense when, e.g., the ciphertexts need
    /// to be communicated from a client to a server for encrypted computation.
    /// </para>
    /// <para>
    /// Serializable objects are created only by the following functions:
    ///     - Encryptor.EncryptSymmetric
    ///     - Encryptor.EncryptZeroSymmetric
    ///     - KeyGenerator.RelinKeys
    ///     - KeyGenerator.GaloisKeys
    /// </para>
    /// <para>
    /// Serializable objects also expose the SaveSize function that behaves just
    /// as the SaveSize functions of other objects in Microsoft SEAL: it returns
    /// an upper bound on the size of a buffer needed to hold the serialized data.
    /// </para>
    /// <para>
    /// The following illustrates the use of serializable objects:
    ///
    ///        +--------------------------+
    ///        | Serializable{GaloisKeys} |  Size 2 MB (example)
    ///        +------------+-------------+
    ///                     |
    ///                     |                Serializable{GaloisKeys}.Save
    ///                     |                with ComprModeType.Deflate
    ///                     |
    ///             +-------v-------+
    ///             | Stream/Buffer |        Size ~1 MB (example)
    ///             +-------+-------+
    ///                     |
    ///                     |
    ///                  +--v--+
    ///                  Network             Minimized communication
    ///                  +--+--+
    ///                     |
    ///                     |                GaloisKeys.Load
    ///                     |
    ///               +-----v------+
    ///               | GaloisKeys |         Size 2 MB (example)
    ///               +------------+
    /// </para>
    /// <typeparam name="T">The type to wrap into a serializable object</typeparam>
    /// </remarks>
    public class Serializable<T> : DisposableObject
        where T : DisposableObject, ISerializableObject, ISettable<T>, new()
    {
        /// <summary>
        /// Constructs a new serializable object by copying a given one.
        /// </summary>
        /// <param name="copy">The serializable object to copy from</param>
        /// <exception cref="ArgumentNullException">if copy is null</exception>
        public Serializable(Serializable<T> copy)
        {
            if (null == copy)
                throw new ArgumentNullException(nameof(copy));

            // Use Activator to get around lack of constructor
            obj_ =  (T)Activator.CreateInstance(typeof(T), copy.obj_);
        }

        /// <summary>
        /// Copies a given serializable object to the current one.
        /// </summary>
        /// <param name="assign">The serializable object to copy from</param>
        /// <exception cref="ArgumentNullException">if assign is null</exception>
        public void Set(Serializable<T> assign)
        {
            if (null == assign)
                throw new ArgumentNullException(nameof(assign));

            obj_.Set(assign.obj_);
        }

        /// <summary>
        /// Returns an upper bound on the size of the serializable object, as if it
        /// was written to an output stream.
        /// </summary>
        /// <param name="comprMode">The compression mode</param>
        /// <exception cref="ArgumentException">if the compression mode is not
        /// supported</exception>
        /// <exception cref="InvalidOperationException">if the size does not fit in
        /// the return type</exception>
        public long SaveSize(ComprModeType? comprMode = null)
            => obj_.SaveSize(comprMode);

        /// <summary>Saves the serializable object to an output stream.</summary>
        /// <remarks>
        /// Saves the serializable object to an output stream. The output is in
        /// binary format and not human-readable.
        /// </remarks>
        /// <param name="stream">The stream to save the serializable object to</param>
        /// <param name="comprMode">The desired compression mode</param>
        /// <exception cref="ArgumentNullException">if stream is null</exception>
        /// <exception cref="ArgumentException">if the stream is closed or does not
        /// support writing, or if compression mode is not supported</exception>
        /// <exception cref="IOException">if I/O operations failed</exception>
        /// <exception cref="InvalidOperationException">if the data to be saved
        /// is invalid, or if compression failed</exception>
        public long Save(Stream stream, ComprModeType? comprMode = null)
            => obj_.Save(stream, comprMode);

        /// <summary>
        /// Constructs a new serializable object wrapping a given object.
        /// </summary>
        /// <param name="obj">The object to wrap</param>
        /// <exception cref="ArgumentNullException">if obj is null</exception>
        internal Serializable(T obj)
        {
            if (null == obj)
                throw new ArgumentNullException(nameof(obj));

            obj_ = obj;
        }

        /// <summary>
        /// Destroy wrapped object.
        /// </summary>
        protected override void DisposeManagedResources()
        {
            obj_.Dispose();
        }

        /// <summary>
        /// The object wrapped by an instance of Serializable.
        /// </summary>
        private readonly T obj_;
    }
}
