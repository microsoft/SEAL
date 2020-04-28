// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

using Microsoft.Research.SEAL.Tools;
using System;
using System.IO;
using System.Runtime.InteropServices;

namespace Microsoft.Research.SEAL
{
    /// <summary>
    /// Class to store a ciphertext element. The data for a ciphertext consists
    /// of two or more polynomials, which are in Microsoft SEAL stored in a CRT
    /// form with respect to the factors of the coefficient modulus. This data
    /// itself is not meant to be modified directly by the user, but is instead
    /// operated on by functions in the Evaluator class. The size of the backing
    /// array of a ciphertext depends on the encryption parameters and the size
    /// of the ciphertext (at least 2). If the PolyModulusDegree encryption
    /// parameter is N, and the number of primes in the CoeffModulus encryption
    /// parameter is K, then the ciphertext backing array requires precisely
    /// 8*N*K*size bytes of memory. A ciphertext also carries with it the
    /// parmsId of its associated encryption parameters, which is used to check
    /// the validity of the ciphertext for homomorphic operations and decryption.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Memory Management
    /// The size of a ciphertext refers to the number of polynomials it contains,
    /// whereas its capacity refers to the number of polynomials that fit in the
    /// current memory allocation. In high-performance applications unnecessary
    /// re-allocations should be avoided by reserving enough memory for the
    /// ciphertext to begin with either by providing the desired capacity to the
    /// constructor as an extra argument, or by calling the reserve function at
    /// any time.
    /// </para>
    /// <para>
    /// Thread Safety
    /// In general, reading from ciphertext is thread-safe as long as no other
    /// thread is concurrently mutating it. This is due to the underlying data
    /// structure storing the ciphertext not being thread-safe.
    /// </para>
    /// </remarks>
    /// <seealso cref="Plaintext">See Plaintext for the class that stores plaintexts.</seealso>
    public class Ciphertext :
        NativeObject,
        ISerializableObject,
        ISettable<Ciphertext>
    {
        /// <summary>
        /// Constructs an empty ciphertext allocating no memory.
        /// </summary>
        public Ciphertext() : this(pool: null)
        {
        }

        /// <summary>
        /// Constructs an empty ciphertext allocating no memory.
        /// </summary>
        /// <param name="pool">The MemoryPoolHandle pointing to a valid memory pool</param>
        /// <exception cref="System.ArgumentException">if pool is uninitialized</exception>
        public Ciphertext(MemoryPoolHandle pool)
        {
            IntPtr poolPtr = pool?.NativePtr ?? IntPtr.Zero;
            NativeMethods.Ciphertext_Create1(poolPtr, out IntPtr ptr);
            NativePtr = ptr;
        }

        /// <summary>
        /// Constructs an empty ciphertext with capacity 2. In addition to the
        /// capacity, the allocation size is determined by the highest-level
        /// parameters associated to the given SEALContext.
        /// </summary>
        /// <param name="context">The SEALContext</param>
        /// <param name="pool">The MemoryPoolHandle pointing to a valid memory pool</param>
        /// <exception cref="ArgumentNullException">if context is null</exception>
        /// <exception cref="ArgumentException">if the context is not set or encryption
        /// parameters are not valid</exception>
        /// <exception cref="ArgumentException">if pool is uninitialized</exception>
        public Ciphertext(SEALContext context, MemoryPoolHandle pool = null)
        {
            if (null == context)
                throw new ArgumentNullException(nameof(context));

            IntPtr poolPtr = pool?.NativePtr ?? IntPtr.Zero;
            NativeMethods.Ciphertext_Create3(context.NativePtr, poolPtr, out IntPtr ptr);
            NativePtr = ptr;
        }

        /// <summary>
        /// Constructs an empty ciphertext with capacity 2. In addition to the
        /// capacity, the allocation size is determined by the encryption parameters
        /// with given ParmsId.
        /// </summary>
        /// <param name="context">The SEALContext</param>
        /// <param name="parmsId">The ParmsId corresponding to the encryption
        /// parameters to be used</param>
        /// <param name="pool">The MemoryPoolHandle pointing to a valid memory pool</param>
        /// <exception cref="ArgumentNullException">if either context or parmsId are null</exception>
        /// <exception cref="ArgumentException">if the context is not set or encryption
        /// parameters are not valid</exception>
        /// <exception cref="ArgumentException">if parmsId is not valid for the encryption
        /// parameters</exception>
        /// <exception cref="ArgumentException">if pool is uninitialized</exception>
        public Ciphertext(SEALContext context, ParmsId parmsId, MemoryPoolHandle pool = null)
        {
            if (null == context)
                throw new ArgumentNullException(nameof(context));
            if (null == parmsId)
                throw new ArgumentNullException(nameof(parmsId));

            IntPtr poolPtr = pool?.NativePtr ?? IntPtr.Zero;
            NativeMethods.Ciphertext_Create4(context.NativePtr, parmsId.Block, poolPtr, out IntPtr ptr);
            NativePtr = ptr;
        }

        /// <summary>
        /// Constructs an empty ciphertext with given capacity. In addition to
        /// the capacity, the allocation size is determined by the given
        /// encryption parameters.
        /// </summary>
        /// <param name="context">The SEALContext</param>
        /// <param name="parmsId">The ParmsId corresponding to the encryption
        /// parameters to be used</param>
        /// <param name="sizeCapacity">The capacity</param>
        /// <param name="pool">The MemoryPoolHandle pointing to a valid memory pool</param>
        /// <exception cref="ArgumentNullException">if either context or parmsId are null</exception>
        /// <exception cref="ArgumentException">if the context is not set or encryption
        /// parameters are not valid</exception>
        /// <exception cref="ArgumentException">if parmsId is not valid for the encryption
        /// parameters</exception>
        /// <exception cref="ArgumentException">if sizeCapacity is less than 2 or too large</exception>
        /// <exception cref="ArgumentException">if pool is uninitialized</exception>
        public Ciphertext(SEALContext context, ParmsId parmsId, ulong sizeCapacity,
            MemoryPoolHandle pool = null)
        {
            if (null == context)
                throw new ArgumentNullException(nameof(context));
            if (null == parmsId)
                throw new ArgumentNullException(nameof(parmsId));

            IntPtr poolPtr = pool?.NativePtr ?? IntPtr.Zero;
            NativeMethods.Ciphertext_Create5(context.NativePtr, parmsId.Block, sizeCapacity, poolPtr, out IntPtr ptr);
            NativePtr = ptr;
        }

        /// <summary>
        /// Constructs a new ciphertext by copying a given one.
        /// </summary>
        /// <param name="copy">The ciphertext to copy from</param>
        /// <exception cref="ArgumentNullException">if copy is null</exception>
        public Ciphertext(Ciphertext copy)
        {
            if (null == copy)
                throw new ArgumentNullException(nameof(copy));

            NativeMethods.Ciphertext_Create2(copy.NativePtr, out IntPtr ptr);
            NativePtr = ptr;
        }

        /// <summary>
        /// Constructs a new ciphertext by copying a given one.
        /// </summary>
        /// <param name="copy">The ciphertext to copy from</param>
        /// <param name="pool">The MemoryPoolHandle pointing to a valid memory pool</param>
        /// <exception cref="ArgumentNullException">if either copy or pool are null</exception>
        /// <exception cref="ArgumentException">if pool is uninitialized</exception>
        public Ciphertext(Ciphertext copy, MemoryPoolHandle pool) : this(pool)
        {
            if (null == copy)
                throw new ArgumentNullException(nameof(copy));

            Set(copy);
        }

        /// <summary>
        /// Constructs a new ciphertext by initializing it with a native
        /// object pointer.
        /// </summary>
        /// <param name="ciphertextPtr">The native Ciphertext pointer</param>
        /// <param name="owned">Whether this object owns the native pointer</param>
        internal Ciphertext(IntPtr ciphertextPtr, bool owned = true)
            : base(ciphertextPtr, owned)
        {
        }

        /// <summary>
        /// Allocates enough memory to accommodate the backing array of a ciphertext
        /// with given capacity. In addition to the capacity, the allocation size is
        /// determined by the encryption parameters corresponing to the given
        /// parmsId.
        /// </summary>
        /// <param name="context">The SEALContext</param>
        /// <param name="parmsId">The ParmsId corresponding to the encryption
        /// parameters to be used</param>
        /// <param name="sizeCapacity">The capacity</param>
        /// <exception cref="ArgumentNullException">if either context or parmsId are null</exception>
        /// <exception cref="ArgumentException">if the context is not set or encryption
        /// parameters are not valid</exception>
        /// <exception cref="ArgumentException">if parmsId is not valid for the encryption
        /// parameters</exception>
        /// <exception cref="ArgumentException">if sizeCapacity is less than 2 or too large</exception>
        public void Reserve(SEALContext context, ParmsId parmsId, ulong sizeCapacity)
        {
            if (null == context)
                throw new ArgumentNullException(nameof(context));
            if (null == parmsId)
                throw new ArgumentNullException(nameof(parmsId));

            NativeMethods.Ciphertext_Reserve(NativePtr, context.NativePtr, parmsId.Block, sizeCapacity);
        }

        /// <summary>
        /// Allocates enough memory to accommodate the backing array of a ciphertext
        /// with given capacity. In addition to the capacity, the allocation size is
        /// determined by the highest-level parameters associated to the given
        /// SEALContext.
        /// </summary>
        /// <param name="context">The SEALContext</param>
        /// <param name="sizeCapacity">The capacity</param>
        /// <exception cref="ArgumentNullException">if context is null</exception>
        /// <exception cref="ArgumentException">if the context is not set or encryption
        /// parameters are not valid</exception>
        /// <exception cref="ArgumentException">if sizeCapacity is less than 2 or too large</exception>
        public void Reserve(SEALContext context, ulong sizeCapacity)
        {
            if (null == context)
                throw new ArgumentNullException(nameof(context));

            NativeMethods.Ciphertext_Reserve(NativePtr, context.NativePtr, sizeCapacity);
        }

        /// <summary>
        /// Allocates enough memory to accommodate the backing array of a ciphertext
        /// with given capacity. In addition to the capacity, the allocation size is
        /// determined by the current encryption parameters.
        /// </summary>
        /// <param name="sizeCapacity">The capacity</param>
        /// <exception cref="ArgumentException">if sizeCapacity is less than 2 or too large</exception>
        public void Reserve(ulong sizeCapacity)
        {
            NativeMethods.Ciphertext_Reserve(NativePtr, sizeCapacity);
        }

        /// <summary>
        /// Resizes the ciphertext to given size, reallocating if the capacity
        /// of the ciphertext is too small. The ciphertext parameters are
        /// determined by the given SEALContext and parmsId.
        ///
        /// This function is mainly intended for internal use and is called
        /// automatically by functions such as Evaluator::multiply and
        /// Evaluator::relinearize. A normal user should never have a reason
        /// to manually resize a ciphertext.
        /// </summary>
        /// <param name="context">The SEALContext</param>
        /// <param name="parmsId">The ParmsId corresponding to the encryption
        /// parameters to be used</param>
        /// <param name="size">The new size</param>
        /// <exception cref="ArgumentNullException">if either context or parmsId are null</exception>
        /// <exception cref="ArgumentException">if the context is not set or encryption
        /// parameters are not valid</exception>
        /// <exception cref="ArgumentException">if parmsId is not valid for the encryption
        /// parameters</exception>
        /// <exception cref="ArgumentException">if size is less than 2 or too large</exception>
        public void Resize(SEALContext context, ParmsId parmsId, ulong size)
        {
            if (null == context)
                throw new ArgumentNullException(nameof(context));
            if (null == parmsId)
                throw new ArgumentNullException(nameof(parmsId));

            NativeMethods.Ciphertext_Resize(NativePtr, context.NativePtr, parmsId.Block, size);
        }

        /// <summary>
        /// Resizes the ciphertext to given size, reallocating if the capacity
        /// of the ciphertext is too small. The ciphertext parameters are
        /// determined by the highest-level parameters associated to the given
        /// SEALContext.
        ///
        /// This function is mainly intended for internal use and is called
        /// automatically by functions such as Evaluator::multiply and
        /// Evaluator::relinearize. A normal user should never have a reason
        /// to manually resize a ciphertext.
        /// </summary>
        /// <param name="context">The SEALContext</param>
        /// <param name="size">The new size</param>
        /// <exception cref="ArgumentNullException">if context is null</exception>
        /// <exception cref="ArgumentException">if the context is not set or encryption
        /// parameters are not valid</exception>
        /// <exception cref="ArgumentException">if size is less than 2 or too large</exception>
        public void Resize(SEALContext context, ulong size)
        {
            if (null == context)
                throw new ArgumentNullException(nameof(context));

            NativeMethods.Ciphertext_Resize(NativePtr, context.NativePtr, size);
        }

        /// <summary>
        /// Resizes the ciphertext to given size, reallocating if the capacity
        /// of the ciphertext is too small.
        ///
        /// This function is mainly intended for internal use and is called
        /// automatically by functions such as Evaluator::multiply and
        /// Evaluator::relinearize. A normal user should never have a reason
        /// to manually resize a ciphertext.
        /// </summary>
        /// <param name="size">The new size</param>
        /// <exception cref="ArgumentException">if size is less than 2 or too large</exception>
        public void Resize(ulong size)
        {
            NativeMethods.Ciphertext_Resize(NativePtr, size);
        }

        /// <summary>
        /// Resizes the ciphertext to the given size, poly modulus degree and
        /// coefficient mod count. This is a helper for loading a ciphertext
        /// from a stream.
        /// </summary>
        /// <param name="size">The new size</param>
        /// <param name="polyModulusDegree">The new poly modulus degree</param>
        /// <param name="coeffModCount">The new coefficient mod count</param>
        private void Resize(ulong size, ulong polyModulusDegree, ulong coeffModCount)
        {
            NativeMethods.Ciphertext_Resize(NativePtr, size, polyModulusDegree, coeffModCount);
        }

        /// <summary>
        /// Resets the ciphertext. This function releases any memory allocated
        /// by the ciphertext, returning it to the memory pool. It also sets all
        /// encryption parameter specific size information to zero.
        /// </summary>
        public void Release()
        {
            NativeMethods.Ciphertext_Release(NativePtr);
        }

        /// <summary>
        /// Copies a given ciphertext to the current one.
        /// </summary>
        /// <param name="assign">The ciphertext to copy from</param>
        /// <exception cref="ArgumentNullException">if assign is null</exception>
        public void Set(Ciphertext assign)
        {
            if (null == assign)
                throw new ArgumentNullException(nameof(assign));

            NativeMethods.Ciphertext_Set(NativePtr, assign.NativePtr);
        }

        /// <summary>
        /// Returns the polynomial coefficient at a particular index in the ciphertext data. If the
        /// polynomial modulus has degree N, and the number of primes in the coefficient modulus is K, then
        /// the ciphertext contains size*N*K coefficients. Thus, the index has a range of [0, size*N*K).
        /// </summary>
        /// <param name="coeffIndex">The index of the coefficient</param>
        /// <exception cref="IndexOutOfRangeException">if coeffIndex is out of range</exception>
        public ulong this[ulong coeffIndex]
        {
            get
            {
                try
                {
                    NativeMethods.Ciphertext_GetDataAt(NativePtr, coeffIndex, out ulong value);
                    return value;
                }
                catch (COMException ex)
                {
                    if ((uint)ex.HResult == NativeMethods.Errors.HRInvalidIndex)
                        throw new IndexOutOfRangeException(nameof(coeffIndex), ex);
                    throw;
                }
            }

            set
            {
                try
                {
                    NativeMethods.Ciphertext_SetDataAt(NativePtr, coeffIndex, value);
                }
                catch (COMException ex)
                {
                    if ((uint)ex.HResult == NativeMethods.Errors.HRInvalidIndex)
                        throw new IndexOutOfRangeException(nameof(coeffIndex), ex);
                    throw;
                }
            }
        }

        /// <summary>
        /// Get the value of a coefficient at the given index from
        /// a particular polynomial in the ciphertext
        /// data. Note that Microsoft SEAL stores each polynomial in the ciphertext
        /// modulo all of the K primes in the coefficient modulus. The data
        /// returned by this function is to the beginning (constant coefficient)
        /// of the first one of these K polynomials.
        /// </summary>
        /// <param name="polyIndex">The index of the polynomial in the ciphertext</param>
        /// <param name="coeffIndex">The index of the polynomial data</param>
        /// <exception cref="IndexOutOfRangeException">if polyIndex is less than 0 or bigger
        /// than the size of the ciphertext</exception>
        /// <exception cref="IndexOutOfRangeException">if coeffIndex is less than 0 or bigger
        /// than the size of the ciphertext</exception>
        public ulong this[ulong polyIndex, ulong coeffIndex]
        {
            get
            {
                try
                {
                    NativeMethods.Ciphertext_GetDataAt(NativePtr, polyIndex, coeffIndex, out ulong data);
                    return data;
                }
                catch(COMException ex)
                {
                    if ((uint)ex.HResult == NativeMethods.Errors.HRInvalidIndex)
                        throw new IndexOutOfRangeException("polyIndex or coeffIndex out of range", ex);
                    throw;
                }
            }
        }

        /// <summary>
        /// Returns the number of primes in the coefficient modulus of the
        /// associated encryption parameters. This directly affects the
        /// allocation size of the ciphertext.
        /// </summary>
        public ulong CoeffModulusSize
        {
            get
            {
                NativeMethods.Ciphertext_CoeffModulusSize(NativePtr, out ulong coeffModCount);
                return coeffModCount;
            }
        }


        /// <summary>
        /// Returns the degree of the polynomial modulus of the associated
        /// encryption parameters.This directly affects the allocation size
        /// of the ciphertext.
        /// </summary>
        public ulong PolyModulusDegree
        {
            get
            {
                NativeMethods.Ciphertext_PolyModulusDegree(NativePtr, out ulong polyModulusDegree);
                return polyModulusDegree;
            }
        }

        /// <summary>
        /// Returns the capacity of the allocation. This means the largest size
        /// of the ciphertext that can be stored in the current allocation with
        /// the current encryption parameters.
        /// </summary>
        public ulong SizeCapacity
        {
            get
            {
                NativeMethods.Ciphertext_SizeCapacity(NativePtr, out ulong sizeCapacity);
                return sizeCapacity;
            }
        }

        /// <summary>
        /// Returns the size of the ciphertext.
        /// </summary>
        public ulong Size
        {
            get
            {
                NativeMethods.Ciphertext_Size(NativePtr, out ulong size);
                return size;
            }
        }

        /// <summary>
        /// Check whether the current ciphertext is transparent, i.e. does not require
        /// a secret key to decrypt. In typical security models such transparent
        /// ciphertexts would not be considered to be valid. Starting from the second
        /// polynomial in the current ciphertext, this function returns true if all
        /// following coefficients are identically zero. Otherwise, returns false.
        /// </summary>
        public bool IsTransparent
        {
            get
            {
                NativeMethods.Ciphertext_IsTransparent(NativePtr, out bool result);
                return result;
            }
        }

        /// <summary>
        /// Returns an upper bound on the size of the ciphertext, as if it was written
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
            NativeMethods.Ciphertext_SaveSize(
                NativePtr, (byte)comprModeValue, out long outBytes);
            return outBytes;
        }

        /// <summary>Saves the ciphertext to an output stream.</summary>
        /// <remarks>
        /// Saves the ciphertext to an output stream. The output is in binary format
        /// and not human-readable.
        /// </remarks>
        /// <param name="stream">The stream to save the ciphertext to</param>
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
                    NativeMethods.Ciphertext_Save(NativePtr, outptr, size,
                    cm, out outBytes),
                SaveSize(comprModeValue), comprModeValue, stream);
        }

        /// <summary>Loads a ciphertext from an input stream overwriting the current
        /// ciphertext.</summary>
        /// <remarks>
        /// Loads a ciphertext from an input stream overwriting the current ciphertext.
        /// No checking of the validity of the ciphertext data against encryption
        /// parameters is performed. This function should not be used unless the
        /// ciphertext comes from a fully trusted source.
        /// </remarks>
        /// <param name="context">The SEALContext</param>
        /// <param name="stream">The stream to load the ciphertext from</param>
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
                    NativeMethods.Ciphertext_UnsafeLoad(NativePtr, context.NativePtr,
                    outptr, size, out outBytes),
                stream);
        }

        /// <summary>Loads a ciphertext from an input stream overwriting the current
        /// ciphertext.</summary>
        /// <remarks>
        /// Loads a ciphertext from an input stream overwriting the current ciphertext.
        /// The loaded ciphertext is verified to be valid for the given SEALContext.
        /// </remarks>
        /// <param name="context">The SEALContext</param>
        /// <param name="stream">The stream to load the ciphertext from</param>
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
                    NativeMethods.Ciphertext_Load(NativePtr, context.NativePtr,
                    outptr, size, out outBytes),
                stream);
        }

        /// <summary>
        /// Returns whether the ciphertext is in NTT form.
        /// </summary>
        public bool IsNTTForm
        {
            get
            {
                NativeMethods.Ciphertext_IsNTTForm(NativePtr, out bool isNTTForm);
                return isNTTForm;
            }

            private set
            {
                NativeMethods.Ciphertext_SetIsNTTForm(NativePtr, value);
            }
        }

        /// <summary>
        /// Returns a copy of ParmsId.
        /// </summary>
        public ParmsId ParmsId
        {
            get
            {
                ParmsId parmsId = new ParmsId();
                NativeMethods.Ciphertext_ParmsId(NativePtr, parmsId.Block);
                return parmsId;
            }
            private set
            {
                NativeMethods.Ciphertext_SetParmsId(NativePtr, value.Block);
            }
        }

        /// <summary>
        /// Returns a reference to the scale. This is only needed when using the
        /// CKKS encryption scheme. The user should have little or no reason to ever
        /// change the scale by hand.
        /// </summary>
        public double Scale
        {
            get
            {
                NativeMethods.Ciphertext_Scale(NativePtr, out double scale);
                return scale;
            }
            set
            {
                NativeMethods.Ciphertext_SetScale(NativePtr, value);
            }
        }

        /// <summary>
        /// Returns the currently used MemoryPoolHandle.
        /// </summary>
        public MemoryPoolHandle Pool
        {
            get
            {
                NativeMethods.Ciphertext_Pool(NativePtr, out IntPtr pool);
                MemoryPoolHandle handle = new MemoryPoolHandle(pool);
                return handle;
            }
        }

        /// <summary>
        /// Destroy native object.
        /// </summary>
        protected override void DestroyNativeObject()
        {
            NativeMethods.Ciphertext_Destroy(NativePtr);
        }
    }
}
