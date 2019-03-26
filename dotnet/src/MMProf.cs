// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

using Microsoft.Research.SEAL.Tools;
using System;

namespace Microsoft.Research.SEAL
{
    /// <summary>
    /// The MMProf is a pure virtual class that every profile for the MemoryManager
    /// should inherit from. The only functionality this class implements is the
    /// GetPool() function that returns a MemoryPoolHandle pointing
    /// to a pool selected by internal logic. The returned MemoryPoolHandle must
    /// point to a valid memory pool.
    /// </summary>
    public abstract class MMProf : NativeObject
    {
        /// <summary>
        /// Returns a MemoryPoolHandle pointing to a pool selected by internal logic
        /// in a derived class.
        /// </summary>
        public MemoryPoolHandle GetPool()
        {
            NativeMethods.MMProf_GetPool(NativePtr, out IntPtr pool);
            MemoryPoolHandle handle = new MemoryPoolHandle(pool);
            return handle;
        }

        /// <summary>
        /// Destroy native backing object.
        /// </summary>
        protected override void DestroyNativeObject()
        {
            NativeMethods.MMProf_Destroy(NativePtr);
        }
    }

    /// <summary>
    /// A memory manager profile that always returns a MemoryPoolHandle pointing to
    /// the global memory pool. Microsoft SEAL uses this memory manager profile by default.
    /// </summary>
    public class MMProfGlobal : MMProf
    {
        /// <summary>
        /// Create a new instance of MMProfGlobal
        /// </summary>
        public MMProfGlobal()
        {
            NativeMethods.MMProf_CreateGlobal(out IntPtr profile);
            NativePtr = profile;
        }
    }

    /// <summary>
    /// A memory manager profile that always returns a MemoryPoolHandle pointing to
    /// specific memory pool.
    /// </summary>
    public class MMProfFixed : MMProf
    {
        /// <summary>
        /// Create a new instance of MMProfFixed
        /// </summary>
        /// <param name="pool">Fixed memory pool handle to use</param>
        /// <exception cref="ArgumentNullException">if pool is null</exception>
        public MMProfFixed(MemoryPoolHandle pool)
        {
            if (null == pool)
                throw new ArgumentNullException(nameof(pool));

            // Create a copy of MemoryPoolHandle, as the profile will take ownership
            // of the pointer and will attempt to delete it when destroyed.
            NativeMethods.MemoryPoolHandle_Create(pool.NativePtr, out IntPtr poolCopy);
            NativeMethods.MMProf_CreateFixed(poolCopy, out IntPtr profile);
            NativePtr = profile;
        }
    }

    /// <summary>
    /// A memory manager profile that always returns a MemoryPoolHandle pointing to
    /// the new thread-safe memory pool. This profile should not be used except in
    /// special circumstances, as it does not result in any reuse of allocated memory.
    /// </summary>
    public class MMProfNew : MMProf
    {
        /// <summary>
        /// Create a new instance of MMProfNew
        /// </summary>
        public MMProfNew()
        {
            NativeMethods.MMProf_CreateNew(out IntPtr profile);
            NativePtr = profile;
        }
    }

    /// <summary>
    /// A memory manager profile that always returns a MemoryPoolHandle pointing to
    /// the thread-local memory pool. This profile should be used with care, as any
    /// memory allocated by it will be released once the thread exits. In other words,
    /// the thread-local memory pool cannot be used to share memory across different
    /// threads. On the other hand, this profile can be useful when a very high number
    /// of threads doing simultaneous allocations would cause contention in the
    /// global memory pool.
    /// </summary>
    public class MMProfThreadLocal : MMProf
    {
        /// <summary>
        /// Create a new instance of MMProfThreadLocal
        /// </summary>
        public MMProfThreadLocal()
        {
            NativeMethods.MMProf_CreateThreadLocal(out IntPtr profile);
            NativePtr = profile;
        }
    }
}
