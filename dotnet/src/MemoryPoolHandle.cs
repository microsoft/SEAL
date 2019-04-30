// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

using Microsoft.Research.SEAL.Tools;
using System;
using System.Runtime.InteropServices;

namespace Microsoft.Research.SEAL
{
    /// <summary>
    /// Manages a shared pointer to a memory pool. Microsoft SEAL uses memory pools for
    /// improved performance due to the large number of memory allocations needed
    /// by the homomorphic encryption operations, and the underlying polynomial
    /// arithmetic. The library automatically creates a shared global memory pool
    /// that is used for all dynamic allocations by default, and the user can
    /// optionally create any number of custom memory pools to be used instead.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Uses in Multi-Threaded Applications
    /// Sometimes the user might want to use specific memory pools for dynamic
    /// allocations in certain functions. For example, in heavily multi-threaded
    /// applications allocating concurrently from a shared memory pool might lead
    /// to significant performance issues due to thread contention. For these cases
    /// Microsoft SEAL provides overloads of the functions that take a MemoryPoolHandle as an
    /// additional argument, and uses the associated memory pool for all dynamic
    /// allocations inside the function. Whenever this functions is called, the
    /// user can then simply pass a thread-local MemoryPoolHandle to be used.
    /// </para>
    /// <para>
    /// Thread-Unsafe Memory Pools
    /// While memory pools are by default thread-safe, in some cases it suffices
    /// to have a memory pool be thread-unsafe. To get a little extra performance,
    /// the user can optionally create such thread-unsafe memory pools and use them
    /// just as they would use thread-safe memory pools.
    /// </para>
    /// <para>
    /// Initialized and Uninitialized Handles
    /// A MemoryPoolHandle has to be set to point either to the global memory pool,
    /// or to a new memory pool. If this is not done, the MemoryPoolHandle is
    /// said to be uninitialized, and cannot be used. Initialization simple means
    /// assigning MemoryPoolHandle::Global() or MemoryPoolHandle::New() to it.
    /// </para>
    /// <para>
    /// Managing Lifetime
    /// Internally, the MemoryPoolHandle wraps a C++ shared pointer pointing to
    /// a memory pool class. Thus, as long as a MemoryPoolHandle pointing to
    /// a particular memory pool exists, the pool stays alive. Classes such as
    /// Evaluator and Ciphertext store their own local copies of a MemoryPoolHandle
    /// to guarantee that the pool stays alive as long as the managing object
    /// itself stays alive. The global memory pool is implemented as a global
    /// C++ std::shared_ptr to a memory pool class, and is thus expected to stay
    /// alive for the entire duration of the program execution. Note that it can
    /// be problematic to create other global objects that use the memory pool
    /// e.g. in their constructor, as one would have to ensure the initialization
    /// order of these global variables to be correct (i.e. global memory pool
    /// first).
    /// </para>
    /// </remarks>
    public class MemoryPoolHandle : NativeObject
    {
        /// <summary>
        /// Creates a new uninitialized MemoryPoolHandle.
        /// </summary>
        public MemoryPoolHandle()
        {
            NativeMethods.MemoryPoolHandle_Create(out IntPtr handlePtr);
            NativePtr = handlePtr;
        }

        /// <summary>
        /// Creates a copy of a given MemoryPoolHandle. As a result, the created
        /// MemoryPoolHandle will point to the same underlying memory pool as the
        /// copied instance.
        /// </summary>
        /// <param name="copy">The MemoryPoolHandle to copy from.</param>
        /// <exception cref="ArgumentNullException">if copy is null.</exception>
        public MemoryPoolHandle(MemoryPoolHandle copy)
        {
            if (null == copy)
                throw new ArgumentNullException(nameof(copy));

            NativeMethods.MemoryPoolHandle_Create(copy.NativePtr, out IntPtr handlePtr);
            NativePtr = handlePtr;
        }

        /// <summary>
        /// Create a MemoryPoolHandle through a native object pointer.
        /// </summary>
        /// <param name="ptr">Pointer to native MemoryPoolHandle</param>
        /// <param name="owned">Whether this instance owns the native pointer</param>
        internal MemoryPoolHandle(IntPtr ptr, bool owned = true)
            : base(ptr, owned)
        {
        }

        /// <summary>
        /// Overwrites the MemoryPoolHandle instance with the specified instance. As
        /// a result, the current MemoryPoolHandle will point to the same underlying
        /// memory pool as the assigned instance.
        /// </summary>
        /// <param name="assign">The MemoryPoolHandle instance to assign to the current
        /// instance</param>
        /// <exception cref="ArgumentNullException">if assign is null.</exception>
        public void Set(MemoryPoolHandle assign)
        {
            if (null == assign)
                throw new ArgumentNullException(nameof(assign));

            NativeMethods.MemoryPoolHandle_Set(NativePtr, assign.NativePtr);
        }

        /// <summary>
        /// Returns a MemoryPoolHandle pointing to the global memory pool.
        /// </summary>
        public static MemoryPoolHandle Global()
        {
            NativeMethods.MemoryPoolHandle_Global(out IntPtr handlePtr);
            MemoryPoolHandle handle = new MemoryPoolHandle(handlePtr);
            return handle;
        }

        /// <summary>
        /// Returns a MemoryPoolHandle pointing to the thread-local memory pool.
        /// </summary>
        public static MemoryPoolHandle ThreadLocal()
        {
            NativeMethods.MemoryPoolHandle_ThreadLocal(out IntPtr handlePtr);
            MemoryPoolHandle handle = new MemoryPoolHandle(handlePtr);
            return handle;
        }

        /// <summary>
        /// Returns a MemoryPoolHandle pointing to a new thread-safe memory pool.
        /// </summary>
        /// <param name="clearOnDestruction">Indicates whether the memory pool data
        /// should be cleared when destroyed.This can be important when memory pools
        /// are used to store private data.</param>
        public static MemoryPoolHandle New(bool clearOnDestruction = false)
        {
            NativeMethods.MemoryPoolHandle_New(clearOnDestruction, out IntPtr handlePtr);
            MemoryPoolHandle handle = new MemoryPoolHandle(handlePtr);
            return handle;
        }

        /// <summary>
        /// Returns the number of different allocation sizes.
        /// </summary>
        /// <remarks>
        /// This function returns the number of different allocation sizes the memory
        /// pool pointed to by the current MemoryPoolHandle has made. For example,
        /// if the memory pool has only allocated two allocations of sizes 128 KB,
        /// this function returns 1. If it has instead allocated one allocation of
        /// size 64 KB and one of 128 KB, this functions returns 2.
        /// </remarks>
        public ulong PoolCount
        {
            get
            {
                NativeMethods.MemoryPoolHandle_PoolCount(NativePtr, out ulong count);
                return count;
            }
        }

        /// <summary>
        /// Returns the size of allocated memory.
        /// </summary>
        /// <remarks>
        /// This functions returns the total amount of memory (in bytes) allocated
        /// by the memory pool pointed to by the current MemoryPoolHandle.
        /// </remarks>
        public ulong AllocByteCount
        {
            get
            {
                NativeMethods.MemoryPoolHandle_AllocByteCount(NativePtr, out ulong count);
                return count;
            }
        }

        /// <summary>
        /// Returns the number of MemoryPoolHandle objects sharing this memory pool.
        /// </summary>
        public long UseCount
        {
            get
            {
                NativeMethods.MemoryPoolHandle_UseCount(NativePtr, out long count);
                return count;
            }
        }

        /// <summary>
        /// Returns whether the MemoryPoolHandle is initialized.
        /// </summary>
        public bool IsInitialized
        {
            get
            {
                NativeMethods.MemoryPoolHandle_IsInitialized(NativePtr, out bool result);
                return result;
            }
        }

        /// <summary>
        /// Compares MemoryPoolHandles. This function returns whether the current
        /// MemoryPoolHandle points to the same memory pool as a given MemoryPoolHandle.
        /// </summary>
        /// <param name="obj">Object to compare to.</param>
        public override bool Equals(object obj)
        {
            MemoryPoolHandle other = obj as MemoryPoolHandle;
            if (null == other)
                return false;

            NativeMethods.MemoryPoolHandle_Equals(NativePtr, other.NativePtr, out bool result);
            return result;
        }

        /// <summary>
        /// Get hash code for this MemoryPoolHandle
        /// </summary>
        public override int GetHashCode()
        {
            return base.GetHashCode();
        }

        /// <summary>
        /// Destroy native object.
        /// </summary>
        protected override void DestroyNativeObject()
        {
            NativeMethods.MemoryPoolHandle_Destroy(NativePtr);
        }
    }
}