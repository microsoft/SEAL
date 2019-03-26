// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

using System;

namespace Microsoft.Research.SEAL.Tools
{
    /// <summary>
    /// Class that encapsulates the behavior of a class backed by a
    /// pointer to a native object.
    ///
    /// In particular, this class encapsulates the correct disposal
    /// of the native pointer.
    /// </summary>
    public abstract class NativeObject : DisposableObject
    {
        /// <summary>
        /// Construct a NativeObject instance
        /// </summary>
        public NativeObject()
        {
            NativePtr = IntPtr.Zero;
            owned_ = true;
        }

        /// <summary>
        /// Construct a NativeObject instance initializing it with a pointer
        /// to a native object.
        /// </summary>
        /// <param name="nativePtr">Pointer to native object.</param>
        /// <param name="owned">Whether this instance owns the native pointer.</param>
        public NativeObject(IntPtr nativePtr, bool owned = true)
        {
            NativePtr = nativePtr;
            owned_ = owned;
        }

        /// <summary>
        /// Descendants should call the appropriate method to
        /// destroy the backing native object.
        /// </summary>
        protected abstract void DestroyNativeObject();

        /// <summary>
        /// Destroy native object if necessary
        /// </summary>
        protected override void DisposeNativeResources()
        {
            base.DisposeNativeResources();

            if (owned_ && !IntPtr.Zero.Equals(NativePtr))
            {
                DestroyNativeObject();
            }

            NativePtr = IntPtr.Zero;
        }

        /// <summary>
        /// Get/Set pointer to native object
        /// </summary>
        internal IntPtr NativePtr
        {
            get;
            set;
        }

        /// <summary>
        /// Whether this instance owns the native pointer.
        /// </summary>
        private readonly bool owned_ = true;
    }
}
