using System;
using System.Collections.Generic;
using System.Text;

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
            Owned = true;
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
            Owned = owned;
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

            if (Owned && !IntPtr.Zero.Equals(NativePtr))
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
        internal bool Owned
        {
            get;
            set;
        }
    }
}
