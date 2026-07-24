// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

using System;
using System.Threading;

namespace Microsoft.Research.SEAL.Tools
{
    /// <summary>
    /// Class that implements the Disposable pattern
    /// </summary>
    public class DisposableObject : IDisposable
    {
        /// <summary>
        /// Derived classes should override this method to release managed resources.
        /// </summary>
        protected virtual void DisposeManagedResources()
        {
        }

        /// <summary>
        /// Derived classes should override this method to release native resources.
        /// </summary>
        protected virtual void DisposeNativeResources()
        {
        }

        /// <summary>
        /// Whether this object is disposed
        /// </summary>
        public bool IsDisposed
        {
            get
            {
                return disposedValue;
            }
        }

        #region IDisposable Support

        // Claims the right to run disposal exactly once, atomically, so that concurrent
        // Dispose calls (or a Dispose racing the finalizer) release the native resource a
        // single time and cannot double-free it.
        private int disposeRequested = 0;
        private bool disposedValue = false; // Set to true once disposal has completed

        private void Dispose(bool disposing)
        {
            if (Interlocked.Exchange(ref disposeRequested, 1) != 0)
            {
                return;
            }

            if (disposing)
            {
                DisposeManagedResources();
            }

            DisposeNativeResources();

            disposedValue = true;
        }

        /// <summary>
        /// DisposableObject destructor
        /// </summary>
        ~DisposableObject()
        {
            // Do not change this code. Put cleanup code in Dispose(bool disposing) above.
            Dispose(false);
        }

        /// <summary>
        /// This code is added to correctly implement the disposable pattern.
        /// </summary>
        public void Dispose()
        {
            // Do not change this code. Put cleanup code in Dispose(bool disposing) above.
            Dispose(true);
            GC.SuppressFinalize(this);
        }

        #endregion
    }
}
