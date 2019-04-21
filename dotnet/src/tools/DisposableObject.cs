// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

using System;

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
            // Derived classes will override this behavior.
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

        private bool disposedValue = false; // To detect redundant calls

        private void Dispose(bool disposing)
        {
            if (!disposedValue)
            {
                if (disposing)
                {
                    DisposeManagedResources();
                }

                DisposeNativeResources();

                disposedValue = true;
            }
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
