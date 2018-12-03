using System;
using System.Collections.Generic;
using System.Text;

namespace Microsoft.Research.SEAL.Tools
{
    public class DisposableObject : IDisposable
    {
        protected virtual void DisposeManagedResources()
        {
            // Derived classes will override this behavior.
        }

        protected virtual void DisposeNativeResources()
        {
            // Derived classes will override this behavior.
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

        ~DisposableObject()
        {
            // Do not change this code. Put cleanup code in Dispose(bool disposing) above.
            Dispose(false);
        }

        // This code added to correctly implement the disposable pattern.
        public void Dispose()
        {
            // Do not change this code. Put cleanup code in Dispose(bool disposing) above.
            Dispose(true);
            GC.SuppressFinalize(this);
        }

        #endregion
    }
}
