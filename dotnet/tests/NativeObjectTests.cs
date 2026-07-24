// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

using Microsoft.Research.SEAL;
using Microsoft.Research.SEAL.Tools;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using System.Collections.Generic;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace SEALNetTest
{
    [TestClass]
    public class NativeObjectTests
    {
        [TestMethod]
        public void IsDisposedTest()
        {
            Ciphertext cipher = new Ciphertext();
            Assert.IsNotNull(cipher);
            Assert.AreEqual(0ul, cipher.Size);
            Assert.AreEqual(0ul, cipher.PolyModulusDegree);
            Assert.AreEqual(0ul, cipher.CoeffModulusSize);

            // After disposing object, accessing any field should fail.
            cipher.Dispose();
            Utilities.AssertThrows<ObjectDisposedException>(() => cipher.Size);
            Utilities.AssertThrows<ObjectDisposedException>(() => cipher.PolyModulusDegree);
            Utilities.AssertThrows<ObjectDisposedException>(() => cipher.CoeffModulusSize);
            Utilities.AssertThrows<ObjectDisposedException>(() => cipher.IsTransparent);
            Utilities.AssertThrows<ObjectDisposedException>(() => cipher.IsNTTForm);
        }

        [TestMethod]
        public void DisposeIsIdempotentTest()
        {
            CountingDisposable obj = new CountingDisposable();

            // Many concurrent Dispose calls must release native resources exactly once.
            Parallel.For(0, 64, i => obj.Dispose());
            Assert.AreEqual(1, obj.NativeDisposeCount);
            Assert.IsTrue(obj.IsDisposed);

            // A subsequent Dispose is a no-op.
            obj.Dispose();
            Assert.AreEqual(1, obj.NativeDisposeCount);
        }

        private sealed class CountingDisposable : DisposableObject
        {
            private int nativeDisposeCount = 0;

            public int NativeDisposeCount => Volatile.Read(ref nativeDisposeCount);

            protected override void DisposeNativeResources()
            {
                // Widen the window between the dispose guard and its completion so that a
                // non-idempotent Dispose would let more than one caller reach this point.
                Thread.Sleep(50);
                Interlocked.Increment(ref nativeDisposeCount);
            }
        }
    }
}
