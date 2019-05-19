// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

using Microsoft.Research.SEAL;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;

namespace SEALNetTest
{
    [TestClass]
    public class MemoryPoolHandleTests
    {
        [TestMethod]
        public void CreateTest()
        {
            MemoryPoolHandle handle = MemoryManager.GetPool();
            Assert.IsNotNull(handle);
            Assert.IsTrue(handle.IsInitialized);

            MemoryPoolHandle handle2 = new MemoryPoolHandle(handle);
            Assert.IsTrue(handle2.IsInitialized);
            Assert.AreEqual(handle.PoolCount, handle2.PoolCount);
            Assert.AreEqual(handle.AllocByteCount, handle2.AllocByteCount);

            MemoryPoolHandle handle5 = new MemoryPoolHandle();
            handle5.Set(handle);
            Assert.IsTrue(handle5.IsInitialized);
            Assert.AreEqual(handle.PoolCount, handle5.PoolCount);
            Assert.AreEqual(handle.AllocByteCount, handle5.AllocByteCount);

            MemoryPoolHandle handle3 = MemoryManager.GetPool(MMProfOpt.ForceNew, clearOnDestruction: true);
            Assert.IsNotNull(handle3);
            Assert.AreEqual(0ul, handle3.PoolCount);
            Assert.AreEqual(0ul, handle3.AllocByteCount);

            MemoryPoolHandle handle4 = MemoryManager.GetPool(MMProfOpt.ForceThreadLocal);
            Assert.IsNotNull(handle4);
            Assert.AreEqual(0ul, handle4.PoolCount);
            Assert.AreEqual(0ul, handle4.AllocByteCount);
        }

        [TestMethod]
        public void EqualsTest()
        {
            MemoryPoolHandle handle1 = MemoryManager.GetPool(MMProfOpt.ForceNew);
            MemoryPoolHandle handle2 = MemoryManager.GetPool(MMProfOpt.Default);
            MemoryPoolHandle handle3 = MemoryManager.GetPool();

            Assert.IsNotNull(handle1);
            Assert.IsNotNull(handle2);
            Assert.IsNotNull(handle3);

            Assert.AreNotEqual(handle1, handle2);
            Assert.AreNotEqual(handle1, handle3);
            Assert.AreEqual(handle2, handle3);

            Assert.AreNotEqual(handle1.GetHashCode(), handle2.GetHashCode());

            Assert.IsFalse(handle3.Equals(null));
        }

        [TestMethod]
        public void StaticMethodsTest()
        {
            MemoryPoolHandle handle1 = MemoryPoolHandle.Global();
            Assert.IsNotNull(handle1);

            MemoryPoolHandle handle2 = MemoryPoolHandle.New(clearOnDestruction: true);
            Assert.IsNotNull(handle2);

            MemoryPoolHandle handle3 = MemoryPoolHandle.ThreadLocal();
            Assert.IsNotNull(handle3);
        }

        [TestMethod]
        public void UseCountTest()
        {
            MemoryPoolHandle pool = MemoryPoolHandle.New();
            Assert.AreEqual(1L, pool.UseCount);
            Plaintext plain = new Plaintext(pool);
            Assert.AreEqual(2L, pool.UseCount);
            Plaintext plain2 = new Plaintext(pool);
            Assert.AreEqual(3L, pool.UseCount);
            plain.Dispose();
            plain2.Dispose();
            Assert.AreEqual(1L, pool.UseCount);
        }

        [TestMethod]
        public void ExceptionsTest()
        {
            MemoryPoolHandle handle = new MemoryPoolHandle();

            Assert.ThrowsException<ArgumentNullException>(() => handle = new MemoryPoolHandle(null));

            Assert.ThrowsException<ArgumentNullException>(() => handle.Set(null));
        }
    }
}