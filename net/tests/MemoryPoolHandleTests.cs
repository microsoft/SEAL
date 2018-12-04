using Microsoft.Research.SEAL;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using System.Collections.Generic;
using System.Text;

namespace SEALNetTest
{
    [TestClass]
    public class MemoryPoolHandleTests
    {
        [TestMethod]
        [ExpectedException(typeof(InvalidOperationException))]
        public void PoolCountUninitializedTest()
        {
            MemoryPoolHandle handle = new MemoryPoolHandle();
            Assert.IsFalse(handle.IsInitialized);
            ulong count = handle.PoolCount;
        }

        [TestMethod]
        [ExpectedException(typeof(InvalidOperationException))]
        public void AllocByteCountUninitializedTest()
        {
            MemoryPoolHandle handle = new MemoryPoolHandle();
            Assert.IsFalse(handle.IsInitialized);
            ulong count = handle.AllocByteCount;
        }

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
        }
    }
}
