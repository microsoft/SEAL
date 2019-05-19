// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

using Microsoft.Research.SEAL;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace SEALNetTest
{
    [TestClass]
    public class MemoryManagerTests
    {
        [TestMethod]
        public void SwitchProfileTest()
        {
            MemoryPoolHandle handle = MemoryManager.GetPool(MMProfOpt.ForceNew);
            MMProfFixed fixedProfile = new MMProfFixed(handle);

            MMProf oldProfile = MemoryManager.SwitchProfile(fixedProfile);
            Assert.IsInstanceOfType(oldProfile, typeof(MMProfGlobal));

            MMProfNew newProfile = new MMProfNew();
            oldProfile = MemoryManager.SwitchProfile(newProfile);

            Assert.IsInstanceOfType(oldProfile, typeof(MMProfFixed));

            MMProfGlobal globalProfile = new MMProfGlobal();
            oldProfile = MemoryManager.SwitchProfile(globalProfile);

            Assert.IsInstanceOfType(oldProfile, typeof(MMProfNew));

            MemoryPoolHandle globalHandle = globalProfile.GetPool();
            Assert.IsNotNull(globalHandle);
            Assert.IsTrue(globalHandle.IsInitialized);
        }
    }
}