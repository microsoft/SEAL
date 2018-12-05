using Microsoft.Research.SEAL;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using System.Collections.Generic;
using System.Text;

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
        }
    }
}
