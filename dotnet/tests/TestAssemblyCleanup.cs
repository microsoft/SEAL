using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Text;

namespace SEALNetTest
{
    [TestClass]
    public class TestAssemblyCleanup
    {
        [AssemblyCleanup]
        public static void AssemblyCleanup()
        {
            // Check that our Assert.Throw workaround is not getting out of hand
            Assert.IsTrue(Utilities.WorkaroundInstanceCount <= 2, $"WorkaroundInstanceCount should be <= 2, it is: {Utilities.WorkaroundInstanceCount}");
            Trace.WriteLine($"Assert.Throw workaround instances found: {Utilities.WorkaroundInstanceCount}");
        }
    }
}
