// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

using Microsoft.Research.SEAL;
using System;
using System.Collections.Generic;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace SEALNetTest
{
    [TestClass]
    public class ModulusTests
    {
        [TestMethod]
        public void CreateTest()
        {
            List<SmallModulus> cm = (List<SmallModulus>)CoeffModulus.Create(2, new int[]{ });
            Assert.AreEqual(0, cm.Count);

            cm = (List<SmallModulus>)CoeffModulus.Create(2, new int[] { 3 });
            Assert.AreEqual(1, cm.Count);
            Assert.AreEqual(5ul, cm[0].Value);

            cm = (List<SmallModulus>)CoeffModulus.Create(2, new int[] { 3, 4 });
            Assert.AreEqual(2, cm.Count);
            Assert.AreEqual(5ul, cm[0].Value);
            Assert.AreEqual(13ul, cm[1].Value);

            cm = (List<SmallModulus>)CoeffModulus.Create(2, new int[] { 3, 5, 4, 5 });
            Assert.AreEqual(4, cm.Count);
            Assert.AreEqual(5ul, cm[0].Value);
            Assert.AreEqual(17ul, cm[1].Value);
            Assert.AreEqual(13ul, cm[2].Value);
            Assert.AreEqual(29ul, cm[3].Value);

            cm = (List<SmallModulus>)CoeffModulus.Create(32, new int[] { 30, 40, 30, 30, 40 });
            Assert.AreEqual(5, cm.Count);
            Assert.AreEqual(30, (int)(Math.Log(cm[0].Value, 2)) + 1);
            Assert.AreEqual(40, (int)(Math.Log(cm[1].Value, 2)) + 1);
            Assert.AreEqual(30, (int)(Math.Log(cm[2].Value, 2)) + 1);
            Assert.AreEqual(30, (int)(Math.Log(cm[3].Value, 2)) + 1);
            Assert.AreEqual(40, (int)(Math.Log(cm[4].Value, 2)) + 1);
            Assert.AreEqual(1ul, cm[0].Value % 64);
            Assert.AreEqual(1ul, cm[1].Value % 64);
            Assert.AreEqual(1ul, cm[2].Value % 64);
            Assert.AreEqual(1ul, cm[3].Value % 64);
            Assert.AreEqual(1ul, cm[4].Value % 64);
        }

        [TestMethod]
        public void ExceptionsTest()
        {
            // Too small polyModulusDegree
            Assert.ThrowsException<ArgumentException>(() => CoeffModulus.Create(1, new int[] { 2 }));

            // Too large polyModulusDegree
            Assert.ThrowsException<ArgumentException>(() => CoeffModulus.Create(65536, new int[] { 30 }));

            // Invalid polyModulusDegree
            Assert.ThrowsException<ArgumentException>(() => CoeffModulus.Create(1023, new int[] { 20 }));

            // Invalid bitSize
            Assert.ThrowsException<ArgumentException>(() => CoeffModulus.Create(2048, new int[] { 0 }));
            Assert.ThrowsException<ArgumentException>(() => CoeffModulus.Create(2048, new int[] { -30 }));
            Assert.ThrowsException<ArgumentException>(() => CoeffModulus.Create(2048, new int[] { 30, -30 }));

            // Too small primes requested
            Assert.ThrowsException<InvalidOperationException>(() => CoeffModulus.Create(2, new int[] { 2 }));
            Assert.ThrowsException<InvalidOperationException>(() => CoeffModulus.Create(2, new int[] { 3, 3, 3 }));
            Assert.ThrowsException<InvalidOperationException>(() => CoeffModulus.Create(1024, new int[] { 8 }));
        }
    }
}
