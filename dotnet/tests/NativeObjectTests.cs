// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

using Microsoft.Research.SEAL;
using Microsoft.Research.SEAL.Tools;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using System.Collections.Generic;
using System.Text;

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
    }
}
