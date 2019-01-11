// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

using Microsoft.Research.SEAL;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using System.Collections.Generic;

namespace SEALNetTest
{
    [TestClass]
    public class DefaultParamsTests
    {
        [TestMethod]
        public void Coeffs128Test()
        {
            List<SmallModulus> coeffs = new List<SmallModulus>(DefaultParams.CoeffModulus128(4096));

            Assert.IsNotNull(coeffs);
            Assert.AreEqual(2, coeffs.Count);
            Assert.AreEqual(0x007fffffff380001ul, coeffs[0].Value);
            Assert.AreEqual(0x003fffffff000001ul, coeffs[1].Value);

            coeffs = new List<SmallModulus>(DefaultParams.CoeffModulus128(16384));

            Assert.IsNotNull(coeffs);
            Assert.AreEqual(8, coeffs.Count);
            Assert.AreEqual(0x007fffffff380001ul, coeffs[0].Value);
            Assert.AreEqual(0x007ffffffef00001ul, coeffs[1].Value);
            Assert.AreEqual(0x007ffffffeac0001ul, coeffs[2].Value);
            Assert.AreEqual(0x007ffffffe700001ul, coeffs[3].Value);
            Assert.AreEqual(0x007ffffffe600001ul, coeffs[4].Value);
            Assert.AreEqual(0x007ffffffe4c0001ul, coeffs[5].Value);
            Assert.AreEqual(0x003fffffff000001ul, coeffs[6].Value);
            Assert.AreEqual(0x003ffffffef40001ul, coeffs[7].Value);
        }

        [TestMethod]
        [ExpectedException(typeof(ArgumentOutOfRangeException))]
        public void Coeffs128FailTest()
        {
            IEnumerable<SmallModulus> coeffs = DefaultParams.CoeffModulus128(1030);
        }

        [TestMethod]
        public void Coeffs192Test()
        {
            List<SmallModulus> coeffs = new List<SmallModulus>(DefaultParams.CoeffModulus192(4096));

            Assert.IsNotNull(coeffs);
            Assert.AreEqual(2, coeffs.Count);
            Assert.AreEqual(0x0000003fffe80001ul, coeffs[0].Value);
            Assert.AreEqual(0x0000001ffffc0001ul, coeffs[1].Value);

            coeffs = new List<SmallModulus>(DefaultParams.CoeffModulus192(8192));

            Assert.IsNotNull(coeffs);
            Assert.AreEqual(3, coeffs.Count);
            Assert.AreEqual(0x0007ffffff9c0001ul, coeffs[0].Value);
            Assert.AreEqual(0x0007ffffff900001ul, coeffs[1].Value);
            Assert.AreEqual(0x0003ffffffb80001ul, coeffs[2].Value);
        }

        [TestMethod]
        [ExpectedException(typeof(ArgumentOutOfRangeException))]
        public void Coeffs192FailTest()
        {
            IEnumerable<SmallModulus> coeffs = DefaultParams.CoeffModulus192(2000);
        }
        
        [TestMethod]
        public void Coeffs256Test()
        {
            List<SmallModulus> coeffs = new List<SmallModulus>(DefaultParams.CoeffModulus256(4096));

            Assert.IsNotNull(coeffs);
            Assert.AreEqual(1, coeffs.Count);
            Assert.AreEqual(0x03ffffffff040001ul, coeffs[0].Value);

            coeffs = new List<SmallModulus>(DefaultParams.CoeffModulus256(8192));

            Assert.IsNotNull(coeffs);
            Assert.AreEqual(2, coeffs.Count);
            Assert.AreEqual(0x07ffffffffcc0001ul, coeffs[0].Value);
            Assert.AreEqual(0x07ffffffffb00001ul, coeffs[1].Value);
        }

        [TestMethod]
        [ExpectedException(typeof(ArgumentOutOfRangeException))]
        public void Coeffs256FailTest()
        {
            IEnumerable<SmallModulus> coeffs = DefaultParams.CoeffModulus256(9000);
        }

        [TestMethod]
        public void SmallMods60BitTest()
        {
            SmallModulus sm = DefaultParams.SmallMods60Bit(45);

            Assert.IsNotNull(sm);
            Assert.AreEqual(60, sm.BitCount);
            Assert.AreEqual(0x0ffffffff1740001ul, sm.Value);

        }

        [TestMethod]
        [ExpectedException(typeof(ArgumentOutOfRangeException))]
        public void SmallMods60BitFailTest()
        {
            SmallModulus sm = DefaultParams.SmallMods60Bit(64);
        }

        [TestMethod]
        public void SmallMods50BitTest()
        {
            SmallModulus sm = DefaultParams.SmallMods50Bit(30);

            Assert.IsNotNull(sm);
            Assert.AreEqual(50, sm.BitCount);
            Assert.AreEqual(0x3FFFFF8B80001ul, sm.Value);

            Assert.ThrowsException<ArgumentOutOfRangeException>(() => DefaultParams.SmallMods50Bit(64));
        }

        [TestMethod]
        public void SmallMods40BitTest()
        {
            SmallModulus sm = DefaultParams.SmallMods40Bit(10);

            Assert.IsNotNull(sm);
            Assert.AreEqual(40, sm.BitCount);
            Assert.AreEqual(0xFFFE100001ul, sm.Value);

            Assert.ThrowsException<ArgumentOutOfRangeException>(() => DefaultParams.SmallMods40Bit(64));
        }

        [TestMethod]
        public void SmallMods30BitTest()
        {
            SmallModulus sm = DefaultParams.SmallMods30Bit(20);

            Assert.IsNotNull(sm);
            Assert.AreEqual(30, sm.BitCount);
            Assert.AreEqual(0x3BE80001ul, sm.Value);

            Assert.ThrowsException<ArgumentOutOfRangeException>(() => DefaultParams.SmallMods30Bit(64));
        }

        [TestMethod]
        public void DBCMaxMinTest()
        {
            int dbcMax = DefaultParams.DBCmax;
            int dbcMin = DefaultParams.DBCmin;

            Assert.AreEqual(60, dbcMax);
            Assert.AreEqual(1, dbcMin);
        }
    }
}
