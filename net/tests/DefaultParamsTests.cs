using Microsoft.Research.SEAL;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using System.Collections.Generic;
using System.Text;

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
        public void SmallMods64BitTest()
        {
            SmallModulus sm = DefaultParams.SmallMods60Bit(45);

            Assert.IsNotNull(sm);
            Assert.AreEqual(60, sm.BitCount);
            Assert.AreEqual(0x0ffffffff1740001ul, sm.Value);

        }

        [TestMethod]
        [ExpectedException(typeof(ArgumentOutOfRangeException))]
        public void SmallMods64BitFailTest()
        {
            SmallModulus sm = DefaultParams.SmallMods60Bit(64);
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
