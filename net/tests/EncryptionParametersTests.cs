using Microsoft.Research.SEAL;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using System.Collections.Generic;
using System.Text;

namespace SEALNetTest
{
    [TestClass]
    public class EncryptionParametersTests
    {
        [TestMethod]
        public void CreateTest()
        {
            EncryptionParameters encParams = new EncryptionParameters(SchemeType.BFV);

            Assert.IsNotNull(encParams);
            Assert.AreEqual(SchemeType.BFV, encParams.Scheme);

            EncryptionParameters encParams2 = new EncryptionParameters(SchemeType.CKKS);

            Assert.IsNotNull(encParams2);
            Assert.AreEqual(SchemeType.CKKS, encParams2.Scheme);

            EncryptionParameters encParams3 = new EncryptionParameters(SchemeType.CKKS);

            Assert.IsNotNull(encParams3);
            Assert.AreEqual(SchemeType.CKKS, encParams3.Scheme);

            Assert.AreEqual(encParams2.ParmsId, encParams3.ParmsId);
            Assert.AreNotEqual(encParams.ParmsId, encParams2.ParmsId);
        }

        [TestMethod]
        public void CoeffModulusTest()
        {
            EncryptionParameters encParams = new EncryptionParameters(SchemeType.BFV);

            Assert.IsNotNull(encParams);
            Assert.AreEqual(4, encParams.ParmsId.Block.Length);

            List<SmallModulus> coeffs = new List<SmallModulus>(encParams.CoeffModulus);
            Assert.IsNotNull(coeffs);
            Assert.AreEqual(0, coeffs.Count);

            coeffs = new List<SmallModulus>(DefaultParams.CoeffModulus128(4096));
            encParams.CoeffModulus = coeffs;

            List<SmallModulus> newCoeffs = new List<SmallModulus>(encParams.CoeffModulus);
            Assert.IsNotNull(newCoeffs);
            Assert.AreEqual(2, newCoeffs.Count);
            Assert.AreEqual(0x007fffffff380001ul, newCoeffs[0].Value);
            Assert.AreEqual(0x003fffffff000001ul, newCoeffs[1].Value);
        }
    }
}
