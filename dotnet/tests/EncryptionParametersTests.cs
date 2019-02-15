// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

using Microsoft.Research.SEAL;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using System.Collections.Generic;
using System.IO;

namespace SEALNetTest
{
    public delegate void TestDelegate(SchemeType scheme);

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

            EncryptionParameters copy = new EncryptionParameters(encParams);

            Assert.AreEqual(encParams.ParmsId, copy.ParmsId);
            Assert.AreEqual(SchemeType.BFV, copy.Scheme);
            Assert.AreEqual(encParams, copy);
            Assert.AreEqual(encParams.GetHashCode(), copy.GetHashCode());

            EncryptionParameters third = new EncryptionParameters(SchemeType.CKKS);
            third.Set(copy);

            Assert.AreEqual(SchemeType.BFV, third.Scheme);
            Assert.AreEqual(encParams, third);
            Assert.AreEqual(encParams.GetHashCode(), third.GetHashCode());
        }

        [TestMethod]
        public void SetPlainModulusCKKSTest()
        {
            EncryptionParameters parms = new EncryptionParameters(SchemeType.CKKS);

            Assert.ThrowsException<InvalidOperationException>(() =>
            {
                parms.PlainModulus = new SmallModulus(8192);
            });

            Assert.ThrowsException<InvalidOperationException>(() =>
            {
                parms.SetPlainModulus(8192);
            });
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

        [TestMethod]
        public void SaveLoadTest()
        {
            TestDelegate save_load_test = delegate(SchemeType scheme)
            {
                List<SmallModulus> coeffModulus = new List<SmallModulus>
                {
                    DefaultParams.SmallMods40Bit(0),
                    DefaultParams.SmallMods40Bit(1)
                };
                EncryptionParameters parms = new EncryptionParameters(scheme)
                {
                    PolyModulusDegree = 8,
                    CoeffModulus = coeffModulus
                };
                if (scheme == SchemeType.BFV)
                    parms.SetPlainModulus(257);

                EncryptionParameters loaded = null;

                using (MemoryStream stream = new MemoryStream())
                {
                    EncryptionParameters.Save(parms, stream);

                    stream.Seek(offset: 0, loc: SeekOrigin.Begin);

                    loaded = EncryptionParameters.Load(stream);
                }

                Assert.AreEqual(scheme, loaded.Scheme);
                Assert.AreEqual(8ul, loaded.PolyModulusDegree);
                if (scheme == SchemeType.BFV)
                    Assert.AreEqual(257ul, loaded.PlainModulus.Value);
                else if (scheme == SchemeType.CKKS)
                    Assert.AreEqual(0ul, loaded.PlainModulus.Value);

                List<SmallModulus> loadedCoeffModulus = new List<SmallModulus>(loaded.CoeffModulus);
                Assert.AreEqual(2, loadedCoeffModulus.Count);
                Assert.AreNotSame(coeffModulus[0], loadedCoeffModulus[0]);
                Assert.AreNotSame(coeffModulus[1], loadedCoeffModulus[1]);
                Assert.AreEqual(coeffModulus[0], loadedCoeffModulus[0]);
                Assert.AreEqual(coeffModulus[1], loadedCoeffModulus[1]);
                Assert.AreEqual(parms.NoiseMaxDeviation, loaded.NoiseMaxDeviation, delta: 0.001);
                Assert.AreEqual(parms.NoiseStandardDeviation, loaded.NoiseStandardDeviation, delta: 0.001);
            };
            save_load_test(SchemeType.BFV);
            save_load_test(SchemeType.CKKS);
        }

        [TestMethod]
        public void EqualsTest()
        {
            EncryptionParameters parms = new EncryptionParameters(SchemeType.BFV)
            {
                PolyModulusDegree = 8,
                PlainModulus = new SmallModulus(257),
                CoeffModulus = new List<SmallModulus>()
                {
                    DefaultParams.SmallMods40Bit(0),
                    DefaultParams.SmallMods40Bit(1)
                }
            };

            EncryptionParameters parms2 = new EncryptionParameters(SchemeType.CKKS);

            Assert.AreNotEqual(parms, parms2);
            Assert.IsFalse(parms.Equals(null));
        }

        [TestMethod]
        public void ExceptionsTest()
        {
            EncryptionParameters parms = new EncryptionParameters(SchemeType.BFV);

            Assert.ThrowsException<ArgumentNullException>(() => parms = new EncryptionParameters(null));

            Assert.ThrowsException<ArgumentNullException>(() => parms.Set(null));

            Assert.ThrowsException<ArgumentNullException>(() => parms.CoeffModulus = null);

            Assert.ThrowsException<ArgumentNullException>(() => EncryptionParameters.Save(parms, null));
            Assert.ThrowsException<ArgumentNullException>(() => EncryptionParameters.Save(null, new MemoryStream()));

            Assert.ThrowsException<ArgumentNullException>(() => EncryptionParameters.Load(null));
            Assert.ThrowsException<ArgumentException>(() => EncryptionParameters.Load(new MemoryStream()));
        }
    }
}
