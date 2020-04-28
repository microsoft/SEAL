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

            EncryptionParameters copy = new EncryptionParameters(encParams);

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

            Utilities.AssertThrows<InvalidOperationException>(() =>
            {
                parms.PlainModulus = new Modulus(8192);
            });

            Utilities.AssertThrows<InvalidOperationException>(() =>
            {
                parms.SetPlainModulus(8192);
            });
        }

        [TestMethod]
        public void CoeffModulusTest()
        {
            EncryptionParameters encParams = new EncryptionParameters(SchemeType.BFV);

            Assert.IsNotNull(encParams);

            List<Modulus> coeffs = new List<Modulus>(encParams.CoeffModulus);
            Assert.IsNotNull(coeffs);
            Assert.AreEqual(0, coeffs.Count);

            encParams.CoeffModulus = CoeffModulus.BFVDefault(4096);

            List<Modulus> newCoeffs = new List<Modulus>(encParams.CoeffModulus);
            Assert.IsNotNull(newCoeffs);
            Assert.AreEqual(3, newCoeffs.Count);
            Assert.AreEqual(0xffffee001ul, newCoeffs[0].Value);
            Assert.AreEqual(0xffffc4001ul, newCoeffs[1].Value);
            Assert.AreEqual(0x1ffffe0001ul, newCoeffs[2].Value);
        }

        [TestMethod]
        public void SaveLoadTest()
        {
            TestDelegate save_load_test = delegate(SchemeType scheme)
            {
                List<Modulus> coeffModulus = (List<Modulus>)CoeffModulus.Create(8, new int[] { 40, 40 });
                EncryptionParameters parms = new EncryptionParameters(scheme)
                {
                    PolyModulusDegree = 8,
                    CoeffModulus = coeffModulus
                };
                if (scheme == SchemeType.BFV)
                    parms.SetPlainModulus(257);

                EncryptionParameters loaded = new EncryptionParameters();

                using (MemoryStream stream = new MemoryStream())
                {
                    parms.Save(stream);
                    stream.Seek(offset: 0, loc: SeekOrigin.Begin);
                    loaded.Load(stream);
                }

                Assert.AreEqual(scheme, loaded.Scheme);
                Assert.AreEqual(8ul, loaded.PolyModulusDegree);
                if (scheme == SchemeType.BFV)
                    Assert.AreEqual(257ul, loaded.PlainModulus.Value);
                else if (scheme == SchemeType.CKKS)
                    Assert.AreEqual(0ul, loaded.PlainModulus.Value);

                List<Modulus> loadedCoeffModulus = new List<Modulus>(loaded.CoeffModulus);
                Assert.AreEqual(2, loadedCoeffModulus.Count);
                Assert.AreNotSame(coeffModulus[0], loadedCoeffModulus[0]);
                Assert.AreNotSame(coeffModulus[1], loadedCoeffModulus[1]);
                Assert.AreEqual(coeffModulus[0], loadedCoeffModulus[0]);
                Assert.AreEqual(coeffModulus[1], loadedCoeffModulus[1]);
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
                PlainModulus = new Modulus(257),
                CoeffModulus = CoeffModulus.Create(8, new int[] { 40, 40 })
            };

            EncryptionParameters parms2 = new EncryptionParameters(SchemeType.CKKS);

            Assert.AreNotEqual(parms, parms2);
            Assert.IsFalse(parms.Equals(null));
        }

        [TestMethod]
        public void ExceptionsTest()
        {
            EncryptionParameters parms = new EncryptionParameters(SchemeType.BFV);
            Utilities.AssertThrows<ArgumentNullException>(() => parms = new EncryptionParameters(null));
            Utilities.AssertThrows<ArgumentNullException>(() => parms.Set(null));
            Utilities.AssertThrows<ArgumentNullException>(() => parms.CoeffModulus = null);
            Utilities.AssertThrows<ArgumentNullException>(() => parms.Save(null));
            Utilities.AssertThrows<ArgumentNullException>(() => parms.Load(null));
            Utilities.AssertThrows<EndOfStreamException>(() => parms.Load(new MemoryStream()));
        }
    }
}
