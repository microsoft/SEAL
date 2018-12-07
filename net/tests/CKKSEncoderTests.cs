// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

using Microsoft.Research.SEAL;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using System.Collections.Generic;
using System.Numerics;

namespace SEALNetTest
{
    [TestClass]
    public class CKKSEncoderTests
    {
        [TestMethod]
        public void EncodeDecodeDoubleTest()
        {
            EncryptionParameters parms = new EncryptionParameters(SchemeType.CKKS);
            parms.PolyModulusDegree = 64;
            List<SmallModulus> coeffModulus = new List<SmallModulus>(4);
            coeffModulus.Add(DefaultParams.SmallMods40Bit(0));
            coeffModulus.Add(DefaultParams.SmallMods40Bit(1));
            coeffModulus.Add(DefaultParams.SmallMods40Bit(2));
            coeffModulus.Add(DefaultParams.SmallMods40Bit(3));
            parms.CoeffModulus = coeffModulus;
            SEALContext context = SEALContext.Create(parms);

            int slots = 16;
            Plaintext plain = new Plaintext();
            double delta = 1 << 16;
            List<Complex> result = new List<Complex>();

            CKKSEncoder encoder = new CKKSEncoder(context);


            double value = 10d;
            encoder.Encode(value, delta, plain);
            encoder.Decode(plain, result);

            for (int i = 0; i < slots; i++)
            {
                double tmp = Math.Abs(value - result[i].Real);
                Assert.IsTrue(tmp < 0.5);
            }
        }

        [TestMethod]
        public void EncodeDecodeUlongTest()
        {

            int slots = 32;
            EncryptionParameters parms = new EncryptionParameters(SchemeType.CKKS);
            parms.PolyModulusDegree = (ulong)slots * 2;
            List<SmallModulus> coeffModulus = new List<SmallModulus>(4);
            coeffModulus.Add(DefaultParams.SmallMods40Bit(0));
            coeffModulus.Add(DefaultParams.SmallMods40Bit(1));
            coeffModulus.Add(DefaultParams.SmallMods40Bit(2));
            coeffModulus.Add(DefaultParams.SmallMods40Bit(3));
            parms.CoeffModulus = coeffModulus;
            SEALContext context = SEALContext.Create(parms);
            CKKSEncoder encoder = new CKKSEncoder(context);

            Plaintext plain = new Plaintext();
            List<Complex> result = new List<Complex>();

            ulong value = 15ul;
            encoder.Encode(value, plain);
            encoder.Decode(plain, result);

            for (int i = 0; i < slots; i++)
            {
                double tmp = Math.Abs(value - result[i].Real);
                Assert.IsTrue(tmp < 0.5);
            }
        }

        [TestMethod]
        public void EncodeDecodeVectorTest()
        {
            int slots = 32;
            EncryptionParameters parms = new EncryptionParameters(SchemeType.CKKS);
            parms.PolyModulusDegree = (ulong)slots * 2;
            List<SmallModulus> coeffModulus = new List<SmallModulus>(4);
            coeffModulus.Add(DefaultParams.SmallMods60Bit(0));
            coeffModulus.Add(DefaultParams.SmallMods60Bit(1));
            coeffModulus.Add(DefaultParams.SmallMods60Bit(2));
            coeffModulus.Add(DefaultParams.SmallMods60Bit(3));
            parms.CoeffModulus = coeffModulus;
            SEALContext context = SEALContext.Create(parms);
            CKKSEncoder encoder = new CKKSEncoder(context);

            List<Complex> values = new List<Complex>(slots);
            Random rnd = new Random();
            int dataBound = 1 << 30;
            double delta = 1ul << 40;

            for (int i = 0; i < slots; i++)
            {
                values.Add(new Complex(rnd.Next() % dataBound, 0));
            }

            Plaintext plain = new Plaintext();
            encoder.Encode(values, delta, plain);

            List<Complex> result = new List<Complex>();
            encoder.Decode(plain, result);

            for (int i = 0; i < slots; i++)
            {
                double tmp = Math.Abs(values[i].Real - result[i].Real);
                Assert.IsTrue(tmp < 0.5);
            }
        }
    }
}
