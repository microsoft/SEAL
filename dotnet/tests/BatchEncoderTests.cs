// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

using Microsoft.Research.SEAL;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using System.Collections.Generic;
using System.Runtime.InteropServices.ComTypes;

namespace SEALNetTest
{
    [TestClass]
    public class BatchEncoderTests
    {
        [TestMethod]
        public void EncodeULongTest()
        {
            EncryptionParameters parms = new EncryptionParameters(SchemeType.BFV);
            parms.PolyModulusDegree = 64;
            parms.CoeffModulus = CoeffModulus.Create(64, new int[]{ 60 });
            parms.PlainModulus = new Modulus(257);

            SEALContext context = new SEALContext(parms,
                expandModChain: false,
                secLevel: SecLevelType.None);

            BatchEncoder encoder = new BatchEncoder(context);

            Assert.AreEqual(64ul, encoder.SlotCount);

            List<ulong> plainList = new List<ulong>();
            for (ulong i = 0; i < encoder.SlotCount; i++)
            {
                plainList.Add((ulong)i);
            }

            Plaintext plain = new Plaintext();
            encoder.Encode(plainList, plain);

            List<ulong> plainList2 = new List<ulong>();
            encoder.Decode(plain, plainList2);

            for (ulong i = 0; i < encoder.SlotCount; i++)
            {
                Assert.AreEqual(plainList[checked((int)i)], plainList2[checked((int)i)]);
            }

            for (ulong i = 0; i < encoder.SlotCount; i++)
            {
                plainList[checked((int)i)] = 5;
            }

            encoder.Encode(plainList, plain);
            Assert.AreEqual("5", plain.ToString());

            encoder.Decode(plain, plainList2);

            for (ulong i = 0; i < encoder.SlotCount; i++)
            {
                Assert.AreEqual(plainList[checked((int)i)], plainList2[checked((int)i)]);
            }

            List<ulong> shortList = new List<ulong>();
            for (ulong i = 0; i < 20; i++)
            {
                shortList.Add(i);
            }

            encoder.Encode(shortList, plain);

            List<ulong> shortList2 = new List<ulong>();
            encoder.Decode(plain, shortList2);

            Assert.AreEqual(20, shortList.Count);
            Assert.AreEqual(64, shortList2.Count);

            for (int i = 0; i < 20; i++)
            {
                Assert.AreEqual(shortList[i], shortList2[i]);
            }

            for (ulong i = 20; i < encoder.SlotCount; i++)
            {
                Assert.AreEqual(0ul, shortList2[checked((int)i)]);
            }
        }

        [TestMethod]
        public void EncodeLongTest()
        {
            EncryptionParameters parms = new EncryptionParameters(SchemeType.BFV);
            parms.PolyModulusDegree = 64;
            parms.CoeffModulus = CoeffModulus.Create(64, new int[] { 60 });
            parms.PlainModulus = new Modulus(257);

            SEALContext context = new SEALContext(parms,
                expandModChain: false,
                secLevel: SecLevelType.None);

            BatchEncoder encoder = new BatchEncoder(context);

            Assert.AreEqual(64ul, encoder.SlotCount);

            List<long> plainList = new List<long>();
            for (ulong i = 0; i < encoder.SlotCount; i++)
            {
                plainList.Add((long)i);
            }

            Plaintext plain = new Plaintext();
            encoder.Encode(plainList, plain);

            List<long> plainList2 = new List<long>();
            encoder.Decode(plain, plainList2);

            for (ulong i = 0; i < encoder.SlotCount; i++)
            {
                Assert.AreEqual(plainList[checked((int)i)], plainList2[checked((int)i)]);
            }

            for (ulong i = 0; i < encoder.SlotCount; i++)
            {
                plainList[checked((int)i)] = 5;
            }

            encoder.Encode(plainList, plain);
            Assert.AreEqual("5", plain.ToString());

            encoder.Decode(plain, plainList2);

            for (ulong i = 0; i < encoder.SlotCount; i++)
            {
                Assert.AreEqual(plainList[checked((int)i)], plainList2[checked((int)i)]);
            }

            List<long> shortList = new List<long>();
            for (int i = 0; i < 20; i++)
            {
                shortList.Add((long)i);
            }

            encoder.Encode(shortList, plain);

            List<long> shortList2 = new List<long>();
            encoder.Decode(plain, shortList2);

            Assert.AreEqual(20, shortList.Count);
            Assert.AreEqual(64, shortList2.Count);

            for (int i = 0; i < 20; i++)
            {
                Assert.AreEqual(shortList[i], shortList2[i]);
            }

            for (ulong i = 20; i < encoder.SlotCount; i++)
            {
                Assert.AreEqual(0L, shortList2[checked((int)i)]);
            }
        }

        [TestMethod]
        public void EncodeInPlaceTest()
        {
            EncryptionParameters parms = new EncryptionParameters(SchemeType.BFV)
            {
                PolyModulusDegree = 64,
                CoeffModulus = CoeffModulus.Create(64, new int[] { 60 }),
                PlainModulus = new Modulus(257)
            };

            SEALContext context = new SEALContext(parms,
                expandModChain: false,
                secLevel: SecLevelType.None);

            BatchEncoder encoder = new BatchEncoder(context);

            Assert.AreEqual(64ul, encoder.SlotCount);

            Plaintext plain = new Plaintext("6x^5 + 5x^4 + 4x^3 + 3x^2 + 2x^1 + 1");
            Assert.AreEqual(6ul, plain.CoeffCount);

            encoder.Encode(plain);

            Assert.AreEqual(64ul, plain.CoeffCount);

            encoder.Decode(plain);
            Assert.AreEqual(64ul, plain.CoeffCount);

            for (ulong i = 0; i < 6; i++)
            {
                Assert.AreEqual((i + 1), plain[i]);
            }

            for (ulong i = 6; i < plain.CoeffCount; i++)
            {
                Assert.AreEqual(0ul, plain[i]);
            }
        }

        [TestMethod]
        public void SchemeIsCKKSTest()
        {
            EncryptionParameters parms = new EncryptionParameters(SchemeType.CKKS)
            {
                PolyModulusDegree = 8,
                CoeffModulus = CoeffModulus.Create(8, new int[] { 40, 40, 40, 40 })
            };

            SEALContext context = new SEALContext(parms,
                expandModChain: false,
                secLevel: SecLevelType.None);

            Utilities.AssertThrows<ArgumentException>(() =>
            {
                BatchEncoder encoder = new BatchEncoder(context);
            });
        }

        [TestMethod]
        public void ExceptionsTest()
        {
            EncryptionParameters parms = new EncryptionParameters(SchemeType.BFV)
            {
                PolyModulusDegree = 64,
                CoeffModulus = CoeffModulus.Create(64, new int[] { 60 }),
                PlainModulus = new Modulus(257)
            };

            SEALContext context = new SEALContext(parms,
                expandModChain: false,
                secLevel: SecLevelType.None);
            BatchEncoder enc = new BatchEncoder(context);
            List<ulong> valu = new List<ulong>();
            List<ulong> valu_null = null;
            List<long> vall = new List<long>();
            List<long> vall_null = null;
            Plaintext plain = new Plaintext();
            Plaintext plain_null = null;
            MemoryPoolHandle pool_uninit = new MemoryPoolHandle();

            Utilities.AssertThrows<ArgumentNullException>(() => enc = new BatchEncoder(null));

            Utilities.AssertThrows<ArgumentNullException>(() => enc.Encode(valu, plain_null));
            Utilities.AssertThrows<ArgumentNullException>(() => enc.Encode(valu_null, plain));

            Utilities.AssertThrows<ArgumentNullException>(() => enc.Encode(vall, plain_null));
            Utilities.AssertThrows<ArgumentNullException>(() => enc.Encode(vall_null, plain));

            Utilities.AssertThrows<ArgumentNullException>(() => enc.Encode(plain_null));
            Utilities.AssertThrows<ArgumentException>(() => enc.Encode(plain, pool_uninit));

            Utilities.AssertThrows<ArgumentNullException>(() => enc.Decode(plain, valu_null));
            Utilities.AssertThrows<ArgumentNullException>(() => enc.Decode(plain_null, valu));
            Utilities.AssertThrows<ArgumentException>(() => enc.Decode(plain, valu, pool_uninit));

            Utilities.AssertThrows<ArgumentNullException>(() => enc.Decode(plain, vall_null));
            Utilities.AssertThrows<ArgumentNullException>(() => enc.Decode(plain_null, vall));
            Utilities.AssertThrows<ArgumentException>(() => enc.Decode(plain, vall, pool_uninit));

            Utilities.AssertThrows<ArgumentNullException>(() => enc.Decode(plain_null));
            Utilities.AssertThrows<ArgumentException>(() => enc.Decode(plain, pool_uninit));
        }
    }
}
