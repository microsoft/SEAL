using Microsoft.Research.SEAL;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using System.Collections.Generic;
using System.Text;

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
            List<SmallModulus> coeffModulus = new List<SmallModulus>();
            coeffModulus.Add(DefaultParams.SmallMods60Bit(0));
            parms.CoeffModulus = coeffModulus;
            parms.PlainModulus = new SmallModulus(257);

            SEALContext context = SEALContext.Create(parms);

            BatchEncoder encoder = new BatchEncoder(context);

            Assert.AreEqual(64, encoder.SlotCount);

            List<ulong> plainList = new List<ulong>();
            for (int i = 0; i < encoder.SlotCount; i++)
            {
                plainList.Add((ulong)i);
            }

            Plaintext plain = new Plaintext();
            encoder.Encode(plainList, plain);

            List<ulong> plainList2 = new List<ulong>();
            encoder.Decode(plain, plainList2);

            for (int i = 0; i < encoder.SlotCount; i++)
            {
                Assert.AreEqual(plainList[i], plainList2[i]);
            }

            for (int i = 0; i < encoder.SlotCount; i++)
            {
                plainList[i] = 5;
            }

            encoder.Encode(plainList, plain);
            Assert.AreEqual("5", plain.ToString());

            encoder.Decode(plain, plainList2);

            for (int i = 0; i < encoder.SlotCount; i++)
            {
                Assert.AreEqual(plainList[i], plainList2[i]);
            }

            List<ulong> shortList = new List<ulong>();
            for (int i = 0; i < 20; i++)
            {
                shortList.Add((ulong)i);
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

            for (int i = 20; i < encoder.SlotCount; i++)
            {
                Assert.AreEqual(0ul, shortList2[i]);
            }
        }

        [TestMethod]
        public void EncodeLongTest()
        {
            EncryptionParameters parms = new EncryptionParameters(SchemeType.BFV);
            parms.PolyModulusDegree = 64;
            List<SmallModulus> coeffModulus = new List<SmallModulus>();
            coeffModulus.Add(DefaultParams.SmallMods60Bit(0));
            parms.CoeffModulus = coeffModulus;
            parms.PlainModulus = new SmallModulus(257);

            SEALContext context = SEALContext.Create(parms);

            BatchEncoder encoder = new BatchEncoder(context);

            Assert.AreEqual(64, encoder.SlotCount);

            List<long> plainList = new List<long>();
            for (int i = 0; i < encoder.SlotCount; i++)
            {
                plainList.Add((long)i);
            }

            Plaintext plain = new Plaintext();
            encoder.Encode(plainList, plain);

            List<long> plainList2 = new List<long>();
            encoder.Decode(plain, plainList2);

            for (int i = 0; i < encoder.SlotCount; i++)
            {
                Assert.AreEqual(plainList[i], plainList2[i]);
            }

            for (int i = 0; i < encoder.SlotCount; i++)
            {
                plainList[i] = 5;
            }

            encoder.Encode(plainList, plain);
            Assert.AreEqual("5", plain.ToString());

            encoder.Decode(plain, plainList2);

            for (int i = 0; i < encoder.SlotCount; i++)
            {
                Assert.AreEqual(plainList[i], plainList2[i]);
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

            for (int i = 20; i < encoder.SlotCount; i++)
            {
                Assert.AreEqual(0L, shortList2[i]);
            }
        }

        [TestMethod]
        public void EncodeInPlaceTest()
        {
            List<SmallModulus> coeffModulus = new List<SmallModulus>()
            {
                DefaultParams.SmallMods60Bit(0)
            };
            EncryptionParameters parms = new EncryptionParameters(SchemeType.BFV)
            {
                PolyModulusDegree = 64,
                CoeffModulus = coeffModulus,
                PlainModulus = new SmallModulus(257)
            };

            SEALContext context = SEALContext.Create(parms);

            BatchEncoder encoder = new BatchEncoder(context);

            Assert.AreEqual(64, encoder.SlotCount);

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
            List<SmallModulus> coeffModulus = new List<SmallModulus>
            {
                DefaultParams.SmallMods40Bit(0),
                DefaultParams.SmallMods40Bit(1),
                DefaultParams.SmallMods40Bit(2),
                DefaultParams.SmallMods40Bit(3)
            };
            EncryptionParameters parms = new EncryptionParameters(SchemeType.CKKS)
            {
                PolyModulusDegree = 8,
                CoeffModulus = coeffModulus
            };

            SEALContext context = SEALContext.Create(parms);

            Assert.ThrowsException<ArgumentException>(() =>
            {
                BatchEncoder encoder = new BatchEncoder(context);
            });
        }
    }
}
