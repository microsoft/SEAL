using Microsoft.Research.SEAL;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;

namespace SEALNetTest
{
    [TestClass]
    public class IntegerEncoderTests
    {
        [TestMethod]
        public void CreateTest()
        {
            IntegerEncoder encoder = new IntegerEncoder(GlobalContext.BFVContext);
            Assert.IsNotNull(encoder);
            Assert.AreEqual(65537ul, encoder.PlainModulus.Value);
        }

        [TestMethod]
        public void EncodeTest()
        {
            IntegerEncoder encoder = new IntegerEncoder(GlobalContext.BFVContext);

            Plaintext plain = encoder.Encode(10);
            Assert.IsNotNull(plain);
            Assert.AreEqual(4ul, plain.CoeffCount);
            Assert.AreEqual(0ul, plain[0]);
            Assert.AreEqual(1ul, plain[1]);
            Assert.AreEqual(0ul, plain[2]);
            Assert.AreEqual(1ul, plain[3]);

            plain = encoder.Encode(13u);
            Assert.AreEqual(4ul, plain.CoeffCount);
            Assert.AreEqual(1ul, plain[0]);
            Assert.AreEqual(0ul, plain[1]);
            Assert.AreEqual(1ul, plain[2]);
            Assert.AreEqual(1ul, plain[3]);

            plain = encoder.Encode(20L);
            Assert.AreEqual(5ul, plain.CoeffCount);
            Assert.AreEqual(0ul, plain[0]);
            Assert.AreEqual(0ul, plain[1]);
            Assert.AreEqual(1ul, plain[2]);
            Assert.AreEqual(0ul, plain[3]);
            Assert.AreEqual(1ul, plain[4]);

            plain = encoder.Encode(15ul);
            Assert.AreEqual(4ul, plain.CoeffCount);
            Assert.AreEqual(1ul, plain[0]);
            Assert.AreEqual(1ul, plain[1]);
            Assert.AreEqual(1ul, plain[2]);
            Assert.AreEqual(1ul, plain[3]);

            BigUInt bui = new BigUInt("AB");
            plain = encoder.Encode(bui);
            Assert.AreEqual(8ul, plain.CoeffCount);
            Assert.AreEqual(1ul, plain[0]);
            Assert.AreEqual(1ul, plain[1]);
            Assert.AreEqual(0ul, plain[2]);
            Assert.AreEqual(1ul, plain[3]);
            Assert.AreEqual(0ul, plain[4]);
            Assert.AreEqual(1ul, plain[5]);
            Assert.AreEqual(0ul, plain[6]);
            Assert.AreEqual(1ul, plain[7]);

            Plaintext plain2 = new Plaintext();

            encoder.Encode(10, plain2);
            Assert.AreEqual(4ul, plain2.CoeffCount);
            Assert.AreEqual(0ul, plain2[0]);
            Assert.AreEqual(1ul, plain2[1]);
            Assert.AreEqual(0ul, plain2[2]);
            Assert.AreEqual(1ul, plain2[3]);

            encoder.Encode(13u, plain2);
            Assert.AreEqual(4ul, plain2.CoeffCount);
            Assert.AreEqual(1ul, plain2[0]);
            Assert.AreEqual(0ul, plain2[1]);
            Assert.AreEqual(1ul, plain2[2]);
            Assert.AreEqual(1ul, plain2[3]);

            encoder.Encode(20L, plain2);
            Assert.AreEqual(5ul, plain2.CoeffCount);
            Assert.AreEqual(0ul, plain2[0]);
            Assert.AreEqual(0ul, plain2[1]);
            Assert.AreEqual(1ul, plain2[2]);
            Assert.AreEqual(0ul, plain2[3]);
            Assert.AreEqual(1ul, plain2[4]);

            encoder.Encode(15ul, plain2);
            Assert.AreEqual(4ul, plain2.CoeffCount);
            Assert.AreEqual(1ul, plain2[0]);
            Assert.AreEqual(1ul, plain2[1]);
            Assert.AreEqual(1ul, plain2[2]);
            Assert.AreEqual(1ul, plain2[3]);

            encoder.Encode(bui, plain2);
            Assert.AreEqual(8ul, plain2.CoeffCount);
            Assert.AreEqual(1ul, plain2[0]);
            Assert.AreEqual(1ul, plain2[1]);
            Assert.AreEqual(0ul, plain2[2]);
            Assert.AreEqual(1ul, plain2[3]);
            Assert.AreEqual(0ul, plain2[4]);
            Assert.AreEqual(1ul, plain2[5]);
            Assert.AreEqual(0ul, plain2[6]);
            Assert.AreEqual(1ul, plain2[7]);
        }

        [TestMethod]
        public void DecodeTest()
        {
            IntegerEncoder encoder = new IntegerEncoder(GlobalContext.BFVContext);

            Plaintext plain = new Plaintext("0x^5 + 1x^4 + 1x^3 + 1x^1 + 0");
            Assert.AreEqual(6ul, plain.CoeffCount);

            ulong resultU64 = encoder.DecodeUInt64(plain);
            Assert.AreEqual(26UL, resultU64);

            long resultI64 = encoder.DecodeInt64(plain);
            Assert.AreEqual(26L, resultI64);

            uint resultU32 = encoder.DecodeUInt32(plain);
            Assert.AreEqual(26U, resultU32);

            int resultI32 = encoder.DecodeInt32(plain);
            Assert.AreEqual(26, resultI32);

            BigUInt bui = encoder.DecodeBigUInt(plain);
            Assert.IsNotNull(bui);
            Assert.AreEqual(0, bui.CompareTo(26ul));
        }

        [TestMethod]
        public void ExceptionsTest()
        {
            SEALContext context = GlobalContext.BFVContext;
            SEALContext context_null = null;
            IntegerEncoder enc = new IntegerEncoder(context);
            BigUInt bui_null = null;
            BigUInt bui = new BigUInt(5ul);
            Plaintext plain = new Plaintext();

            Assert.ThrowsException<ArgumentNullException>(() => enc = new IntegerEncoder(context_null));
            Assert.ThrowsException<ArgumentException>(() => enc = new IntegerEncoder(GlobalContext.CKKSContext));

            Assert.ThrowsException<ArgumentNullException>(() => enc.Encode(1ul, null));
            Assert.ThrowsException<ArgumentNullException>(() => enc.Encode(1L, null));
            Assert.ThrowsException<ArgumentNullException>(() => enc.Encode(1, null));
            Assert.ThrowsException<ArgumentNullException>(() => enc.Encode(1u, null));
            Assert.ThrowsException<ArgumentNullException>(() => enc.Encode(bui_null));
            Assert.ThrowsException<ArgumentNullException>(() => enc.Encode(bui, null));
            Assert.ThrowsException<ArgumentNullException>(() => enc.Encode(bui_null, plain));

            Assert.ThrowsException<ArgumentNullException>(() => enc.DecodeUInt32(null));
            Assert.ThrowsException<ArgumentNullException>(() => enc.DecodeUInt64(null));
            Assert.ThrowsException<ArgumentNullException>(() => enc.DecodeInt32(null));
            Assert.ThrowsException<ArgumentNullException>(() => enc.DecodeInt64(null));
            Assert.ThrowsException<ArgumentNullException>(() => enc.DecodeBigUInt(null));
        }
    }
}
