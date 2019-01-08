using Microsoft.Research.SEAL;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace SEALNetTest
{
    [TestClass]
    public class IntegerEncoderTests
    {
        [TestMethod]
        public void CreateTest()
        {
            IntegerEncoder encoder = new IntegerEncoder(new SmallModulus(8192));
            Assert.IsNotNull(encoder);
            Assert.AreEqual(2ul, encoder.Base);
            Assert.AreEqual(8192ul, encoder.PlainModulus.Value);

            IntegerEncoder encoder2 = new IntegerEncoder(new SmallModulus(4096), 16);
            Assert.IsNotNull(encoder2);
            Assert.AreEqual(16ul, encoder2.Base);
            Assert.AreEqual(4096ul, encoder2.PlainModulus.Value);

            IntegerEncoder encoder3 = new IntegerEncoder(encoder);
            Assert.IsNotNull(encoder3);
            Assert.AreEqual(2ul, encoder3.Base);
            Assert.AreEqual(8192ul, encoder3.PlainModulus.Value);
        }

        [TestMethod]
        public void EncodeTest()
        {
            IntegerEncoder encoder = new IntegerEncoder(new SmallModulus(1024));

            Plaintext plain = encoder.Encode(10);
            Assert.IsNotNull(plain);
            Assert.AreEqual(4ul, plain.CoeffCount);
            Assert.AreEqual(0ul, plain[0]);
            Assert.AreEqual(1ul, plain[1]);
            Assert.AreEqual(0ul, plain[2]);
            Assert.AreEqual(1ul, plain[3]);

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
        }

        [TestMethod]
        public void DecodeTest()
        {
            IntegerEncoder encoder = new IntegerEncoder(new SmallModulus(1024));

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
        }
    }
}
