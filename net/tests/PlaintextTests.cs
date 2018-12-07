using Microsoft.Research.SEAL;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using System.Collections.Generic;
using System.IO;
using System.Text;

namespace SEALNetTest
{
    [TestClass]
    public class PlaintextTests
    {
        [TestMethod]
        public void CreateTest()
        {
            Plaintext plain = new Plaintext();
            Assert.IsNotNull(plain);
            Assert.AreEqual(0ul, plain.CoeffCount);

            Plaintext plain2 = new Plaintext(capacity: 20, coeffCount: 10);
            Assert.IsNotNull(plain2);
            Assert.AreEqual(20ul, plain2.Capacity);
            Assert.AreEqual(10ul, plain2.CoeffCount);
        }
        
        [TestMethod]
        public void CreateWithHexTest()
        {
            Plaintext plain = new Plaintext("6x^5 + 5x^4 + 4x^3 + 3x^2 + 2x^1 + 1");
            Assert.IsNotNull(plain);
            Assert.AreEqual(6ul, plain.CoeffCount);
            Assert.AreEqual(1ul, plain[0]);
            Assert.AreEqual(2ul, plain[1]);
            Assert.AreEqual(3ul, plain[2]);
            Assert.AreEqual(4ul, plain[3]);
            Assert.AreEqual(5ul, plain[4]);
            Assert.AreEqual(6ul, plain[5]);
        }

        [TestMethod]
        public void ToStringTest()
        {
            Plaintext plain = new Plaintext(coeffCount: 6);
            plain[0] = 1;
            plain[1] = 2;
            plain[2] = 3;
            plain[3] = 4;
            plain[4] = 5;
            plain[5] = 6;

            Assert.AreEqual(6ul, plain.CoeffCount);

            string str = plain.ToString();
            Assert.AreEqual("6x^5 + 5x^4 + 4x^3 + 3x^2 + 2x^1 + 1", str);
        }

        [TestMethod]
        public void SetZeroTest()
        {
            Plaintext plain = new Plaintext(coeffCount: 10);
            plain[0] = 1;
            plain[1] = 2;
            plain[2] = 3;
            plain[3] = 4;
            plain[4] = 5;
            plain[5] = 6;
            plain[6] = 7;
            plain[7] = 8;
            plain[8] = 9;
            plain[9] = 10;

            plain.SetZero(6, 3);

            Assert.AreEqual(1ul, plain[0]);
            Assert.AreEqual(2ul, plain[1]);
            Assert.AreEqual(3ul, plain[2]);
            Assert.AreEqual(4ul, plain[3]);
            Assert.AreEqual(5ul, plain[4]);
            Assert.AreEqual(6ul, plain[5]);
            Assert.AreEqual(0ul, plain[6]);
            Assert.AreEqual(0ul, plain[7]);
            Assert.AreEqual(0ul, plain[8]);
            Assert.AreEqual(10ul, plain[9]);

            plain[0] = 1;
            plain[1] = 2;
            plain[2] = 3;
            plain[3] = 4;
            plain[4] = 5;
            plain[5] = 6;
            plain[6] = 7;
            plain[7] = 8;
            plain[8] = 9;
            plain[9] = 10;

            plain.SetZero(4);

            Assert.AreEqual(1ul, plain[0]);
            Assert.AreEqual(2ul, plain[1]);
            Assert.AreEqual(3ul, plain[2]);
            Assert.AreEqual(4ul, plain[3]);
            Assert.AreEqual(0ul, plain[4]);
            Assert.AreEqual(0ul, plain[5]);
            Assert.AreEqual(0ul, plain[6]);
            Assert.AreEqual(0ul, plain[7]);
            Assert.AreEqual(0ul, plain[8]);
            Assert.AreEqual(0ul, plain[9]);

            plain[0] = 1;
            plain[1] = 2;
            plain[2] = 3;
            plain[3] = 4;
            plain[4] = 5;
            plain[5] = 6;
            plain[6] = 7;
            plain[7] = 8;
            plain[8] = 9;
            plain[9] = 10;

            plain.SetZero();

            Assert.AreEqual(0ul, plain[0]);
            Assert.AreEqual(0ul, plain[1]);
            Assert.AreEqual(0ul, plain[2]);
            Assert.AreEqual(0ul, plain[3]);
            Assert.AreEqual(0ul, plain[4]);
            Assert.AreEqual(0ul, plain[5]);
            Assert.AreEqual(0ul, plain[6]);
            Assert.AreEqual(0ul, plain[7]);
            Assert.AreEqual(0ul, plain[8]);
            Assert.AreEqual(0ul, plain[9]);
        }

        [TestMethod]
        public void ReserveResizeTest()
        {
            Plaintext plain = new Plaintext();
            MemoryPoolHandle handle = plain.Pool;

            Assert.AreEqual(0ul, plain.CoeffCount);
            Assert.AreEqual(0ul, plain.Capacity);

            plain.Reserve(capacity: 10);

            ulong alloced = handle.AllocByteCount;
            Assert.IsTrue(alloced > 0ul);

            Assert.AreEqual(0ul, plain.CoeffCount);
            Assert.AreEqual(10ul, plain.Capacity);

            plain.Resize(coeffCount: 11);

            Assert.AreEqual(11ul, plain.CoeffCount);
            Assert.AreEqual(11ul, plain.Capacity);
            Assert.AreEqual(0ul, plain.SignificantCoeffCount);
            Assert.IsTrue(handle.AllocByteCount > 0ul);
        }

        [TestMethod]
        public void ShrinkToFitTest()
        {
            Plaintext plain = new Plaintext();

            plain.Reserve(10000);

            Assert.AreEqual(10000ul, plain.Capacity);
            Assert.AreEqual(0ul, plain.CoeffCount);

            plain.Set("1");

            Assert.AreEqual(10000ul, plain.Capacity);
            Assert.AreEqual(1ul, plain.CoeffCount);
            Assert.AreEqual(1ul, plain.SignificantCoeffCount);

            plain.ShrinkToFit();

            Assert.AreEqual(1ul, plain.Capacity);
            Assert.AreEqual(1ul, plain.CoeffCount);
            Assert.AreEqual(1ul, plain[0]);
        }

        [TestMethod]
        public void ReleaseTest()
        {
            Plaintext plain = new Plaintext();
            plain.Reserve(10000);

            plain.Set("3x^2 + 4x^1 + 5");

            Assert.AreEqual(10000ul, plain.Capacity);
            Assert.AreEqual(3ul, plain.CoeffCount);

            plain.Release();

            Assert.AreEqual(0ul, plain.Capacity);
            Assert.AreEqual(0ul, plain.CoeffCount);
        }

        [TestMethod]
        public void EqualsTest()
        {
            Plaintext plain1 = new Plaintext();
            Plaintext plain2 = new Plaintext();

            plain1.Reserve(10000);
            plain2.Reserve(500);

            plain1.Set("4x^3 + 5x^2 + 6x^1 + 7");
            plain2.Set("4x^3 + 5x^2 + 6x^1 + 7");

            Assert.AreEqual(10000ul, plain1.Capacity);
            Assert.AreEqual(500ul, plain2.Capacity);

            Assert.AreNotSame(plain1, plain2);
            Assert.AreEqual(plain1, plain2);
        }

        [TestMethod]
        public void SaveLoadTest()
        {
            Plaintext plain = new Plaintext("6x^40 + 5x^35 + 4x^30 + 3x^20 + 2x^10 + 5");
            Plaintext other = new Plaintext();

            Assert.AreNotSame(plain, other);
            Assert.AreNotEqual(plain, other);

            using (MemoryStream stream = new MemoryStream())
            {
                plain.Save(stream);

                stream.Seek(offset: 0, loc: SeekOrigin.Begin);

                other.UnsafeLoad(stream);
            }

            Assert.AreNotSame(plain, other);
            Assert.AreEqual(plain, other);
        }

        [TestMethod]
        public void HashCodeTest()
        {
            Plaintext plain1 = new Plaintext("6x^40 + 5x^35 + 4x^30 + 3x^20 + 2x^10 + 5");
            Plaintext plain2 = new Plaintext("1");
            Plaintext plain3 = new Plaintext("0");
            Plaintext plain4 = new Plaintext("6x^40 + 5x^35 + 4x^30 + 3x^20 + 2x^10 + 5");

            Assert.AreNotEqual(plain1.GetHashCode(), plain2.GetHashCode());
            Assert.AreNotEqual(plain1.GetHashCode(), plain3.GetHashCode());
            Assert.AreNotEqual(plain2.GetHashCode(), plain3.GetHashCode());
            Assert.AreNotEqual(plain2.GetHashCode(), plain4.GetHashCode());
            Assert.AreNotEqual(plain3.GetHashCode(), plain4.GetHashCode());

            Assert.AreEqual(plain1.GetHashCode(), plain4.GetHashCode());
        }
    }
}
