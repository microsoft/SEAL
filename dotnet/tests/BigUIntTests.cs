// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

using Microsoft.Research.SEAL;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using System.IO;
using System.Numerics;

namespace SEALNetTest
{
    [TestClass]
    public class BigUIntTests
    {
        [TestMethod]
        public void EmptyConstructorTest()
        {
            BigUInt bui = new BigUInt();

            Assert.IsTrue(bui.IsZero);
            Assert.AreEqual(0, bui.BitCount);
        }

        [TestMethod]
        public void BitCountConstructorTest()
        {
            BigUInt bui = new BigUInt(bitCount: 70);

            Assert.IsTrue(bui.IsZero);
            Assert.AreEqual(70, bui.BitCount);
            Assert.AreEqual(2ul, bui.UInt64Count);
            Assert.AreEqual(0, bui.GetSignificantBitCount());
        }

        [TestMethod]
        public void HexStringConstructorTest()
        {
            BigUInt bui = new BigUInt("1234567890ABCDEF1234567890ABCDEF");

            Assert.IsFalse(bui.IsZero);
            Assert.AreEqual(2ul, bui.UInt64Count);
            Assert.AreEqual(125, bui.BitCount);
            Assert.AreEqual(125, bui.GetSignificantBitCount());

            Assert.AreEqual(0x1234567890ABCDEFul, bui.Data(0));
            Assert.AreEqual(0x1234567890ABCDEFul, bui.Data(1));

            bui = new BigUInt("FEDCBAFEDCBA0987654321");

            Assert.IsFalse(bui.IsZero);
            Assert.AreEqual(2ul, bui.UInt64Count);
            Assert.AreEqual(88, bui.BitCount);
            Assert.AreEqual(88, bui.GetSignificantBitCount());

            Assert.AreEqual(0xFEDCBAul, bui.Data(1));
            Assert.AreEqual(0xFEDCBA0987654321ul, bui.Data(0));

            bui = new BigUInt(bitCount: 80, hexString: "DEADBEEF");

            Assert.IsFalse(bui.IsZero);
            Assert.AreEqual(2ul, bui.UInt64Count);
            Assert.AreEqual(80, bui.BitCount);
            Assert.AreEqual(32, bui.GetSignificantBitCount());
            Assert.AreEqual(0ul, bui.Data(1));
            Assert.AreEqual(0xDEADBEEFul, bui.Data(0));
        }

        [TestMethod]
        public void U64ConstructorTest()
        {
            BigUInt bui = new BigUInt(bitCount: 80, value: 12345ul);

            Assert.IsFalse(bui.IsZero);
            Assert.AreEqual(2ul, bui.UInt64Count);
            Assert.AreEqual(14, bui.GetSignificantBitCount());
            Assert.AreEqual(0ul, bui.Data(1));
            Assert.AreEqual(12345ul, bui.Data(0));
        }

        [TestMethod]
        public void BigIntegerConstructorTest()
        {
            BigInteger bi = new BigInteger(12345);
            BigUInt bui = new BigUInt(bi);

            Assert.IsFalse(bui.IsZero);
            Assert.AreEqual(14, bui.BitCount);
            Assert.AreEqual(2ul, bui.ByteCount);
            Assert.AreEqual(14, bui.GetSignificantBitCount());
            Assert.AreEqual(1ul, bui.UInt64Count);
            Assert.AreEqual(12345ul, bui.Data(0));
        }

        [TestMethod]
        public void CopyConstructorTest()
        {
            BigUInt bui1 = new BigUInt("DEADBEEF");
            BigUInt bui2 = new BigUInt("1234567890ABCDEF1234567890ABCDEF");

            BigUInt bui3 = new BigUInt(bui1);

            Assert.AreEqual(1ul, bui3.UInt64Count);
            Assert.AreEqual(32, bui3.GetSignificantBitCount());
            Assert.AreEqual(0xDEADBEEFul, bui3.Data(0));
            Assert.IsTrue(bui1.Equals(bui3));

            bui3 = new BigUInt(bui2);

            Assert.AreEqual(2ul, bui3.UInt64Count);
            Assert.AreEqual(125, bui3.BitCount);
            Assert.AreEqual(125, bui3.GetSignificantBitCount());
            Assert.AreEqual(0x1234567890ABCDEFul, bui3.Data(0));
            Assert.AreEqual(0x1234567890ABCDEFul, bui3.Data(1));
            Assert.IsTrue(bui2.Equals(bui3));
        }

        [TestMethod]
        public void EmptyBigUIntNET()
        {
            var biguint = new BigUInt();
            Assert.AreEqual(0, biguint.BitCount);
            Assert.AreEqual(0ul, biguint.ByteCount);
            Assert.AreEqual(0ul, biguint.UInt64Count);
            Assert.IsTrue(biguint.UInt64Count == 0ul);
            Assert.AreEqual(0, biguint.GetSignificantBitCount());
            Assert.AreEqual("0", biguint.ToString());
            Assert.IsTrue(biguint.IsZero);
            Assert.IsFalse(biguint.IsAlias);
            biguint.SetZero();

            var biguint2 = new BigUInt();
            Assert.IsTrue(biguint.Equals(biguint2));

            biguint.Resize(1);
            Assert.AreEqual(1, biguint.BitCount);
            Assert.IsTrue(biguint.UInt64Count != 0ul);
            Assert.IsFalse(biguint.IsAlias);

            biguint.Resize(0);
            Assert.AreEqual(0, biguint.BitCount);
            Assert.IsTrue(biguint.UInt64Count == 0ul);
            Assert.IsFalse(biguint.IsAlias);
        }

        [TestMethod]
        public void BigUInt64BitsNET()
        {
            var biguint = new BigUInt(64);
            Assert.AreEqual(64, biguint.BitCount);
            Assert.AreEqual(8ul, biguint.ByteCount);
            Assert.AreEqual(1ul, biguint.UInt64Count);
            Assert.AreEqual(0, biguint.GetSignificantBitCount());
            Assert.AreEqual("0", biguint.ToString());
            Assert.IsTrue(biguint.IsZero);
            Assert.IsTrue(biguint.UInt64Count != 0);
            Assert.AreEqual(0UL, biguint.Data(0));
            Assert.AreEqual(0, biguint[0]);
            Assert.AreEqual(0, biguint[1]);
            Assert.AreEqual(0, biguint[2]);
            Assert.AreEqual(0, biguint[3]);
            Assert.AreEqual(0, biguint[4]);
            Assert.AreEqual(0, biguint[5]);
            Assert.AreEqual(0, biguint[6]);
            Assert.AreEqual(0, biguint[7]);

            biguint.Set(1);
            Assert.AreEqual(1, biguint.GetSignificantBitCount());
            Assert.AreEqual("1", biguint.ToString());
            Assert.IsFalse(biguint.IsZero);
            Assert.AreEqual(1UL, biguint.Data(0));
            Assert.AreEqual(1, biguint[0]);
            Assert.AreEqual(0, biguint[1]);
            Assert.AreEqual(0, biguint[2]);
            Assert.AreEqual(0, biguint[3]);
            Assert.AreEqual(0, biguint[4]);
            Assert.AreEqual(0, biguint[5]);
            Assert.AreEqual(0, biguint[6]);
            Assert.AreEqual(0, biguint[7]);
            biguint.SetZero();
            Assert.IsTrue(biguint.IsZero);
            Assert.AreEqual(0UL, biguint.Data(0));

            biguint.Set("7FFFFFFFFFFFFFFF");
            Assert.AreEqual(63, biguint.GetSignificantBitCount());
            Assert.IsFalse(biguint.IsZero);
            Assert.AreEqual("7FFFFFFFFFFFFFFF", biguint.ToString());
            Assert.AreEqual(0x7FFFFFFFFFFFFFFFUL, biguint.Data(0));
            Assert.AreEqual(0xFF, biguint[0]);
            Assert.AreEqual(0xFF, biguint[1]);
            Assert.AreEqual(0xFF, biguint[2]);
            Assert.AreEqual(0xFF, biguint[3]);
            Assert.AreEqual(0xFF, biguint[4]);
            Assert.AreEqual(0xFF, biguint[5]);
            Assert.AreEqual(0xFF, biguint[6]);
            Assert.AreEqual(0x7F, biguint[7]);

            biguint.Set("FFFFFFFFFFFFFFFF");
            Assert.AreEqual(64, biguint.GetSignificantBitCount());
            Assert.IsFalse(biguint.IsZero);
            Assert.AreEqual("FFFFFFFFFFFFFFFF", biguint.ToString());
            Assert.AreEqual(0xFFFFFFFFFFFFFFFFUL, biguint.Data(0));
            Assert.AreEqual(0xFF, biguint[0]);
            Assert.AreEqual(0xFF, biguint[1]);
            Assert.AreEqual(0xFF, biguint[2]);
            Assert.AreEqual(0xFF, biguint[3]);
            Assert.AreEqual(0xFF, biguint[4]);
            Assert.AreEqual(0xFF, biguint[5]);
            Assert.AreEqual(0xFF, biguint[6]);
            Assert.AreEqual(0xFF, biguint[7]);

            biguint.Set(0x8001);
            Assert.AreEqual(16, biguint.GetSignificantBitCount());
            Assert.AreEqual("8001", biguint.ToString());
            Assert.AreEqual(0x8001UL, biguint.Data(0));
            Assert.AreEqual(0x01, biguint[0]);
            Assert.AreEqual(0x80, biguint[1]);
            Assert.AreEqual(0x00, biguint[2]);
            Assert.AreEqual(0x00, biguint[3]);
            Assert.AreEqual(0x00, biguint[4]);
            Assert.AreEqual(0x00, biguint[5]);
            Assert.AreEqual(0x00, biguint[6]);
            Assert.AreEqual(0x00, biguint[7]);
        }

        [TestMethod]
        public void BigUInt99BitsNET()
        {
            var biguint = new BigUInt(99);
            Assert.AreEqual(99, biguint.BitCount);
            Assert.IsTrue(biguint.UInt64Count != 0ul);
            Assert.AreEqual(13ul, biguint.ByteCount);
            Assert.AreEqual(2ul, biguint.UInt64Count);
            Assert.AreEqual(0, biguint.GetSignificantBitCount());
            Assert.AreEqual("0", biguint.ToString());
            Assert.IsTrue(biguint.IsZero);
            Assert.AreEqual(0UL, biguint.Data(0));
            Assert.AreEqual(0UL, biguint.Data(1));
            Assert.AreEqual(0, biguint[0]);
            Assert.AreEqual(0, biguint[1]);
            Assert.AreEqual(0, biguint[2]);
            Assert.AreEqual(0, biguint[3]);
            Assert.AreEqual(0, biguint[4]);
            Assert.AreEqual(0, biguint[5]);
            Assert.AreEqual(0, biguint[6]);
            Assert.AreEqual(0, biguint[7]);
            Assert.AreEqual(0, biguint[8]);
            Assert.AreEqual(0, biguint[9]);
            Assert.AreEqual(0, biguint[10]);
            Assert.AreEqual(0, biguint[11]);
            Assert.AreEqual(0, biguint[12]);

            biguint.Set(1);
            Assert.AreEqual(1, biguint.GetSignificantBitCount());
            Assert.AreEqual("1", biguint.ToString());
            Assert.IsFalse(biguint.IsZero);
            Assert.AreEqual(13ul, biguint.ByteCount);
            Assert.AreEqual(2ul, biguint.UInt64Count);
            Assert.AreEqual(1UL, biguint.Data(0));
            Assert.AreEqual(0UL, biguint.Data(1));
            Assert.AreEqual(1, biguint[0]);
            Assert.AreEqual(0, biguint[1]);
            Assert.AreEqual(0, biguint[2]);
            Assert.AreEqual(0, biguint[3]);
            Assert.AreEqual(0, biguint[4]);
            Assert.AreEqual(0, biguint[5]);
            Assert.AreEqual(0, biguint[6]);
            Assert.AreEqual(0, biguint[7]);
            Assert.AreEqual(0, biguint[8]);
            Assert.AreEqual(0, biguint[9]);
            Assert.AreEqual(0, biguint[10]);
            Assert.AreEqual(0, biguint[11]);
            Assert.AreEqual(0, biguint[12]);
            biguint.SetZero();
            Assert.IsTrue(biguint.IsZero);
            Assert.AreEqual(0UL, biguint.Data(0));
            Assert.AreEqual(0UL, biguint.Data(1));

            biguint.Set("7FFFFFFFFFFFFFFFFFFFFFFFF");
            Assert.AreEqual(99, biguint.GetSignificantBitCount());
            Assert.AreEqual("7FFFFFFFFFFFFFFFFFFFFFFFF", biguint.ToString());
            Assert.IsFalse(biguint.IsZero);
            Assert.AreEqual(0xFFFFFFFFFFFFFFFFUL, biguint.Data(0));
            Assert.AreEqual(0x7FFFFFFFFUL, biguint.Data(1));
            Assert.AreEqual(0xFF, biguint[0]);
            Assert.AreEqual(0xFF, biguint[1]);
            Assert.AreEqual(0xFF, biguint[2]);
            Assert.AreEqual(0xFF, biguint[3]);
            Assert.AreEqual(0xFF, biguint[4]);
            Assert.AreEqual(0xFF, biguint[5]);
            Assert.AreEqual(0xFF, biguint[6]);
            Assert.AreEqual(0xFF, biguint[7]);
            Assert.AreEqual(0xFF, biguint[8]);
            Assert.AreEqual(0xFF, biguint[9]);
            Assert.AreEqual(0xFF, biguint[10]);
            Assert.AreEqual(0xFF, biguint[11]);
            Assert.AreEqual(0x07, biguint[12]);
            biguint.SetZero();
            Assert.IsTrue(biguint.IsZero);
            Assert.AreEqual(0UL, biguint.Data(0));
            Assert.AreEqual(0UL, biguint.Data(1));

            biguint.Set("4000000000000000000000000");
            Assert.AreEqual(99, biguint.GetSignificantBitCount());
            Assert.AreEqual("4000000000000000000000000", biguint.ToString());
            Assert.IsFalse(biguint.IsZero);
            Assert.AreEqual(0UL, biguint.Data(0));
            Assert.AreEqual(0x400000000UL, biguint.Data(1));
            Assert.AreEqual(0, biguint[0]);
            Assert.AreEqual(0, biguint[1]);
            Assert.AreEqual(0, biguint[2]);
            Assert.AreEqual(0, biguint[3]);
            Assert.AreEqual(0, biguint[4]);
            Assert.AreEqual(0, biguint[5]);
            Assert.AreEqual(0, biguint[6]);
            Assert.AreEqual(0, biguint[7]);
            Assert.AreEqual(0, biguint[8]);
            Assert.AreEqual(0, biguint[9]);
            Assert.AreEqual(0, biguint[10]);
            Assert.AreEqual(0, biguint[11]);
            Assert.AreEqual(0x04, biguint[12]);

            biguint.Set(0x8001);
            Assert.AreEqual(16, biguint.GetSignificantBitCount());
            Assert.AreEqual("8001", biguint.ToString());
            Assert.IsFalse(biguint.IsZero);
            Assert.AreEqual(0x8001UL, biguint.Data(0));
            Assert.AreEqual(0UL, biguint.Data(1));
            Assert.AreEqual(0x01, biguint[0]);
            Assert.AreEqual(0x80, biguint[1]);
            Assert.AreEqual(0, biguint[2]);
            Assert.AreEqual(0, biguint[3]);
            Assert.AreEqual(0, biguint[4]);
            Assert.AreEqual(0, biguint[5]);
            Assert.AreEqual(0, biguint[6]);
            Assert.AreEqual(0, biguint[7]);
            Assert.AreEqual(0, biguint[8]);
            Assert.AreEqual(0, biguint[9]);
            Assert.AreEqual(0, biguint[10]);
            Assert.AreEqual(0, biguint[11]);
            Assert.AreEqual(0, biguint[12]);

            var biguint2 = new BigUInt("123");
            Assert.IsFalse(biguint.Equals(biguint2));
            Assert.IsFalse(biguint2.Equals(biguint));
            Assert.AreNotEqual(biguint.GetHashCode(), biguint2.GetHashCode());

            biguint.Set(biguint2);
            Assert.IsTrue(biguint.Equals(biguint2));
            Assert.IsTrue(biguint2.Equals(biguint));
            Assert.AreEqual(biguint.GetHashCode(), biguint2.GetHashCode());
            Assert.AreEqual(9, biguint.GetSignificantBitCount());
            Assert.AreEqual("123", biguint.ToString());
            Assert.AreEqual(0x123UL, biguint.Data(0));
            Assert.AreEqual(0UL, biguint.Data(1));
            Assert.AreEqual(0x23, biguint[0]);
            Assert.AreEqual(0x01, biguint[1]);
            Assert.AreEqual(0, biguint[2]);
            Assert.AreEqual(0, biguint[3]);
            Assert.AreEqual(0, biguint[4]);
            Assert.AreEqual(0, biguint[5]);
            Assert.AreEqual(0, biguint[6]);
            Assert.AreEqual(0, biguint[7]);
            Assert.AreEqual(0, biguint[8]);
            Assert.AreEqual(0, biguint[9]);
            Assert.AreEqual(0, biguint[10]);
            Assert.AreEqual(0, biguint[11]);
            Assert.AreEqual(0, biguint[12]);

            biguint.Resize(8);
            Assert.AreEqual(8, biguint.BitCount);
            Assert.AreEqual(1ul, biguint.UInt64Count);
            Assert.AreEqual("23", biguint.ToString());

            biguint.Resize(100);
            Assert.AreEqual(100, biguint.BitCount);
            Assert.AreEqual(2ul, biguint.UInt64Count);
            Assert.AreEqual("23", biguint.ToString());

            biguint.Resize(0);
            Assert.AreEqual(0, biguint.BitCount);
            Assert.AreEqual(0ul, biguint.UInt64Count);
            Assert.IsTrue(biguint.UInt64Count == 0);
        }

        [TestMethod]
        public void SaveLoadUIntNET()
        {
            using (MemoryStream stream = new MemoryStream())
            {
                var value = new BigUInt();
                var value2 = new BigUInt("100");
                stream.Seek(0, SeekOrigin.Begin);
                value.Save(stream);
                stream.Seek(0, SeekOrigin.Begin);
                value2.Load(stream);
                Assert.AreEqual(value, value2);

                value.Set("123");
                stream.Seek(0, SeekOrigin.Begin);
                value.Save(stream);
                stream.Seek(0, SeekOrigin.Begin);
                value2.Load(stream);
                Assert.AreEqual(value, value2);

                value.Set("FFFFFFFFFFFFFFFFFFFFFFFFFF");
                stream.Seek(0, SeekOrigin.Begin);
                value.Save(stream);
                stream.Seek(0, SeekOrigin.Begin);
                value2.Load(stream);
                Assert.AreEqual(value, value2);

                value.Set("0");
                stream.Seek(0, SeekOrigin.Begin);
                value.Save(stream);
                stream.Seek(0, SeekOrigin.Begin);
                value2.Load(stream);
                Assert.AreEqual(value, value2);
            }
        }

        [TestMethod]
        public void DuplicateToNET()
        {
            var original = new BigUInt(123);
            original.Set(56789);

            var target = new BigUInt();

            original.DuplicateTo(target);
            Assert.AreEqual(target.BitCount, original.BitCount);
            Assert.IsTrue(target.Equals(original));
        }

        [TestMethod]
        public void DuplicateFromNET()
        {
            var original = new BigUInt(123);
            original.Set(56789);

            var target = new BigUInt();

            target.DuplicateFrom(original);
            Assert.AreEqual(target.BitCount, original.BitCount);
            Assert.IsTrue(target.Equals(original));
        }

        [TestMethod]
        public void ToBigIntegerTest()
        {
            BigUInt bui = new BigUInt("DEADBEEF");
            BigInteger bi = bui.ToBigInteger();
            Assert.IsNotNull(bi);
            Assert.IsFalse(bi.IsEven);
            Assert.IsFalse(bi.IsZero);
            Assert.AreEqual(0, bi.CompareTo(0xDEADBEEFul));
        }

        [TestMethod]
        public void ToDecimalStringTest()
        {
            BigUInt bui = new BigUInt("DEADBEEF");
            string decStr = bui.ToDecimalString();
            Assert.IsNotNull(decStr);
            Assert.IsTrue("3735928559".Equals(decStr));
        }

        [TestMethod]
        public void CompareToTest()
        {
            BigUInt bui = new BigUInt("DEADBEEF");
            BigUInt other = new BigUInt("DEADBFFF");
            Assert.IsTrue(bui.CompareTo(other) < 0);
            Assert.IsTrue(other.CompareTo(bui) > 0);

            BigUInt third = new BigUInt(bui);
            Assert.AreNotSame(bui, third);
            Assert.AreEqual(0, bui.CompareTo(third));
            Assert.IsTrue(bui.CompareTo(null) > 0);
        }

        [TestMethod]
        public void ModuloInvertFail1Test()
        {
            // Should fail when modulus is zero
            BigUInt bui = new BigUInt("DEADBEEF");
            BigUInt mod = new BigUInt();

            Assert.IsTrue(mod.IsZero);
            Assert.IsFalse(bui.IsZero);

            Utilities.AssertThrows<ArgumentException>(() => bui.ModuloInvert(mod));
        }

        [TestMethod]
        public void ModuloInvertFail2Test()
        {
            // Should fail when modulus is not greater than the BigUInt value
            BigUInt bui = new BigUInt("DEADBEEF");
            BigUInt mod = new BigUInt("BEEF");

            Assert.IsFalse(mod.IsZero);
            Assert.IsFalse(bui.IsZero);

            Utilities.AssertThrows<ArgumentException>(() => bui.ModuloInvert(mod));
        }

        [TestMethod]
        public void ModuloInvertFail3Test()
        {
            // Should fail when biguint value and modulus are not coprime
            BigUInt bui = new BigUInt(bitCount: 64, value: 12);
            BigUInt mod = new BigUInt(bitCount: 64, value: 24);

            Assert.IsFalse(mod.IsZero);
            Assert.IsFalse(bui.IsZero);

            Utilities.AssertThrows<ArgumentException>(() => bui.ModuloInvert(mod));
        }

        [TestMethod]
        public void ModuloInvertTest()
        {
            BigUInt bui = new BigUInt(bitCount: 64, value: 12);
            BigUInt mod = new BigUInt(bitCount: 64, value: 25);

            BigUInt inverse1 = bui.ModuloInvert(mod);

            Assert.AreEqual(23ul, inverse1.Data(0));

            BigUInt inverse2 = bui.ModuloInvert(modulus: 25ul);

            Assert.AreEqual(23ul, inverse2.Data(0));
        }

        [TestMethod]
        public void TryModuloInvertFail1Test()
        {
            BigUInt bui = new BigUInt("DEADBEEF");
            BigUInt mod = new BigUInt();
            BigUInt inverse = new BigUInt();

            // Should fail when modulus is zero
            Assert.IsTrue(mod.IsZero);
            Utilities.AssertThrows<ArgumentException>(() => bui.TryModuloInvert(mod, inverse));
        }

        [TestMethod]
        public void TryModuloInvertFail2Test()
        {
            BigUInt bui = new BigUInt("DEADBEEF");
            BigUInt mod = new BigUInt("BEEF");
            BigUInt inverse = new BigUInt();

            // Should fail when biguint is bigger than modulus
            Assert.IsFalse(mod.IsZero);
            Utilities.AssertThrows<ArgumentException>(() => bui.TryModuloInvert(mod, inverse));
        }

        [TestMethod]
        public void TryModuloInvertTest()
        {
            BigUInt bui = new BigUInt(bitCount: 64, value: 12);
            BigUInt mod = new BigUInt(bitCount: 64, value: 25);
            BigUInt inverse1 = new BigUInt();
            BigUInt inverse2 = new BigUInt();

            Assert.IsTrue(bui.TryModuloInvert(mod, inverse1));

            Assert.AreEqual(23ul, inverse1.Data(0));

            Assert.IsTrue(bui.TryModuloInvert(modulus: 25ul, inverse: inverse2));

            Assert.AreEqual(23ul, inverse2.Data(0));

            // Should fail (but not throw) when biguint value and modulus are not coprime
            BigUInt bui2 = new BigUInt(bitCount: 64, value: 12);
            BigUInt mod2 = new BigUInt(bitCount: 64, value: 24);

            Assert.IsFalse(mod2.IsZero);
            Assert.IsFalse(bui2.IsZero);

            Assert.IsFalse(bui2.TryModuloInvert(mod2, inverse1));
        }

        [TestMethod]
        public void DivideRemainderTest()
        {
            BigUInt bui = new BigUInt("DEADBEEF");
            BigUInt op = new BigUInt("BEEF");
            BigUInt remainder = new BigUInt();

            BigUInt result = bui.DivideRemainder(op, remainder);

            Assert.AreEqual(1ul, result.UInt64Count);
            Assert.AreEqual(0x12a90ul, result.Data(0));
            Assert.AreEqual(1ul, remainder.UInt64Count);
            Assert.AreEqual(0x227Ful, remainder.Data(0));

            BigUInt result2 = bui.DivideRemainder(0xDEADul, remainder);

            Assert.AreEqual(1ul, result2.UInt64Count);
            Assert.AreEqual(0x10000ul, result2.Data(0));
            Assert.AreEqual(1ul, remainder.UInt64Count);
            Assert.AreEqual(0xBEEFul, remainder.Data(0));
        }

        [TestMethod]
        public void OperatorPlusTest()
        {
            BigUInt bui = new BigUInt("DEADBEEF");
            BigUInt newone = +bui;

            Assert.AreEqual(1ul, newone.UInt64Count);
            Assert.AreEqual(0xDEADBEEFul, newone.Data(0));
        }

        [TestMethod]
        public void OperatorMinusTest()
        {
            BigUInt bui = new BigUInt("DEADBEEF");
            BigUInt newone = -bui;

            Assert.AreEqual(1ul, newone.UInt64Count);
            Assert.AreEqual(0x21524111ul, newone.Data(0));
        }

        [TestMethod]
        public void OperatorTildeTest()
        {
            BigUInt bui = new BigUInt("DEADBEEF");
            BigUInt newone = ~bui;

            Assert.AreEqual(1ul, newone.UInt64Count);
            Assert.AreEqual(0x21524110ul, newone.Data(0));
        }

        [TestMethod]
        public void OperatorPlusPlusTest()
        {
            BigUInt bui = new BigUInt("12345678901234567890");
            bui++;

            Assert.AreEqual(2ul, bui.UInt64Count);
            Assert.AreEqual(0x1234ul, bui.Data(1));
            Assert.AreEqual(0x5678901234567891ul, bui.Data(0));
        }

        [TestMethod]
        public void OperatorMinusMinusTest()
        {
            BigUInt bui = new BigUInt("12345678901234567890");
            bui--;

            Assert.AreEqual(2ul, bui.UInt64Count);
            Assert.AreEqual(0x1234ul, bui.Data(1));
            Assert.AreEqual(0x567890123456788Ful, bui.Data(0));
        }

        [TestMethod]
        public void OperatorAddTest()
        {
            BigUInt bui = new BigUInt("1234567890");
            BigUInt op = new BigUInt("6543210");

            BigUInt result = bui + op;

            Assert.AreEqual(1ul, result.UInt64Count);
            Assert.AreEqual(0x123AAAAAA0ul, result.Data(0));

            BigUInt result2 = bui + 0x9876543210ul;

            Assert.AreEqual(1ul, result2.UInt64Count);
            Assert.AreEqual(0xAAAAAAAAA0ul, result2.Data(0));
        }

        [TestMethod]
        public void OperatorSubTest()
        {
            BigUInt bui = new BigUInt("1234567890");
            BigUInt op = new BigUInt("6543210");

            BigUInt result = bui - op;

            Assert.AreEqual(1ul, result.UInt64Count);
            Assert.AreEqual(0x122E024680ul, result.Data(0));

            result = bui - 0x76543210ul;

            Assert.AreEqual(1ul, result.UInt64Count);
            Assert.AreEqual(0x11BE024680ul, result.Data(0));
        }

        [TestMethod]
        public void OperatorMultTest()
        {
            BigUInt bui = new BigUInt("12345");
            BigUInt op = new BigUInt("ABCDEF");

            BigUInt result = bui * op;

            Assert.AreEqual(1ul, result.UInt64Count);
            Assert.AreEqual(0xC379652E6Bul, result.Data(0));

            result = bui * 0xFEDCBAul;

            Assert.AreEqual(1ul, result.UInt64Count);
            Assert.AreEqual(0x121F998EC22ul, result.Data(0));
        }

        [TestMethod]
        public void OperatorDivTest()
        {
            BigUInt bui = new BigUInt("1234567890");
            BigUInt op = new BigUInt("BEEF");

            BigUInt result = bui / op;

            Assert.AreEqual(1ul, result.UInt64Count);
            Assert.AreEqual(0x18687Dul, result.Data(0));

            result = bui / 0xDEAD;

            Assert.AreEqual(1ul, result.UInt64Count);
            Assert.AreEqual(0x14EDC6ul, result.Data(0));
        }

        [TestMethod]
        public void OperatorAndTest()
        {
            BigUInt bui = new BigUInt("CDCDCDCDABABABABABABABAB");
            BigUInt op  = new BigUInt("FEFEFEFEFEFEFEFEFEFEFEFE");

            BigUInt result = bui & op;

            Assert.AreEqual(2ul, result.UInt64Count);
            Assert.AreEqual(0xCCCCCCCCul, result.Data(1));
            Assert.AreEqual(0xAAAAAAAAAAAAAAAAul, result.Data(0));

            result = bui & 0xF0F0F0F0F0;

            Assert.AreEqual(2ul, result.UInt64Count);
            Assert.AreEqual(0ul, result.Data(1));
            Assert.AreEqual(0xA0A0A0A0A0ul, result.Data(0));
        }

        [TestMethod]
        public void OperatorOrTest()
        {
            BigUInt bui = new BigUInt("CDCDCDCDABABABABABABABAB");
            BigUInt op  = new BigUInt("E0E0E0E0E0E0E0E0E0E0E0E0");

            BigUInt result = bui | op;

            Assert.AreEqual(2ul, result.UInt64Count);
            Assert.AreEqual(0xEDEDEDEDul, result.Data(1));
            Assert.AreEqual(0xEBEBEBEBEBEBEBEBul, result.Data(0));

            result = bui | 0x1010101010;

            Assert.AreEqual(2ul, result.UInt64Count);
            Assert.AreEqual(0xCDCDCDCDul, result.Data(1));
            Assert.AreEqual(0xABABABBBBBBBBBBBul, result.Data(0));
        }

        [TestMethod]
        public void OperatorXorTest()
        {
            BigUInt bui = new BigUInt("CDCDCDCDABABABABABABABAB");
            BigUInt op  = new BigUInt("0000FFFFFFFF000000000000");

            BigUInt result = bui ^ op;

            Assert.AreEqual(2ul, result.UInt64Count);
            Assert.AreEqual(0xCDCD3232ul, result.Data(1));
            Assert.AreEqual(0x5454ABABABABABABul, result.Data(0));

            result = bui ^ 0xF0F0F0F0F0;

            Assert.AreEqual(2ul, result.UInt64Count);
            Assert.AreEqual(0xCDCDCDCDul, result.Data(1));
            Assert.AreEqual(0xABABAB5B5B5B5B5Bul, result.Data(0));
        }

        [TestMethod]
        public void OperatorShiftLeftTest()
        {
            BigUInt bui = new BigUInt("CDCDCDCDABABABABABABABAB");

            BigUInt result = bui << 1;

            Assert.AreEqual(2ul, result.UInt64Count);
            Assert.AreEqual(0x19B9B9B9Bul, result.Data(1));
            Assert.AreEqual(0x5757575757575756ul, result.Data(0));

            result = bui << 2;

            Assert.AreEqual(2ul, result.UInt64Count);
            Assert.AreEqual(0x337373736ul, result.Data(1));
            Assert.AreEqual(0xAEAEAEAEAEAEAEACul, result.Data(0));
        }

        [TestMethod]
        public void OperatorShiftRightTest()
        {
            BigUInt bui = new BigUInt("CDCDCDCDABABABABABABABAB");

            BigUInt result = bui >> 1;

            Assert.AreEqual(2ul, result.UInt64Count);
            Assert.AreEqual(0x66E6E6E6ul, result.Data(1));
            Assert.AreEqual(0xD5D5D5D5D5D5D5D5ul, result.Data(0));

            result = bui >> 2;

            Assert.AreEqual(2ul, result.UInt64Count);
            Assert.AreEqual(0x33737373ul, result.Data(1));
            Assert.AreEqual(0x6AEAEAEAEAEAEAEAul, result.Data(0));
        }

        [TestMethod]
        public void OperatorDoubleTest()
        {
            BigUInt bui = new BigUInt("12345");

            double value = (double)bui;

            Assert.AreEqual(74565.0, value, delta: 0.1);

            bui = new BigUInt("12345678901234567890");

            value = (double)bui;

            Assert.AreEqual(8.59680582719788E+22, value, delta: 3.5e7);
        }

        [TestMethod]
        public void OperatorFloatTest()
        {
            BigUInt bui = new BigUInt("12345");
            float value = (float)bui;

            Assert.AreEqual(74565.0f, value, delta: 0.1);

            bui.Set("12345678901234567890");

            value = (float)bui;

            Assert.AreEqual(8.59680582719788E+22f, value, delta: 0.1f);
        }

        [TestMethod]
        public void OperatorUInt64Test()
        {
            BigUInt bui = new BigUInt("ABCDEF1234567890ABCDEF");
            ulong value = (ulong)bui;

            Assert.AreEqual(0x1234567890ABCDEFul, value);
        }

        [TestMethod]
        public void OperatorInt64Test()
        {
            BigUInt bui = new BigUInt("ABCDEF124567890ABCDEF");
            long value = (long)bui;

            Assert.AreEqual(-1070635735584092689, value);
        }

        [TestMethod]
        public void OperatorUInt32Test()
        {
            BigUInt bui = new BigUInt("ABCDEF1234567890ABCDEF");
            uint value = (uint)bui;

            Assert.AreEqual(0x90ABCDEFu, value);
        }

        [TestMethod]
        public void OperatorInt32Test()
        {
            BigUInt bui = new BigUInt("ABCDEF1234567890ABCDEF");
            int value = (int)bui;

            Assert.AreEqual(-1867788817, value);
        }

        [TestMethod]
        public void ExceptionsTest()
        {
            BigUInt bui = new BigUInt("DEADBEEF");
            BigUInt bui1 = null;

            Utilities.AssertThrows<ArgumentNullException>(() => bui1 = new BigUInt((BigUInt)null));
            Utilities.AssertThrows<ArgumentNullException>(() => bui1 = new BigUInt((string)null));
            Utilities.AssertThrows<ArgumentException>(() => bui1 = new BigUInt(bitCount: -1));
            Utilities.AssertThrows<ArgumentNullException>(() => bui1 = new BigUInt(bitCount: 64, hexString: null));
            Utilities.AssertThrows<ArgumentException>(() => bui1 = new BigUInt(bitCount: -1, hexString: "ABCDEF"));
            Utilities.AssertThrows<ArgumentException>(() => bui1 = new BigUInt(bitCount: -1, value: 10ul));

            bui1 = new BigUInt();
            BigUInt bui2 = new BigUInt();

            Utilities.AssertThrows<ArgumentOutOfRangeException>(() => bui.Data(1));

            Utilities.AssertThrows<ArgumentOutOfRangeException>(() => bui[5] );
            Utilities.AssertThrows<ArgumentOutOfRangeException>(() => bui[5] = 2);

            Utilities.AssertThrows<ArgumentNullException>(() => bui.DivideRemainder(bui1, null));
            Utilities.AssertThrows<ArgumentNullException>(() => bui.DivideRemainder(null, bui2));
            Utilities.AssertThrows<ArgumentException>(() => bui.DivideRemainder(bui1, bui2));

            Utilities.AssertThrows<ArgumentNullException>(() => bui.DivideRemainder(1ul, null));
            Utilities.AssertThrows<ArgumentException>(() => bui.DivideRemainder(0ul, bui2));

            Utilities.AssertThrows<ArgumentNullException>(() => bui.DuplicateFrom(null));
            Utilities.AssertThrows<ArgumentNullException>(() => bui.DuplicateTo(null));

            Assert.IsFalse(bui.Equals(null));

            Utilities.AssertThrows<ArgumentNullException>(() => bui.Load(null));
            Utilities.AssertThrows<ArgumentNullException>(() => bui.ModuloInvert(null));
            Utilities.AssertThrows<ArgumentException>(() => bui.Resize(bitCount: -1));
            Utilities.AssertThrows<ArgumentNullException>(() => bui.Save(null));

            Utilities.AssertThrows<ArgumentNullException>(() => bui.Set((BigUInt)null));
            Utilities.AssertThrows<ArgumentNullException>(() => bui.Set((string)null));

            Utilities.AssertThrows<ArgumentNullException>(() => bui.TryModuloInvert(bui1, null));
            Utilities.AssertThrows<ArgumentNullException>(() => bui.TryModuloInvert(null, bui2));
            Utilities.AssertThrows<ArgumentException>(() => bui.TryModuloInvert(bui1, bui2));
            Utilities.AssertThrows<ArgumentNullException>(() => bui.TryModuloInvert(1ul, null));

            bui2 = null;

            Utilities.AssertThrows<ArgumentNullException>(() => bui2 = +bui2);
            Utilities.AssertThrows<ArgumentNullException>(() => bui2 = -bui2);
            Utilities.AssertThrows<ArgumentNullException>(() => bui2 = ~bui2);
            Utilities.AssertThrows<ArgumentNullException>(() => bui2++);
            Utilities.AssertThrows<ArgumentNullException>(() => bui2--);

            Utilities.AssertThrows<ArgumentNullException>(() => bui1 = bui + bui2);
            Utilities.AssertThrows<ArgumentNullException>(() => bui1 = bui2 + bui);
            Utilities.AssertThrows<ArgumentNullException>(() => bui1 = bui2 + 1ul);

            Utilities.AssertThrows<ArgumentNullException>(() => bui1 = bui - bui2);
            Utilities.AssertThrows<ArgumentNullException>(() => bui1 = bui2 - bui);
            Utilities.AssertThrows<ArgumentNullException>(() => bui1 = bui2 - 1ul);

            Utilities.AssertThrows<ArgumentNullException>(() => bui1 = bui * bui2);
            Utilities.AssertThrows<ArgumentNullException>(() => bui1 = bui2 * bui);
            Utilities.AssertThrows<ArgumentNullException>(() => bui1 = bui2 * 1ul);

            Utilities.AssertThrows<ArgumentNullException>(() => bui1 = bui / bui2);
            Utilities.AssertThrows<ArgumentNullException>(() => bui1 = bui2 / bui);
            Utilities.AssertThrows<ArgumentException>(() => bui1 = bui / bui1);
            Utilities.AssertThrows<ArgumentNullException>(() => bui1 = bui2 / 1ul);
            Utilities.AssertThrows<ArgumentException>(() => bui1 = bui / 0ul);

            Utilities.AssertThrows<ArgumentNullException>(() => bui1 = bui ^ bui2);
            Utilities.AssertThrows<ArgumentNullException>(() => bui1 = bui2 ^ bui);
            Utilities.AssertThrows<ArgumentNullException>(() => bui1 = bui2 ^ 1ul);

            Utilities.AssertThrows<ArgumentNullException>(() => bui1 = bui & bui2);
            Utilities.AssertThrows<ArgumentNullException>(() => bui1 = bui2 & bui);
            Utilities.AssertThrows<ArgumentNullException>(() => bui1 = bui2 & 1ul);

            Utilities.AssertThrows<ArgumentNullException>(() => bui1 = bui | bui2);
            Utilities.AssertThrows<ArgumentNullException>(() => bui1 = bui2 | bui);
            Utilities.AssertThrows<ArgumentNullException>(() => bui1 = bui2 | 1ul);

            Utilities.AssertThrows<ArgumentNullException>(() => bui1 = bui2 << 5);
            Utilities.AssertThrows<ArgumentException>(() => bui1 = bui1 << -1);

            Utilities.AssertThrows<ArgumentNullException>(() => bui1 = bui2 >> 5);
            Utilities.AssertThrows<ArgumentException>(() => bui1 = bui1 >> -1);

            Utilities.AssertThrows<ArgumentNullException>(() => { double d = (double)bui2; });
            Utilities.AssertThrows<ArgumentNullException>(() => { float f = (float)bui2; });
            Utilities.AssertThrows<ArgumentNullException>(() => { ulong u = (ulong)bui2; });
            Utilities.AssertThrows<ArgumentNullException>(() => { long l = (long)bui2; });
            Utilities.AssertThrows<ArgumentNullException>(() => { uint u = (uint)bui2; });
            Utilities.AssertThrows<ArgumentNullException>(() => { int i = (int)bui2; });
        }
    }
}
