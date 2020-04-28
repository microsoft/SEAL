// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

using Microsoft.Research.SEAL;
using System;
using System.IO;
using System.Collections.Generic;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace SEALNetTest
{
    [TestClass]
    public class ModulusTests
    {
        [TestMethod]
        public void EmptyConstructorTest()
        {
            Modulus sm = new Modulus();

            Assert.IsNotNull(sm);
            Assert.IsTrue(sm.IsZero);
            Assert.AreEqual(0ul, sm.Value);
            Assert.AreEqual(0, sm.BitCount);
            Assert.AreEqual(1ul, sm.UInt64Count);
            Assert.IsFalse(sm.IsPrime);
        }

        [TestMethod]
        public void ValueConstructorTest()
        {
            Modulus sm = new Modulus(5);

            Assert.IsNotNull(sm);
            Assert.IsFalse(sm.IsZero);
            Assert.AreEqual(5ul, sm.Value);
            Assert.AreEqual(3, sm.BitCount);
            Assert.IsTrue(sm.IsPrime);

            // Value is exactly 61 bits
            Modulus sm2 = new Modulus(0x1FFFFFFFFFFFFFFFul);

            Assert.IsNotNull(sm2);
            Assert.IsFalse(sm2.IsZero);
            Assert.AreEqual(0x1FFFFFFFFFFFFFFFul, sm2.Value);
            Assert.AreEqual(61, sm2.BitCount);
            Assert.AreEqual(1ul, sm2.UInt64Count);
            Assert.IsTrue(sm2.IsPrime);

            Modulus sm3 = new Modulus(0xF00000F000079ul);

            Assert.IsNotNull(sm3);
            Assert.IsFalse(sm3.IsZero);
            Assert.AreEqual(0xF00000F000079ul, sm3.Value);
            Assert.AreEqual(52, sm3.BitCount);
            Assert.AreEqual(1ul, sm3.UInt64Count);
            Assert.IsTrue(sm3.IsPrime);
        }

        [TestMethod]
        public void CopyConstructorTest()
        {
            Modulus sm = new Modulus(10);
            Modulus copy = new Modulus(sm);

            Assert.IsNotNull(copy);
            Assert.IsFalse(copy.IsZero);
            Assert.AreEqual(10ul, copy.Value);
        }

        [TestMethod]
        public void ExplicitCreateTest()
        {
            Modulus sm = (Modulus)34ul;
            Assert.IsNotNull(sm);
            Assert.AreEqual(34ul, sm.Value);
        }

        [TestMethod]
        public void ConstructorFail1Test()
        {
            // Should fail if value is 1
            Utilities.AssertThrows<ArgumentException>(() => { Modulus sm = new Modulus(1); });
        }

        [TestMethod]
        public void ConstructorFail2Test()
        {
            // Should fail if value is larger than 61 bits
            Utilities.AssertThrows<ArgumentException>(() => { Modulus sm = new Modulus(0x2000000000000000ul); });
        }

        [TestMethod]
        public void SetTest()
        {
            Modulus sm1 = new Modulus(456);
            Modulus sm2 = new Modulus();

            Assert.IsFalse(sm1.IsZero);
            Assert.AreEqual(456ul, sm1.Value);
            Assert.IsFalse(sm1.IsPrime);
            Assert.IsTrue(sm2.IsZero);
            Assert.AreEqual(0ul, sm2.Value);
            Assert.IsFalse(sm2.IsPrime);

            sm2.Set(sm1);

            Assert.IsFalse(sm2.IsZero);
            Assert.AreEqual(456ul, sm2.Value);
            Assert.IsFalse(sm2.IsPrime);

            sm2.Set(value: 65537ul);

            Assert.IsFalse(sm2.IsZero);
            Assert.AreEqual(65537ul, sm2.Value);
            Assert.IsTrue(sm2.IsPrime);
        }

        [TestMethod]
        public void SetFail1Test()
        {
            // Should faile if set to 1
            Modulus sm = new Modulus();
            Utilities.AssertThrows<ArgumentException>(() => sm.Set(1));
        }

        [TestMethod]
        public void SetFail2Test()
        {
            // Should fail if set to bigger than 61 bits
            Modulus sm = new Modulus();
            Utilities.AssertThrows<ArgumentException>(() => sm.Set(0x2000000000000000ul));
        }

        [TestMethod]
        public void ConstRatioTest()
        {
            Modulus sm = new Modulus();
            sm.Set(0x1234567890ABCDEFul);

            Tuple<ulong, ulong, ulong> ratio = sm.ConstRatio;

            Assert.IsNotNull(ratio);
            Assert.AreNotEqual(0ul, ratio.Item1);
            Assert.AreNotEqual(0ul, ratio.Item2);
            Assert.AreNotEqual(0ul, ratio.Item3);

            sm.Set(0xF00000F000079ul);
            ratio = sm.ConstRatio;

            Assert.IsNotNull(ratio);
            Assert.AreEqual(1224979096621368355ul, ratio.Item1);
            Assert.AreEqual(4369ul, ratio.Item2);
            Assert.AreEqual(1144844808538997ul, ratio.Item3);
        }

        [TestMethod]
        public void EqualsTest()
        {
            Modulus sm1 = new Modulus(0x12345ul);
            Modulus sm2 = new Modulus(0x12345ul);

            Assert.AreEqual(sm1, sm2);
            Assert.AreEqual(sm1.GetHashCode(), sm2.GetHashCode());
            Assert.IsTrue(sm1.Equals(0x12345ul));
            Assert.IsFalse(sm1.Equals(0x1234ul));

            Assert.IsFalse(sm1.Equals(null));
        }

        [TestMethod]
        public void CompareToTest()
        {
            Modulus sminv = null;
            Modulus sm0 = new Modulus();
            Modulus sm2 = new Modulus(2);
            Modulus sm5 = new Modulus(5);
            Modulus smbig = new Modulus(0xFFFFFFF);
            Assert.AreEqual(1, sm0.CompareTo(sminv));
            Assert.AreEqual(0, sm0.CompareTo(sm0));
            Assert.AreEqual(-1, sm2.CompareTo(sm5));
            Assert.AreEqual(-1, sm2.CompareTo(smbig));
            Assert.AreEqual(1, sm2.CompareTo(sminv));
            Assert.AreEqual(0, sm5.CompareTo(sm5));
            Assert.AreEqual(0, smbig.CompareTo(smbig));
            Assert.AreEqual(1, smbig.CompareTo(sm0));
            Assert.AreEqual(1, smbig.CompareTo(sm5));
            Assert.AreEqual(1, smbig.CompareTo(sminv));
            Assert.AreEqual(-1, sm5.CompareTo(6));
            Assert.AreEqual(0, sm5.CompareTo(5));
            Assert.AreEqual(1, sm5.CompareTo(4));
            Assert.AreEqual(1, sm5.CompareTo(0));
        }

        [TestMethod]
        public void SaveLoadTest()
        {
            Modulus sm1 = new Modulus(65537ul);
            Modulus sm2 = new Modulus();

            Assert.AreNotSame(sm1, sm2);
            Assert.AreNotEqual(sm1, sm2);
            Assert.AreNotEqual(sm1.IsPrime, sm2.IsPrime);

            using (MemoryStream stream = new MemoryStream())
            {
                sm1.Save(stream);
                stream.Seek(offset: 0, loc: SeekOrigin.Begin);
                sm2.Load(stream);
            }

            Assert.AreNotSame(sm1, sm2);
            Assert.AreEqual(sm1, sm2);
            Assert.AreEqual(sm1.BitCount, sm2.BitCount);
            Assert.AreEqual(sm1.UInt64Count, sm2.UInt64Count);
            Assert.AreEqual(sm1.ConstRatio.Item1, sm2.ConstRatio.Item1);
            Assert.AreEqual(sm1.ConstRatio.Item2, sm2.ConstRatio.Item2);
            Assert.AreEqual(sm1.ConstRatio.Item3, sm2.ConstRatio.Item3);
            Assert.AreEqual(sm1.IsPrime, sm2.IsPrime);
        }

        [TestMethod]
        public void CreateTest()
        {
            List<Modulus> cm = (List<Modulus>)CoeffModulus.Create(2, new int[]{ });
            Assert.AreEqual(0, cm.Count);

            cm = (List<Modulus>)CoeffModulus.Create(2, new int[] { 3 });
            Assert.AreEqual(1, cm.Count);
            Assert.AreEqual(5ul, cm[0].Value);

            cm = (List<Modulus>)CoeffModulus.Create(2, new int[] { 3, 4 });
            Assert.AreEqual(2, cm.Count);
            Assert.AreEqual(5ul, cm[0].Value);
            Assert.AreEqual(13ul, cm[1].Value);

            cm = (List<Modulus>)CoeffModulus.Create(2, new int[] { 3, 5, 4, 5 });
            Assert.AreEqual(4, cm.Count);
            Assert.AreEqual(5ul, cm[0].Value);
            Assert.AreEqual(17ul, cm[1].Value);
            Assert.AreEqual(13ul, cm[2].Value);
            Assert.AreEqual(29ul, cm[3].Value);

            cm = (List<Modulus>)CoeffModulus.Create(32, new int[] { 30, 40, 30, 30, 40 });
            Assert.AreEqual(5, cm.Count);
            Assert.AreEqual(30, (int)(Math.Log(cm[0].Value, 2)) + 1);
            Assert.AreEqual(40, (int)(Math.Log(cm[1].Value, 2)) + 1);
            Assert.AreEqual(30, (int)(Math.Log(cm[2].Value, 2)) + 1);
            Assert.AreEqual(30, (int)(Math.Log(cm[3].Value, 2)) + 1);
            Assert.AreEqual(40, (int)(Math.Log(cm[4].Value, 2)) + 1);
            Assert.AreEqual(1ul, cm[0].Value % 64);
            Assert.AreEqual(1ul, cm[1].Value % 64);
            Assert.AreEqual(1ul, cm[2].Value % 64);
            Assert.AreEqual(1ul, cm[3].Value % 64);
            Assert.AreEqual(1ul, cm[4].Value % 64);
        }

        [TestMethod]
        public void ExceptionsTest()
        {
            Modulus sm = new Modulus(0x12345ul);

            Utilities.AssertThrows<ArgumentNullException>(() => sm = new Modulus(null));
            Utilities.AssertThrows<ArgumentNullException>(() => sm.Set(null));
            Utilities.AssertThrows<ArgumentNullException>(() => sm.Save(null));
            Utilities.AssertThrows<ArgumentNullException>(() => sm.Load(null));
            Utilities.AssertThrows<EndOfStreamException>(() => sm.Load(new MemoryStream()));

            // Too small polyModulusDegree
            Utilities.AssertThrows<ArgumentException>(() => CoeffModulus.Create(1, new int[] { 2 }));

            // Too large polyModulusDegree
            Utilities.AssertThrows<ArgumentException>(() => CoeffModulus.Create(262144, new int[] { 30 }));

            // Invalid polyModulusDegree
            Utilities.AssertThrows<ArgumentException>(() => CoeffModulus.Create(1023, new int[] { 20 }));

            // Invalid bitSize
            Utilities.AssertThrows<ArgumentException>(() => CoeffModulus.Create(2048, new int[] { 0 }));
            Utilities.AssertThrows<ArgumentException>(() => CoeffModulus.Create(2048, new int[] { -30 }));
            Utilities.AssertThrows<ArgumentException>(() => CoeffModulus.Create(2048, new int[] { 30, -30 }));

            // Too small primes requested
            Utilities.AssertThrows<InvalidOperationException>(() => CoeffModulus.Create(2, new int[] { 2 }));
            Utilities.AssertThrows<InvalidOperationException>(() => CoeffModulus.Create(2, new int[] { 3, 3, 3 }));
            Utilities.AssertThrows<InvalidOperationException>(() => CoeffModulus.Create(1024, new int[] { 8 }));
        }
    }
}
