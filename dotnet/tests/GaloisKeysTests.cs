// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

using Microsoft.Research.SEAL;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;

namespace SEALNetTest
{
    [TestClass]
    public class GaloisKeysTests
    {
        [TestMethod]
        public void CreateTest()
        {
            GaloisKeys keys = new GaloisKeys();

            Assert.IsNotNull(keys);
            Assert.AreEqual(0ul, keys.Size);
            Assert.AreEqual(0, keys.DecompositionBitCount);
        }

        [TestMethod]
        public void CreateNonEmptyTest()
        {
            SEALContext context = GlobalContext.Context;
            KeyGenerator keygen = new KeyGenerator(context);

            GaloisKeys keys = keygen.GaloisKeys(decompositionBitCount: 30);

            Assert.IsNotNull(keys);
            Assert.AreEqual(30, keys.DecompositionBitCount);
            Assert.AreEqual(22ul, keys.Size);

            GaloisKeys copy = new GaloisKeys(keys);

            Assert.IsNotNull(copy);
            Assert.AreEqual(30, copy.DecompositionBitCount);
            Assert.AreEqual(22ul, copy.Size);
        }

        [TestMethod]
        public void SaveLoadTest()
        {
            SEALContext context = GlobalContext.Context;
            KeyGenerator keyGen = new KeyGenerator(context);

            GaloisKeys keys = keyGen.GaloisKeys(decompositionBitCount: 30);
            GaloisKeys other = new GaloisKeys();

            Assert.IsNotNull(keys);
            Assert.AreEqual(30, keys.DecompositionBitCount);
            Assert.AreEqual(22ul, keys.Size);

            using (MemoryStream ms = new MemoryStream())
            {
                keys.Save(ms);

                ms.Seek(offset: 0, loc: SeekOrigin.Begin);

                other.Load(context, ms);
            }

            Assert.AreEqual(30, other.DecompositionBitCount);
            Assert.AreEqual(22ul, other.Size);
            Assert.IsTrue(other.IsMetadataValidFor(context));

            List<IEnumerable<Ciphertext>> keysData = new List<IEnumerable<Ciphertext>>(keys.Data);
            List<IEnumerable<Ciphertext>> otherData = new List<IEnumerable<Ciphertext>>(other.Data);

            Assert.AreEqual(keysData.Count, otherData.Count);
            for (int i = 0; i < keysData.Count; i++)
            {
                List<Ciphertext> keysCiphers = new List<Ciphertext>(keysData[i]);
                List<Ciphertext> otherCiphers = new List<Ciphertext>(otherData[i]);

                Assert.AreEqual(keysCiphers.Count, otherCiphers.Count);

                for (int j = 0; j < keysCiphers.Count; j++)
                {
                    Ciphertext keysCipher = keysCiphers[j];
                    Ciphertext otherCipher = otherCiphers[j];

                    Assert.AreEqual(keysCipher.Size, otherCipher.Size);
                    Assert.AreEqual(keysCipher.PolyModulusDegree, otherCipher.PolyModulusDegree);
                    Assert.AreEqual(keysCipher.CoeffModCount, otherCipher.CoeffModCount);

                    ulong coeffCount = keysCipher.Size * keysCipher.PolyModulusDegree * keysCipher.CoeffModCount;
                    for (ulong k = 0; k < coeffCount; k++)
                    {
                        Assert.AreEqual(keysCipher[k], otherCipher[k]);
                    }
                }
            }
        }

        [TestMethod]
        public void SetTest()
        {
            SEALContext context = GlobalContext.Context;
            KeyGenerator keygen = new KeyGenerator(context);

            GaloisKeys keys = keygen.GaloisKeys(decompositionBitCount: 30);

            Assert.IsNotNull(keys);
            Assert.AreEqual(30, keys.DecompositionBitCount);
            Assert.AreEqual(22ul, keys.Size);

            GaloisKeys keys2 = new GaloisKeys();

            Assert.IsNotNull(keys2);
            Assert.AreEqual(0, keys2.DecompositionBitCount);
            Assert.AreEqual(0ul, keys2.Size);

            keys2.Set(keys);

            Assert.AreNotSame(keys, keys2);
            Assert.AreEqual(30, keys2.DecompositionBitCount);
            Assert.AreEqual(22ul, keys2.Size);
        }

        [TestMethod]
        public void KeyTest()
        {
            SEALContext context = GlobalContext.Context;
            KeyGenerator keygen = new KeyGenerator(context);

            GaloisKeys keys = keygen.GaloisKeys(decompositionBitCount: 30);
            MemoryPoolHandle handle = keys.Pool;

            Assert.IsNotNull(keys);
            Assert.AreEqual(30, keys.DecompositionBitCount);
            Assert.AreEqual(22ul, keys.Size);

            Assert.IsFalse(keys.HasKey(galoisElt: 1));
            Assert.IsTrue(keys.HasKey(galoisElt: 3));
            Assert.IsFalse(keys.HasKey(galoisElt: 5));
            Assert.IsFalse(keys.HasKey(galoisElt: 7));
            Assert.IsTrue(keys.HasKey(galoisElt: 9));
            Assert.IsFalse(keys.HasKey(galoisElt: 11));

            IEnumerable<Ciphertext> key = keys.Key(3);
            Assert.AreEqual(2, key.Count());

            IEnumerable<Ciphertext> key2 = keys.Key(9);
            Assert.AreEqual(2, key2.Count());

            Assert.IsTrue(handle.AllocByteCount > 0ul);
        }
        
        [TestMethod]
        public void KeyEltTest()
        {
            SEALContext context = GlobalContext.Context;
            KeyGenerator keygen = new KeyGenerator(context);

            GaloisKeys keys = keygen.GaloisKeys(decompositionBitCount: 15, galoisElts: new ulong[] { 1, 3 });
            Assert.IsNotNull(keys);

            Assert.AreEqual(15, keys.DecompositionBitCount);
            Assert.AreEqual(2ul, keys.Size);

            Assert.IsTrue(keys.HasKey(1));
            Assert.IsTrue(keys.HasKey(3));
            Assert.IsFalse(keys.HasKey(5));
        }

        [TestMethod]
        public void KeyStepTest()
        {
            EncryptionParameters parms = new EncryptionParameters(SchemeType.CKKS)
            {
                PolyModulusDegree = 64,
                CoeffModulus = new List<SmallModulus>() {  DefaultParams.SmallMods60Bit(0) }
            };
            SEALContext context = SEALContext.Create(parms);
            KeyGenerator keygen = new KeyGenerator(context);

            GaloisKeys keys = keygen.GaloisKeys(decompositionBitCount: 15, steps: new int[] { 1, 2, 3 });
            Assert.IsNotNull(keys);

            Assert.AreEqual(15, keys.DecompositionBitCount);
            Assert.AreEqual(3ul, keys.Size);

            Assert.IsFalse(keys.HasKey(1));
            Assert.IsTrue(keys.HasKey(3));
            Assert.IsFalse(keys.HasKey(5));
            Assert.IsFalse(keys.HasKey(7));
            Assert.IsTrue(keys.HasKey(9));
            Assert.IsFalse(keys.HasKey(11));
            Assert.IsFalse(keys.HasKey(13));
            Assert.IsFalse(keys.HasKey(15));
            Assert.IsFalse(keys.HasKey(17));
            Assert.IsFalse(keys.HasKey(19));
            Assert.IsFalse(keys.HasKey(21));
            Assert.IsFalse(keys.HasKey(23));
            Assert.IsFalse(keys.HasKey(25));
            Assert.IsTrue(keys.HasKey(27));
        }

        [TestMethod]
        public void ExceptionsTest()
        {
            SEALContext context = GlobalContext.Context;
            GaloisKeys keys = new GaloisKeys();

            Assert.ThrowsException<ArgumentNullException>(() => keys = new GaloisKeys(null));

            Assert.ThrowsException<ArgumentNullException>(() => keys.Set(null));

            Assert.ThrowsException<ArgumentNullException>(() => keys.IsValidFor(null));
            Assert.ThrowsException<ArgumentNullException>(() => keys.IsMetadataValidFor(null));

            Assert.ThrowsException<ArgumentNullException>(() => keys.Save(null));

            Assert.ThrowsException<ArgumentNullException>(() => keys.UnsafeLoad(null));
            Assert.ThrowsException<ArgumentException>(() => keys.UnsafeLoad(new MemoryStream()));

            Assert.ThrowsException<ArgumentNullException>(() => keys.Load(context, null));
            Assert.ThrowsException<ArgumentNullException>(() => keys.Load(null, new MemoryStream()));
        }
    }
}
