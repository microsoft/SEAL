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
        }

        [TestMethod]
        public void CreateNonEmptyTest()
        {
            SEALContext context = GlobalContext.BFVContext;
            KeyGenerator keygen = new KeyGenerator(context);

            GaloisKeys keys = keygen.GaloisKeys();

            Assert.IsNotNull(keys);
            Assert.AreEqual(24ul, keys.Size);

            GaloisKeys copy = new GaloisKeys(keys);

            Assert.IsNotNull(copy);
            Assert.AreEqual(24ul, copy.Size);
        }

        [TestMethod]
        public void SaveLoadTest()
        {
            SEALContext context = GlobalContext.BFVContext;
            KeyGenerator keyGen = new KeyGenerator(context);

            GaloisKeys keys = keyGen.GaloisKeys();
            GaloisKeys other = new GaloisKeys();

            Assert.IsNotNull(keys);
            Assert.AreEqual(24ul, keys.Size);

            using (MemoryStream ms = new MemoryStream())
            {
                keys.Save(ms);

                ms.Seek(offset: 0, loc: SeekOrigin.Begin);

                other.Load(context, ms);
            }

            Assert.AreEqual(24ul, other.Size);
            Assert.IsTrue(ValCheck.IsMetadataValidFor(other, context));

            List<IEnumerable<PublicKey>> keysData = new List<IEnumerable<PublicKey>>(keys.Data);
            List<IEnumerable<PublicKey>> otherData = new List<IEnumerable<PublicKey>>(other.Data);

            Assert.AreEqual(keysData.Count, otherData.Count);
            for (int i = 0; i < keysData.Count; i++)
            {
                List<PublicKey> keysCiphers = new List<PublicKey>(keysData[i]);
                List<PublicKey> otherCiphers = new List<PublicKey>(otherData[i]);

                Assert.AreEqual(keysCiphers.Count, otherCiphers.Count);

                for (int j = 0; j < keysCiphers.Count; j++)
                {
                    PublicKey keysCipher = keysCiphers[j];
                    PublicKey otherCipher = otherCiphers[j];

                    Assert.AreEqual(keysCipher.Data.Size, otherCipher.Data.Size);
                    Assert.AreEqual(keysCipher.Data.PolyModulusDegree, otherCipher.Data.PolyModulusDegree);
                    Assert.AreEqual(keysCipher.Data.CoeffModCount, otherCipher.Data.CoeffModCount);

                    ulong coeffCount = keysCipher.Data.Size * keysCipher.Data.PolyModulusDegree * keysCipher.Data.CoeffModCount;
                    for (ulong k = 0; k < coeffCount; k++)
                    {
                        Assert.AreEqual(keysCipher.Data[k], otherCipher.Data[k]);
                    }
                }
            }
        }

        [TestMethod]
        public void SetTest()
        {
            SEALContext context = GlobalContext.BFVContext;
            KeyGenerator keygen = new KeyGenerator(context);

            GaloisKeys keys = keygen.GaloisKeys();

            Assert.IsNotNull(keys);
            Assert.AreEqual(24ul, keys.Size);

            GaloisKeys keys2 = new GaloisKeys();

            Assert.IsNotNull(keys2);
            Assert.AreEqual(0ul, keys2.Size);

            keys2.Set(keys);

            Assert.AreNotSame(keys, keys2);
            Assert.AreEqual(24ul, keys2.Size);
        }

        [TestMethod]
        public void KeyTest()
        {
            SEALContext context = GlobalContext.BFVContext;
            KeyGenerator keygen = new KeyGenerator(context);

            GaloisKeys keys = keygen.GaloisKeys();
            MemoryPoolHandle handle = keys.Pool;

            Assert.IsNotNull(keys);
            Assert.AreEqual(24ul, keys.Size);

            Assert.IsFalse(keys.HasKey(galoisElt: 1));
            Assert.IsTrue(keys.HasKey(galoisElt: 3));
            Assert.IsFalse(keys.HasKey(galoisElt: 5));
            Assert.IsFalse(keys.HasKey(galoisElt: 7));
            Assert.IsTrue(keys.HasKey(galoisElt: 9));
            Assert.IsFalse(keys.HasKey(galoisElt: 11));

            IEnumerable<PublicKey> key = keys.Key(3);
            Assert.AreEqual(4, key.Count());

            IEnumerable<PublicKey> key2 = keys.Key(9);
            Assert.AreEqual(4, key2.Count());

            Assert.IsTrue(handle.AllocByteCount > 0ul);
        }

        [TestMethod]
        public void KeyEltTest()
        {
            SEALContext context = GlobalContext.BFVContext;
            KeyGenerator keygen = new KeyGenerator(context);

            GaloisKeys keys = keygen.GaloisKeys(galoisElts: new ulong[] { 1, 3 });
            Assert.IsNotNull(keys);

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
                CoeffModulus = CoeffModulus.Create(64, new int[] { 60 })
            };
            SEALContext context = new SEALContext(parms,
                expandModChain: false,
                secLevel: SecLevelType.None);
            KeyGenerator keygen = new KeyGenerator(context);

            GaloisKeys keys = keygen.GaloisKeys(steps: new int[] { 1, 2, 3 });
            Assert.IsNotNull(keys);

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
            SEALContext context = GlobalContext.BFVContext;
            GaloisKeys keys = new GaloisKeys();

            Assert.ThrowsException<ArgumentNullException>(() => keys = new GaloisKeys(null));

            Assert.ThrowsException<ArgumentNullException>(() => keys.Set(null));

            Assert.ThrowsException<ArgumentNullException>(() => ValCheck.IsValidFor(keys, null));
            Assert.ThrowsException<ArgumentNullException>(() => ValCheck.IsMetadataValidFor(keys, null));

            Assert.ThrowsException<ArgumentNullException>(() => keys.Save(null));

            Assert.ThrowsException<ArgumentNullException>(() => keys.UnsafeLoad(null));
            Assert.ThrowsException<ArgumentException>(() => keys.UnsafeLoad(new MemoryStream()));

            Assert.ThrowsException<ArgumentNullException>(() => keys.Load(context, null));
            Assert.ThrowsException<ArgumentNullException>(() => keys.Load(null, new MemoryStream()));
        }
    }
}
