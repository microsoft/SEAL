// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

using Microsoft.Research.SEAL;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using System.Collections.Generic;
using System.IO;

namespace SEALNetTest
{
    [TestClass]
    public class RelinKeysTests
    {
        [TestMethod]
        public void CreateRelinKeysTest()
        {
            RelinKeys keys = new RelinKeys();

            Assert.IsNotNull(keys);
            Assert.AreEqual(0ul, keys.Size);
        }

        [TestMethod]
        public void CreateNonEmptyRelinKeysTest()
        {
            SEALContext context = GlobalContext.BFVContext;
            KeyGenerator keygen = new KeyGenerator(context);

            RelinKeys keys = keygen.RelinKeys();

            Assert.IsNotNull(keys);
            Assert.AreEqual(1ul, keys.Size);

            RelinKeys copy = new RelinKeys(keys);

            Assert.IsNotNull(copy);
            Assert.AreEqual(1ul, copy.Size);

            RelinKeys copy2 = new RelinKeys();

            copy2.Set(keys);
            Assert.IsNotNull(copy2);
            Assert.AreEqual(1ul, copy2.Size);
        }

        [TestMethod]
        public void SaveLoadTest()
        {
            SEALContext context = GlobalContext.BFVContext;
            KeyGenerator keygen = new KeyGenerator(context);

            RelinKeys keys = keygen.RelinKeys();

            Assert.IsNotNull(keys);
            Assert.AreEqual(1ul, keys.Size);

            RelinKeys other = new RelinKeys();
            MemoryPoolHandle handle = other.Pool;

            Assert.AreEqual(0ul, other.Size);
            ulong alloced = handle.AllocByteCount;

            using (MemoryStream ms = new MemoryStream())
            {
                keys.Save(ms);
                ms.Seek(offset: 0, loc: SeekOrigin.Begin);
                other.Load(context, ms);
            }

            Assert.AreEqual(1ul, other.Size);
            Assert.IsTrue(ValCheck.IsMetadataValidFor(other, context));
            Assert.IsTrue(handle.AllocByteCount > 0ul);

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
        public void GetKeyTest()
        {
            SEALContext context = GlobalContext.BFVContext;
            KeyGenerator keygen = new KeyGenerator(context);
            RelinKeys relinKeys = keygen.RelinKeys();

            Assert.IsTrue(relinKeys.HasKey(2));
            Assert.IsFalse(relinKeys.HasKey(3));

            Assert.ThrowsException<ArgumentException>(() => relinKeys.Key(0));
            Assert.ThrowsException<ArgumentException>(() => relinKeys.Key(1));

            List<PublicKey> key1 = new List<PublicKey>(relinKeys.Key(2));
            Assert.AreEqual(4, key1.Count);
            Assert.AreEqual(5ul, key1[0].Data.CoeffModCount);
        }

        [TestMethod]
        public void ExceptionsTest()
        {
            RelinKeys keys = new RelinKeys();
            SEALContext context = GlobalContext.BFVContext;

            Assert.ThrowsException<ArgumentNullException>(() => keys = new RelinKeys(null));

            Assert.ThrowsException<ArgumentNullException>(() => keys.Set(null));

            Assert.ThrowsException<ArgumentNullException>(() => ValCheck.IsValidFor(keys, null));
            Assert.ThrowsException<ArgumentNullException>(() => ValCheck.IsMetadataValidFor(keys, null));

            Assert.ThrowsException<ArgumentNullException>(() => keys.Save(null));

            Assert.ThrowsException<ArgumentNullException>(() => keys.Load(context, null));
            Assert.ThrowsException<ArgumentNullException>(() => keys.Load(null, new MemoryStream()));
            Assert.ThrowsException<ArgumentException>(() => keys.Load(context, new MemoryStream()));
            Assert.ThrowsException<ArgumentNullException>(() => keys.UnsafeLoad(null));
        }
    }
}
