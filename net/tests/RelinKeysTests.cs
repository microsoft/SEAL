using Microsoft.Research.SEAL;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using System.Collections.Generic;
using System.IO;
using System.Text;

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
            Assert.AreEqual(0, keys.DecompositionBitCount);
        }

        [TestMethod]
        public void CreateNonEmptyRelinKeysTest()
        {
            SEALContext context = GlobalContext.Context;
            KeyGenerator keygen = new KeyGenerator(context);

            RelinKeys keys = keygen.RelinKeys(decompositionBitCount: 30);

            Assert.IsNotNull(keys);
            Assert.AreEqual(30, keys.DecompositionBitCount);
            Assert.AreEqual(1ul, keys.Size);
        }

        [TestMethod]
        public void SaveLoadTest()
        {
            SEALContext context = GlobalContext.Context;
            KeyGenerator keygen = new KeyGenerator(context);

            RelinKeys keys = keygen.RelinKeys(decompositionBitCount: 30, count: 2);

            Assert.IsNotNull(keys);
            Assert.AreEqual(30, keys.DecompositionBitCount);
            Assert.AreEqual(2ul, keys.Size);

            RelinKeys other = new RelinKeys();
            MemoryPoolHandle handle = other.Pool;

            Assert.AreEqual(0, other.DecompositionBitCount);
            Assert.AreEqual(0ul, other.Size);
            ulong alloced = handle.AllocByteCount;

            using (MemoryStream ms = new MemoryStream())
            {
                keys.Save(ms);

                ms.Seek(offset: 0, loc: SeekOrigin.Begin);

                other.Load(context, ms);
            }

            Assert.AreEqual(30, other.DecompositionBitCount);
            Assert.AreEqual(2ul, other.Size);
            Assert.IsTrue(handle.AllocByteCount > 0ul);

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
        public void GetKeyTest()
        {
            SEALContext context = GlobalContext.Context;
            KeyGenerator keygen = new KeyGenerator(context);
            RelinKeys relinKeys = keygen.RelinKeys(decompositionBitCount: 60, count: 3);

            Assert.IsFalse(relinKeys.HasKey(0));
            Assert.IsFalse(relinKeys.HasKey(1));
            Assert.IsTrue(relinKeys.HasKey(2));
            Assert.IsTrue(relinKeys.HasKey(3));
            Assert.IsTrue(relinKeys.HasKey(4));
            Assert.IsFalse(relinKeys.HasKey(5));

            List<Ciphertext> key1 = new List<Ciphertext>(relinKeys.Key(2));
            Assert.AreEqual(2, key1.Count);
            Assert.AreEqual(2ul, key1[0].CoeffModCount);
            Assert.AreEqual(2ul, key1[1].CoeffModCount);

            List<Ciphertext> key2 = new List<Ciphertext>(relinKeys.Key(3));
            Assert.AreEqual(2, key2.Count);
            Assert.AreEqual(2ul, key2[0].CoeffModCount);
            Assert.AreEqual(2ul, key2[1].CoeffModCount);

            List<Ciphertext> key3 = new List<Ciphertext>(relinKeys.Key(4));
            Assert.AreEqual(2, key3.Count);
            Assert.AreEqual(2ul, key3[0].CoeffModCount);
            Assert.AreEqual(2ul, key3[1].CoeffModCount);
        }
    }
}
