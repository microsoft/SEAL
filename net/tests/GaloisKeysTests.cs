using Microsoft.Research.SEAL;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;

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
            Assert.AreEqual(0, keys.Size);
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
            Assert.AreEqual(22, keys.Size);
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
            Assert.AreEqual(22, keys.Size);

            using (MemoryStream ms = new MemoryStream())
            {
                keys.Save(ms);

                ms.Seek(offset: 0, loc: SeekOrigin.Begin);

                other.Load(ms);
            }

            Assert.AreEqual(30, other.DecompositionBitCount);
            Assert.AreEqual(22, other.Size);

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

                    int coeffCount = keysCipher.Size * keysCipher.PolyModulusDegree * keysCipher.CoeffModCount;
                    for (int k = 0; k < coeffCount; k++)
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
            Assert.AreEqual(22, keys.Size);

            GaloisKeys keys2 = new GaloisKeys();

            Assert.IsNotNull(keys2);
            Assert.AreEqual(0, keys2.DecompositionBitCount);
            Assert.AreEqual(0, keys2.Size);

            keys2.Set(keys);

            Assert.AreNotSame(keys, keys2);
            Assert.AreEqual(30, keys2.DecompositionBitCount);
            Assert.AreEqual(22, keys2.Size);
        }

        [TestMethod]
        public void KeyTest()
        {
            SEALContext context = GlobalContext.Context;
            KeyGenerator keygen = new KeyGenerator(context);

            GaloisKeys keys = keygen.GaloisKeys(decompositionBitCount: 30);

            Assert.IsNotNull(keys);
            Assert.AreEqual(30, keys.DecompositionBitCount);
            Assert.AreEqual(22, keys.Size);

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
        }
    }
}
