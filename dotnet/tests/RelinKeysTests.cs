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

            RelinKeys keys = keygen.RelinKeysLocal();

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

            RelinKeys keys = keygen.RelinKeysLocal();

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
            Assert.IsTrue(ValCheck.IsValidFor(other, context));
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
                    Assert.AreEqual(keysCipher.Data.CoeffModulusSize, otherCipher.Data.CoeffModulusSize);

                    ulong coeffCount = keysCipher.Data.Size * keysCipher.Data.PolyModulusDegree * keysCipher.Data.CoeffModulusSize;
                    for (ulong k = 0; k < coeffCount; k++)
                    {
                        Assert.AreEqual(keysCipher.Data[k], otherCipher.Data[k]);
                    }
                }
            }
        }

        [TestMethod]
        public void SeededKeyTest()
        {
            EncryptionParameters parms = new EncryptionParameters(SchemeType.BFV)
            {
                PolyModulusDegree = 128,
                PlainModulus = new Modulus(1 << 6),
                CoeffModulus = CoeffModulus.Create(128, new int[] { 40, 40, 40 })
            };
            SEALContext context = new SEALContext(parms,
                expandModChain: false,
                secLevel: SecLevelType.None);
            KeyGenerator keygen = new KeyGenerator(context);

            RelinKeys relinKeys = new RelinKeys();
            using (MemoryStream stream = new MemoryStream())
            {
                keygen.RelinKeys().Save(stream);
                stream.Seek(0, SeekOrigin.Begin);
                relinKeys.Load(context, stream);
            }

            Encryptor encryptor = new Encryptor(context, keygen.PublicKey);
            Decryptor decryptor = new Decryptor(context, keygen.SecretKey);
            Evaluator evaluator = new Evaluator(context);

            Ciphertext encrypted1 = new Ciphertext(context);
            Ciphertext encrypted2 = new Ciphertext(context);
            Plaintext plain1 = new Plaintext();
            Plaintext plain2 = new Plaintext();

            plain1.Set(0);
            encryptor.Encrypt(plain1, encrypted1);
            evaluator.SquareInplace(encrypted1);
            evaluator.RelinearizeInplace(encrypted1, relinKeys);
            decryptor.Decrypt(encrypted1, plain2);

            Assert.AreEqual(1ul, plain2.CoeffCount);
            Assert.AreEqual(0ul, plain2[0]);

            plain1.Set("1x^10 + 2");
            encryptor.Encrypt(plain1, encrypted1);
            evaluator.SquareInplace(encrypted1);
            evaluator.RelinearizeInplace(encrypted1, relinKeys);
            evaluator.SquareInplace(encrypted1);
            evaluator.Relinearize(encrypted1, relinKeys, encrypted2);
            decryptor.Decrypt(encrypted2, plain2);

            // {1x^40 + 8x^30 + 18x^20 + 20x^10 + 10}
            Assert.AreEqual(41ul, plain2.CoeffCount);
            Assert.AreEqual(16ul, plain2[0]);
            Assert.AreEqual(32ul, plain2[10]);
            Assert.AreEqual(24ul, plain2[20]);
            Assert.AreEqual(8ul,  plain2[30]);
            Assert.AreEqual(1ul,  plain2[40]);
        }

        [TestMethod]
        public void GetKeyTest()
        {
            SEALContext context = GlobalContext.BFVContext;
            KeyGenerator keygen = new KeyGenerator(context);
            RelinKeys relinKeys = keygen.RelinKeysLocal();

            Assert.IsTrue(relinKeys.HasKey(2));
            Assert.IsFalse(relinKeys.HasKey(3));

            Utilities.AssertThrows<ArgumentException>(() => relinKeys.Key(0));
            Utilities.AssertThrows<ArgumentException>(() => relinKeys.Key(1));

            List<PublicKey> key1 = new List<PublicKey>(relinKeys.Key(2));
            Assert.AreEqual(4, key1.Count);
            Assert.AreEqual(5ul, key1[0].Data.CoeffModulusSize);
        }

        [TestMethod]
        public void ExceptionsTest()
        {
            RelinKeys keys = new RelinKeys();
            SEALContext context = GlobalContext.BFVContext;

            Utilities.AssertThrows<ArgumentNullException>(() => keys = new RelinKeys(null));
            Utilities.AssertThrows<ArgumentNullException>(() => keys.Set(null));

            Utilities.AssertThrows<ArgumentNullException>(() => ValCheck.IsValidFor(keys, null));

            Utilities.AssertThrows<ArgumentNullException>(() => keys.Save(null));

            Utilities.AssertThrows<ArgumentNullException>(() => keys.Load(context, null));
            Utilities.AssertThrows<ArgumentNullException>(() => keys.Load(null, new MemoryStream()));
            Utilities.AssertThrows<EndOfStreamException>(() => keys.Load(context, new MemoryStream()));
            Utilities.AssertThrows<ArgumentNullException>(() => keys.UnsafeLoad(null, new MemoryStream()));
            Utilities.AssertThrows<ArgumentNullException>(() => keys.UnsafeLoad(context, null));
        }
    }
}
