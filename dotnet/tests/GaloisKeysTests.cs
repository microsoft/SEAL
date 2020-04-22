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

            GaloisKeys keys = keygen.GaloisKeysLocal();

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

            GaloisKeys keys = keyGen.GaloisKeysLocal();
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
            Assert.IsTrue(ValCheck.IsValidFor(other, context));

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
                PolyModulusDegree = 8,
                PlainModulus = new Modulus(257),
                CoeffModulus = CoeffModulus.Create(8, new int[] { 40, 40 })
            };
            SEALContext context = new SEALContext(parms,
                expandModChain: false,
                secLevel: SecLevelType.None);
            KeyGenerator keygen = new KeyGenerator(context);
            Encryptor encryptor = new Encryptor(context, keygen.PublicKey);
            Decryptor decryptor = new Decryptor(context, keygen.SecretKey);
            Evaluator evaluator = new Evaluator(context);
            BatchEncoder encoder = new BatchEncoder(context);

            GaloisKeys galoisKeys = new GaloisKeys();
            using (MemoryStream stream = new MemoryStream())
            {
                keygen.GaloisKeys().Save(stream);
                stream.Seek(0, SeekOrigin.Begin);
                galoisKeys.Load(context, stream);
            }

            Plaintext plain = new Plaintext();
            List<ulong> vec = new List<ulong>
            {
                1, 2, 3, 4,
                5, 6, 7, 8
            };

            encoder.Encode(vec, plain);

            Ciphertext encrypted = new Ciphertext();
            Ciphertext encdest = new Ciphertext();
            Plaintext plaindest = new Plaintext();

            encryptor.Encrypt(plain, encrypted);
            evaluator.RotateColumns(encrypted, galoisKeys, encdest);
            decryptor.Decrypt(encdest, plaindest);
            encoder.Decode(plaindest, vec);

            Assert.IsTrue(AreCollectionsEqual(vec, new List<ulong>
            {
                5, 6, 7, 8,
                1, 2, 3, 4
            }));

            evaluator.RotateRows(encdest, -1, galoisKeys, encrypted);
            decryptor.Decrypt(encrypted, plaindest);
            encoder.Decode(plaindest, vec);

            Assert.IsTrue(AreCollectionsEqual(vec, new List<ulong>
            {
                8, 5, 6, 7,
                4, 1, 2, 3
            }));

            evaluator.RotateRowsInplace(encrypted, 2, galoisKeys);
            decryptor.Decrypt(encrypted, plaindest);
            encoder.Decode(plaindest, vec);

            Assert.IsTrue(AreCollectionsEqual(vec, new List<ulong>
            {
                6, 7, 8, 5,
                2, 3, 4, 1
            }));

            evaluator.RotateColumnsInplace(encrypted, galoisKeys);
            decryptor.Decrypt(encrypted, plaindest);
            encoder.Decode(plaindest, vec);

            Assert.IsTrue(AreCollectionsEqual(vec, new List<ulong>
            {
                2, 3, 4, 1,
                6, 7, 8, 5
            }));
        }

        [TestMethod]
        public void SetTest()
        {
            SEALContext context = GlobalContext.BFVContext;
            KeyGenerator keygen = new KeyGenerator(context);

            GaloisKeys keys = keygen.GaloisKeysLocal();

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

            GaloisKeys keys = keygen.GaloisKeysLocal();
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

            GaloisKeys keys = keygen.GaloisKeysLocal(galoisElts: new uint[] { 1, 3 });
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
                CoeffModulus = CoeffModulus.Create(64, new int[] { 60, 60 })
            };
            SEALContext context = new SEALContext(parms,
                expandModChain: false,
                secLevel: SecLevelType.None);
            KeyGenerator keygen = new KeyGenerator(context);

            GaloisKeys keys = keygen.GaloisKeysLocal(steps: new int[] { 1, 2, 3 });
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

            Utilities.AssertThrows<ArgumentNullException>(() => keys = new GaloisKeys(null));

            Utilities.AssertThrows<ArgumentNullException>(() => keys.Set(null));

            Utilities.AssertThrows<ArgumentNullException>(() => ValCheck.IsValidFor(keys, null));

            Utilities.AssertThrows<ArgumentNullException>(() => keys.Save(null));

            Utilities.AssertThrows<ArgumentNullException>(() => keys.UnsafeLoad(context, null));
            Utilities.AssertThrows<EndOfStreamException>(() => keys.UnsafeLoad(context, new MemoryStream()));
            Utilities.AssertThrows<ArgumentNullException>(() => keys.UnsafeLoad(null, new MemoryStream()));

            Utilities.AssertThrows<ArgumentNullException>(() => keys.Load(context, null));
            Utilities.AssertThrows<ArgumentNullException>(() => keys.Load(null, new MemoryStream()));
        }

        /// <summary>
        /// Returns true if the two given collections have equivalent elements, false otherwise
        /// </summary>
        private static bool AreCollectionsEqual<T>(IEnumerable<T> coll1, IEnumerable<T> coll2)
        {
            int size1 = coll1.Count();
            int size2 = coll2.Count();

            if (size1 != size2)
                return false;

            IEnumerator<T> en1 = coll1.GetEnumerator();
            IEnumerator<T> en2 = coll2.GetEnumerator();

            while (en1.MoveNext() && en2.MoveNext())
            {
                if (!en1.Current.Equals(en2.Current))
                    return false;
            }

            return true;
        }
    }
}
