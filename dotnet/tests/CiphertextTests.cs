// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

using Microsoft.Research.SEAL;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using System.Collections.Generic;
using System.IO;
using System.Numerics;

namespace SEALNetTest
{
    [TestClass]
    public class CiphertextTests
    {
        [TestMethod]
        public void CreateTest()
        {
            Ciphertext cipher = new Ciphertext();
            Assert.IsNotNull(cipher);
            Assert.AreEqual(0ul, cipher.Size);
            Assert.AreEqual(0ul, cipher.PolyModulusDegree);
            Assert.AreEqual(0ul, cipher.CoeffModulusSize);

            Ciphertext copy = new Ciphertext(cipher);
            Assert.IsNotNull(copy);
            Assert.AreEqual(0ul, copy.Size);
            Assert.AreEqual(0ul, copy.PolyModulusDegree);
            Assert.AreEqual(0ul, copy.CoeffModulusSize);
        }

        [TestMethod]
        public void Create2Test()
        {
            SEALContext context = GlobalContext.BFVContext;
            ParmsId parms = context.FirstParmsId;

            Assert.AreNotEqual(0ul, parms.Block[0]);
            Assert.AreNotEqual(0ul, parms.Block[1]);
            Assert.AreNotEqual(0ul, parms.Block[2]);
            Assert.AreNotEqual(0ul, parms.Block[3]);

            Ciphertext cipher = new Ciphertext(context, parms);

            Assert.AreEqual(parms, cipher.ParmsId);
        }

        [TestMethod]
        public void Create3Test()
        {
            SEALContext context = GlobalContext.BFVContext;
            ParmsId parms = context.FirstParmsId;

            Assert.AreNotEqual(0ul, parms.Block[0]);
            Assert.AreNotEqual(0ul, parms.Block[1]);
            Assert.AreNotEqual(0ul, parms.Block[2]);
            Assert.AreNotEqual(0ul, parms.Block[3]);

            Ciphertext cipher = new Ciphertext(context, parms, sizeCapacity: 5);

            Assert.AreEqual(5ul, cipher.SizeCapacity);
        }

        [TestMethod]
        public void ResizeTest()
        {
            SEALContext context = GlobalContext.BFVContext;
            ParmsId parms = context.FirstParmsId;

            Ciphertext cipher = new Ciphertext(context, parms);

            Assert.AreEqual(2ul, cipher.SizeCapacity);

            cipher.Reserve(context, parms, sizeCapacity: 10);
            Assert.AreEqual(10ul, cipher.SizeCapacity);

            Ciphertext cipher2 = new Ciphertext();

            Assert.AreEqual(0ul, cipher2.SizeCapacity);

            cipher2.Reserve(context, 5);
            Assert.AreEqual(5ul, cipher2.SizeCapacity);

            Ciphertext cipher3 = new Ciphertext();

            Assert.AreEqual(0ul, cipher3.SizeCapacity);

            cipher3.Reserve(4);
            Assert.AreEqual(0ul, cipher3.SizeCapacity);

            Ciphertext cipher4 = new Ciphertext(context);
            cipher4.Resize(context, context.GetContextData(context.FirstParmsId).NextContextData.ParmsId, 4);
            Assert.AreEqual(10ul, cipher.SizeCapacity);

            Ciphertext cipher5 = new Ciphertext(context);
            cipher5.Resize(context, 6ul);
            Assert.AreEqual(6ul, cipher5.SizeCapacity);
        }

        [TestMethod]
        public void ReleaseTest()
        {
            Ciphertext cipher = new Ciphertext();

            Assert.AreEqual(0ul, cipher.Size);
            cipher.Resize(4);
            Assert.AreEqual(4ul, cipher.Size);
            cipher.Release();
            Assert.AreEqual(0ul, cipher.Size);
        }

        [TestMethod]
        public void SaveLoadTest()
        {
            SEALContext context = GlobalContext.BFVContext;
            KeyGenerator keygen = new KeyGenerator(context);
            Encryptor encryptor = new Encryptor(context, keygen.PublicKey);
            Plaintext plain = new Plaintext("2x^3 + 4x^2 + 5x^1 + 6");
            Ciphertext cipher = new Ciphertext();

            encryptor.Encrypt(plain, cipher);

            Assert.AreEqual(2ul, cipher.Size);
            Assert.AreEqual(8192ul, cipher.PolyModulusDegree);
            Assert.AreEqual(4ul, cipher.CoeffModulusSize);

            Ciphertext loaded = new Ciphertext();

            Assert.AreEqual(0ul, loaded.Size);
            Assert.AreEqual(0ul, loaded.PolyModulusDegree);
            Assert.AreEqual(0ul, loaded.CoeffModulusSize);

            using (MemoryStream mem = new MemoryStream())
            {
                cipher.Save(mem);

                mem.Seek(offset: 0, loc: SeekOrigin.Begin);

                loaded.Load(context, mem);
            }

            Assert.AreEqual(2ul, loaded.Size);
            Assert.AreEqual(8192ul, loaded.PolyModulusDegree);
            Assert.AreEqual(4ul, loaded.CoeffModulusSize);
            Assert.IsTrue(ValCheck.IsValidFor(loaded, context));

            ulong ulongCount = cipher.Size * cipher.PolyModulusDegree * cipher.CoeffModulusSize;
            for (ulong i = 0; i < ulongCount; i++)
            {
                Assert.AreEqual(cipher[i], loaded[i]);
            }
        }

        [TestMethod]
        public void IndexTest()
        {
            SEALContext context = GlobalContext.BFVContext;
            KeyGenerator keygen = new KeyGenerator(context);
            Encryptor encryptor = new Encryptor(context, keygen.PublicKey);
            Plaintext plain = new Plaintext("1");
            Ciphertext cipher = new Ciphertext();

            encryptor.Encrypt(plain, cipher);

            Assert.AreEqual(2ul, cipher.Size);
            Assert.AreNotEqual(0ul, cipher[0, 0]);
            Assert.AreNotEqual(0ul, cipher[0, 1]);
            Assert.AreNotEqual(0ul, cipher[0, 2]);
            Assert.AreNotEqual(0ul, cipher[1, 0]);
            Assert.AreNotEqual(0ul, cipher[1, 1]);
            Assert.AreNotEqual(0ul, cipher[1, 2]);
        }

        [TestMethod]
        public void IndexRangeFail1Test()
        {
            SEALContext context = GlobalContext.BFVContext;
            KeyGenerator keygen = new KeyGenerator(context);
            Encryptor encryptor = new Encryptor(context, keygen.PublicKey);
            Plaintext plain = new Plaintext("1");
            Ciphertext cipher = new Ciphertext(context);

            encryptor.Encrypt(plain, cipher);

            Utilities.AssertThrows<IndexOutOfRangeException>(() =>
            {
                // We only have 2 polynomials
                ulong data = cipher[2, 0];
            });
        }

        [TestMethod]
        public void IndexRangeFail2Test()
        {
            SEALContext context = GlobalContext.BFVContext;
            KeyGenerator keygen = new KeyGenerator(context);
            Encryptor encryptor = new Encryptor(context, keygen.PublicKey);
            Plaintext plain = new Plaintext("1");
            Ciphertext cipher = new Ciphertext();

            encryptor.Encrypt(plain, cipher);

            // We only have 2 polynomials
            ulong data = cipher[1, 0];

            // We should have 8192 coefficients
            data = cipher[0, 32767]; // This will succeed

            Utilities.AssertThrows<IndexOutOfRangeException>(() =>
            {
                data = cipher[0, 32768]; // This will fail
            });
        }

        [TestMethod]
        public void IndexRangeFail3Test()
        {
            SEALContext context = GlobalContext.BFVContext;
            KeyGenerator keygen = new KeyGenerator(context);
            Encryptor encryptor = new Encryptor(context, keygen.PublicKey);
            Plaintext plain = new Plaintext("1");
            Ciphertext cipher = new Ciphertext();

            encryptor.Encrypt(plain, cipher);
            ulong data = 0;

            Utilities.AssertThrows<IndexOutOfRangeException>(() => data = cipher[65536]);
            Utilities.AssertThrows<IndexOutOfRangeException>(() => cipher[65536] = 10ul);
        }

        [TestMethod]
        public void ScaleTest()
        {
            EncryptionParameters parms = new EncryptionParameters(SchemeType.CKKS)
            {
                PolyModulusDegree = 8,
                CoeffModulus = CoeffModulus.Create(8, new int[] { 40, 40, 40, 40 })
            };
            SEALContext context = new SEALContext(parms,
                expandModChain: true,
                secLevel: SecLevelType.None);
            KeyGenerator keygen = new KeyGenerator(context);
            GaloisKeys galoisKeys = keygen.GaloisKeysLocal();
            Encryptor encryptor = new Encryptor(context, keygen.PublicKey);
            Evaluator evaluator = new Evaluator(context);
            CKKSEncoder encoder = new CKKSEncoder(context);

            MemoryPoolHandle pool = MemoryManager.GetPool(MMProfOpt.ForceNew);
            Assert.AreEqual(0ul, pool.AllocByteCount);

            Ciphertext encrypted = new Ciphertext(pool);
            Plaintext plain = new Plaintext();

            MemoryPoolHandle cipherPool = encrypted.Pool;
            Assert.IsNotNull(cipherPool);
            Assert.AreEqual(0ul, cipherPool.AllocByteCount);

            List<Complex> input = new List<Complex>()
            {
                new Complex(1, 1),
                new Complex(2, 2),
                new Complex(3, 3),
                new Complex(4, 4)
            };
            double delta = Math.Pow(2, 70);
            encoder.Encode(input, context.FirstParmsId, delta, plain);
            encryptor.Encrypt(plain, encrypted);

            Assert.AreEqual(delta, encrypted.Scale, delta: Math.Pow(2, 60));

            Ciphertext encrypted2 = new Ciphertext();
            encrypted2.Set(encrypted);
            Assert.AreEqual(delta, encrypted2.Scale, delta: Math.Pow(2, 60));

            evaluator.RescaleToNextInplace(encrypted);

            Assert.AreEqual(Math.Pow(2, 30), encrypted.Scale, delta: 10000);
            Assert.AreNotEqual(0ul, cipherPool.AllocByteCount);

            double newScale = Math.Pow(2, 10);
            encrypted.Scale = newScale;
            Assert.AreEqual(newScale, encrypted.Scale, delta: 100);
        }

        [TestMethod]
        public void ExceptionsTest()
        {
            SEALContext context = GlobalContext.BFVContext;
            MemoryPoolHandle pool = MemoryManager.GetPool(MMProfOpt.ForceGlobal);
            MemoryPoolHandle poolu = new MemoryPoolHandle();
            Ciphertext cipher = new Ciphertext();
            Ciphertext copy = null;

            Utilities.AssertThrows<ArgumentNullException>(() => copy = new Ciphertext((Ciphertext)null));

            Utilities.AssertThrows<ArgumentNullException>(() => cipher = new Ciphertext(context, null, pool));
            Utilities.AssertThrows<ArgumentNullException>(() => cipher = new Ciphertext(null, context.FirstParmsId, pool));
            Utilities.AssertThrows<ArgumentException>(() => cipher = new Ciphertext(context, ParmsId.Zero, pool));

            Utilities.AssertThrows<ArgumentNullException>(() => cipher = new Ciphertext((SEALContext)null, poolu));
            Utilities.AssertThrows<ArgumentException>(() => cipher = new Ciphertext(context, poolu));

            Utilities.AssertThrows<ArgumentNullException>(() => cipher = new Ciphertext(context, null, 6ul));
            Utilities.AssertThrows<ArgumentNullException>(() => cipher = new Ciphertext(null, context.FirstParmsId, 6ul, poolu));
            Utilities.AssertThrows<ArgumentException>(() => cipher = new Ciphertext(context, ParmsId.Zero, 6ul, poolu));

            Utilities.AssertThrows<ArgumentNullException>(() => cipher.Reserve(context, null, 10ul));
            Utilities.AssertThrows<ArgumentNullException>(() => cipher.Reserve(null, ParmsId.Zero, 10ul));
            Utilities.AssertThrows<ArgumentException>(() => cipher.Reserve(context, ParmsId.Zero, 10ul));

            Utilities.AssertThrows<ArgumentNullException>(() => cipher.Reserve(null, 10ul));

            Utilities.AssertThrows<ArgumentNullException>(() => cipher.Resize(context, null, 10ul));
            Utilities.AssertThrows<ArgumentNullException>(() => cipher.Resize(null, ParmsId.Zero, 10ul));
            Utilities.AssertThrows<ArgumentException>(() => cipher.Resize(context, ParmsId.Zero, 10ul));

            Utilities.AssertThrows<ArgumentNullException>(() => cipher.Resize(null, 10ul));

            Utilities.AssertThrows<ArgumentNullException>(() => cipher.Set(null));

            Utilities.AssertThrows<ArgumentNullException>(() => ValCheck.IsValidFor(cipher, null));

            Utilities.AssertThrows<ArgumentNullException>(() => cipher.Save(null));

            Utilities.AssertThrows<ArgumentNullException>(() => cipher.UnsafeLoad(context, null));
            Utilities.AssertThrows<ArgumentNullException>(() => cipher.UnsafeLoad(null, new MemoryStream()));
            Utilities.AssertThrows<EndOfStreamException>(() => cipher.UnsafeLoad(context, new MemoryStream()));

            Utilities.AssertThrows<ArgumentNullException>(() => cipher.Load(null, new MemoryStream()));
            Utilities.AssertThrows<ArgumentNullException>(() => cipher.Load(context, null));
        }
    }
}
