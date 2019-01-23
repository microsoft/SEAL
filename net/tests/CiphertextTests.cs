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
            Assert.AreEqual(0ul, cipher.CoeffModCount);

            Ciphertext copy = new Ciphertext(cipher);
            Assert.IsNotNull(copy);
            Assert.AreEqual(0ul, copy.Size);
            Assert.AreEqual(0ul, copy.PolyModulusDegree);
            Assert.AreEqual(0ul, copy.CoeffModCount);
        }

        [TestMethod]
        public void Create2Test()
        {
            SEALContext context = GlobalContext.Context;
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
            SEALContext context = GlobalContext.Context;
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
            SEALContext context = GlobalContext.Context;
            ParmsId parms = context.FirstParmsId;

            Ciphertext cipher = new Ciphertext(context, parms);

            Assert.AreEqual(2ul, cipher.SizeCapacity);
            Assert.AreEqual(16384ul, cipher.UInt64CountCapacity);

            cipher.Reserve(context, parms, sizeCapacity: 10);
            Assert.AreEqual(10ul, cipher.SizeCapacity);
            Assert.AreEqual(16384ul * 5, cipher.UInt64CountCapacity);

            Ciphertext cipher2 = new Ciphertext();

            Assert.AreEqual(2ul, cipher2.SizeCapacity);

            cipher2.Reserve(context, 5);
            Assert.AreEqual(5ul, cipher2.SizeCapacity);

            Ciphertext cipher3 = new Ciphertext();

            Assert.AreEqual(2ul, cipher3.SizeCapacity);

            cipher3.Reserve(4);
            Assert.AreEqual(4ul, cipher3.SizeCapacity);

            Ciphertext cipher4 = new Ciphertext(context);
            cipher4.Resize(context, context.GetContextData(context.FirstParmsId).NextContextData.Parms.ParmsId, 4);
            Assert.AreEqual(10ul, cipher.SizeCapacity);

            Ciphertext cipher5 = new Ciphertext(context);
            cipher5.Resize(context, 6ul);
            Assert.AreEqual(2ul, cipher5.SizeCapacity);
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
            SEALContext context = GlobalContext.Context;
            KeyGenerator keygen = new KeyGenerator(context);
            Encryptor encryptor = new Encryptor(context, keygen.PublicKey);
            Plaintext plain = new Plaintext("2x^3 + 4x^2 + 5x^1 + 6");
            Ciphertext cipher = new Ciphertext();

            encryptor.Encrypt(plain, cipher);

            Assert.AreEqual(2ul, cipher.Size);
            Assert.AreEqual(4096ul, cipher.PolyModulusDegree);
            Assert.AreEqual(2ul, cipher.CoeffModCount);

            Ciphertext loaded = new Ciphertext();

            Assert.AreEqual(0ul, loaded.Size);
            Assert.AreEqual(0ul, loaded.PolyModulusDegree);
            Assert.AreEqual(0ul, loaded.CoeffModCount);

            using (MemoryStream mem = new MemoryStream())
            {
                cipher.Save(mem);

                mem.Seek(offset: 0, loc: SeekOrigin.Begin);

                loaded.Load(context, mem);
            }

            Assert.AreEqual(2ul, loaded.Size);
            Assert.AreEqual(4096ul, loaded.PolyModulusDegree);
            Assert.AreEqual(2ul, loaded.CoeffModCount);
            Assert.IsTrue(loaded.IsMetadataValidFor(context));

            ulong ulongCount = cipher.Size * cipher.PolyModulusDegree * cipher.CoeffModCount;
            for (ulong i = 0; i < ulongCount; i++)
            {
                Assert.AreEqual(cipher[i], loaded[i]);
            }
        }

        [TestMethod]
        public void IndexTest()
        {
            SEALContext context = GlobalContext.Context;
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
            SEALContext context = GlobalContext.Context;
            KeyGenerator keygen = new KeyGenerator(context);
            Encryptor encryptor = new Encryptor(context, keygen.PublicKey);
            Plaintext plain = new Plaintext("1");
            Ciphertext cipher = new Ciphertext();

            encryptor.Encrypt(plain, cipher);

            Assert.ThrowsException<IndexOutOfRangeException>(() =>
            {
                // We only have 2 polynomials
                ulong data = cipher[2, 0];
            });
        }

        [TestMethod]
        public void IndexRangeFail2Test()
        {
            SEALContext context = GlobalContext.Context;
            KeyGenerator keygen = new KeyGenerator(context);
            Encryptor encryptor = new Encryptor(context, keygen.PublicKey);
            Plaintext plain = new Plaintext("1");
            Ciphertext cipher = new Ciphertext();

            encryptor.Encrypt(plain, cipher);

            // We only have 2 polynomials
            ulong data = cipher[1, 0];

            // We should have 8192 coefficients
            data = cipher[0, 8191]; // This will succeed

            Assert.ThrowsException<IndexOutOfRangeException>(() =>
            {
                data = cipher[0, 8192]; // This will fail
            });
        }

        [TestMethod]
        public void IndexRangeFail3Test()
        {
            SEALContext context = GlobalContext.Context;
            KeyGenerator keygen = new KeyGenerator(context);
            Encryptor encryptor = new Encryptor(context, keygen.PublicKey);
            Plaintext plain = new Plaintext("1");
            Ciphertext cipher = new Ciphertext();

            encryptor.Encrypt(plain, cipher);
            ulong data = 0;

            Assert.ThrowsException<IndexOutOfRangeException>(() => data = cipher[65536]);
            Assert.ThrowsException<IndexOutOfRangeException>(() => cipher[65536] = 10ul);
        }

        [TestMethod]
        public void ScaleTest()
        {
            List<SmallModulus> coeffModulus = new List<SmallModulus>()
            {
                DefaultParams.SmallMods40Bit(0),
                DefaultParams.SmallMods40Bit(1),
                DefaultParams.SmallMods40Bit(2),
                DefaultParams.SmallMods40Bit(3)
            };
            EncryptionParameters parms = new EncryptionParameters(SchemeType.CKKS)
            {
                CoeffModulus = coeffModulus,
                PolyModulusDegree = 8
            };
            SEALContext context = SEALContext.Create(parms);
            KeyGenerator keygen = new KeyGenerator(context);
            GaloisKeys galoisKeys = keygen.GaloisKeys(decompositionBitCount: 4);
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
            encoder.Encode(input, parms.ParmsId, delta, plain);
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
            SEALContext context = GlobalContext.Context;
            MemoryPoolHandle pool = MemoryManager.GetPool(MMProfOpt.ForceGlobal);
            MemoryPoolHandle poolu = new MemoryPoolHandle();
            Ciphertext cipher = new Ciphertext();
            Ciphertext copy = null;

            Assert.ThrowsException<ArgumentNullException>(() => copy = new Ciphertext((Ciphertext)null));

            Assert.ThrowsException<ArgumentNullException>(() => cipher = new Ciphertext(context, null, pool));
            Assert.ThrowsException<ArgumentNullException>(() => cipher = new Ciphertext(null, context.FirstParmsId, pool));
            Assert.ThrowsException<ArgumentException>(() => cipher = new Ciphertext(context, ParmsId.Zero, pool));

            Assert.ThrowsException<ArgumentNullException>(() => cipher = new Ciphertext((SEALContext)null, poolu));
            Assert.ThrowsException<ArgumentException>(() => cipher = new Ciphertext(context, poolu));

            Assert.ThrowsException<ArgumentNullException>(() => cipher = new Ciphertext(context, null, 6ul));
            Assert.ThrowsException<ArgumentNullException>(() => cipher = new Ciphertext(null, context.FirstParmsId, 6ul, poolu));
            Assert.ThrowsException<ArgumentException>(() => cipher = new Ciphertext(context, ParmsId.Zero, 6ul, poolu));

            Assert.ThrowsException<ArgumentNullException>(() => cipher.Reserve(context, null, 10ul));
            Assert.ThrowsException<ArgumentNullException>(() => cipher.Reserve(null, ParmsId.Zero, 10ul));
            Assert.ThrowsException<ArgumentException>(() => cipher.Reserve(context, ParmsId.Zero, 10ul));

            Assert.ThrowsException<ArgumentNullException>(() => cipher.Reserve(null, 10ul));

            Assert.ThrowsException<ArgumentNullException>(() => cipher.Resize(context, null, 10ul));
            Assert.ThrowsException<ArgumentNullException>(() => cipher.Resize(null, ParmsId.Zero, 10ul));
            Assert.ThrowsException<ArgumentException>(() => cipher.Resize(context, ParmsId.Zero, 10ul));

            Assert.ThrowsException<ArgumentNullException>(() => cipher.Resize(null, 10ul));

            Assert.ThrowsException<ArgumentNullException>(() => cipher.Set(null));

            Assert.ThrowsException<ArgumentNullException>(() => cipher.IsValidFor(null));
            Assert.ThrowsException<ArgumentNullException>(() => cipher.IsMetadataValidFor(null));

            Assert.ThrowsException<ArgumentNullException>(() => cipher.Save(null));

            Assert.ThrowsException<ArgumentNullException>(() => cipher.UnsafeLoad(null));
            Assert.ThrowsException<ArgumentException>(() => cipher.UnsafeLoad(new MemoryStream()));

            Assert.ThrowsException<ArgumentNullException>(() => cipher.Load(null, new MemoryStream()));
            Assert.ThrowsException<ArgumentNullException>(() => cipher.Load(context, null));
        }
    }
}
