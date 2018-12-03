using Microsoft.Research.SEAL;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using System.Collections.Generic;
using System.IO;
using System.Numerics;
using System.Text;

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
            Assert.AreEqual(0, cipher.Size);
            Assert.AreEqual(0, cipher.PolyModulusDegree);
            Assert.AreEqual(0, cipher.CoeffModCount);
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

            Assert.AreEqual(5, cipher.SizeCapacity);
        }

        [TestMethod]
        public void ResizeTest()
        {
            SEALContext context = GlobalContext.Context;
            ParmsId parms = context.FirstParmsId;

            Ciphertext cipher = new Ciphertext(context, parms);

            Assert.AreEqual(2, cipher.SizeCapacity);
            Assert.AreEqual(16384, cipher.UInt64CountCapacity);

            cipher.Reserve(context, parms, sizeCapacity: 10);
            Assert.AreEqual(10, cipher.SizeCapacity);
            Assert.AreEqual(16384 * 5, cipher.UInt64CountCapacity);

            Ciphertext cipher2 = new Ciphertext();

            Assert.AreEqual(2, cipher2.SizeCapacity);

            cipher2.Reserve(context, 5);
            Assert.AreEqual(5, cipher2.SizeCapacity);

            Ciphertext cipher3 = new Ciphertext();

            Assert.AreEqual(2, cipher3.SizeCapacity);

            cipher3.Reserve(4);
            Assert.AreEqual(4, cipher3.SizeCapacity);
        }
        
        [TestMethod]
        public void ReleaseTest()
        {
            Ciphertext cipher = new Ciphertext();

            Assert.AreEqual(0, cipher.Size);
            cipher.Resize(4);
            Assert.AreEqual(4, cipher.Size);
            cipher.Release();
            Assert.AreEqual(0, cipher.Size);
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

            Assert.AreEqual(2, cipher.Size);
            Assert.AreEqual(4096, cipher.PolyModulusDegree);
            Assert.AreEqual(2, cipher.CoeffModCount);

            Ciphertext loaded = new Ciphertext();

            Assert.AreEqual(0, loaded.Size);
            Assert.AreEqual(0, loaded.PolyModulusDegree);
            Assert.AreEqual(0, loaded.CoeffModCount);

            using (MemoryStream mem = new MemoryStream())
            {
                cipher.Save(mem);

                mem.Seek(offset: 0, loc: SeekOrigin.Begin);

                loaded.Load(mem);
            }

            Assert.AreEqual(2, loaded.Size);
            Assert.AreEqual(4096, loaded.PolyModulusDegree);
            Assert.AreEqual(2, loaded.CoeffModCount);

            int ulongCount = cipher.Size * cipher.PolyModulusDegree * cipher.CoeffModCount;
            for (int i = 0; i < ulongCount; i++)
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

            Assert.AreEqual(2, cipher.Size);
            Assert.AreNotEqual(0ul, cipher[0, 0]);
            Assert.AreNotEqual(0ul, cipher[0, 1]);
            Assert.AreNotEqual(0ul, cipher[0, 2]);
            Assert.AreNotEqual(0ul, cipher[1, 0]);
            Assert.AreNotEqual(0ul, cipher[1, 1]);
            Assert.AreNotEqual(0ul, cipher[1, 2]);
        }

        [TestMethod]
        [ExpectedException(typeof(IndexOutOfRangeException))]
        public void IndexRangeFail1Test()
        {
            SEALContext context = GlobalContext.Context;
            KeyGenerator keygen = new KeyGenerator(context);
            Encryptor encryptor = new Encryptor(context, keygen.PublicKey);
            Plaintext plain = new Plaintext("1");
            Ciphertext cipher = new Ciphertext();

            encryptor.Encrypt(plain, cipher);

            // We only have 2 polynomials
            ulong data = cipher[2, 0];
        }

        [TestMethod]
        [ExpectedException(typeof(IndexOutOfRangeException))]
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
            data = cipher[0, 8192]; // This will fail
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

            Ciphertext encrypted = new Ciphertext();
            Plaintext plain = new Plaintext();

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

            evaluator.RescaleToNextInplace(encrypted);

            Assert.AreEqual(Math.Pow(2, 30), encrypted.Scale, delta: 10000);
        }
    }
}
