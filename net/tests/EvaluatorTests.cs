// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

using Microsoft.Research.SEAL;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Numerics;

namespace SEALNetTest
{
    [TestClass]
    public class EvaluatorTests
    {
        [TestMethod]
        public void CreateTest()
        {
            Evaluator evaluator = new Evaluator(GlobalContext.Context);
            Assert.IsNotNull(evaluator);
        }

        [TestMethod]
        public void NegateTest()
        {
            List<SmallModulus> coeffModulus = new List<SmallModulus>
            {
                DefaultParams.SmallMods40Bit(0)
            };
            EncryptionParameters parms = new EncryptionParameters(SchemeType.BFV)
            {
                PolyModulusDegree = 64,
                PlainModulus = new SmallModulus(1 << 6),
                CoeffModulus = coeffModulus
            };
            SEALContext context = SEALContext.Create(parms);
            KeyGenerator keygen = new KeyGenerator(context);

            Assert.IsTrue(context.ParametersSet);

            Encryptor encryptor = new Encryptor(context, keygen.PublicKey);
            Decryptor decryptor = new Decryptor(context, keygen.SecretKey);
            Evaluator evaluator = new Evaluator(context);

            Ciphertext encrypted = new Ciphertext();
            Ciphertext encdestination = new Ciphertext();
            Plaintext plain = new Plaintext("3x^2 + 2x^1 + 1");
            Plaintext plaindest = new Plaintext();
            encryptor.Encrypt(plain, encrypted);
            evaluator.Negate(encrypted, encdestination);
            decryptor.Decrypt(encdestination, plaindest);

            // coefficients are negated (modulo 64)
            Assert.AreEqual(0x3Ful, plaindest[0]);
            Assert.AreEqual(0x3Eul, plaindest[1]);
            Assert.AreEqual(0x3Dul, plaindest[2]);

            plain = new Plaintext("6x^3 + 7x^2 + 8x^1 + 9");
            encryptor.Encrypt(plain, encrypted);
            evaluator.NegateInplace(encrypted);
            decryptor.Decrypt(encrypted, plain);

            // coefficients are negated (modulo 64)
            Assert.AreEqual(0x37ul, plain[0]);
            Assert.AreEqual(0x38ul, plain[1]);
            Assert.AreEqual(0x39ul, plain[2]);
            Assert.AreEqual(0x3Aul, plain[3]);
        }

        [TestMethod]
        public void AddTest()
        {
            List<SmallModulus> coeffModulus = new List<SmallModulus>
            {
                DefaultParams.SmallMods40Bit(0)
            };
            EncryptionParameters parms = new EncryptionParameters(SchemeType.BFV)
            {
                PolyModulusDegree = 64,
                PlainModulus = new SmallModulus(1 << 6),
                CoeffModulus = coeffModulus
            };
            SEALContext context = SEALContext.Create(parms);
            KeyGenerator keygen = new KeyGenerator(context);

            Encryptor encryptor = new Encryptor(context, keygen.PublicKey);
            Decryptor decryptor = new Decryptor(context, keygen.SecretKey);
            Evaluator evaluator = new Evaluator(context);

            Ciphertext encrypted1 = new Ciphertext();
            Ciphertext encrypted2 = new Ciphertext();
            Ciphertext encdestination = new Ciphertext();

            Plaintext plain1 = new Plaintext("5x^4 + 4x^3 + 3x^2 + 2x^1 + 1");
            Plaintext plain2 = new Plaintext("4x^7 + 5x^6 + 6x^5 + 7x^4 + 8x^3 + 9x^2 + Ax^1 + B");
            Plaintext plaindest = new Plaintext();

            encryptor.Encrypt(plain1, encrypted1);
            encryptor.Encrypt(plain2, encrypted2);
            evaluator.Add(encrypted1, encrypted2, encdestination);
            decryptor.Decrypt(encdestination, plaindest);

            Assert.AreEqual(12ul, plaindest[0]);
            Assert.AreEqual(12ul, plaindest[1]);
            Assert.AreEqual(12ul, plaindest[2]);
            Assert.AreEqual(12ul, plaindest[3]);
            Assert.AreEqual(12ul, plaindest[4]);
            Assert.AreEqual(6ul, plaindest[5]);
            Assert.AreEqual(5ul, plaindest[6]);
            Assert.AreEqual(4ul, plaindest[7]);

            plain1 = new Plaintext("1x^2 + 2x^1 + 3");
            plain2 = new Plaintext("2x^3 + 2x^2 + 2x^1 + 2");

            encryptor.Encrypt(plain1, encrypted1);
            encryptor.Encrypt(plain2, encrypted2);
            evaluator.AddInplace(encrypted1, encrypted2);
            decryptor.Decrypt(encrypted1, plaindest);

            Assert.AreEqual(5ul, plaindest[0]);
            Assert.AreEqual(4ul, plaindest[1]);
            Assert.AreEqual(3ul, plaindest[2]);
            Assert.AreEqual(2ul, plaindest[3]);
        }
        
        [TestMethod]
        public void AddPlainTest()
        {
            List<SmallModulus> coeffModulus = new List<SmallModulus>
            {
                DefaultParams.SmallMods40Bit(0)
            };
            EncryptionParameters parms = new EncryptionParameters(SchemeType.BFV)
            {
                PolyModulusDegree = 64,
                PlainModulus = new SmallModulus(1 << 6),
                CoeffModulus = coeffModulus
            };
            SEALContext context = SEALContext.Create(parms);
            KeyGenerator keygen = new KeyGenerator(context);

            Encryptor encryptor = new Encryptor(context, keygen.PublicKey);
            Decryptor decryptor = new Decryptor(context, keygen.SecretKey);
            Evaluator evaluator = new Evaluator(context);

            Ciphertext encrypted = new Ciphertext();
            Ciphertext encdest = new Ciphertext();
            Plaintext plain = new Plaintext("3x^2 + 2x^1 + 1");
            Plaintext plaindest = new Plaintext();

            encryptor.Encrypt(new Plaintext("2x^2 + 2x^1 + 2"), encrypted);
            evaluator.AddPlain(encrypted, plain, encdest);
            decryptor.Decrypt(encdest, plaindest);

            Assert.AreEqual(3ul, plaindest[0]);
            Assert.AreEqual(4ul, plaindest[1]);
            Assert.AreEqual(5ul, plaindest[2]);

            plain.Set("1x^2 + 1x^1 + 1");
            encryptor.Encrypt(new Plaintext("2x^3 + 2x^2 + 2x^1 + 2"), encrypted);
            evaluator.AddPlainInplace(encrypted, plain);
            decryptor.Decrypt(encrypted, plaindest);

            Assert.AreEqual(4ul, plaindest.CoeffCount);
            Assert.AreEqual(3ul, plaindest[0]);
            Assert.AreEqual(3ul, plaindest[1]);
            Assert.AreEqual(3ul, plaindest[2]);
            Assert.AreEqual(2ul, plaindest[3]);
        }

        [TestMethod]
        public void AddManyTest()
        {
            List<SmallModulus> coeffModulus = new List<SmallModulus>
            {
                DefaultParams.SmallMods40Bit(0)
            };
            EncryptionParameters parms = new EncryptionParameters(SchemeType.BFV)
            {
                PolyModulusDegree = 64,
                PlainModulus = new SmallModulus(1 << 6),
                CoeffModulus = coeffModulus
            };
            SEALContext context = SEALContext.Create(parms);
            KeyGenerator keygen = new KeyGenerator(context);

            Encryptor encryptor = new Encryptor(context, keygen.PublicKey);
            Decryptor decryptor = new Decryptor(context, keygen.SecretKey);
            Evaluator evaluator = new Evaluator(context);

            Ciphertext[] encrypteds = new Ciphertext[6];

            for(int i = 0; i < encrypteds.Length; i++)
            {
                encrypteds[i] = new Ciphertext();
                encryptor.Encrypt(new Plaintext((i + 1).ToString()), encrypteds[i]);
            }

            Ciphertext encdest = new Ciphertext();
            Plaintext plaindest = new Plaintext();
            evaluator.AddMany(encrypteds, encdest);
            decryptor.Decrypt(encdest, plaindest);

            // 1+2+3+4+5+6
            Assert.AreEqual(21ul, plaindest[0]);
        }

        [TestMethod]
        public void SubTest()
        {
            List<SmallModulus> coeffModulus = new List<SmallModulus>
            {
                DefaultParams.SmallMods40Bit(0)
            };
            EncryptionParameters parms = new EncryptionParameters(SchemeType.BFV)
            {
                PolyModulusDegree = 64,
                PlainModulus = new SmallModulus(1 << 6),
                CoeffModulus = coeffModulus
            };
            SEALContext context = SEALContext.Create(parms);
            KeyGenerator keygen = new KeyGenerator(context);

            Encryptor encryptor = new Encryptor(context, keygen.PublicKey);
            Decryptor decryptor = new Decryptor(context, keygen.SecretKey);
            Evaluator evaluator = new Evaluator(context);

            Ciphertext encrypted1 = new Ciphertext();
            Ciphertext encrypted2 = new Ciphertext();
            Ciphertext encdest = new Ciphertext();
            Plaintext plain1 = new Plaintext("Ax^2 + Bx^1 + C");
            Plaintext plain2 = new Plaintext("5x^3 + 5x^2 + 5x^1 + 5");
            Plaintext plaindest = new Plaintext();

            encryptor.Encrypt(plain1, encrypted1);
            encryptor.Encrypt(plain2, encrypted2);
            evaluator.Sub(encrypted1, encrypted2, encdest);
            decryptor.Decrypt(encdest, plaindest);

            Assert.AreEqual(7ul, plaindest[0]);
            Assert.AreEqual(6ul, plaindest[1]);
            Assert.AreEqual(5ul, plaindest[2]);
            Assert.AreEqual(0x3Bul, plaindest[3]);

            plain1.Set("Ax^3 + Bx^2 + Cx^1 + D");
            plain2.Set("5x^2 + 5x^1 + 5");

            encryptor.Encrypt(plain1, encrypted1);
            encryptor.Encrypt(plain2, encrypted2);
            evaluator.SubInplace(encrypted1, encrypted2);
            decryptor.Decrypt(encrypted1, plaindest);

            Assert.AreEqual(8ul, plaindest[0]);
            Assert.AreEqual(7ul, plaindest[1]);
            Assert.AreEqual(6ul, plaindest[2]);
            Assert.AreEqual(10ul, plaindest[3]);
        }

        [TestMethod]
        public void SubPlainTest()
        {
            List<SmallModulus> coeffModulus = new List<SmallModulus>
            {
                DefaultParams.SmallMods40Bit(0)
            };
            EncryptionParameters parms = new EncryptionParameters(SchemeType.BFV)
            {
                PolyModulusDegree = 64,
                PlainModulus = new SmallModulus(1 << 6),
                CoeffModulus = coeffModulus
            };
            SEALContext context = SEALContext.Create(parms);
            KeyGenerator keygen = new KeyGenerator(context);

            Encryptor encryptor = new Encryptor(context, keygen.PublicKey);
            Decryptor decryptor = new Decryptor(context, keygen.SecretKey);
            Evaluator evaluator = new Evaluator(context);

            Ciphertext encrypted = new Ciphertext();
            Ciphertext encdest = new Ciphertext();
            Plaintext plain = new Plaintext("5x^2 + 4x^1 + 3");
            Plaintext plaindest = new Plaintext();

            encryptor.Encrypt(new Plaintext("3x^1 + 4"), encrypted);
            evaluator.SubPlain(encrypted, plain, encdest);
            decryptor.Decrypt(encdest, plaindest);

            Assert.AreEqual(3ul, plaindest.CoeffCount);
            Assert.AreEqual(1ul, plaindest[0]);
            Assert.AreEqual(0x3Ful, plaindest[1]); // -1
            Assert.AreEqual(0x3Bul, plaindest[2]); // -5

            plain.Set("6x^3 + 1x^2 + 7x^1 + 2");
            encryptor.Encrypt(new Plaintext("Ax^2 + Bx^1 + C"), encrypted);
            evaluator.SubPlainInplace(encrypted, plain);
            decryptor.Decrypt(encrypted, plaindest);

            Assert.AreEqual(4ul, plaindest.CoeffCount);
            Assert.AreEqual(10ul, plaindest[0]);
            Assert.AreEqual(4ul, plaindest[1]);
            Assert.AreEqual(9ul, plaindest[2]);
            Assert.AreEqual(0x3Aul, plaindest[3]); // -6
        }

        [TestMethod]
        public void MultiplyTest()
        {
            List<SmallModulus> coeffModulus = new List<SmallModulus>
            {
                DefaultParams.SmallMods40Bit(0)
            };
            EncryptionParameters parms = new EncryptionParameters(SchemeType.BFV)
            {
                PolyModulusDegree = 64,
                PlainModulus = new SmallModulus(1 << 6),
                CoeffModulus = coeffModulus
            };
            SEALContext context = SEALContext.Create(parms);
            KeyGenerator keygen = new KeyGenerator(context);

            Encryptor encryptor = new Encryptor(context, keygen.PublicKey);
            Decryptor decryptor = new Decryptor(context, keygen.SecretKey);
            Evaluator evaluator = new Evaluator(context);

            Ciphertext encrypted1 = new Ciphertext();
            Ciphertext encrypted2 = new Ciphertext();
            Ciphertext encdest = new Ciphertext();
            Plaintext plaindest = new Plaintext();

            encryptor.Encrypt(new Plaintext("1x^4 + 2x^3 + 3x^2 + 4x^1 + 5"), encrypted1);
            encryptor.Encrypt(new Plaintext("3x^2 + 2x^1 + 1"), encrypted2);
            evaluator.Multiply(encrypted1, encrypted2, encdest);
            decryptor.Decrypt(encdest, plaindest);

            // {3x^6 + 8x^5 + Ex^4 + 14x^3 + 1Ax^2 + Ex^1 + 5}
            Assert.AreEqual(7ul, plaindest.CoeffCount);
            Assert.AreEqual(5ul, plaindest[0]);
            Assert.AreEqual(14ul, plaindest[1]);
            Assert.AreEqual(26ul, plaindest[2]);
            Assert.AreEqual(20ul, plaindest[3]);
            Assert.AreEqual(14ul, plaindest[4]);
            Assert.AreEqual(8ul, plaindest[5]);
            Assert.AreEqual(3ul, plaindest[6]);

            encryptor.Encrypt(new Plaintext("2x^2 + 3x^1 + 4"), encrypted1);
            encryptor.Encrypt(new Plaintext("4x^1 + 5"), encrypted2);
            evaluator.MultiplyInplace(encrypted1, encrypted2);
            decryptor.Decrypt(encrypted1, plaindest);

            // {8x^3 + 16x^2 + 1Fx^1 + 14}
            Assert.AreEqual(4ul, plaindest.CoeffCount);
            Assert.AreEqual(20ul, plaindest[0]);
            Assert.AreEqual(31ul, plaindest[1]);
            Assert.AreEqual(22ul, plaindest[2]);
            Assert.AreEqual(8ul, plaindest[3]);
        }

        [TestMethod]
        public void MultiplyManyTest()
        {
            List<SmallModulus> coeffModulus = new List<SmallModulus>
            {
                DefaultParams.SmallMods40Bit(0),
                DefaultParams.SmallMods40Bit(1)
            };
            EncryptionParameters parms = new EncryptionParameters(SchemeType.BFV)
            {
                PolyModulusDegree = 128,
                PlainModulus = new SmallModulus(1 << 6),
                CoeffModulus = coeffModulus
            };
            SEALContext context = SEALContext.Create(parms);
            KeyGenerator keygen = new KeyGenerator(context);

            Encryptor encryptor = new Encryptor(context, keygen.PublicKey);
            Decryptor decryptor = new Decryptor(context, keygen.SecretKey);
            Evaluator evaluator = new Evaluator(context);
            RelinKeys relinKeys = keygen.RelinKeys(decompositionBitCount: 4);

            Ciphertext[] encrypteds = new Ciphertext[4];
            Ciphertext encdest = new Ciphertext();
            Plaintext plaindest = new Plaintext();

            for (int i = 0; i < encrypteds.Length; i++)
            {
                encrypteds[i] = new Ciphertext();
                encryptor.Encrypt(new Plaintext((i + 1).ToString()), encrypteds[i]);
            }

            evaluator.MultiplyMany(encrypteds, relinKeys, encdest);
            decryptor.Decrypt(encdest, plaindest);

            Assert.AreEqual(1ul, plaindest.CoeffCount);
            Assert.AreEqual(24ul, plaindest[0]);

            Assert.ThrowsException<ArgumentException>(() =>
            {
                // Uninitialized memory pool handle
                MemoryPoolHandle pool = new MemoryPoolHandle();
                evaluator.MultiplyMany(encrypteds, relinKeys, encdest, pool);
            });
        }

        [TestMethod]
        public void MultiplyPlainTest()
        {
            List<SmallModulus> coeffModulus = new List<SmallModulus>
            {
                DefaultParams.SmallMods40Bit(0),
                DefaultParams.SmallMods40Bit(1)
            };
            EncryptionParameters parms = new EncryptionParameters(SchemeType.BFV)
            {
                PolyModulusDegree = 128,
                PlainModulus = new SmallModulus(1 << 6),
                CoeffModulus = coeffModulus
            };
            SEALContext context = SEALContext.Create(parms);
            KeyGenerator keygen = new KeyGenerator(context);

            Encryptor encryptor = new Encryptor(context, keygen.PublicKey);
            Decryptor decryptor = new Decryptor(context, keygen.SecretKey);
            Evaluator evaluator = new Evaluator(context);
            RelinKeys relinKeys = keygen.RelinKeys(decompositionBitCount: 4);

            Ciphertext encrypted = new Ciphertext();
            Ciphertext encdest = new Ciphertext();
            Plaintext plain = new Plaintext("2x^2 + 1");
            Plaintext plaindest = new Plaintext();

            encryptor.Encrypt(new Plaintext("3x^2 + 2"), encrypted);
            evaluator.MultiplyPlain(encrypted, plain, encdest);
            decryptor.Decrypt(encdest, plaindest);

            // {6x^4 + 7x^2 + 2}
            Assert.AreEqual(5ul, plaindest.CoeffCount);
            Assert.AreEqual(2ul, plaindest[0]);
            Assert.AreEqual(0ul, plaindest[1]);
            Assert.AreEqual(7ul, plaindest[2]);
            Assert.AreEqual(0ul, plaindest[3]);
            Assert.AreEqual(6ul, plaindest[4]);

            encryptor.Encrypt(new Plaintext("4x^1 + 3"), encrypted);
            plain.Set("2x^2 + 1");
            evaluator.MultiplyPlainInplace(encrypted, plain);
            decryptor.Decrypt(encrypted, plaindest);

            // {8x^3 + 6x^2 + 4x^1 + 3}
            Assert.AreEqual(4ul, plaindest.CoeffCount);
            Assert.AreEqual(3ul, plaindest[0]);
            Assert.AreEqual(4ul, plaindest[1]);
            Assert.AreEqual(6ul, plaindest[2]);
            Assert.AreEqual(8ul, plaindest[3]);

            Assert.ThrowsException<ArgumentException>(() =>
            {
                // Uninitialized pool
                MemoryPoolHandle pool = new MemoryPoolHandle();
                evaluator.MultiplyPlain(encrypted, plain, encdest, pool);
            });
        }

        [TestMethod]
        public void SquareTest()
        {
            List<SmallModulus> coeffModulus = new List<SmallModulus>
            {
                DefaultParams.SmallMods40Bit(0),
                DefaultParams.SmallMods40Bit(1)
            };
            EncryptionParameters parms = new EncryptionParameters(SchemeType.BFV)
            {
                PolyModulusDegree = 128,
                PlainModulus = new SmallModulus(1 << 6),
                CoeffModulus = coeffModulus
            };
            SEALContext context = SEALContext.Create(parms);
            KeyGenerator keygen = new KeyGenerator(context);

            Encryptor encryptor = new Encryptor(context, keygen.PublicKey);
            Decryptor decryptor = new Decryptor(context, keygen.SecretKey);
            Evaluator evaluator = new Evaluator(context);

            Ciphertext encrypted = new Ciphertext();
            Ciphertext encdest = new Ciphertext();
            Plaintext plain = new Plaintext("2x^2 + 3x^1 + 4");
            Plaintext plaindest = new Plaintext();

            encryptor.Encrypt(plain, encrypted);
            evaluator.Square(encrypted, encdest);
            decryptor.Decrypt(encdest, plaindest);

            // {4x^4 + Cx^3 + 19x^2 + 18x^1 + 10}
            Assert.AreEqual(5ul, plaindest.CoeffCount);
            Assert.AreEqual(16ul, plaindest[0]);
            Assert.AreEqual(24ul, plaindest[1]);
            Assert.AreEqual(25ul, plaindest[2]);
            Assert.AreEqual(12ul, plaindest[3]);
            Assert.AreEqual(4ul, plaindest[4]);

            encryptor.Encrypt(new Plaintext("3x^1 + 2"), encrypted);
            evaluator.SquareInplace(encrypted);
            decryptor.Decrypt(encrypted, plaindest);

            // {9x^2 + Cx^1 + 4}
            Assert.AreEqual(3ul, plaindest.CoeffCount);
            Assert.AreEqual(4ul, plaindest[0]);
            Assert.AreEqual(12ul, plaindest[1]);
            Assert.AreEqual(9ul, plaindest[2]);
        }

        [TestMethod]
        public void ExponentiateTest()
        {
            List<SmallModulus> coeffModulus = new List<SmallModulus>
            {
                DefaultParams.SmallMods40Bit(0),
                DefaultParams.SmallMods40Bit(1)
            };
            EncryptionParameters parms = new EncryptionParameters(SchemeType.BFV)
            {
                PolyModulusDegree = 128,
                PlainModulus = new SmallModulus(1 << 6),
                CoeffModulus = coeffModulus
            };
            SEALContext context = SEALContext.Create(parms);
            KeyGenerator keygen = new KeyGenerator(context);

            Encryptor encryptor = new Encryptor(context, keygen.PublicKey);
            Decryptor decryptor = new Decryptor(context, keygen.SecretKey);
            Evaluator evaluator = new Evaluator(context);
            RelinKeys relinKeys = keygen.RelinKeys(decompositionBitCount: 4);

            Ciphertext encrypted = new Ciphertext();
            Ciphertext encdest = new Ciphertext();
            Plaintext plain = new Plaintext();

            encryptor.Encrypt(new Plaintext("2x^2 + 1"), encrypted);
            evaluator.Exponentiate(encrypted, 3, relinKeys, encdest);
            decryptor.Decrypt(encdest, plain);

            // {8x^6 + Cx^4 + 6x^2 + 1}
            Assert.AreEqual(7ul, plain.CoeffCount);
            Assert.AreEqual(1ul, plain[0]);
            Assert.AreEqual(0ul, plain[1]);
            Assert.AreEqual(6ul, plain[2]);
            Assert.AreEqual(0ul, plain[3]);
            Assert.AreEqual(12ul, plain[4]);
            Assert.AreEqual(0ul, plain[5]);
            Assert.AreEqual(8ul, plain[6]);

            encryptor.Encrypt(new Plaintext("3x^3 + 2"), encrypted);
            evaluator.ExponentiateInplace(encrypted, 4, relinKeys);
            decryptor.Decrypt(encrypted, plain);

            // {11x^12 + 18x^9 + 18x^6 + 20x^3 + 10}
            Assert.AreEqual(13ul, plain.CoeffCount);
            Assert.AreEqual(16ul, plain[0]);
            Assert.AreEqual(0ul, plain[1]);
            Assert.AreEqual(0ul, plain[2]);
            Assert.AreEqual(32ul, plain[3]);
            Assert.AreEqual(0ul, plain[4]);
            Assert.AreEqual(0ul, plain[5]);
            Assert.AreEqual(24ul, plain[6]);
            Assert.AreEqual(0ul, plain[7]);
            Assert.AreEqual(0ul, plain[8]);
            Assert.AreEqual(24ul, plain[9]);
            Assert.AreEqual(0ul, plain[10]);
            Assert.AreEqual(0ul, plain[11]);
            Assert.AreEqual(17ul, plain[12]);
        }

        [TestMethod]
        public void ApplyGaloisTest()
        {
            List<SmallModulus> coeffModulus = new List<SmallModulus>
            {
                DefaultParams.SmallMods40Bit(0),
                DefaultParams.SmallMods40Bit(1)
            };
            EncryptionParameters parms = new EncryptionParameters(SchemeType.BFV)
            {
                PolyModulusDegree = 8,
                PlainModulus = new SmallModulus(257),
                CoeffModulus = coeffModulus
            };
            SEALContext context = SEALContext.Create(parms);
            KeyGenerator keygen = new KeyGenerator(context);
            GaloisKeys galoisKeys = keygen.GaloisKeys(decompositionBitCount: 24, galoisElts: new ulong[] { 1ul, 3ul, 5ul, 15ul });

            Encryptor encryptor = new Encryptor(context, keygen.PublicKey);
            Decryptor decryptor = new Decryptor(context, keygen.SecretKey);
            Evaluator evaluator = new Evaluator(context);

            Plaintext plain = new Plaintext("1");
            Plaintext plaindest = new Plaintext();
            Ciphertext encrypted = new Ciphertext();
            Ciphertext encdest = new Ciphertext();

            encryptor.Encrypt(plain, encrypted);
            evaluator.ApplyGalois(encrypted, galoisElt: 1, galoisKeys: galoisKeys, destination: encdest);
            decryptor.Decrypt(encdest, plaindest);

            Assert.AreEqual(1ul, plaindest.CoeffCount);
            Assert.AreEqual(1ul, plaindest[0]);

            plain.Set("1x^1");
            encryptor.Encrypt(plain, encrypted);
            evaluator.ApplyGalois(encrypted, galoisElt: 1, galoisKeys: galoisKeys, destination: encdest);
            decryptor.Decrypt(encdest, plaindest);

            // {1x^1}
            Assert.AreEqual(2ul, plaindest.CoeffCount);
            Assert.AreEqual(0ul, plaindest[0]);
            Assert.AreEqual(1ul, plaindest[1]);

            evaluator.ApplyGalois(encdest, galoisElt: 3, galoisKeys: galoisKeys, destination: encrypted);
            decryptor.Decrypt(encrypted, plaindest);

            // {1x^3}
            Assert.AreEqual(4ul, plaindest.CoeffCount);
            Assert.AreEqual(0ul, plaindest[0]);
            Assert.AreEqual(0ul, plaindest[1]);
            Assert.AreEqual(0ul, plaindest[2]);
            Assert.AreEqual(1ul, plaindest[3]);

            evaluator.ApplyGalois(encrypted, galoisElt: 5, galoisKeys: galoisKeys, destination: encdest);
            decryptor.Decrypt(encdest, plaindest);

            // {100x^7}
            Assert.AreEqual(8ul, plaindest.CoeffCount);
            Assert.AreEqual(0ul, plaindest[0]);
            Assert.AreEqual(0ul, plaindest[1]);
            Assert.AreEqual(0ul, plaindest[2]);
            Assert.AreEqual(0ul, plaindest[3]);
            Assert.AreEqual(0ul, plaindest[4]);
            Assert.AreEqual(0ul, plaindest[5]);
            Assert.AreEqual(0ul, plaindest[6]);
            Assert.AreEqual(256ul, plaindest[7]);

            plain.Set("1x^2");
            encryptor.Encrypt(plain, encrypted);
            evaluator.ApplyGaloisInplace(encrypted, 1, galoisKeys);
            decryptor.Decrypt(encrypted, plaindest);

            // {1x^2}
            Assert.AreEqual(3ul, plaindest.CoeffCount);
            Assert.AreEqual(0ul, plaindest[0]);
            Assert.AreEqual(0ul, plaindest[1]);
            Assert.AreEqual(1ul, plaindest[2]);

            evaluator.ApplyGaloisInplace(encrypted, 3, galoisKeys);
            decryptor.Decrypt(encrypted, plaindest);

            // {1x^6}
            Assert.AreEqual(7ul, plaindest.CoeffCount);
            Assert.AreEqual(0ul, plaindest[0]);
            Assert.AreEqual(0ul, plaindest[1]);
            Assert.AreEqual(0ul, plaindest[2]);
            Assert.AreEqual(0ul, plaindest[3]);
            Assert.AreEqual(0ul, plaindest[4]);
            Assert.AreEqual(0ul, plaindest[5]);
            Assert.AreEqual(1ul, plaindest[6]);

            evaluator.ApplyGaloisInplace(encrypted, 5, galoisKeys);
            decryptor.Decrypt(encrypted, plaindest);

            // {100x^6}
            Assert.AreEqual(7ul, plaindest.CoeffCount);
            Assert.AreEqual(0ul, plaindest[0]);
            Assert.AreEqual(0ul, plaindest[1]);
            Assert.AreEqual(0ul, plaindest[2]);
            Assert.AreEqual(0ul, plaindest[3]);
            Assert.AreEqual(0ul, plaindest[4]);
            Assert.AreEqual(0ul, plaindest[5]);
            Assert.AreEqual(256ul, plaindest[6]);
        }

        [TestMethod]
        public void TransformPlainToNTTTest()
        {
            List<SmallModulus> coeffModulus = new List<SmallModulus>
            {
                DefaultParams.SmallMods40Bit(0),
                DefaultParams.SmallMods40Bit(1)
            };
            EncryptionParameters parms = new EncryptionParameters(SchemeType.BFV)
            {
                PolyModulusDegree = 128,
                PlainModulus = new SmallModulus(1 << 6),
                CoeffModulus = coeffModulus
            };
            SEALContext context = SEALContext.Create(parms);
            Evaluator evaluator = new Evaluator(context);

            Plaintext plain = new Plaintext("0");
            Plaintext plaindest = new Plaintext();
            Assert.IsFalse(plain.IsNTTForm);

            evaluator.TransformToNTT(plain, parms.ParmsId, plaindest);
            Assert.IsTrue(plaindest.IsZero);
            Assert.IsTrue(plaindest.IsNTTForm);
            Assert.IsTrue(plaindest.ParmsId == parms.ParmsId);

            plain = new Plaintext("1");
            Assert.IsFalse(plain.IsNTTForm);

            evaluator.TransformToNTTInplace(plain, parms.ParmsId);
            Assert.IsTrue(plain.IsNTTForm);

            for (ulong i = 0; i < 256; i++)
            {
                Assert.AreEqual(1ul, plain[i]);
            }
        }

        [TestMethod]
        public void TransformEncryptedToNTTTest()
        {
            List<SmallModulus> coeffModulus = new List<SmallModulus>
            {
                DefaultParams.SmallMods40Bit(0),
                DefaultParams.SmallMods40Bit(1)
            };
            EncryptionParameters parms = new EncryptionParameters(SchemeType.BFV)
            {
                PolyModulusDegree = 128,
                PlainModulus = new SmallModulus(1 << 6),
                CoeffModulus = coeffModulus
            };
            SEALContext context = SEALContext.Create(parms);
            KeyGenerator keygen = new KeyGenerator(context);

            Encryptor encryptor = new Encryptor(context, keygen.PublicKey);
            Decryptor decryptor = new Decryptor(context, keygen.SecretKey);
            Evaluator evaluator = new Evaluator(context);

            Ciphertext encrypted = new Ciphertext();
            Ciphertext encdest = new Ciphertext();
            Ciphertext encdest2 = new Ciphertext();
            Plaintext plaindest = new Plaintext();

            encryptor.Encrypt(new Plaintext("0"), encrypted);
            Assert.IsFalse(encrypted.IsNTTForm);

            evaluator.TransformToNTT(encrypted, encdest);
            Assert.IsTrue(encdest.IsNTTForm);

            evaluator.TransformFromNTT(encdest, encdest2);
            Assert.IsFalse(encdest2.IsNTTForm);

            decryptor.Decrypt(encdest2, plaindest);
            Assert.AreEqual(1ul, plaindest.CoeffCount);
            Assert.AreEqual(0ul, plaindest[0]);
            Assert.AreEqual(parms.ParmsId, encdest2.ParmsId);

            encryptor.Encrypt(new Plaintext("1"), encrypted);
            Assert.IsFalse(encrypted.IsNTTForm);

            evaluator.TransformToNTTInplace(encrypted);
            Assert.IsTrue(encrypted.IsNTTForm);

            evaluator.TransformFromNTTInplace(encrypted);
            Assert.IsFalse(encrypted.IsNTTForm);

            decryptor.Decrypt(encrypted, plaindest);

            Assert.AreEqual(1ul, plaindest.CoeffCount);
            Assert.AreEqual(1ul, plaindest[0]);
            Assert.AreEqual(parms.ParmsId, encrypted.ParmsId);
        }

        [TestMethod]
        public void ModSwitchToNextTest()
        {
            List<SmallModulus> coeffModulus = new List<SmallModulus>
            {
                DefaultParams.SmallMods30Bit(0),
                DefaultParams.SmallMods30Bit(1),
                DefaultParams.SmallMods30Bit(2)
            };
            EncryptionParameters parms = new EncryptionParameters(SchemeType.BFV)
            {
                PolyModulusDegree = 128,
                PlainModulus = new SmallModulus(1 << 6),
                CoeffModulus = coeffModulus
            };
            SEALContext context = SEALContext.Create(parms);
            KeyGenerator keygen = new KeyGenerator(context);

            Encryptor encryptor = new Encryptor(context, keygen.PublicKey);
            Decryptor decryptor = new Decryptor(context, keygen.SecretKey);
            Evaluator evaluator = new Evaluator(context);

            Ciphertext encrypted = new Ciphertext(context);
            Ciphertext encdest = new Ciphertext();
            Plaintext plain = new Plaintext();

            plain.Set("0");
            encryptor.Encrypt(plain, encrypted);
            evaluator.ModSwitchToNext(encrypted, encdest);
            decryptor.Decrypt(encdest, plain);

            Assert.AreEqual(1ul, plain.CoeffCount);
            Assert.AreEqual(0ul, plain[0]);

            plain.Set("1");
            encryptor.Encrypt(plain, encrypted);
            evaluator.ModSwitchToNextInplace(encrypted);
            decryptor.Decrypt(encrypted, plain);

            Assert.AreEqual(1ul, plain.CoeffCount);
            Assert.AreEqual(1ul, plain[0]);
        }

        [TestMethod]
        public void ModSwitchToTest()
        {
            List<SmallModulus> coeffModulus = new List<SmallModulus>
            {
                DefaultParams.SmallMods30Bit(0),
                DefaultParams.SmallMods30Bit(1),
                DefaultParams.SmallMods30Bit(2)
            };
            EncryptionParameters parms = new EncryptionParameters(SchemeType.BFV)
            {
                PolyModulusDegree = 128,
                PlainModulus = new SmallModulus(1 << 6),
                CoeffModulus = coeffModulus
            };
            SEALContext context = SEALContext.Create(parms);
            KeyGenerator keygen = new KeyGenerator(context);

            Encryptor encryptor = new Encryptor(context, keygen.PublicKey);
            Decryptor decryptor = new Decryptor(context, keygen.SecretKey);
            Evaluator evaluator = new Evaluator(context);

            Ciphertext encrypted = new Ciphertext(context);
            Ciphertext encdest = new Ciphertext(context);
            Plaintext plaindest = new Plaintext();

            encryptor.Encrypt(new Plaintext("1"), encrypted);
            evaluator.ModSwitchTo(encrypted, parms.ParmsId, encdest);
            decryptor.Decrypt(encdest, plaindest);

            Assert.IsTrue(encdest.ParmsId == parms.ParmsId);
            Assert.AreEqual(1ul, plaindest.CoeffCount);
            Assert.AreEqual(1ul, plaindest[0]);

            encryptor.Encrypt(new Plaintext("2"), encrypted);
            evaluator.ModSwitchToInplace(encrypted, parms.ParmsId);
            decryptor.Decrypt(encrypted, plaindest);

            Assert.IsTrue(encrypted.ParmsId == parms.ParmsId);
            Assert.AreEqual(1ul, plaindest.CoeffCount);
            Assert.AreEqual(2ul, plaindest[0]);
        }

        [TestMethod]
        public void ModSwitchToPlainTest()
        {
            EncryptionParameters parms = new EncryptionParameters(SchemeType.CKKS)
            {
                PolyModulusDegree = 1024,
                CoeffModulus = new List<SmallModulus>()
                {
                    DefaultParams.SmallMods40Bit(0),
                    DefaultParams.SmallMods40Bit(1),
                    DefaultParams.SmallMods40Bit(2),
                    DefaultParams.SmallMods40Bit(3)
                }
            };

            SEALContext context = SEALContext.Create(parms);
            CKKSEncoder encoder = new CKKSEncoder(context);
            KeyGenerator keygen = new KeyGenerator(context);
            SecretKey secretKey = keygen.SecretKey;
            PublicKey publicKey = keygen.PublicKey;
            RelinKeys relinKeys = keygen.RelinKeys(60);

            Encryptor encryptor = new Encryptor(context, publicKey);
            Evaluator evaluator = new Evaluator(context);
            Decryptor decryptor = new Decryptor(context, secretKey);

            double scale = parms.CoeffModulus.Last().Value;
            Plaintext coeff1 = new Plaintext();
            Plaintext coeff2 = new Plaintext();
            Plaintext coeff3 = new Plaintext();
            encoder.Encode(2.0, scale, coeff1);
            encoder.Encode(3.0, scale, coeff2);
            encoder.Encode(1.0, scale, coeff3);

            Ciphertext encX1 = new Ciphertext();
            Ciphertext encX2 = new Ciphertext();
            Ciphertext encX3 = new Ciphertext();
            encryptor.Encrypt(coeff1, encX1);
            evaluator.Square(encX1, encX3);
            evaluator.MultiplyPlain(encX1, coeff2, encX2);
            evaluator.RelinearizeInplace(encX3, relinKeys);
            evaluator.RescaleToNextInplace(encX3);
            evaluator.RelinearizeInplace(encX2, relinKeys);
            evaluator.RescaleToInplace(encX2, encX3.ParmsId);

            evaluator.ModSwitchToInplace(coeff3, encX3.ParmsId);
            evaluator.ModSwitchToNextInplace(coeff2);

            evaluator.MultiplyPlainInplace(encX3, coeff3);

            Plaintext result = new Plaintext();
            decryptor.Decrypt(encX3, result);
            Assert.IsNotNull(result);

            List<double> destination = new List<double>();
            encoder.Decode(result, destination);

            Assert.IsNotNull(destination);
            foreach(double val in destination)
            {
                Assert.AreEqual(4.0, val, delta: 0.001);
            }

            encoder.Decode(coeff2, destination);

            foreach(double val in destination)
            {
                Assert.AreEqual(3.0, val, delta: 0.001);
            }

            decryptor.Decrypt(encX2, result);
            encoder.Decode(result, destination);

            foreach (double val in destination)
            {
                Assert.AreEqual(6.0, val, delta: 0.001);
            }
        }

        [TestMethod]
        public void RotateMatrixTest()
        {
            List<SmallModulus> coeffModulus = new List<SmallModulus>
            {
                DefaultParams.SmallMods40Bit(0),
                DefaultParams.SmallMods40Bit(1)
            };
            EncryptionParameters parms = new EncryptionParameters(SchemeType.BFV)
            {
                PolyModulusDegree = 8,
                PlainModulus = new SmallModulus(257),
                CoeffModulus = coeffModulus
            };
            SEALContext context = SEALContext.Create(parms);
            KeyGenerator keygen = new KeyGenerator(context);
            GaloisKeys galoisKeys = keygen.GaloisKeys(decompositionBitCount: 24);

            Encryptor encryptor = new Encryptor(context, keygen.PublicKey);
            Decryptor decryptor = new Decryptor(context, keygen.SecretKey);
            Evaluator evaluator = new Evaluator(context);
            BatchEncoder encoder = new BatchEncoder(context);

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
        public void RelinearizeTest()
        {
            List<SmallModulus> coeffModulus = new List<SmallModulus>
            {
                DefaultParams.SmallMods40Bit(0),
                DefaultParams.SmallMods40Bit(1),
                DefaultParams.SmallMods40Bit(2)
            };
            EncryptionParameters parms = new EncryptionParameters(SchemeType.BFV)
            {
                PolyModulusDegree = 128,
                PlainModulus = new SmallModulus(1 << 6),
                CoeffModulus = coeffModulus
            };
            SEALContext context = SEALContext.Create(parms);
            KeyGenerator keygen = new KeyGenerator(context);
            RelinKeys relinKeys = keygen.RelinKeys(decompositionBitCount: 60, count: 3);

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
        public void RotateVectorTest()
        {
            int slotSize = 4;
            List<SmallModulus> coeffModulus = new List<SmallModulus>
            {
                DefaultParams.SmallMods40Bit(0),
                DefaultParams.SmallMods40Bit(1),
                DefaultParams.SmallMods40Bit(2),
                DefaultParams.SmallMods40Bit(3)
            };
            EncryptionParameters parms = new EncryptionParameters(SchemeType.CKKS)
            {
                PolyModulusDegree = 2 * (ulong)slotSize,
                CoeffModulus = coeffModulus
            };
            SEALContext context = SEALContext.Create(parms);
            KeyGenerator keygen = new KeyGenerator(context);
            GaloisKeys galoisKeys = keygen.GaloisKeys(decompositionBitCount: 4);

            Encryptor encryptor = new Encryptor(context, keygen.PublicKey);
            Decryptor decryptor = new Decryptor(context, keygen.SecretKey);
            Evaluator evaluator = new Evaluator(context);
            CKKSEncoder encoder = new CKKSEncoder(context);

            const double delta = 1ul << 30;

            Ciphertext encrypted = new Ciphertext();
            Plaintext plain = new Plaintext();

            List<Complex> input = new List<Complex>
            {
                new Complex(1, 1),
                new Complex(2, 2),
                new Complex(3, 3),
                new Complex(4, 4)
            };

            List<Complex> output = new List<Complex>();

            encoder.Encode(input, parms.ParmsId, delta, plain);

            int shift = 1;
            encryptor.Encrypt(plain, encrypted);
            evaluator.RotateVectorInplace(encrypted, shift, galoisKeys);
            decryptor.Decrypt(encrypted, plain);
            encoder.Decode(plain, output);

            for (int i = 0; i < slotSize; i++)
            {
                Assert.AreEqual(input[(i + shift) % slotSize].Real, Math.Round(output[i].Real), delta: 0.1);
                Assert.AreEqual(input[(i + shift) % slotSize].Imaginary, Math.Round(output[i].Imaginary), delta: 0.1);
            }

            encoder.Encode(input, parms.ParmsId, delta, plain);
            shift = 3;
            encryptor.Encrypt(plain, encrypted);
            evaluator.RotateVectorInplace(encrypted, shift, galoisKeys);
            decryptor.Decrypt(encrypted, plain);
            encoder.Decode(plain, output);

            for (int i = 0; i < slotSize; i++)
            {
                Assert.AreEqual(input[(i + shift) % slotSize].Real, Math.Round(output[i].Real), delta: 0.1);
                Assert.AreEqual(input[(i + shift) % slotSize].Imaginary, Math.Round(output[i].Imaginary), delta: 0.1);
            }
        }

        [TestMethod]
        public void ComplexConjugateTest()
        {
            int slotSize = 4;
            List<SmallModulus> coeffModulus = new List<SmallModulus>
            {
                DefaultParams.SmallMods40Bit(0),
                DefaultParams.SmallMods40Bit(1),
                DefaultParams.SmallMods40Bit(2),
                DefaultParams.SmallMods40Bit(3)
            };
            EncryptionParameters parms = new EncryptionParameters(SchemeType.CKKS)
            {
                PolyModulusDegree = 2 * (ulong)slotSize,
                CoeffModulus = coeffModulus
            };
            SEALContext context = SEALContext.Create(parms);
            KeyGenerator keygen = new KeyGenerator(context);
            GaloisKeys galoisKeys = keygen.GaloisKeys(decompositionBitCount: 4);

            Encryptor encryptor = new Encryptor(context, keygen.PublicKey);
            Decryptor decryptor = new Decryptor(context, keygen.SecretKey);
            Evaluator evaluator = new Evaluator(context);
            CKKSEncoder encoder = new CKKSEncoder(context);

            const double delta = 1ul << 30;

            Ciphertext encrypted = new Ciphertext();
            Plaintext plain = new Plaintext();

            List<Complex> input = new List<Complex>
            {
                new Complex(1, 1),
                new Complex(2, 2),
                new Complex(3, 3),
                new Complex(4, 4)
            };

            List<Complex> output = new List<Complex>();

            encoder.Encode(input, parms.ParmsId, delta, plain);
            encryptor.Encrypt(plain, encrypted);
            evaluator.ComplexConjugateInplace(encrypted, galoisKeys);
            decryptor.Decrypt(encrypted, plain);
            encoder.Decode(plain, output);

            for (int i = 0; i < slotSize; i++)
            {
                Assert.AreEqual(input[i].Real, output[i].Real, delta: 0.1);
                Assert.AreEqual(-input[i].Imaginary, output[i].Imaginary, delta: 0.1);
            }
        }

        [TestMethod]
        public void ExceptionsTest()
        {
            EncryptionParameters parms = new EncryptionParameters(SchemeType.BFV)
            {
                PolyModulusDegree = 64,
                PlainModulus = new SmallModulus(1 << 6),
                CoeffModulus = new List<SmallModulus>() { DefaultParams.SmallMods40Bit(0) }
            };
            SEALContext context = SEALContext.Create(parms);

            Evaluator evaluator = null;
            Assert.ThrowsException<ArgumentNullException>(() => evaluator = new Evaluator(null));
            evaluator = new Evaluator(context);

            KeyGenerator keygen = new KeyGenerator(context);
            GaloisKeys galoisKeys = keygen.GaloisKeys(30);
            RelinKeys relinKeys = keygen.RelinKeys(30);

            Ciphertext encrypted1 = new Ciphertext();
            Ciphertext encrypted2 = new Ciphertext();
            Ciphertext encrypted3 = new Ciphertext();
            Plaintext plain1 = new Plaintext();
            Plaintext plain2 = new Plaintext();
            List<Ciphertext> encrypteds = new List<Ciphertext>();

            MemoryPoolHandle pool = MemoryManager.GetPool(MMProfOpt.ForceGlobal);

            Assert.ThrowsException<ArgumentNullException>(() => evaluator.Add(null, encrypted2, encrypted3));
            Assert.ThrowsException<ArgumentNullException>(() => evaluator.Add(encrypted1, null, encrypted3));
            Assert.ThrowsException<ArgumentNullException>(() => evaluator.Add(encrypted1, encrypted2, null));
            Assert.ThrowsException<ArgumentException>(() => evaluator.Add(encrypted1, encrypted2, encrypted3));

            Assert.ThrowsException<ArgumentNullException>(() => evaluator.AddInplace(encrypted1, null));
            Assert.ThrowsException<ArgumentNullException>(() => evaluator.AddInplace(null, encrypted2));

            Assert.ThrowsException<ArgumentNullException>(() => evaluator.AddMany(encrypteds, null));
            Assert.ThrowsException<ArgumentNullException>(() => evaluator.AddMany(null, encrypted2));

            Assert.ThrowsException<ArgumentNullException>(() => evaluator.AddPlain(encrypted1, plain1, null));
            Assert.ThrowsException<ArgumentNullException>(() => evaluator.AddPlain(encrypted1, null, encrypted2));
            Assert.ThrowsException<ArgumentNullException>(() => evaluator.AddPlain(null, plain1, encrypted2));
            Assert.ThrowsException<ArgumentException>(() => evaluator.AddPlain(encrypted1, plain1, encrypted2));

            Assert.ThrowsException<ArgumentNullException>(() => evaluator.AddPlainInplace(encrypted1, null));
            Assert.ThrowsException<ArgumentNullException>(() => evaluator.AddPlainInplace(null, plain1));

            Assert.ThrowsException<ArgumentNullException>(() => evaluator.ApplyGalois(encrypted1, 1, galoisKeys, null));
            Assert.ThrowsException<ArgumentNullException>(() => evaluator.ApplyGalois(encrypted1, 1, null, encrypted2));
            Assert.ThrowsException<ArgumentNullException>(() => evaluator.ApplyGalois(null, 1, galoisKeys, encrypted2));
            Assert.ThrowsException<ArgumentException>(() => evaluator.ApplyGalois(encrypted1, 1, galoisKeys, encrypted2, pool));

            Assert.ThrowsException<ArgumentNullException>(() => evaluator.ApplyGaloisInplace(encrypted1, 1, null));
            Assert.ThrowsException<ArgumentNullException>(() => evaluator.ApplyGaloisInplace(null, 1, galoisKeys));

            Assert.ThrowsException<ArgumentNullException>(() => evaluator.ComplexConjugate(encrypted1, galoisKeys, null));
            Assert.ThrowsException<ArgumentNullException>(() => evaluator.ComplexConjugate(encrypted1, null, encrypted2));
            Assert.ThrowsException<ArgumentNullException>(() => evaluator.ComplexConjugate(null, galoisKeys, encrypted2));

            Assert.ThrowsException<ArgumentNullException>(() => evaluator.ComplexConjugateInplace(encrypted1, null));
            Assert.ThrowsException<ArgumentNullException>(() => evaluator.ComplexConjugateInplace(null, galoisKeys));

            Assert.ThrowsException<ArgumentNullException>(() => evaluator.Exponentiate(encrypted1, 2, relinKeys, null));
            Assert.ThrowsException<ArgumentNullException>(() => evaluator.Exponentiate(encrypted1, 2, null, encrypted2));
            Assert.ThrowsException<ArgumentNullException>(() => evaluator.Exponentiate(null, 2, relinKeys, encrypted2));

            Assert.ThrowsException<ArgumentNullException>(() => evaluator.ExponentiateInplace(encrypted1, 2, null));
            Assert.ThrowsException<ArgumentNullException>(() => evaluator.ExponentiateInplace(null, 2, relinKeys));

            Assert.ThrowsException<ArgumentNullException>(() => evaluator.ModSwitchTo(plain1, ParmsId.Zero, null));
            Assert.ThrowsException<ArgumentNullException>(() => evaluator.ModSwitchTo(plain1, null, plain2));
            Assert.ThrowsException<ArgumentNullException>(() => evaluator.ModSwitchTo(null, ParmsId.Zero, plain2));

            Assert.ThrowsException<ArgumentNullException>(() => evaluator.ModSwitchTo(encrypted1, ParmsId.Zero, null));
            Assert.ThrowsException<ArgumentNullException>(() => evaluator.ModSwitchTo(encrypted1, null, encrypted2));
            Assert.ThrowsException<ArgumentNullException>(() => evaluator.ModSwitchTo(null, ParmsId.Zero, encrypted2));
            Assert.ThrowsException<ArgumentException>(() => evaluator.ModSwitchTo(encrypted1, ParmsId.Zero, encrypted2, pool));

            Assert.ThrowsException<ArgumentNullException>(() => evaluator.ModSwitchToInplace(encrypted1, null));
            Assert.ThrowsException<ArgumentNullException>(() => evaluator.ModSwitchToInplace(encrypted: null, parmsId: ParmsId.Zero));
            Assert.ThrowsException<ArgumentException>(() => evaluator.ModSwitchToInplace(encrypted1, ParmsId.Zero, pool));

            Assert.ThrowsException<ArgumentNullException>(() => evaluator.ModSwitchToInplace(plain1, null));
            Assert.ThrowsException<ArgumentNullException>(() => evaluator.ModSwitchToInplace(plain: null, parmsId: ParmsId.Zero));

            Assert.ThrowsException<ArgumentNullException>(() => evaluator.ModSwitchToNext(plain1, null));
            Assert.ThrowsException<ArgumentNullException>(() => evaluator.ModSwitchToNext(null, plain2));

            Assert.ThrowsException<ArgumentNullException>(() => evaluator.ModSwitchToNextInplace(null));

            Assert.ThrowsException<ArgumentNullException>(() => evaluator.ModSwitchToNext(encrypted1, null));
            Assert.ThrowsException<ArgumentNullException>(() => evaluator.ModSwitchToNext(null, encrypted2));
            Assert.ThrowsException<ArgumentException>(() => evaluator.ModSwitchToNext(encrypted1, encrypted2, pool));

            Assert.ThrowsException<ArgumentNullException>(() => evaluator.ModSwitchToNextInplace(encrypted: null));
            Assert.ThrowsException<ArgumentException>(() => evaluator.ModSwitchToNextInplace(encrypted1, pool));

            Assert.ThrowsException<ArgumentNullException>(() => evaluator.Multiply(encrypted1, encrypted2, null));
            Assert.ThrowsException<ArgumentNullException>(() => evaluator.Multiply(encrypted1, null, encrypted3));
            Assert.ThrowsException<ArgumentNullException>(() => evaluator.Multiply(null, encrypted2, encrypted3));
            Assert.ThrowsException<ArgumentException>(() => evaluator.Multiply(encrypted1, encrypted2, encrypted3, pool));

            Assert.ThrowsException<ArgumentNullException>(() => evaluator.MultiplyInplace(encrypted1, null));
            Assert.ThrowsException<ArgumentNullException>(() => evaluator.MultiplyInplace(null, encrypted2));
            Assert.ThrowsException<ArgumentException>(() => evaluator.MultiplyInplace(encrypted1, encrypted2, pool));

            Assert.ThrowsException<ArgumentNullException>(() => evaluator.MultiplyMany(encrypteds, relinKeys, null));
            Assert.ThrowsException<ArgumentNullException>(() => evaluator.MultiplyMany(encrypteds, null, encrypted2));
            Assert.ThrowsException<ArgumentNullException>(() => evaluator.MultiplyMany(null, relinKeys, encrypted2));
            Assert.ThrowsException<ArgumentException>(() => evaluator.MultiplyMany(encrypteds, relinKeys, encrypted2, pool));

            Assert.ThrowsException<ArgumentNullException>(() => evaluator.MultiplyPlain(encrypted1, plain1, null));
            Assert.ThrowsException<ArgumentNullException>(() => evaluator.MultiplyPlain(encrypted1, null, encrypted2));
            Assert.ThrowsException<ArgumentNullException>(() => evaluator.MultiplyPlain(null, plain1, encrypted2));
            Assert.ThrowsException<ArgumentException>(() => evaluator.MultiplyPlain(encrypted1, plain1, encrypted2, pool));

            Assert.ThrowsException<ArgumentNullException>(() => evaluator.MultiplyPlainInplace(encrypted1, null));
            Assert.ThrowsException<ArgumentNullException>(() => evaluator.MultiplyPlainInplace(null, plain1));

            Assert.ThrowsException<ArgumentNullException>(() => evaluator.Negate(encrypted1, null));
            Assert.ThrowsException<ArgumentNullException>(() => evaluator.Negate(null, encrypted2));
            Assert.ThrowsException<ArgumentException>(() => evaluator.Negate(encrypted1, encrypted2));

            Assert.ThrowsException<ArgumentNullException>(() => evaluator.NegateInplace(null));

            Assert.ThrowsException<ArgumentNullException>(() => evaluator.Relinearize(encrypted1, relinKeys, null));
            Assert.ThrowsException<ArgumentNullException>(() => evaluator.Relinearize(encrypted1, null, encrypted2));
            Assert.ThrowsException<ArgumentNullException>(() => evaluator.Relinearize(null, relinKeys, encrypted2));
            Assert.ThrowsException<ArgumentException>(() => evaluator.Relinearize(encrypted1, relinKeys, encrypted2, pool));

            Assert.ThrowsException<ArgumentNullException>(() => evaluator.RelinearizeInplace(encrypted1, null));
            Assert.ThrowsException<ArgumentNullException>(() => evaluator.RelinearizeInplace(null, relinKeys));
            Assert.ThrowsException<ArgumentException>(() => evaluator.RelinearizeInplace(encrypted1, relinKeys, pool));

            Assert.ThrowsException<ArgumentNullException>(() => evaluator.RescaleTo(encrypted1, ParmsId.Zero, null));
            Assert.ThrowsException<ArgumentNullException>(() => evaluator.RescaleTo(encrypted1, null, encrypted2));
            Assert.ThrowsException<ArgumentNullException>(() => evaluator.RescaleTo(null, ParmsId.Zero, encrypted2));
            Assert.ThrowsException<ArgumentException>(() => evaluator.RescaleTo(encrypted1, ParmsId.Zero, encrypted2, pool));

            Assert.ThrowsException<ArgumentNullException>(() => evaluator.RescaleToInplace(encrypted1, null));
            Assert.ThrowsException<ArgumentNullException>(() => evaluator.RescaleToInplace(null, ParmsId.Zero));
            Assert.ThrowsException<ArgumentException>(() => evaluator.RescaleToInplace(encrypted1, ParmsId.Zero, pool));

            Assert.ThrowsException<ArgumentNullException>(() => evaluator.RescaleToNext(encrypted1, null));
            Assert.ThrowsException<ArgumentNullException>(() => evaluator.RescaleToNext(null, encrypted2));
            Assert.ThrowsException<ArgumentException>(() => evaluator.RescaleToNext(encrypted1, encrypted2, pool));

            Assert.ThrowsException<ArgumentNullException>(() => evaluator.RescaleToNextInplace(null));
            Assert.ThrowsException<ArgumentException>(() => evaluator.RescaleToNextInplace(encrypted1, pool));

            Assert.ThrowsException<ArgumentNullException>(() => evaluator.RotateColumns(encrypted1, galoisKeys, null));
            Assert.ThrowsException<ArgumentNullException>(() => evaluator.RotateColumns(encrypted1, null, encrypted2));
            Assert.ThrowsException<ArgumentNullException>(() => evaluator.RotateColumns(null, galoisKeys, encrypted2));
            Assert.ThrowsException<ArgumentException>(() => evaluator.RotateColumns(encrypted1, galoisKeys, encrypted2, pool));

            Assert.ThrowsException<ArgumentNullException>(() => evaluator.RotateColumnsInplace(encrypted1, null));
            Assert.ThrowsException<ArgumentNullException>(() => evaluator.RotateColumnsInplace(null, galoisKeys));
            Assert.ThrowsException<ArgumentException>(() => evaluator.RotateColumnsInplace(encrypted1, galoisKeys, pool));

            Assert.ThrowsException<ArgumentNullException>(() => evaluator.RotateRows(encrypted1, 1, galoisKeys, null));
            Assert.ThrowsException<ArgumentNullException>(() => evaluator.RotateRows(encrypted1, 1, null, encrypted2));
            Assert.ThrowsException<ArgumentNullException>(() => evaluator.RotateRows(null, 1, galoisKeys, encrypted2));
            Assert.ThrowsException<ArgumentException>(() => evaluator.RotateRows(encrypted1, 1, galoisKeys, encrypted2, pool));

            Assert.ThrowsException<ArgumentNullException>(() => evaluator.RotateRowsInplace(encrypted1, 1, null));
            Assert.ThrowsException<ArgumentNullException>(() => evaluator.RotateRowsInplace(null, 1, galoisKeys));
            Assert.ThrowsException<ArgumentException>(() => evaluator.RotateRowsInplace(encrypted1, 1, galoisKeys, pool));

            Assert.ThrowsException<ArgumentNullException>(() => evaluator.RotateVector(encrypted1, 1, galoisKeys, null));
            Assert.ThrowsException<ArgumentNullException>(() => evaluator.RotateVector(encrypted1, 1, null, encrypted2));
            Assert.ThrowsException<ArgumentNullException>(() => evaluator.RotateVector(null, 1, galoisKeys, encrypted2));

            Assert.ThrowsException<ArgumentNullException>(() => evaluator.RotateVectorInplace(encrypted1, 1, null));
            Assert.ThrowsException<ArgumentNullException>(() => evaluator.RotateVectorInplace(null, 1, galoisKeys));

            Assert.ThrowsException<ArgumentNullException>(() => evaluator.Square(encrypted1, null));
            Assert.ThrowsException<ArgumentNullException>(() => evaluator.Square(null, encrypted2));
            Assert.ThrowsException<ArgumentException>(() => evaluator.Square(encrypted1, encrypted2, pool));

            Assert.ThrowsException<ArgumentNullException>(() => evaluator.SquareInplace(null));
            Assert.ThrowsException<ArgumentException>(() => evaluator.SquareInplace(encrypted1, pool));

            Assert.ThrowsException<ArgumentNullException>(() => evaluator.Sub(encrypted1, encrypted2, null));
            Assert.ThrowsException<ArgumentNullException>(() => evaluator.Sub(encrypted1, null, encrypted3));
            Assert.ThrowsException<ArgumentNullException>(() => evaluator.Sub(null, encrypted2, encrypted3));
            Assert.ThrowsException<ArgumentException>(() => evaluator.Sub(encrypted1, encrypted2, encrypted3));

            Assert.ThrowsException<ArgumentNullException>(() => evaluator.SubInplace(encrypted1, null));
            Assert.ThrowsException<ArgumentNullException>(() => evaluator.SubInplace(null, encrypted2));

            Assert.ThrowsException<ArgumentNullException>(() => evaluator.SubPlain(encrypted1, plain1, null));
            Assert.ThrowsException<ArgumentNullException>(() => evaluator.SubPlain(encrypted1, null, encrypted2));
            Assert.ThrowsException<ArgumentNullException>(() => evaluator.SubPlain(null, plain1, encrypted2));
            Assert.ThrowsException<ArgumentException>(() => evaluator.SubPlain(encrypted1, plain1, encrypted2));

            Assert.ThrowsException<ArgumentNullException>(() => evaluator.SubPlainInplace(encrypted1, null));
            Assert.ThrowsException<ArgumentNullException>(() => evaluator.SubPlainInplace(null, plain1));
            Assert.ThrowsException<ArgumentException>(() => evaluator.SubPlainInplace(encrypted1, plain1));

            Assert.ThrowsException<ArgumentNullException>(() => evaluator.TransformFromNTT(encrypted1, null));
            Assert.ThrowsException<ArgumentNullException>(() => evaluator.TransformFromNTT(null, encrypted2));
            Assert.ThrowsException<ArgumentException>(() => evaluator.TransformFromNTT(encrypted1, encrypted2));

            Assert.ThrowsException<ArgumentNullException>(() => evaluator.TransformFromNTTInplace(null));

            Assert.ThrowsException<ArgumentNullException>(() => evaluator.TransformToNTT(encrypted1, null));
            Assert.ThrowsException<ArgumentNullException>(() => evaluator.TransformToNTT(null, encrypted2));

            Assert.ThrowsException<ArgumentNullException>(() => evaluator.TransformToNTTInplace(null));

            Assert.ThrowsException<ArgumentNullException>(() => evaluator.TransformToNTT(plain1, ParmsId.Zero, null));
            Assert.ThrowsException<ArgumentNullException>(() => evaluator.TransformToNTT(plain1, null, plain2));
            Assert.ThrowsException<ArgumentNullException>(() => evaluator.TransformToNTT(null, ParmsId.Zero, plain2));
            Assert.ThrowsException<ArgumentException>(() => evaluator.TransformToNTT(plain1, ParmsId.Zero, plain2, pool));

            Assert.ThrowsException<ArgumentNullException>(() => evaluator.TransformToNTTInplace(plain1, null));
            Assert.ThrowsException<ArgumentNullException>(() => evaluator.TransformToNTTInplace(null, ParmsId.Zero));
            Assert.ThrowsException<ArgumentException>(() => evaluator.TransformToNTTInplace(plain1, ParmsId.Zero, pool));
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
