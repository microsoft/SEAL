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
            Evaluator evaluator = new Evaluator(GlobalContext.BFVContext);
            Assert.IsNotNull(evaluator);
        }

        [TestMethod]
        public void NegateTest()
        {
            EncryptionParameters parms = new EncryptionParameters(SchemeType.BFV)
            {
                PolyModulusDegree = 64,
                PlainModulus = new Modulus(1 << 6),
                CoeffModulus = CoeffModulus.Create(64, new int[] { 40 })
            };
            SEALContext context = new SEALContext(parms,
                expandModChain: false,
                secLevel: SecLevelType.None);
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
            EncryptionParameters parms = new EncryptionParameters(SchemeType.BFV)
            {
                PolyModulusDegree = 64,
                PlainModulus = new Modulus(1 << 6),
                CoeffModulus = CoeffModulus.Create(64, new int[] { 40 })
            };
            SEALContext context = new SEALContext(parms,
                expandModChain: false,
                secLevel: SecLevelType.None);
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
            EncryptionParameters parms = new EncryptionParameters(SchemeType.BFV)
            {
                PolyModulusDegree = 64,
                PlainModulus = new Modulus(1 << 6),
                CoeffModulus = CoeffModulus.Create(64, new int[] { 40 })
            };
            SEALContext context = new SEALContext(parms,
                expandModChain: false,
                secLevel: SecLevelType.None);
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
            EncryptionParameters parms = new EncryptionParameters(SchemeType.BFV)
            {
                PolyModulusDegree = 64,
                PlainModulus = new Modulus(1 << 6),
                CoeffModulus = CoeffModulus.Create(64, new int[] { 40 })
            };
            SEALContext context = new SEALContext(parms,
                expandModChain: false,
                secLevel: SecLevelType.None);
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
            EncryptionParameters parms = new EncryptionParameters(SchemeType.BFV)
            {
                PolyModulusDegree = 64,
                PlainModulus = new Modulus(1 << 6),
                CoeffModulus = CoeffModulus.Create(64, new int[] { 40 })
            };
            SEALContext context = new SEALContext(parms,
                expandModChain: false,
                secLevel: SecLevelType.None);
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
            EncryptionParameters parms = new EncryptionParameters(SchemeType.BFV)
            {
                PolyModulusDegree = 64,
                PlainModulus = new Modulus(1 << 6),
                CoeffModulus = CoeffModulus.Create(64, new int[] { 40 })
            };
            SEALContext context = new SEALContext(parms,
                expandModChain: false,
                secLevel: SecLevelType.None);
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
            EncryptionParameters parms = new EncryptionParameters(SchemeType.BFV)
            {
                PolyModulusDegree = 64,
                PlainModulus = new Modulus(1 << 6),
                CoeffModulus = CoeffModulus.Create(64, new int[] { 40 })
            };
            SEALContext context = new SEALContext(parms,
                expandModChain: false,
                secLevel: SecLevelType.None);
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

            Encryptor encryptor = new Encryptor(context, keygen.PublicKey);
            Decryptor decryptor = new Decryptor(context, keygen.SecretKey);
            Evaluator evaluator = new Evaluator(context);
            RelinKeys relinKeys = keygen.RelinKeysLocal();

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

            Utilities.AssertThrows<ArgumentException>(() =>
            {
                // Uninitialized memory pool handle
                MemoryPoolHandle pool = new MemoryPoolHandle();
                evaluator.MultiplyMany(encrypteds, relinKeys, encdest, pool);
            });
        }

        [TestMethod]
        public void MultiplyPlainTest()
        {
            EncryptionParameters parms = new EncryptionParameters(SchemeType.BFV)
            {
                PolyModulusDegree = 128,
                PlainModulus = new Modulus(1 << 6),
                CoeffModulus = CoeffModulus.Create(128, new int[] { 40, 40 })
            };
            SEALContext context = new SEALContext(parms,
                expandModChain: false,
                secLevel: SecLevelType.None);
            KeyGenerator keygen = new KeyGenerator(context);

            Encryptor encryptor = new Encryptor(context, keygen.PublicKey);
            Decryptor decryptor = new Decryptor(context, keygen.SecretKey);
            Evaluator evaluator = new Evaluator(context);
            RelinKeys relinKeys = keygen.RelinKeysLocal();

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

            encryptor.Encrypt(new Plaintext("4x^1 + 3"), encrypted);
            plain.Set("3x^5");
            evaluator.MultiplyPlainInplace(encrypted, plain);
            decryptor.Decrypt(encrypted, plaindest);

            // {Cx^6 + 9x^5}
            Assert.AreEqual(7ul, plaindest.CoeffCount);
            Assert.AreEqual(2ul, plaindest.NonZeroCoeffCount);
            Assert.AreEqual(0ul, plaindest[0]);
            Assert.AreEqual(0ul, plaindest[1]);
            Assert.AreEqual(0ul, plaindest[2]);
            Assert.AreEqual(0ul, plaindest[3]);
            Assert.AreEqual(0ul, plaindest[4]);
            Assert.AreEqual(9ul, plaindest[5]);
            Assert.AreEqual(12ul, plaindest[6]);

            Utilities.AssertThrows<ArgumentException>(() =>
            {
                // Uninitialized pool
                MemoryPoolHandle pool = new MemoryPoolHandle();
                evaluator.MultiplyPlain(encrypted, plain, encdest, pool);
            });
        }

        [TestMethod]
        public void SquareTest()
        {
            EncryptionParameters parms = new EncryptionParameters(SchemeType.BFV)
            {
                PolyModulusDegree = 128,
                PlainModulus = new Modulus(1 << 6),
                CoeffModulus = CoeffModulus.Create(128, new int[] { 40, 40 })
            };
            SEALContext context = new SEALContext(parms,
                expandModChain: false,
                secLevel: SecLevelType.None);
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

            Encryptor encryptor = new Encryptor(context, keygen.PublicKey);
            Decryptor decryptor = new Decryptor(context, keygen.SecretKey);
            Evaluator evaluator = new Evaluator(context);
            RelinKeys relinKeys = keygen.RelinKeysLocal();

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
            GaloisKeys galoisKeys = keygen.GaloisKeysLocal(galoisElts: new uint[] { 1u, 3u, 5u, 15u });

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
            EncryptionParameters parms = new EncryptionParameters(SchemeType.BFV)
            {
                PolyModulusDegree = 128,
                PlainModulus = new Modulus(1 << 6),
                CoeffModulus = CoeffModulus.Create(128, new int[] { 40, 40, 40 })
            };
            SEALContext context = new SEALContext(parms,
                expandModChain: false,
                secLevel: SecLevelType.None);
            Evaluator evaluator = new Evaluator(context);

            Plaintext plain = new Plaintext("0");
            Plaintext plaindest = new Plaintext();
            Assert.IsFalse(plain.IsNTTForm);

            evaluator.TransformToNTT(plain, context.FirstParmsId, plaindest);
            Assert.IsTrue(plaindest.IsZero);
            Assert.IsTrue(plaindest.IsNTTForm);
            Assert.IsTrue(plaindest.ParmsId == context.FirstParmsId);

            plain = new Plaintext("1");
            Assert.IsFalse(plain.IsNTTForm);

            evaluator.TransformToNTTInplace(plain, context.FirstParmsId);
            Assert.IsTrue(plain.IsNTTForm);

            for (ulong i = 0; i < 256; i++)
            {
                Assert.AreEqual(1ul, plain[i]);
            }
        }

        [TestMethod]
        public void TransformEncryptedToNTTTest()
        {
            EncryptionParameters parms = new EncryptionParameters(SchemeType.BFV)
            {
                PolyModulusDegree = 128,
                PlainModulus = new Modulus(1 << 6),
                CoeffModulus = CoeffModulus.Create(128, new int[] { 40, 40 })
            };
            SEALContext context = new SEALContext(parms,
                expandModChain: false,
                secLevel: SecLevelType.None);
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
            Assert.AreEqual(context.FirstParmsId, encdest2.ParmsId);

            encryptor.Encrypt(new Plaintext("1"), encrypted);
            Assert.IsFalse(encrypted.IsNTTForm);

            evaluator.TransformToNTTInplace(encrypted);
            Assert.IsTrue(encrypted.IsNTTForm);

            evaluator.TransformFromNTTInplace(encrypted);
            Assert.IsFalse(encrypted.IsNTTForm);

            decryptor.Decrypt(encrypted, plaindest);

            Assert.AreEqual(1ul, plaindest.CoeffCount);
            Assert.AreEqual(1ul, plaindest[0]);
            Assert.AreEqual(context.FirstParmsId, encrypted.ParmsId);
        }

        [TestMethod]
        public void ModSwitchToNextTest()
        {
            EncryptionParameters parms = new EncryptionParameters(SchemeType.BFV)
            {
                PolyModulusDegree = 128,
                PlainModulus = new Modulus(1 << 6),
                CoeffModulus = CoeffModulus.Create(128, new int[] { 30, 30, 30 })
            };
            SEALContext context = new SEALContext(parms,
                expandModChain: true,
                secLevel: SecLevelType.None);
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
            EncryptionParameters parms = new EncryptionParameters(SchemeType.BFV)
            {
                PolyModulusDegree = 128,
                PlainModulus = new Modulus(1 << 6),
                CoeffModulus = CoeffModulus.Create(128, new int[] { 30, 30, 30, 30 })
            };
            SEALContext context = new SEALContext(parms,
                expandModChain: true,
                secLevel: SecLevelType.None);
            KeyGenerator keygen = new KeyGenerator(context);

            Encryptor encryptor = new Encryptor(context, keygen.PublicKey);
            Decryptor decryptor = new Decryptor(context, keygen.SecretKey);
            Evaluator evaluator = new Evaluator(context);

            Ciphertext encrypted = new Ciphertext(context);
            Ciphertext encdest = new Ciphertext(context);
            Plaintext plaindest = new Plaintext();

            encryptor.Encrypt(new Plaintext("1"), encrypted);
            ParmsId destParmsId = context.FirstContextData.NextContextData
                .NextContextData.ParmsId;

            evaluator.ModSwitchTo(encrypted, context.FirstParmsId, encdest);
            decryptor.Decrypt(encdest, plaindest);

            Assert.IsTrue(encrypted.ParmsId == context.FirstParmsId);
            Assert.IsTrue(encdest.ParmsId == context.FirstParmsId);
            Assert.AreEqual(1ul, plaindest.CoeffCount);
            Assert.AreEqual(1ul, plaindest[0]);

            evaluator.ModSwitchTo(encrypted, destParmsId, encdest);
            decryptor.Decrypt(encdest, plaindest);

            Assert.IsTrue(encrypted.ParmsId == context.FirstParmsId);
            Assert.IsTrue(encdest.ParmsId == destParmsId);
            Assert.AreEqual(1ul, plaindest.CoeffCount);
            Assert.AreEqual(1ul, plaindest[0]);

            encryptor.Encrypt(new Plaintext("3x^2 + 2x^1 + 1"), encrypted);
            evaluator.ModSwitchToInplace(encrypted, context.FirstParmsId);
            decryptor.Decrypt(encrypted, plaindest);

            Assert.IsTrue(encrypted.ParmsId == context.FirstParmsId);
            Assert.AreEqual(3ul, plaindest.CoeffCount);
            Assert.AreEqual(1ul, plaindest[0]);
            Assert.AreEqual(2ul, plaindest[1]);
            Assert.AreEqual(3ul, plaindest[2]);

            evaluator.ModSwitchToInplace(encrypted, destParmsId);
            decryptor.Decrypt(encrypted, plaindest);

            Assert.IsTrue(encrypted.ParmsId == destParmsId);
            Assert.AreEqual(3ul, plaindest.CoeffCount);
            Assert.AreEqual(1ul, plaindest[0]);
            Assert.AreEqual(2ul, plaindest[1]);
            Assert.AreEqual(3ul, plaindest[2]);
        }

        [TestMethod]
        public void ModSwitchToPlainTest()
        {
            EncryptionParameters parms = new EncryptionParameters(SchemeType.CKKS)
            {
                PolyModulusDegree = 1024,
                CoeffModulus = CoeffModulus.Create(1024, new int[] { 40, 40, 40, 40, 40 })
            };

            SEALContext context = new SEALContext(parms,
                expandModChain: true,
                secLevel: SecLevelType.None);
            CKKSEncoder encoder = new CKKSEncoder(context);
            KeyGenerator keygen = new KeyGenerator(context);
            SecretKey secretKey = keygen.SecretKey;
            PublicKey publicKey = keygen.PublicKey;
            RelinKeys relinKeys = keygen.RelinKeysLocal();

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
            GaloisKeys galoisKeys = keygen.GaloisKeysLocal();

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
            RelinKeys relinKeys = keygen.RelinKeysLocal();

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
        public void RotateVectorTest()
        {
            int slotSize = 4;
            EncryptionParameters parms = new EncryptionParameters(SchemeType.CKKS)
            {
                PolyModulusDegree = 2 * (ulong)slotSize,
                CoeffModulus = CoeffModulus.Create(2 * (ulong)slotSize, new int[] { 40, 40, 40, 40 })
            };
            SEALContext context = new SEALContext(parms,
                expandModChain: false,
                secLevel: SecLevelType.None);
            KeyGenerator keygen = new KeyGenerator(context);
            GaloisKeys galoisKeys = keygen.GaloisKeysLocal();

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

            encoder.Encode(input, context.FirstParmsId, delta, plain);

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

            encoder.Encode(input, context.FirstParmsId, delta, plain);
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
            EncryptionParameters parms = new EncryptionParameters(SchemeType.CKKS)
            {
                PolyModulusDegree = 2 * (ulong)slotSize,
                CoeffModulus = CoeffModulus.Create(2 * (ulong)slotSize, new int[] { 40, 40, 40, 40 })
            };
            SEALContext context = new SEALContext(parms,
                expandModChain: false,
                secLevel: SecLevelType.None);
            KeyGenerator keygen = new KeyGenerator(context);
            GaloisKeys galoisKeys = keygen.GaloisKeysLocal();

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

            encoder.Encode(input, context.FirstParmsId, delta, plain);
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
                PlainModulus = new Modulus(65537ul),
                CoeffModulus = CoeffModulus.Create(64, new int[] { 40, 40 })
            };
            SEALContext context = new SEALContext(parms,
                expandModChain: false,
                secLevel: SecLevelType.None);

            Evaluator evaluator = null;
            Utilities.AssertThrows<ArgumentNullException>(() => evaluator = new Evaluator(null));
            evaluator = new Evaluator(context);

            KeyGenerator keygen = new KeyGenerator(context);
            GaloisKeys galoisKeys = keygen.GaloisKeysLocal();
            RelinKeys relinKeys = keygen.RelinKeysLocal();

            Ciphertext encrypted1 = new Ciphertext();
            Ciphertext encrypted2 = new Ciphertext();
            Ciphertext encrypted3 = new Ciphertext();
            Plaintext plain1 = new Plaintext();
            Plaintext plain2 = new Plaintext();
            List<Ciphertext> encrypteds = new List<Ciphertext>();

            MemoryPoolHandle pool = MemoryManager.GetPool(MMProfOpt.ForceGlobal);

            Utilities.AssertThrows<ArgumentNullException>(() => evaluator.Add(null, encrypted2, encrypted3));
            Utilities.AssertThrows<ArgumentNullException>(() => evaluator.Add(encrypted1, null, encrypted3));
            Utilities.AssertThrows<ArgumentNullException>(() => evaluator.Add(encrypted1, encrypted2, null));
            Utilities.AssertThrows<ArgumentException>(() => evaluator.Add(encrypted1, encrypted2, encrypted3));

            Utilities.AssertThrows<ArgumentNullException>(() => evaluator.AddInplace(encrypted1, null));
            Utilities.AssertThrows<ArgumentNullException>(() => evaluator.AddInplace(null, encrypted2));

            Utilities.AssertThrows<ArgumentNullException>(() => evaluator.AddMany(encrypteds, null));
            Utilities.AssertThrows<ArgumentNullException>(() => evaluator.AddMany(null, encrypted2));

            Utilities.AssertThrows<ArgumentNullException>(() => evaluator.AddPlain(encrypted1, plain1, null));
            Utilities.AssertThrows<ArgumentNullException>(() => evaluator.AddPlain(encrypted1, null, encrypted2));
            Utilities.AssertThrows<ArgumentNullException>(() => evaluator.AddPlain(null, plain1, encrypted2));
            Utilities.AssertThrows<ArgumentException>(() => evaluator.AddPlain(encrypted1, plain1, encrypted2));

            Utilities.AssertThrows<ArgumentNullException>(() => evaluator.AddPlainInplace(encrypted1, null));
            Utilities.AssertThrows<ArgumentNullException>(() => evaluator.AddPlainInplace(null, plain1));

            Utilities.AssertThrows<ArgumentNullException>(() => evaluator.ApplyGalois(encrypted1, 1, galoisKeys, null));
            Utilities.AssertThrows<ArgumentNullException>(() => evaluator.ApplyGalois(encrypted1, 1, null, encrypted2));
            Utilities.AssertThrows<ArgumentNullException>(() => evaluator.ApplyGalois(null, 1, galoisKeys, encrypted2));
            Utilities.AssertThrows<ArgumentException>(() => evaluator.ApplyGalois(encrypted1, 1, galoisKeys, encrypted2, pool));

            Utilities.AssertThrows<ArgumentNullException>(() => evaluator.ApplyGaloisInplace(encrypted1, 1, null));
            Utilities.AssertThrows<ArgumentNullException>(() => evaluator.ApplyGaloisInplace(null, 1, galoisKeys));

            Utilities.AssertThrows<ArgumentNullException>(() => evaluator.ComplexConjugate(encrypted1, galoisKeys, null));
            Utilities.AssertThrows<ArgumentNullException>(() => evaluator.ComplexConjugate(encrypted1, null, encrypted2));
            Utilities.AssertThrows<ArgumentNullException>(() => evaluator.ComplexConjugate(null, galoisKeys, encrypted2));

            Utilities.AssertThrows<ArgumentNullException>(() => evaluator.ComplexConjugateInplace(encrypted1, null));
            Utilities.AssertThrows<ArgumentNullException>(() => evaluator.ComplexConjugateInplace(null, galoisKeys));

            Utilities.AssertThrows<ArgumentNullException>(() => evaluator.Exponentiate(encrypted1, 2, relinKeys, null));
            Utilities.AssertThrows<ArgumentNullException>(() => evaluator.Exponentiate(encrypted1, 2, null, encrypted2));
            Utilities.AssertThrows<ArgumentNullException>(() => evaluator.Exponentiate(null, 2, relinKeys, encrypted2));

            Utilities.AssertThrows<ArgumentNullException>(() => evaluator.ExponentiateInplace(encrypted1, 2, null));
            Utilities.AssertThrows<ArgumentNullException>(() => evaluator.ExponentiateInplace(null, 2, relinKeys));

            Utilities.AssertThrows<ArgumentNullException>(() => evaluator.ModSwitchTo(plain1, ParmsId.Zero, null));
            Utilities.AssertThrows<ArgumentNullException>(() => evaluator.ModSwitchTo(plain1, null, plain2));
            Utilities.AssertThrows<ArgumentNullException>(() => evaluator.ModSwitchTo(null, ParmsId.Zero, plain2));

            Utilities.AssertThrows<ArgumentNullException>(() => evaluator.ModSwitchTo(encrypted1, ParmsId.Zero, null));
            Utilities.AssertThrows<ArgumentNullException>(() => evaluator.ModSwitchTo(encrypted1, null, encrypted2));
            Utilities.AssertThrows<ArgumentNullException>(() => evaluator.ModSwitchTo(null, ParmsId.Zero, encrypted2));
            Utilities.AssertThrows<ArgumentException>(() => evaluator.ModSwitchTo(encrypted1, ParmsId.Zero, encrypted2, pool));

            Utilities.AssertThrows<ArgumentNullException>(() => evaluator.ModSwitchToInplace(encrypted1, null));
            Utilities.AssertThrows<ArgumentNullException>(() => evaluator.ModSwitchToInplace(encrypted: null, parmsId: ParmsId.Zero));
            Utilities.AssertThrows<ArgumentException>(() => evaluator.ModSwitchToInplace(encrypted1, ParmsId.Zero, pool));

            Utilities.AssertThrows<ArgumentNullException>(() => evaluator.ModSwitchToInplace(plain1, null));
            Utilities.AssertThrows<ArgumentNullException>(() => evaluator.ModSwitchToInplace(plain: null, parmsId: ParmsId.Zero));

            Utilities.AssertThrows<ArgumentNullException>(() => evaluator.ModSwitchToNext(plain1, null));
            Utilities.AssertThrows<ArgumentNullException>(() => evaluator.ModSwitchToNext(null, plain2));

            Utilities.AssertThrows<ArgumentNullException>(() => evaluator.ModSwitchToNextInplace(null));

            Utilities.AssertThrows<ArgumentNullException>(() => evaluator.ModSwitchToNext(encrypted1, null));
            Utilities.AssertThrows<ArgumentNullException>(() => evaluator.ModSwitchToNext(null, encrypted2));
            Utilities.AssertThrows<ArgumentException>(() => evaluator.ModSwitchToNext(encrypted1, encrypted2, pool));

            Utilities.AssertThrows<ArgumentNullException>(() => evaluator.ModSwitchToNextInplace(encrypted: null));
            Utilities.AssertThrows<ArgumentException>(() => evaluator.ModSwitchToNextInplace(encrypted1, pool));

            Utilities.AssertThrows<ArgumentNullException>(() => evaluator.Multiply(encrypted1, encrypted2, null));
            Utilities.AssertThrows<ArgumentNullException>(() => evaluator.Multiply(encrypted1, null, encrypted3));
            Utilities.AssertThrows<ArgumentNullException>(() => evaluator.Multiply(null, encrypted2, encrypted3));
            Utilities.AssertThrows<ArgumentException>(() => evaluator.Multiply(encrypted1, encrypted2, encrypted3, pool));

            Utilities.AssertThrows<ArgumentNullException>(() => evaluator.MultiplyInplace(encrypted1, null));
            Utilities.AssertThrows<ArgumentNullException>(() => evaluator.MultiplyInplace(null, encrypted2));
            Utilities.AssertThrows<ArgumentException>(() => evaluator.MultiplyInplace(encrypted1, encrypted2, pool));

            Utilities.AssertThrows<ArgumentNullException>(() => evaluator.MultiplyMany(encrypteds, relinKeys, null));
            Utilities.AssertThrows<ArgumentNullException>(() => evaluator.MultiplyMany(encrypteds, null, encrypted2));
            Utilities.AssertThrows<ArgumentNullException>(() => evaluator.MultiplyMany(null, relinKeys, encrypted2));
            Utilities.AssertThrows<ArgumentException>(() => evaluator.MultiplyMany(encrypteds, relinKeys, encrypted2, pool));

            Utilities.AssertThrows<ArgumentNullException>(() => evaluator.MultiplyPlain(encrypted1, plain1, null));
            Utilities.AssertThrows<ArgumentNullException>(() => evaluator.MultiplyPlain(encrypted1, null, encrypted2));
            Utilities.AssertThrows<ArgumentNullException>(() => evaluator.MultiplyPlain(null, plain1, encrypted2));
            Utilities.AssertThrows<ArgumentException>(() => evaluator.MultiplyPlain(encrypted1, plain1, encrypted2, pool));

            Utilities.AssertThrows<ArgumentNullException>(() => evaluator.MultiplyPlainInplace(encrypted1, null));
            Utilities.AssertThrows<ArgumentNullException>(() => evaluator.MultiplyPlainInplace(null, plain1));

            Utilities.AssertThrows<ArgumentNullException>(() => evaluator.Negate(encrypted1, null));
            Utilities.AssertThrows<ArgumentNullException>(() => evaluator.Negate(null, encrypted2));
            Utilities.AssertThrows<ArgumentException>(() => evaluator.Negate(encrypted1, encrypted2));

            Utilities.AssertThrows<ArgumentNullException>(() => evaluator.NegateInplace(null));

            Utilities.AssertThrows<ArgumentNullException>(() => evaluator.Relinearize(encrypted1, relinKeys, null));
            Utilities.AssertThrows<ArgumentNullException>(() => evaluator.Relinearize(encrypted1, null, encrypted2));
            Utilities.AssertThrows<ArgumentNullException>(() => evaluator.Relinearize(null, relinKeys, encrypted2));
            Utilities.AssertThrows<ArgumentException>(() => evaluator.Relinearize(encrypted1, relinKeys, encrypted2, pool));

            Utilities.AssertThrows<ArgumentNullException>(() => evaluator.RelinearizeInplace(encrypted1, null));
            Utilities.AssertThrows<ArgumentNullException>(() => evaluator.RelinearizeInplace(null, relinKeys));
            Utilities.AssertThrows<ArgumentException>(() => evaluator.RelinearizeInplace(encrypted1, relinKeys, pool));

            Utilities.AssertThrows<ArgumentNullException>(() => evaluator.RescaleTo(encrypted1, ParmsId.Zero, null));
            Utilities.AssertThrows<ArgumentNullException>(() => evaluator.RescaleTo(encrypted1, null, encrypted2));
            Utilities.AssertThrows<ArgumentNullException>(() => evaluator.RescaleTo(null, ParmsId.Zero, encrypted2));
            Utilities.AssertThrows<ArgumentException>(() => evaluator.RescaleTo(encrypted1, ParmsId.Zero, encrypted2, pool));

            Utilities.AssertThrows<ArgumentNullException>(() => evaluator.RescaleToInplace(encrypted1, null));
            Utilities.AssertThrows<ArgumentNullException>(() => evaluator.RescaleToInplace(null, ParmsId.Zero));
            Utilities.AssertThrows<ArgumentException>(() => evaluator.RescaleToInplace(encrypted1, ParmsId.Zero, pool));

            Utilities.AssertThrows<ArgumentNullException>(() => evaluator.RescaleToNext(encrypted1, null));
            Utilities.AssertThrows<ArgumentNullException>(() => evaluator.RescaleToNext(null, encrypted2));
            Utilities.AssertThrows<ArgumentException>(() => evaluator.RescaleToNext(encrypted1, encrypted2, pool));

            Utilities.AssertThrows<ArgumentNullException>(() => evaluator.RescaleToNextInplace(null));
            Utilities.AssertThrows<ArgumentException>(() => evaluator.RescaleToNextInplace(encrypted1, pool));

            Utilities.AssertThrows<ArgumentNullException>(() => evaluator.RotateColumns(encrypted1, galoisKeys, null));
            Utilities.AssertThrows<ArgumentNullException>(() => evaluator.RotateColumns(encrypted1, null, encrypted2));
            Utilities.AssertThrows<ArgumentNullException>(() => evaluator.RotateColumns(null, galoisKeys, encrypted2));
            Utilities.AssertThrows<ArgumentException>(() => evaluator.RotateColumns(encrypted1, galoisKeys, encrypted2, pool));

            Utilities.AssertThrows<ArgumentNullException>(() => evaluator.RotateColumnsInplace(encrypted1, null));
            Utilities.AssertThrows<ArgumentNullException>(() => evaluator.RotateColumnsInplace(null, galoisKeys));
            Utilities.AssertThrows<ArgumentException>(() => evaluator.RotateColumnsInplace(encrypted1, galoisKeys, pool));

            Utilities.AssertThrows<ArgumentNullException>(() => evaluator.RotateRows(encrypted1, 1, galoisKeys, null));
            Utilities.AssertThrows<ArgumentNullException>(() => evaluator.RotateRows(encrypted1, 1, null, encrypted2));
            Utilities.AssertThrows<ArgumentNullException>(() => evaluator.RotateRows(null, 1, galoisKeys, encrypted2));
            Utilities.AssertThrows<ArgumentException>(() => evaluator.RotateRows(encrypted1, 1, galoisKeys, encrypted2, pool));

            Utilities.AssertThrows<ArgumentNullException>(() => evaluator.RotateRowsInplace(encrypted1, 1, null));
            Utilities.AssertThrows<ArgumentNullException>(() => evaluator.RotateRowsInplace(null, 1, galoisKeys));
            Utilities.AssertThrows<ArgumentException>(() => evaluator.RotateRowsInplace(encrypted1, 1, galoisKeys, pool));

            Utilities.AssertThrows<ArgumentNullException>(() => evaluator.RotateVector(encrypted1, 1, galoisKeys, null));
            Utilities.AssertThrows<ArgumentNullException>(() => evaluator.RotateVector(encrypted1, 1, null, encrypted2));
            Utilities.AssertThrows<ArgumentNullException>(() => evaluator.RotateVector(null, 1, galoisKeys, encrypted2));

            Utilities.AssertThrows<ArgumentNullException>(() => evaluator.RotateVectorInplace(encrypted1, 1, null));
            Utilities.AssertThrows<ArgumentNullException>(() => evaluator.RotateVectorInplace(null, 1, galoisKeys));

            Utilities.AssertThrows<ArgumentNullException>(() => evaluator.Square(encrypted1, null));
            Utilities.AssertThrows<ArgumentNullException>(() => evaluator.Square(null, encrypted2));
            Utilities.AssertThrows<ArgumentException>(() => evaluator.Square(encrypted1, encrypted2, pool));

            Utilities.AssertThrows<ArgumentNullException>(() => evaluator.SquareInplace(null));
            Utilities.AssertThrows<ArgumentException>(() => evaluator.SquareInplace(encrypted1, pool));

            Utilities.AssertThrows<ArgumentNullException>(() => evaluator.Sub(encrypted1, encrypted2, null));
            Utilities.AssertThrows<ArgumentNullException>(() => evaluator.Sub(encrypted1, null, encrypted3));
            Utilities.AssertThrows<ArgumentNullException>(() => evaluator.Sub(null, encrypted2, encrypted3));
            Utilities.AssertThrows<ArgumentException>(() => evaluator.Sub(encrypted1, encrypted2, encrypted3));

            Utilities.AssertThrows<ArgumentNullException>(() => evaluator.SubInplace(encrypted1, null));
            Utilities.AssertThrows<ArgumentNullException>(() => evaluator.SubInplace(null, encrypted2));

            Utilities.AssertThrows<ArgumentNullException>(() => evaluator.SubPlain(encrypted1, plain1, null));
            Utilities.AssertThrows<ArgumentNullException>(() => evaluator.SubPlain(encrypted1, null, encrypted2));
            Utilities.AssertThrows<ArgumentNullException>(() => evaluator.SubPlain(null, plain1, encrypted2));
            Utilities.AssertThrows<ArgumentException>(() => evaluator.SubPlain(encrypted1, plain1, encrypted2));

            Utilities.AssertThrows<ArgumentNullException>(() => evaluator.SubPlainInplace(encrypted1, null));
            Utilities.AssertThrows<ArgumentNullException>(() => evaluator.SubPlainInplace(null, plain1));
            Utilities.AssertThrows<ArgumentException>(() => evaluator.SubPlainInplace(encrypted1, plain1));

            Utilities.AssertThrows<ArgumentNullException>(() => evaluator.TransformFromNTT(encrypted1, null));
            Utilities.AssertThrows<ArgumentNullException>(() => evaluator.TransformFromNTT(null, encrypted2));
            Utilities.AssertThrows<ArgumentException>(() => evaluator.TransformFromNTT(encrypted1, encrypted2));

            Utilities.AssertThrows<ArgumentNullException>(() => evaluator.TransformFromNTTInplace(null));

            Utilities.AssertThrows<ArgumentNullException>(() => evaluator.TransformToNTT(encrypted1, null));
            Utilities.AssertThrows<ArgumentNullException>(() => evaluator.TransformToNTT(null, encrypted2));

            Utilities.AssertThrows<ArgumentNullException>(() => evaluator.TransformToNTTInplace(null));

            Utilities.AssertThrows<ArgumentNullException>(() => evaluator.TransformToNTT(plain1, ParmsId.Zero, null));
            Utilities.AssertThrows<ArgumentNullException>(() => evaluator.TransformToNTT(plain1, null, plain2));
            Utilities.AssertThrows<ArgumentNullException>(() => evaluator.TransformToNTT(null, ParmsId.Zero, plain2));
            Utilities.AssertThrows<ArgumentException>(() => evaluator.TransformToNTT(plain1, ParmsId.Zero, plain2, pool));

            Utilities.AssertThrows<ArgumentNullException>(() => evaluator.TransformToNTTInplace(plain1, null));
            Utilities.AssertThrows<ArgumentNullException>(() => evaluator.TransformToNTTInplace(null, ParmsId.Zero));
            Utilities.AssertThrows<ArgumentException>(() => evaluator.TransformToNTTInplace(plain1, ParmsId.Zero, pool));
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
