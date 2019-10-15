// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

using Microsoft.Research.SEAL;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;

namespace SEALNetTest
{
    [TestClass]
    public class DecryptorTests
    {
        SEALContext context_;
        KeyGenerator keyGen_;
        SecretKey secretKey_;
        PublicKey publicKey_;

        [TestInitialize]
        public void TestInit()
        {
            context_ = GlobalContext.BFVContext;
            keyGen_ = new KeyGenerator(context_);
            secretKey_ = keyGen_.SecretKey;
            publicKey_ = keyGen_.PublicKey;
        }

        [TestMethod]
        public void CreateTest()
        {
            Decryptor decryptor = new Decryptor(context_, secretKey_);

            Assert.IsNotNull(decryptor);
        }

        [TestMethod]
        public void DecryptTest()
        {
            Encryptor encryptor = new Encryptor(context_, publicKey_);
            Decryptor decryptor = new Decryptor(context_, secretKey_);

            Plaintext plain = new Plaintext("1x^1 + 2");
            Ciphertext cipher = new Ciphertext();

            Assert.AreEqual(0ul, cipher.Size);

            encryptor.Encrypt(plain, cipher);

            Assert.AreEqual(2ul, cipher.Size);

            Plaintext decrypted = new Plaintext();
            Assert.AreEqual(0ul, decrypted.CoeffCount);

            decryptor.Decrypt(cipher, decrypted);

            Assert.AreEqual(2ul, decrypted.CoeffCount);
            Assert.AreEqual(2ul, decrypted[0]);
            Assert.AreEqual(1ul, decrypted[1]);
        }

        [TestMethod]
        public void InvariantNoiseBudgetTest()
        {
            Encryptor encryptor = new Encryptor(context_, publicKey_);
            Decryptor decryptor = new Decryptor(context_, secretKey_);

            Plaintext plain = new Plaintext("1");
            Ciphertext cipher = new Ciphertext();

            encryptor.Encrypt(plain, cipher);

            int budget = decryptor.InvariantNoiseBudget(cipher);
            Assert.IsTrue(budget > 80);
        }

        [TestMethod]
        public void ExceptionsTest()
        {
            Decryptor decryptor = new Decryptor(context_, secretKey_);
            SecretKey secret = new SecretKey();
            Ciphertext cipher = new Ciphertext();
            Plaintext plain = new Plaintext();

            Utilities.AssertThrows<ArgumentNullException>(() => decryptor = new Decryptor(context_, null));
            Utilities.AssertThrows<ArgumentNullException>(() => decryptor = new Decryptor(null, secretKey_));
            Utilities.AssertThrows<ArgumentException>(() => decryptor = new Decryptor(context_, secret));

            Utilities.AssertThrows<ArgumentNullException>(() => decryptor.Decrypt(cipher, null));
            Utilities.AssertThrows<ArgumentNullException>(() => decryptor.Decrypt(null, plain));
            Utilities.AssertThrows<ArgumentException>(() => decryptor.Decrypt(cipher, plain));

            Utilities.AssertThrows<ArgumentNullException>(() => decryptor.InvariantNoiseBudget(null));
        }
    }
}
