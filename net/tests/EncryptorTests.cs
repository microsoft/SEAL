// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

using Microsoft.Research.SEAL;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;

namespace SEALNetTest
{
    [TestClass]
    public class EncryptorTests
    {
        [TestMethod]
        public void EncryptTest()
        {
            SEALContext context = GlobalContext.Context;
            KeyGenerator keyGen = new KeyGenerator(context);
            PublicKey publicKey = keyGen.PublicKey;
            Encryptor encryptor = new Encryptor(context, publicKey);

            Assert.IsNotNull(encryptor);

            Ciphertext cipher = new Ciphertext();
            Plaintext plain = new Plaintext("1x^1 + 1");

            Assert.AreEqual(0ul, cipher.Size);

            encryptor.Encrypt(plain, cipher);

            Assert.IsNotNull(cipher);
            Assert.AreEqual(2ul, cipher.Size);
        }

        [TestMethod]
        public void ExceptionsTest()
        {
            SEALContext context = GlobalContext.Context;
            KeyGenerator keygen = new KeyGenerator(context);
            PublicKey pubKey = keygen.PublicKey;
            PublicKey pubKey_invalid = new PublicKey();
            Encryptor encryptor = new Encryptor(context, pubKey);
            Plaintext plain = new Plaintext();
            Ciphertext cipher = new Ciphertext();
            MemoryPoolHandle pool_invalid = new MemoryPoolHandle();

            Assert.ThrowsException<ArgumentNullException>(() => encryptor = new Encryptor(context, null));
            Assert.ThrowsException<ArgumentNullException>(() => encryptor = new Encryptor(null, pubKey));
            Assert.ThrowsException<ArgumentException>(() => encryptor = new Encryptor(context, pubKey_invalid));

            Assert.ThrowsException<ArgumentNullException>(() => encryptor.Encrypt(plain, null));
            Assert.ThrowsException<ArgumentNullException>(() => encryptor.Encrypt(null, cipher));
            Assert.ThrowsException<ArgumentException>(() => encryptor.Encrypt(plain, cipher, pool_invalid));
        }
    }
}
