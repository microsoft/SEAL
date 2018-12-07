// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

using Microsoft.Research.SEAL;
using Microsoft.VisualStudio.TestTools.UnitTesting;

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
    }
}
