using Microsoft.Research.SEAL;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using System.Collections.Generic;
using System.Text;

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

            Assert.AreEqual(0, cipher.Size);

            encryptor.Encrypt(plain, cipher);

            Assert.IsNotNull(cipher);
            Assert.AreEqual(2, cipher.Size);
        }
    }
}
