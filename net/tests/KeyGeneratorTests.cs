using Microsoft.Research.SEAL;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using System.Collections.Generic;
using System.Text;

namespace SEALNetTest
{
    [TestClass]
    public class KeyGeneratorTests
    {
        [TestMethod]
        public void CreateTest()
        {
            SEALContext context = GlobalContext.Context;
            KeyGenerator keygen = new KeyGenerator(context);

            Assert.IsNotNull(keygen);

            PublicKey pubKey = keygen.PublicKey;
            SecretKey secKey = keygen.SecretKey;

            Assert.IsNotNull(pubKey);
            Assert.IsNotNull(secKey);

            Ciphertext cipher = pubKey.Data;
            Assert.IsNotNull(cipher);
            Assert.AreEqual(16384, cipher.UInt64Count);

            Plaintext plain = secKey.Data;
            Assert.IsNotNull(plain);
            Assert.AreEqual(8192, plain.CoeffCount);
        }

        [TestMethod]
        public void Create2Test()
        {
            SEALContext context = GlobalContext.Context;
            KeyGenerator keygen1 = new KeyGenerator(context);
            Encryptor encryptor1 = new Encryptor(context, keygen1.PublicKey);
            Decryptor decryptor1 = new Decryptor(context, keygen1.SecretKey);

            Ciphertext cipher = new Ciphertext();
            Plaintext plain = new Plaintext("2x^1 + 5");
            Plaintext plain2 = new Plaintext();

            encryptor1.Encrypt(plain, cipher);
            decryptor1.Decrypt(cipher, plain2);

            Assert.AreNotSame(plain, plain2);
            Assert.AreEqual(plain, plain2);

            KeyGenerator keygen2 = new KeyGenerator(context, keygen1.SecretKey);
            Encryptor encryptor2 = new Encryptor(context, keygen2.PublicKey);
            Decryptor decryptor2 = new Decryptor(context, keygen2.SecretKey);

            Plaintext plain3 = new Plaintext();
            decryptor2.Decrypt(cipher, plain3);

            Assert.AreNotSame(plain, plain3);
            Assert.AreEqual(plain, plain3);

            KeyGenerator keygen3 = new KeyGenerator(context, keygen1.SecretKey, keygen1.PublicKey);
            Encryptor encryptor3 = new Encryptor(context, keygen3.PublicKey);
            Decryptor decryptor3 = new Decryptor(context, keygen3.SecretKey);

            Plaintext plain4 = new Plaintext();
            decryptor3.Decrypt(cipher, plain4);

            Assert.AreNotSame(plain, plain4);
            Assert.AreEqual(plain, plain4);

            Ciphertext cipher2 = new Ciphertext();
            plain2.Release();

            encryptor3.Encrypt(plain, cipher2);
            decryptor2.Decrypt(cipher2, plain2);

            Assert.AreNotSame(plain, plain2);
            Assert.AreEqual(plain, plain2);
        }
    }
}
