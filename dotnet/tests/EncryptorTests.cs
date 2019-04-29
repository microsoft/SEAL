// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

using Microsoft.Research.SEAL;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using System.Collections.Generic;
using System.Numerics;

namespace SEALNetTest
{
    [TestClass]
    public class EncryptorTests
    {
        [TestMethod]
        public void EncryptTest()
        {
            SEALContext context = GlobalContext.BFVContext;
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
        public void EncryptZeroTest()
        {
            {
                SEALContext context = GlobalContext.BFVContext;
                KeyGenerator keyGen = new KeyGenerator(context);
                PublicKey publicKey = keyGen.PublicKey;
                SecretKey secretKey = keyGen.SecretKey;
                Encryptor encryptor = new Encryptor(context, publicKey);
                Decryptor decryptor = new Decryptor(context, secretKey);

                Assert.IsNotNull(encryptor);
                Assert.IsNotNull(decryptor);

                Ciphertext cipher = new Ciphertext();
                encryptor.EncryptZero(cipher);
                Assert.IsFalse(cipher.IsNTTForm);
                Assert.IsFalse(cipher.IsTransparent);
                Assert.AreEqual(cipher.Scale, 1.0, double.Epsilon);
                Plaintext plain = new Plaintext();
                decryptor.Decrypt(cipher, plain);
                Assert.IsTrue(plain.IsZero);

                ParmsId nextParms = context.FirstContextData.NextContextData.ParmsId;
                encryptor.EncryptZero(nextParms, cipher);
                Assert.IsFalse(cipher.IsNTTForm);
                Assert.IsFalse(cipher.IsTransparent);
                Assert.AreEqual(cipher.Scale, 1.0, double.Epsilon);
                Assert.AreEqual(cipher.ParmsId, nextParms);
                decryptor.Decrypt(cipher, plain);
                Assert.IsTrue(plain.IsZero);
            }
            {
                SEALContext context = GlobalContext.CKKSContext;
                KeyGenerator keyGen = new KeyGenerator(context);
                PublicKey publicKey = keyGen.PublicKey;
                SecretKey secretKey = keyGen.SecretKey;
                Encryptor encryptor = new Encryptor(context, publicKey);
                Decryptor decryptor = new Decryptor(context, secretKey);
                CKKSEncoder encoder = new CKKSEncoder(context);

                Assert.IsNotNull(encryptor);
                Assert.IsNotNull(decryptor);

                Ciphertext cipher = new Ciphertext();
                encryptor.EncryptZero(cipher);
                Assert.IsTrue(cipher.IsNTTForm);
                Assert.IsFalse(cipher.IsTransparent);
                Assert.AreEqual(cipher.Scale, 1.0, double.Epsilon);
                cipher.Scale = Math.Pow(2.0, 30);
                Plaintext plain = new Plaintext();
                decryptor.Decrypt(cipher, plain);

                List<Complex> res = new List<Complex>();
                encoder.Decode(plain, res);
                foreach (Complex val in res)
                {
                    Assert.AreEqual(val.Real, 0.0, 0.01);
                    Assert.AreEqual(val.Imaginary, 0.0, 0.01);
                }

                ParmsId nextParms = context.FirstContextData.NextContextData.ParmsId;
                encryptor.EncryptZero(nextParms, cipher);
                Assert.IsTrue(cipher.IsNTTForm);
                Assert.IsFalse(cipher.IsTransparent);
                Assert.AreEqual(cipher.Scale, 1.0, double.Epsilon);
                cipher.Scale = Math.Pow(2.0, 30);
                Assert.AreEqual(cipher.ParmsId, nextParms);
                decryptor.Decrypt(cipher, plain);
                Assert.AreEqual(plain.ParmsId, nextParms);

                encoder.Decode(plain, res);
                foreach (Complex val in res)
                {
                    Assert.AreEqual(val.Real, 0.0, 0.01);
                    Assert.AreEqual(val.Imaginary, 0.0, 0.01);
                }
            }
        }

        [TestMethod]
        public void ExceptionsTest()
        {
            SEALContext context = GlobalContext.BFVContext;
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
            Assert.ThrowsException<ArgumentException>(() => encryptor.EncryptZero(cipher, pool_invalid));
        }
    }
}
