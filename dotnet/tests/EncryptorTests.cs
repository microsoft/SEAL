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
    public class EncryptorTests
    {
        [TestMethod]
        public void EncryptTest()
        {
            {
                SEALContext context = GlobalContext.BFVContext;
                KeyGenerator keyGen = new KeyGenerator(context);
                PublicKey publicKey = keyGen.PublicKey;
                SecretKey secretKey = keyGen.SecretKey;
                Encryptor encryptor = new Encryptor(context, publicKey, secretKey);

                Assert.IsNotNull(encryptor);

                Plaintext plain = new Plaintext("1x^1 + 1");

                Ciphertext cipher = new Ciphertext();
                Assert.AreEqual(0ul, cipher.Size);
                encryptor.Encrypt(plain, cipher);
                Assert.IsNotNull(cipher);
                Assert.AreEqual(2ul, cipher.Size);
            }
            {
                SEALContext context = GlobalContext.BFVContext;
                KeyGenerator keyGen = new KeyGenerator(context);
                SecretKey secretKey = keyGen.SecretKey;
                Encryptor encryptor = new Encryptor(context, secretKey);

                Assert.IsNotNull(encryptor);

                Plaintext plain = new Plaintext("1x^1 + 1");

                Ciphertext cipher = new Ciphertext();
                Assert.AreEqual(0ul, cipher.Size);
                encryptor.EncryptSymmetric(plain, cipher);
                Assert.IsNotNull(cipher);
                Assert.AreEqual(2ul, cipher.Size);
            }
        }

        [TestMethod]
        public void EncryptZeroTest()
        {
            {
                SEALContext context = GlobalContext.BFVContext;
                KeyGenerator keyGen = new KeyGenerator(context);
                PublicKey publicKey = keyGen.PublicKey;
                SecretKey secretKey = keyGen.SecretKey;
                Decryptor decryptor = new Decryptor(context, secretKey);

                Assert.IsNotNull(decryptor);

                Ciphertext cipher = new Ciphertext();
                Plaintext plain = new Plaintext();
                ParmsId nextParms = context.FirstContextData.NextContextData.ParmsId;

                {
                    Encryptor encryptor = new Encryptor(context, publicKey);
                    Assert.IsNotNull(encryptor);

                    encryptor.EncryptZero(cipher);
                    Assert.IsFalse(cipher.IsNTTForm);
                    Assert.IsFalse(cipher.IsTransparent);
                    Assert.AreEqual(cipher.Scale, 1.0, double.Epsilon);
                    decryptor.Decrypt(cipher, plain);
                    Assert.IsTrue(plain.IsZero);

                    encryptor.EncryptZero(nextParms, cipher);
                    Assert.IsFalse(cipher.IsNTTForm);
                    Assert.IsFalse(cipher.IsTransparent);
                    Assert.AreEqual(cipher.Scale, 1.0, double.Epsilon);
                    Assert.AreEqual(cipher.ParmsId, nextParms);
                    decryptor.Decrypt(cipher, plain);
                    Assert.IsTrue(plain.IsZero);
                }
                {
                    Encryptor encryptor = new Encryptor(context, secretKey);

                    encryptor.EncryptZeroSymmetric(cipher);
                    Assert.IsFalse(cipher.IsNTTForm);
                    Assert.IsFalse(cipher.IsTransparent);
                    Assert.AreEqual(cipher.Scale, 1.0, double.Epsilon);
                    decryptor.Decrypt(cipher, plain);
                    Assert.IsTrue(plain.IsZero);

                    encryptor.EncryptZeroSymmetric(nextParms, cipher);
                    Assert.IsFalse(cipher.IsNTTForm);
                    Assert.IsFalse(cipher.IsTransparent);
                    Assert.AreEqual(cipher.Scale, 1.0, double.Epsilon);
                    Assert.AreEqual(cipher.ParmsId, nextParms);
                    decryptor.Decrypt(cipher, plain);
                    Assert.IsTrue(plain.IsZero);
                }
                using (MemoryStream stream = new MemoryStream())
                {
                    Encryptor encryptor = new Encryptor(context, secretKey);

                    encryptor.EncryptZeroSymmetric().Save(stream);
                    stream.Seek(0, SeekOrigin.Begin);
                    cipher.Load(context, stream);
                    Assert.IsFalse(cipher.IsNTTForm);
                    Assert.IsFalse(cipher.IsTransparent);
                    Assert.AreEqual(cipher.Scale, 1.0, double.Epsilon);
                    decryptor.Decrypt(cipher, plain);
                    Assert.IsTrue(plain.IsZero);
                }
                using (MemoryStream stream = new MemoryStream())
                {
                    Encryptor encryptor = new Encryptor(context, secretKey);

                    encryptor.EncryptZeroSymmetric(nextParms).Save(stream);
                    stream.Seek(0, SeekOrigin.Begin);
                    cipher.Load(context, stream);
                    Assert.IsFalse(cipher.IsNTTForm);
                    Assert.IsFalse(cipher.IsTransparent);
                    Assert.AreEqual(cipher.Scale, 1.0, double.Epsilon);
                    Assert.AreEqual(cipher.ParmsId, nextParms);
                    decryptor.Decrypt(cipher, plain);
                    Assert.IsTrue(plain.IsZero);
                }
            }
            {
                SEALContext context = GlobalContext.CKKSContext;
                KeyGenerator keyGen = new KeyGenerator(context);
                PublicKey publicKey = keyGen.PublicKey;
                SecretKey secretKey = keyGen.SecretKey;
                Decryptor decryptor = new Decryptor(context, secretKey);
                CKKSEncoder encoder = new CKKSEncoder(context);

                Assert.IsNotNull(decryptor);

                Ciphertext cipher = new Ciphertext();
                Plaintext plain = new Plaintext();
                ParmsId nextParms = context.FirstContextData.NextContextData.ParmsId;
                List<Complex> res = new List<Complex>();

                {
                    Encryptor encryptor = new Encryptor(context, publicKey);
                    Assert.IsNotNull(encryptor);

                    encryptor.EncryptZero(cipher);
                    Assert.IsTrue(cipher.IsNTTForm);
                    Assert.IsFalse(cipher.IsTransparent);
                    Assert.AreEqual(cipher.Scale, 1.0, double.Epsilon);
                    cipher.Scale = Math.Pow(2.0, 30);
                    decryptor.Decrypt(cipher, plain);

                    encoder.Decode(plain, res);
                    foreach (Complex val in res)
                    {
                        Assert.AreEqual(val.Real, 0.0, 0.01);
                        Assert.AreEqual(val.Imaginary, 0.0, 0.01);
                    }

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
                {
                    Encryptor encryptor = new Encryptor(context, secretKey);

                    encryptor.EncryptZeroSymmetric(cipher);
                    Assert.IsTrue(cipher.IsNTTForm);
                    Assert.IsFalse(cipher.IsTransparent);
                    Assert.AreEqual(cipher.Scale, 1.0, double.Epsilon);
                    cipher.Scale = Math.Pow(2.0, 30);
                    decryptor.Decrypt(cipher, plain);

                    encoder.Decode(plain, res);
                    foreach (Complex val in res)
                    {
                        Assert.AreEqual(val.Real, 0.0, 0.01);
                        Assert.AreEqual(val.Imaginary, 0.0, 0.01);
                    }

                    encryptor.EncryptZeroSymmetric(nextParms, cipher);
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
                using (MemoryStream stream = new MemoryStream())
                {
                    Encryptor encryptor = new Encryptor(context, secretKey);

                    encryptor.EncryptZeroSymmetric().Save(stream);
                    stream.Seek(0, SeekOrigin.Begin);
                    cipher.Load(context, stream);
                    Assert.IsTrue(cipher.IsNTTForm);
                    Assert.IsFalse(cipher.IsTransparent);
                    Assert.AreEqual(cipher.Scale, 1.0, double.Epsilon);
                    cipher.Scale = Math.Pow(2.0, 30);
                    decryptor.Decrypt(cipher, plain);

                    encoder.Decode(plain, res);
                    foreach (Complex val in res)
                    {
                        Assert.AreEqual(val.Real, 0.0, 0.01);
                        Assert.AreEqual(val.Imaginary, 0.0, 0.01);
                    }
                }
                using (MemoryStream stream = new MemoryStream())
                {
                    Encryptor encryptor = new Encryptor(context, secretKey);

                    encryptor.EncryptZeroSymmetric(nextParms).Save(stream);
                    stream.Seek(0, SeekOrigin.Begin);
                    cipher.Load(context, stream);
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
        }

        [TestMethod]
        public void ExceptionsTest()
        {
            SEALContext context = GlobalContext.BFVContext;
            KeyGenerator keygen = new KeyGenerator(context);
            PublicKey pubKey = keygen.PublicKey;
            PublicKey pubKey_invalid = new PublicKey();
            SecretKey secKey = keygen.SecretKey;
            SecretKey secKey_invalid = new SecretKey();
            Encryptor encryptor = new Encryptor(context, pubKey);
            Plaintext plain = new Plaintext();
            Ciphertext cipher = new Ciphertext();
            MemoryPoolHandle pool_invalid = new MemoryPoolHandle();
            ParmsId parmsId_invalid = new ParmsId();

            Utilities.AssertThrows<ArgumentNullException>(() => encryptor = new Encryptor(context, null));
            Utilities.AssertThrows<ArgumentNullException>(() => encryptor = new Encryptor(null, pubKey));
            Utilities.AssertThrows<ArgumentException>(() => encryptor = new Encryptor(context, pubKey_invalid));
            Utilities.AssertThrows<ArgumentException>(() => encryptor = new Encryptor(context, pubKey_invalid, secKey));
            encryptor = new Encryptor(context, pubKey, secKey);
            Utilities.AssertThrows<ArgumentException>(() => encryptor.SetPublicKey(pubKey_invalid));
            Utilities.AssertThrows<ArgumentException>(() => encryptor.SetSecretKey(secKey_invalid));

            Utilities.AssertThrows<ArgumentNullException>(() => encryptor.Encrypt(plain, null));
            Utilities.AssertThrows<ArgumentNullException>(() => encryptor.Encrypt(null, cipher));
            Utilities.AssertThrows<ArgumentException>(() => encryptor.Encrypt(plain, cipher, pool_invalid));
            Utilities.AssertThrows<ArgumentException>(() => encryptor.EncryptZero(cipher, pool_invalid));
            Utilities.AssertThrows<ArgumentException>(() => encryptor.EncryptZero(parmsId_invalid, cipher));

            Utilities.AssertThrows<ArgumentNullException>(() => encryptor.EncryptSymmetric(plain, destination: null));
            Utilities.AssertThrows<ArgumentNullException>(() => encryptor.EncryptSymmetric(null, cipher));
            Utilities.AssertThrows<ArgumentException>(() => encryptor.EncryptSymmetric(plain, cipher, pool_invalid));
            Utilities.AssertThrows<ArgumentException>(() => encryptor.EncryptZeroSymmetric(cipher, pool_invalid));
            Utilities.AssertThrows<ArgumentException>(() => encryptor.EncryptZeroSymmetric(parmsId_invalid, cipher));

            Utilities.AssertThrows<ArgumentNullException>(() => encryptor.EncryptSymmetric(plain).Save(null));
            Utilities.AssertThrows<ArgumentNullException>(() => encryptor.EncryptZeroSymmetric().Save(null));
        }
    }
}
