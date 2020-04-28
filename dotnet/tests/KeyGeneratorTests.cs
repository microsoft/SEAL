// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

using Microsoft.Research.SEAL;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using System.Collections.Generic;
using System.IO;

namespace SEALNetTest
{
    [TestClass]
    public class KeyGeneratorTests
    {
        [TestMethod]
        public void CreateTest()
        {
            SEALContext context = GlobalContext.BFVContext;
            KeyGenerator keygen = new KeyGenerator(context);

            Assert.IsNotNull(keygen);

            PublicKey pubKey = keygen.PublicKey;
            SecretKey secKey = keygen.SecretKey;

            Assert.IsNotNull(pubKey);
            Assert.IsNotNull(secKey);

            Ciphertext cipher = pubKey.Data;
            Assert.IsNotNull(cipher);

            Plaintext plain = secKey.Data;
            Assert.IsNotNull(plain);
            Assert.AreEqual(40960ul, plain.CoeffCount);
        }

        [TestMethod]
        public void Create2Test()
        {
            SEALContext context = GlobalContext.BFVContext;
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
        }

        [TestMethod]
        public void KeyCopyTest()
        {
            SEALContext context = GlobalContext.BFVContext;
            PublicKey pk = null;
            SecretKey sk = null;

            using (KeyGenerator keygen = new KeyGenerator(context))
            {
                pk = keygen.PublicKey;
                sk = keygen.SecretKey;
            }

            ParmsId parmsIdPK = pk.ParmsId;
            ParmsId parmsIdSK = sk.ParmsId;
            Assert.AreEqual(parmsIdPK, parmsIdSK);
            Assert.AreEqual(parmsIdPK, context.KeyParmsId);
        }

        [TestMethod]
        public void ExceptionsTest()
        {
            SEALContext context = GlobalContext.BFVContext;
            KeyGenerator keygen = new KeyGenerator(context);
            SecretKey secret = new SecretKey();
            List<uint> elts = new List<uint> { 16385 };
            List<uint> elts_null = null;
            List<int> steps = new List<int> { 4096 };
            List<int> steps_null = null;

            Utilities.AssertThrows<ArgumentNullException>(() => keygen = new KeyGenerator(null));

            Utilities.AssertThrows<ArgumentNullException>(() => keygen = new KeyGenerator(context, null));
            Utilities.AssertThrows<ArgumentNullException>(() => keygen = new KeyGenerator(null, keygen.SecretKey));
            Utilities.AssertThrows<ArgumentException>(() => keygen = new KeyGenerator(context, secret));

            Utilities.AssertThrows<ArgumentNullException>(() => keygen.GaloisKeys(elts_null));
            Utilities.AssertThrows<ArgumentException>(() => keygen.GaloisKeys(elts));
            Utilities.AssertThrows<ArgumentNullException>(() => keygen.GaloisKeys(steps_null));
            Utilities.AssertThrows<ArgumentException>(() => keygen.GaloisKeys(steps));

            EncryptionParameters smallParms = new EncryptionParameters(SchemeType.CKKS);
            smallParms.PolyModulusDegree = 128;
            smallParms.CoeffModulus = CoeffModulus.Create(smallParms.PolyModulusDegree, new int[] { 60 });
            context = new SEALContext(smallParms, true, SecLevelType.None);
            keygen = new KeyGenerator(context);
            Utilities.AssertThrows<InvalidOperationException>(() => keygen.RelinKeys());
            Utilities.AssertThrows<InvalidOperationException>(() => keygen.GaloisKeys());
        }
    }
}
