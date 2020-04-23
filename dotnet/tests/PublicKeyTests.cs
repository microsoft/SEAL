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
    public class PublicKeyTests
    {
        [TestMethod]
        public void CreateTest()
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

            PublicKey pub = keygen.PublicKey;
            PublicKey copy = new PublicKey(pub);

            Assert.IsNotNull(copy);
            Assert.AreEqual(2ul, copy.Data.Size);
            Assert.IsTrue(copy.Data.IsNTTForm);

            PublicKey copy2 = new PublicKey();
            copy2.Set(copy);

            Assert.AreEqual(2ul, copy2.Data.Size);
            Assert.IsTrue(copy2.Data.IsNTTForm);
        }

        [TestMethod]
        public void SaveLoadTest()
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

            PublicKey pub = keygen.PublicKey;

            Assert.IsNotNull(pub);
            Assert.AreEqual(2ul, pub.Data.Size);
            Assert.IsTrue(pub.Data.IsNTTForm);

            PublicKey pub2 = new PublicKey();
            MemoryPoolHandle handle = pub2.Pool;

            Assert.AreEqual(0ul, pub2.Data.Size);
            Assert.IsFalse(pub2.Data.IsNTTForm);
            Assert.AreEqual(ParmsId.Zero, pub2.ParmsId);

            using (MemoryStream stream = new MemoryStream())
            {
                pub.Save(stream);

                stream.Seek(offset: 0, loc: SeekOrigin.Begin);

                pub2.Load(context, stream);
            }

            Assert.AreNotSame(pub, pub2);
            Assert.AreEqual(2ul, pub2.Data.Size);
            Assert.IsTrue(pub2.Data.IsNTTForm);
            Assert.AreEqual(pub.ParmsId, pub2.ParmsId);
            Assert.AreNotEqual(ParmsId.Zero, pub2.ParmsId);
            Assert.IsTrue(handle.AllocByteCount != 0ul);
        }

        [TestMethod]
        public void ExceptionsTest()
        {
            SEALContext context = GlobalContext.BFVContext;
            PublicKey key = new PublicKey();

            Utilities.AssertThrows<ArgumentNullException>(() => key = new PublicKey(null));

            Utilities.AssertThrows<ArgumentNullException>(() => key.Set(null));

            Utilities.AssertThrows<ArgumentNullException>(() => key.Save(null));
            Utilities.AssertThrows<ArgumentNullException>(() => key.UnsafeLoad(context, null));
            Utilities.AssertThrows<ArgumentNullException>(() => key.UnsafeLoad(null, new MemoryStream()));

            Utilities.AssertThrows<ArgumentNullException>(() => key.Load(context, null));
            Utilities.AssertThrows<ArgumentNullException>(() => key.Load(null, new MemoryStream()));
            Utilities.AssertThrows<EndOfStreamException>(() => key.Load(context, new MemoryStream()));

            Utilities.AssertThrows<ArgumentNullException>(() => ValCheck.IsValidFor(key, null));
        }
    }
}
