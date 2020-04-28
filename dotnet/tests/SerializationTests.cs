// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

using Microsoft.VisualStudio.TestTools.UnitTesting;
using Microsoft.Research.SEAL;
using System;
using System.IO;
using System.Text;

namespace SEALNetTest
{
    [TestClass]
    public class SerializationTests
    {
        [TestMethod]
        public void IsValidHeader()
        {
            Assert.AreEqual(Serialization.SEALHeaderSize, 0x10);

            Serialization.SEALHeader header = new Serialization.SEALHeader();
            Assert.IsTrue(Serialization.IsValidHeader(header));

            Serialization.SEALHeader invalidHeader = new Serialization.SEALHeader();
            invalidHeader.Magic = 0x1212;
            Assert.IsFalse(Serialization.IsValidHeader(invalidHeader));
            invalidHeader.Magic = Serialization.SEALMagic;
            Assert.AreEqual(Serialization.SEALHeaderSize, invalidHeader.HeaderSize);
            invalidHeader.VersionMajor = 0x02;
            Assert.IsFalse(Serialization.IsValidHeader(invalidHeader));
            invalidHeader.VersionMajor = SEALVersion.Major;
            invalidHeader.ComprMode = (ComprModeType)0x02;
            Assert.IsFalse(Serialization.IsValidHeader(invalidHeader));
        }

        [TestMethod]
        public void SEALHeaderSaveLoad()
        {
            Serialization.SEALHeader header = new Serialization.SEALHeader();
            Serialization.SEALHeader loaded = new Serialization.SEALHeader();
            using (MemoryStream mem = new MemoryStream())
            {
                header.ComprMode = Serialization.ComprModeDefault;
                header.Size = 256;
                Assert.IsTrue(Serialization.IsValidHeader(header));

                Serialization.SaveHeader(header, mem);
                mem.Seek(offset: 0, loc: SeekOrigin.Begin);
                Serialization.LoadHeader(mem, loaded);

                Assert.AreEqual(loaded.Magic, header.Magic);
                Assert.AreEqual(loaded.HeaderSize, header.HeaderSize);
                Assert.AreEqual(loaded.VersionMajor, header.VersionMajor);
                Assert.AreEqual(loaded.VersionMinor, header.VersionMinor);
                Assert.AreEqual(loaded.ComprMode, header.ComprMode);
                Assert.AreEqual(loaded.Reserved, header.Reserved);
                Assert.AreEqual(loaded.Size, header.Size);
            }
        }

        [TestMethod]
        public void SEALHeaderUpgrade()
        {
            LegacyHeaders.SEALHeader_3_4 header_3_4 = new LegacyHeaders.SEALHeader_3_4();

            using MemoryStream mem = new MemoryStream();
            using BinaryWriter writer = new BinaryWriter(mem, Encoding.UTF8, true);
            writer.Write(header_3_4.Magic);
            writer.Write(header_3_4.ZeroByte);
            writer.Write((byte)header_3_4.ComprMode);
            writer.Write(header_3_4.Size);
            writer.Write(header_3_4.Reserved);
            mem.Seek(offset: 0, loc: SeekOrigin.Begin);

            {
                Serialization.SEALHeader loaded = new Serialization.SEALHeader();
                Serialization.LoadHeader(mem, loaded);
                Assert.IsTrue(Serialization.IsValidHeader(loaded));
                Assert.AreEqual(header_3_4.ComprMode, loaded.ComprMode);
                Assert.AreEqual(header_3_4.Size, loaded.Size);
                mem.Seek(offset: 0, loc: SeekOrigin.Begin);
            }
            {
                Serialization.SEALHeader loaded = new Serialization.SEALHeader();
                Serialization.LoadHeader(mem, loaded, false);
                Assert.IsFalse(Serialization.IsValidHeader(loaded));
                mem.Seek(offset: 0, loc: SeekOrigin.Begin);
            }
        }

        [TestMethod]
        public void ExceptionsTest()
        {
            SEALContext context = GlobalContext.BFVContext;
            Ciphertext cipher = new Ciphertext();

            using (MemoryStream mem = new MemoryStream())
            {
                KeyGenerator keygen = new KeyGenerator(context);
                Encryptor encryptor = new Encryptor(context, keygen.PublicKey);
                Plaintext plain = new Plaintext("2x^3 + 4x^2 + 5x^1 + 6");
                encryptor.Encrypt(plain, cipher);
                cipher.Save(mem);
                mem.Seek(offset: 8, loc: SeekOrigin.Begin);
                BinaryWriter writer = new BinaryWriter(mem, Encoding.UTF8, true);
                writer.Write((ulong)0x80000000);

                mem.Seek(offset: 0, loc: SeekOrigin.Begin);
                Utilities.AssertThrows<InvalidOperationException>(() => cipher.Load(context, mem));
            }
        }
    }
}
