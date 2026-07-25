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
            invalidHeader.ComprMode = (ComprModeType)0x03;
            Assert.IsFalse(Serialization.IsValidHeader(invalidHeader));
        }

        [TestMethod]
        public void PreviousMinorVersionCompatibility()
        {
            Serialization.SEALHeader header = new Serialization.SEALHeader();
            for (byte minor = 0; minor <= SEALVersion.Minor; minor++)
            {
                header.VersionMinor = minor;
                Assert.IsTrue(Serialization.IsCompatibleVersion(header));
            }

            header.VersionMinor = checked((byte)(SEALVersion.Minor + 1));
            Assert.IsFalse(Serialization.IsCompatibleVersion(header));
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
/*
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
*/
        [TestMethod]
        public void ExceptionsTest()
        {
            {
                SEALContext context = GlobalContext.BFVContext;
                Ciphertext cipher = new Ciphertext();

                using (MemoryStream mem = new MemoryStream())
                {
                    KeyGenerator keygen = new KeyGenerator(context);
                    keygen.CreatePublicKey(out PublicKey publicKey);
                    Encryptor encryptor = new Encryptor(context, publicKey);

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
            {
                SEALContext context = GlobalContext.BGVContext;
                Ciphertext cipher = new Ciphertext();

                using (MemoryStream mem = new MemoryStream())
                {
                    KeyGenerator keygen = new KeyGenerator(context);
                    keygen.CreatePublicKey(out PublicKey publicKey);
                    Encryptor encryptor = new Encryptor(context, publicKey);

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

        [TestMethod]
        public void TruncatedStreamLoadTest()
        {
            SEALContext context = GlobalContext.BFVContext;

            // A bare 16-byte header claiming a near-int.MaxValue size must be rejected before
            // allocating a buffer of that size.
            using (MemoryStream mem = new MemoryStream())
            {
                Serialization.SEALHeader header = new Serialization.SEALHeader();
                header.ComprMode = Serialization.ComprModeDefault;
                header.Size = 0x7FFFFFC7;
                Serialization.SaveHeader(header, mem);
                mem.Seek(offset: 0, loc: SeekOrigin.Begin);

                Ciphertext cipher = new Ciphertext();
                Utilities.AssertThrows<EndOfStreamException>(() => cipher.Load(context, mem));
            }

            // A truncated body whose header still claims the full size must throw rather than hand
            // native code a length past the end of the read buffer.
            {
                KeyGenerator keygen = new KeyGenerator(context);
                keygen.CreatePublicKey(out PublicKey publicKey);
                Encryptor encryptor = new Encryptor(context, publicKey);

                Ciphertext cipher = new Ciphertext();
                Plaintext plain = new Plaintext("2x^3 + 4x^2 + 5x^1 + 6");
                encryptor.Encrypt(plain, cipher);

                byte[] full;
                using (MemoryStream mem = new MemoryStream())
                {
                    cipher.Save(mem);
                    full = mem.ToArray();
                }

                byte[] truncated = new byte[full.Length - 8];
                Array.Copy(full, truncated, truncated.Length);
                using (MemoryStream mem = new MemoryStream(truncated))
                {
                    Ciphertext loaded = new Ciphertext();
                    Utilities.AssertThrows<EndOfStreamException>(() => loaded.Load(context, mem));
                }
            }
        }
    }
}
