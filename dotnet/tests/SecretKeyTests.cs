// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

using Microsoft.Research.SEAL;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using System.Collections.Generic;
using System.IO;
using System.Reflection;

namespace SEALNetTest
{
    [TestClass]
    public class SecretKeyTests
    {
        private sealed class FailingWriteStream : Stream
        {
            public byte[] Buffer { get; private set; }

            public override bool CanRead => false;

            public override bool CanSeek => false;

            public override bool CanWrite => true;

            public override long Length => throw new NotSupportedException();

            public override long Position
            {
                get => throw new NotSupportedException();
                set => throw new NotSupportedException();
            }

            public override void Flush()
            {
            }

            public override int Read(byte[] buffer, int offset, int count)
            {
                throw new NotSupportedException();
            }

            public override long Seek(long offset, SeekOrigin origin)
            {
                throw new NotSupportedException();
            }

            public override void SetLength(long value)
            {
                throw new NotSupportedException();
            }

            public override void Write(byte[] buffer, int offset, int count)
            {
                Buffer = buffer;
                throw new IOException();
            }
        }

        private sealed class CapturingReadStream : Stream
        {
            private readonly MemoryStream stream_;

            public CapturingReadStream(byte[] data)
            {
                stream_ = new MemoryStream(data, writable: false);
            }

            public byte[] Buffer { get; private set; }

            public override bool CanRead => true;

            public override bool CanSeek => true;

            public override bool CanWrite => false;

            public override long Length => stream_.Length;

            public override long Position
            {
                get => stream_.Position;
                set => stream_.Position = value;
            }

            public override void Flush()
            {
            }

            public override int Read(byte[] buffer, int offset, int count)
            {
                if (Buffer == null || buffer.Length > Buffer.Length)
                {
                    Buffer = buffer;
                }
                return stream_.Read(buffer, offset, count);
            }

            public override long Seek(long offset, SeekOrigin origin)
            {
                return stream_.Seek(offset, origin);
            }

            public override void SetLength(long value)
            {
                throw new NotSupportedException();
            }

            public override void Write(byte[] buffer, int offset, int count)
            {
                throw new NotSupportedException();
            }

            protected override void Dispose(bool disposing)
            {
                if (disposing)
                {
                    stream_.Dispose();
                }
                base.Dispose(disposing);
            }
        }

        private static void AssertBufferCleared(byte[] buffer)
        {
            Assert.IsNotNull(buffer);
            Assert.IsTrue(buffer.Length > 0);
            for (int i = 0; i < buffer.Length; i++)
            {
                Assert.AreEqual(0, buffer[i]);
            }
        }

        [TestMethod]
        public void CreateTest()
        {
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

                SecretKey secret = keygen.SecretKey;
                SecretKey copy = new SecretKey(secret);

                Assert.AreEqual(64ul, copy.Data.CoeffCount);
                Assert.IsTrue(copy.Data.IsNTTForm);

                SecretKey copy2 = new SecretKey();
                copy2.Set(copy);

                Assert.AreEqual(64ul, copy2.Data.CoeffCount);
                Assert.IsTrue(copy2.Data.IsNTTForm);
            }
            {
                EncryptionParameters parms = new EncryptionParameters(SchemeType.BGV)
                {
                    PolyModulusDegree = 64,
                    PlainModulus = new Modulus(1 << 6),
                    CoeffModulus = CoeffModulus.Create(64, new int[] { 40 })
                };
                SEALContext context = new SEALContext(parms,
                    expandModChain: false,
                    secLevel: SecLevelType.None);
                KeyGenerator keygen = new KeyGenerator(context);

                SecretKey secret = keygen.SecretKey;
                SecretKey copy = new SecretKey(secret);

                Assert.AreEqual(64ul, copy.Data.CoeffCount);
                Assert.IsTrue(copy.Data.IsNTTForm);

                SecretKey copy2 = new SecretKey();
                copy2.Set(copy);

                Assert.AreEqual(64ul, copy2.Data.CoeffCount);
                Assert.IsTrue(copy2.Data.IsNTTForm);
            }
        }

        [TestMethod]
        public void SaveLoadTest()
        {
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

                SecretKey secret = keygen.SecretKey;

                Assert.AreEqual(64ul, secret.Data.CoeffCount);
                Assert.IsTrue(secret.Data.IsNTTForm);
                Assert.AreNotEqual(ParmsId.Zero, secret.ParmsId);

                SecretKey secret2 = new SecretKey();
                Assert.IsNotNull(secret2);
                Assert.AreEqual(0ul, secret2.Data.CoeffCount);
                Assert.IsFalse(secret2.Data.IsNTTForm);

                using (MemoryStream stream = new MemoryStream())
                {
                    secret.Save(stream);
                    stream.Seek(offset: 0, loc: SeekOrigin.Begin);
                    secret2.Load(context, stream);
                }

                Assert.AreNotSame(secret, secret2);
                Assert.AreEqual(64ul, secret2.Data.CoeffCount);
                Assert.IsTrue(secret2.Data.IsNTTForm);
                Assert.AreNotEqual(ParmsId.Zero, secret2.ParmsId);
                Assert.AreEqual(secret.ParmsId, secret2.ParmsId);
            }
            {
                EncryptionParameters parms = new EncryptionParameters(SchemeType.BGV)
                {
                    PolyModulusDegree = 64,
                    PlainModulus = new Modulus(1 << 6),
                    CoeffModulus = CoeffModulus.Create(64, new int[] { 40 })
                };
                SEALContext context = new SEALContext(parms,
                    expandModChain: false,
                    secLevel: SecLevelType.None);
                KeyGenerator keygen = new KeyGenerator(context);

                SecretKey secret = keygen.SecretKey;

                Assert.AreEqual(64ul, secret.Data.CoeffCount);
                Assert.IsTrue(secret.Data.IsNTTForm);
                Assert.AreNotEqual(ParmsId.Zero, secret.ParmsId);

                SecretKey secret2 = new SecretKey();
                Assert.IsNotNull(secret2);
                Assert.AreEqual(0ul, secret2.Data.CoeffCount);
                Assert.IsFalse(secret2.Data.IsNTTForm);

                using (MemoryStream stream = new MemoryStream())
                {
                    secret.Save(stream);
                    stream.Seek(offset: 0, loc: SeekOrigin.Begin);
                    secret2.Load(context, stream);
                }

                Assert.AreNotSame(secret, secret2);
                Assert.AreEqual(64ul, secret2.Data.CoeffCount);
                Assert.IsTrue(secret2.Data.IsNTTForm);
                Assert.AreNotEqual(ParmsId.Zero, secret2.ParmsId);
                Assert.AreEqual(secret.ParmsId, secret2.ParmsId);
            }
        }

        [TestMethod]
        public void SaveBufferClearedOnExceptionTest()
        {
            EncryptionParameters parms = new EncryptionParameters(SchemeType.BFV)
            {
                PolyModulusDegree = 64,
                PlainModulus = new Modulus(1 << 6),
                CoeffModulus = CoeffModulus.Create(64, new int[] { 40 })
            };
            SEALContext context = new SEALContext(parms,
                expandModChain: false, secLevel: SecLevelType.None);
            SecretKey secret = new KeyGenerator(context).SecretKey;

            FailingWriteStream output = new FailingWriteStream();
            Utilities.AssertThrows<IOException>(
                () => secret.Save(output, ComprModeType.None));
            AssertBufferCleared(output.Buffer);
        }

        [TestMethod]
        public void LoadBufferClearedOnExceptionTest()
        {
            EncryptionParameters parms = new EncryptionParameters(SchemeType.BFV)
            {
                PolyModulusDegree = 64,
                PlainModulus = new Modulus(1 << 6),
                CoeffModulus = CoeffModulus.Create(64, new int[] { 40 })
            };
            SEALContext context = new SEALContext(parms,
                expandModChain: false, secLevel: SecLevelType.None);
            SecretKey secret = new KeyGenerator(context).SecretKey;

            byte[] serialized;
            using (MemoryStream stream = new MemoryStream())
            {
                secret.Save(stream, ComprModeType.None);
                serialized = stream.ToArray();
            }

            EncryptionParameters otherParms = new EncryptionParameters(SchemeType.BFV)
            {
                PolyModulusDegree = 64,
                PlainModulus = new Modulus((1 << 6) + 1),
                CoeffModulus = CoeffModulus.Create(64, new int[] { 40 })
            };
            SEALContext otherContext = new SEALContext(otherParms,
                expandModChain: false, secLevel: SecLevelType.None);

            using (CapturingReadStream input = new CapturingReadStream(serialized))
            {
                SecretKey loaded = new SecretKey();
                Utilities.AssertThrows<InvalidOperationException>(
                    () => loaded.Load(otherContext, input));
                AssertBufferCleared(input.Buffer);
            }
        }

        [TestMethod]
        public void ExceptionsTest()
        {
            {
                SEALContext context = GlobalContext.BFVContext;
                SecretKey key = new SecretKey();

                Utilities.AssertThrows<ArgumentNullException>(() => key = new SecretKey(null));

                Utilities.AssertThrows<ArgumentNullException>(() => key.Set(null));

                Utilities.AssertThrows<ArgumentNullException>(() => ValCheck.IsValidFor(key, null));

                Utilities.AssertThrows<ArgumentNullException>(() => key.Save(null));

                Utilities.AssertThrows<ArgumentNullException>(() => key.UnsafeLoad(null, new MemoryStream()));
                Utilities.AssertThrows<ArgumentNullException>(() => key.UnsafeLoad(context, null));
                Utilities.AssertThrows<ArgumentNullException>(() => key.Load(context, null));
                Utilities.AssertThrows<ArgumentNullException>(() => key.Load(null, new MemoryStream()));
                Utilities.AssertThrows<EndOfStreamException>(() => key.Load(context, new MemoryStream()));
            }
            {
                SEALContext context = GlobalContext.BGVContext;
                SecretKey key = new SecretKey();

                Utilities.AssertThrows<ArgumentNullException>(() => key = new SecretKey(null));

                Utilities.AssertThrows<ArgumentNullException>(() => key.Set(null));

                Utilities.AssertThrows<ArgumentNullException>(() => ValCheck.IsValidFor(key, null));

                Utilities.AssertThrows<ArgumentNullException>(() => key.Save(null));

                Utilities.AssertThrows<ArgumentNullException>(() => key.UnsafeLoad(null, new MemoryStream()));
                Utilities.AssertThrows<ArgumentNullException>(() => key.UnsafeLoad(context, null));
                Utilities.AssertThrows<ArgumentNullException>(() => key.Load(context, null));
                Utilities.AssertThrows<ArgumentNullException>(() => key.Load(null, new MemoryStream()));
                Utilities.AssertThrows<EndOfStreamException>(() => key.Load(context, new MemoryStream()));
            }
        }

        [TestMethod]
        public void DataRootsParentTest()
        {
            SEALContext context = GlobalContext.BFVContext;
            KeyGenerator keygen = new KeyGenerator(context);

            SecretKey secretKey = keygen.SecretKey;
            Plaintext data = secretKey.Data;
            Assert.IsTrue(data.CoeffCount > 0);

            // The returned view holds an interior pointer into the SecretKey, so it must
            // keep a reference to that SecretKey to stop it being finalized while the view
            // is reachable. (owner_ is otherwise unobservable, so read it reflectively.)
            FieldInfo ownerField = typeof(Plaintext).GetField(
                "owner_", BindingFlags.NonPublic | BindingFlags.Instance);
            Assert.IsNotNull(ownerField);
            Assert.AreSame(secretKey, ownerField.GetValue(data));
        }
    }
}
