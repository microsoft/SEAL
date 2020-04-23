// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

using System;
using System.IO;
using System.Text;
using System.Runtime.InteropServices;

namespace Microsoft.Research.SEAL
{
    /// <summary>
    /// A type to describe the compression algorithm applied to serialized data.
    /// Ciphertext and key data consist of a large number of 64-bit words storing
    /// integers modulo prime numbers much smaller than the word size, resulting in
    /// a large number of zero bytes in the output. Any compression algorithm should
    /// be able to clean up these zero bytes and hence compress both ciphertext and
    /// key data.
    /// </summary>
    public enum ComprModeType : byte
    {
        /// <summary>No compression is used.</summary>
        None = 0,

        /// <summary>Use Deflate compression.</summary>
        Deflate = 1,
    }

    /// <summary>Class to provide functionality for serialization.</summary>
    /// <remarks>
    /// Class to provide functionality for serialization. Most users of the library
    /// should never have to call these functions explicitly, as they are called
    /// internally by functions such as Ciphertext.Save and Ciphertext.Load.
    /// </remarks>
    public abstract class Serialization
    {
        /// <summary>
        /// The compression mode used by default.
        /// </summary>
        public static readonly ComprModeType ComprModeDefault = ((Func<ComprModeType>)(() => {
            NativeMethods.Serialization_ComprModeDefault(out byte comprMode);
            return (ComprModeType)comprMode;
        }))();

        /// <summary>The magic value indicating a Microsoft SEAL header.</summary>
        public static readonly ushort SEALMagic = ((Func<ushort>)(() => {
            NativeMethods.Serialization_SEALMagic(out ushort sealMagic);
            return sealMagic;
        }))();

        /// <summary>The size in bytes of the SEALHeader.</summary>
        public static readonly byte SEALHeaderSize = ((Func<byte>)(() => {
            NativeMethods.Serialization_SEALHeaderSize(out byte sealHeaderSize);
            return sealHeaderSize;
        }))();

        /// <summary>Struct to contain header information for serialization.</summary>
        /// <remarks>
        /// Struct to contain header information for serialization. The size of the header is 16 bytes and it consists
        /// of the following fields:
        ///
        /// 1. a magic number identifying this is a SEALHeader struct (2 bytes)
        /// 2. size in bytes of the SEALHeader struct (1 byte)
        /// 3. Microsoft SEAL's major version number (1 byte)
        /// 4. Microsoft SEAL's minor version number (1 byte)
        /// 5. a ComprModeType indicating whether data after the header is compressed (1 byte)
        /// 6. reserved for future use and data alignment (2 bytes)
        /// 7. the size in bytes of the entire serialized object, including the header (8 bytes)
        /// </remarks>
        [StructLayout(LayoutKind.Explicit, Size=16)]
        public class SEALHeader : ISettable<SEALHeader>
        {
            /// <summary>A magic number identifying this is a SEALHeader struct (2 bytes)</summary>
            [FieldOffset(0)]public ushort Magic = SEALMagic;

            /// <summary>Size in bytes of the SEALHeader struct (1 byte)</summary>
            [FieldOffset(2)]public byte HeaderSize = SEALHeaderSize;

            /// <summary>Microsoft SEAL's major version number (1 byte)</summary>
            [FieldOffset(3)]public byte VersionMajor = SEALVersion.Major;

            /// <summary>Microsoft SEAL's minor version number (1 byte)</summary>
            [FieldOffset(4)]public byte VersionMinor = SEALVersion.Minor;

            /// <summary>A compr_mode_type indicating whether data after the header is compressed (1 byte)</summary>
            [FieldOffset(5)]public ComprModeType ComprMode = ComprModeDefault;

            /// <summary>Reserved for future use and data alignment (2 bytes)</summary>
            [FieldOffset(6)]public ushort Reserved = 0;

            /// <summary>The size in bytes of the entire serialized object, including the header (8 bytes)</summary>
            [FieldOffset(8)]public ulong Size = 0;

            /// <summary>
            /// Copies a given SEALHeader to the current one.
            /// </summary>
            /// <param name="assign">The SEALHeader to copy from</param>
            /// <exception cref="ArgumentNullException">if assign is null</exception>
            public void Set(SEALHeader assign)
            {
                if (null == assign)
                    throw new ArgumentNullException(nameof(assign));

                Magic = assign.Magic;
                HeaderSize = assign.HeaderSize;
                VersionMajor = assign.VersionMajor;
                VersionMinor = assign.VersionMinor;
                ComprMode = assign.ComprMode;
                Reserved = assign.Reserved;
                Size = assign.Size;
            }
        };

        private static bool IsSupportedComprMode(byte comprMode)
        {
            NativeMethods.Serialization_IsSupportedComprMode(comprMode, out bool result);
            return result;
        }

        /// <summary>Returns true if the given value corresponds to a supported compression mode.</summary>
        /// <param name="comprMode">The compression mode to validate</param>
        public static bool IsSupportedComprMode(ComprModeType comprMode) =>
            IsSupportedComprMode((byte)comprMode);

        /// <summary>Returns true if the SEALHeader has a version number compatible with this version of
        /// Microsoft SEAL.</summary>
        /// <param name="header">The SEALHeader</param>
        public static bool IsCompatibleVersion(SEALHeader header)
        {
            byte[] headerArray = new byte[SEALHeaderSize];
            using (MemoryStream stream = new MemoryStream(headerArray))
            {
                SaveHeader(header, stream);
                NativeMethods.Serialization_IsCompatibleVersion(
                    headerArray, (ulong)headerArray.Length, out bool result);
                return result;
            }
        }

        /// <summary>Returns true if the given SEALHeader is valid for this version of Microsoft SEAL.</summary>
        /// <param name="header">The SEALHeader</param>
        public static bool IsValidHeader(SEALHeader header)
        {
            byte[] headerArray = new byte[SEALHeaderSize];
            using (MemoryStream stream = new MemoryStream(headerArray))
            {
                SaveHeader(header, stream);
                NativeMethods.Serialization_IsValidHeader(
                    headerArray, (ulong)headerArray.Length, out bool result);
                return result;
            }
        }

        /// <summary>Saves a SEALHeader to a given binary stream.</summary>
        /// <remarks>
        /// Saves a SEALHeader to a given stream. The output is in binary format and not human-readable.
        /// </remarks>
        /// <param name="header">The SEALHeader to save to the stream</param>
        /// <param name="stream">The stream to save the SEALHeader to</param>
        /// <exception cref="ArgumentNullException">if header or stream is null</exception>
        /// <exception cref="ArgumentException">if the stream is closed or does not support writing</exception>
        /// <exception cref="IOException">if I/O operations failed</exception>
        public static void SaveHeader(SEALHeader header, Stream stream)
        {
            if (null == header)
                throw new ArgumentNullException(nameof(header));
            if (null == stream)
                throw new ArgumentNullException(nameof(stream));
            if (!stream.CanWrite)
                throw new ArgumentException(nameof(stream));

            using (BinaryWriter writer = new BinaryWriter(stream, Encoding.UTF8, true))
            {
                writer.Write(header.Magic);
                writer.Write(header.HeaderSize);
                writer.Write(header.VersionMajor);
                writer.Write(header.VersionMinor);
                writer.Write((byte)header.ComprMode);
                writer.Write(header.Reserved);
                writer.Write(header.Size);
            }
        }

        /// <summary>Loads a SEALHeader from a given stream.</summary>
        /// <param name="stream">The stream to load the SEALHeader from</param>
        /// <param name="header">The SEALHeader to populate with the loaded data</param>
        /// <param name="tryUpgradeIfInvalid">If the loaded SEALHeader is invalid, attempt to identify its format and
        /// upgrade to the current SEALHeader version</param>
        /// <exception cref="ArgumentNullException">if header or stream is null</exception>
        /// <exception cref="ArgumentException">if the stream is closed or does not support reading</exception>
        /// <exception cref="InvalidOperationException">if the loaded data is not a valid SEALHeader or if the loaded
        /// compression mode is not supported</exception>
        /// <exception cref="EndOfStreamException">if the stream ended unexpectedly</exception>
        /// <exception cref="IOException">if I/O operations failed</exception>
        public static void LoadHeader(Stream stream, SEALHeader header, bool tryUpgradeIfInvalid = true)
        {
            if (null == header)
                throw new ArgumentNullException(nameof(header));
            if (null == stream)
                throw new ArgumentNullException(nameof(stream));
            if (!stream.CanRead)
                throw new ArgumentException(nameof(stream));

            using (BinaryReader reader = new BinaryReader(stream, Encoding.UTF8, true))
            {
                header.Magic = reader.ReadUInt16();
                header.HeaderSize = reader.ReadByte();
                header.VersionMajor = reader.ReadByte();
                header.VersionMinor = reader.ReadByte();
                header.ComprMode = (ComprModeType)reader.ReadByte();
                header.Reserved = reader.ReadUInt16();
                header.Size = reader.ReadUInt64();
            }

            // If header is invalid this may be an older header and we can try to automatically upgrade it
            if (tryUpgradeIfInvalid && !IsValidHeader(header))
            {
                // Try interpret the data as a Microsoft SEAL 3.4 header
                LegacyHeaders.SEALHeader_3_4 header_3_4 = new LegacyHeaders.SEALHeader_3_4(header);

                SEALHeader newHeader = new SEALHeader();
                // Copy over the fields; of course the result may not be valid depending on whether the input was a
                // valid version 3.4 header
                newHeader.ComprMode = header_3_4.ComprMode;
                newHeader.Size = header_3_4.Size;

                // Now validate the new header and discard if still not valid; something else is probably wrong
                if (IsValidHeader(newHeader))
                {
                    header.Set(newHeader);
                }
            }
        }

        internal delegate void SaveDelegate(
            byte[] outptr, ulong size, byte comprMode, out long outBytes);

        internal delegate void LoadDelegate(
            byte[] inptr, ulong size, out long inBytes);

        /// <summary>Saves data to a given binary stream.</summary>
        /// <remarks>
        /// First this function allocates a buffer of size <paramref name="size" />. The buffer is used by the
        /// <paramref name="SaveData"/> delegate that writes some number of bytes to the buffer and outputs (in
        /// out-parameter) the number of bytes written (less than the size of the buffer). The contents of the buffer
        /// are then written to <paramref name="stream"/> and the function returns the output value of
        /// <paramref name="SaveData"/>. This function is intended only for internal use.
        /// </remarks>
        /// <param name="SaveData">The delegate that writes some number of bytes to a given buffer</param>
        /// <param name="size">An upper bound on the number of bytes that <paramref name="SaveData" /> requires</param>
        /// <param name="comprMode">The desired compression mode</param>
        /// <param name="stream">The destination stream</param>
        /// <exception cref="ArgumentNullException">if SaveData or stream is null</exception>
        /// <exception cref="ArgumentException">if the stream is closed or does not support writing, or if size is
        /// negative or too large</exception>
        /// <exception cref="IOException">if I/O operations failed</exception>
        /// <exception cref="InvalidOperationException">if the data to be saved is invalid, if compression mode is not
        /// supported, or if compression failed</exception>
        internal static long Save(SaveDelegate SaveData, long size,
            ComprModeType comprMode, Stream stream)
        {
            if (null == stream)
                throw new ArgumentNullException(nameof(stream));
            if (null == SaveData)
                throw new ArgumentNullException(nameof(SaveData));
            if (!stream.CanWrite)
                throw new ArgumentException(nameof(stream));
            if (!IsSupportedComprMode(comprMode))
                throw new InvalidOperationException("Unsupported compression mode");

            try
            {
                int sizeInt = checked((int)size);
                byte[] buffer = new byte[sizeInt];
                SaveData(buffer, checked((ulong)sizeInt), (byte)comprMode, out long outBytes);
                int intOutBytes = checked((int)outBytes);
                using (BinaryWriter writer = new BinaryWriter(stream, Encoding.UTF8, true))
                {
                    writer.Write(buffer, 0, intOutBytes);
                }

                // Clear the buffer for safety reasons
                Array.Clear(buffer, 0, intOutBytes);

                return outBytes;
            }
            catch (OverflowException ex)
            {
                throw new ArgumentException($"{nameof(size)} is out of bounds", ex);
            }
        }

        /// <summary>Loads data from a given binary stream.</summary>
        /// <remarks>
        /// This function calls the <see cref="LoadHeader" /> function to first load a <see cref="SEALHeader" /> object
        /// from <paramref name="stream"/>. The <see cref="SEALHeader.Size"/> is then read from the
        /// <see cref="SEALHeader" /> and a buffer of corresponding size is allocated. Next, the buffer is filled with
        /// data read from <paramref name="stream"/> and <paramref name="LoadData"/> is called with the buffer as input,
        /// which outputs (in out-parameter) the number bytes read from the buffer. This should match exactly the size
        /// of the buffer. Finally, the function returns the output value of <paramref name="LoadData"/>. This function
        /// is intended only for internal use.
        /// </remarks>
        /// <param name="LoadData">The delegate that reads some number of bytes to a given buffer</param>
        /// <param name="stream">The input stream</param>
        /// <exception cref="ArgumentNullException">if LoadData or stream is null</exception>
        /// <exception cref="ArgumentException">if the stream is closed or does not support reading</exception>
        /// <exception cref="EndOfStreamException">if the stream ended unexpectedly</exception>
        /// <exception cref="IOException">if I/O operations failed</exception>
        /// <exception cref="InvalidOperationException">if the loaded data is invalid, if the loaded compression mode is
        /// not supported, or if size of the object is more than 2 GB</exception>
        internal static long Load(LoadDelegate LoadData, Stream stream)
        {
            if (null == stream)
                throw new ArgumentNullException(nameof(stream));
            if (null == LoadData)
                throw new ArgumentNullException(nameof(LoadData));
            if (!stream.CanRead)
                throw new ArgumentException(nameof(stream));

            try
            {
                SEALHeader header = new SEALHeader();
                var pos = stream.Position;
                LoadHeader(stream, header);

                // Check the validity of the header
                if (!IsCompatibleVersion(header))
                    throw new InvalidOperationException("Incompatible version");
                if (!IsSupportedComprMode(header.ComprMode))
                    throw new InvalidOperationException("Unsupported compression mode");
                if (!IsValidHeader(header))
                    throw new InvalidOperationException("Loaded SEALHeader is invalid");
                if (header.Size > checked((ulong)int.MaxValue))
                    throw new InvalidOperationException("Object size is larger than 2 GB");

                int sizeInt = checked((int)header.Size);
                stream.Seek(pos, SeekOrigin.Begin);

                byte[] buffer = null;
                using (BinaryReader reader = new BinaryReader(stream, Encoding.UTF8, true))
                {
                    buffer = reader.ReadBytes(sizeInt);
                }

                LoadData(buffer, header.Size, out long outBytes);

                // Clear the buffer for safety reasons
                Array.Clear(buffer, 0, sizeInt);

                return outBytes;
            }
            catch (OverflowException ex)
            {
                throw new InvalidOperationException("Size indicated by loaded SEALHeader is out of bounds", ex);
            }
        }
    }

    /// <summary>Class to contain header information for legacy headers.</summary>
    public abstract class LegacyHeaders
    {
        /// <summary>Class to enable compatibility with Microsoft SEAL 3.4 headers.</summary>
        [StructLayout(LayoutKind.Explicit, Size=16)]
        public class SEALHeader_3_4 : ISettable<SEALHeader_3_4>, ISettable<Serialization.SEALHeader>
        {
            /// <summary>SEALMagic</summary>
            [FieldOffset(0)]public ushort Magic = Serialization.SEALMagic;

            /// <summary>ZeroByte</summary>
            [FieldOffset(2)]public byte ZeroByte = 0;

            /// <summary>ComprModeType</summary>
            [FieldOffset(3)]public ComprModeType ComprMode = Serialization.ComprModeDefault;

            /// <summary>Size</summary>
            [FieldOffset(4)]public uint Size = 0;

            /// <summary>Reserved</summary>
            [FieldOffset(8)]public ulong Reserved = 0;

            /// <summary>Creates a new SEALHeader_3_4.</summary>
            public SEALHeader_3_4()
            {
            }

            /// <summary>
            /// Constructs a new SEALHeader_3_4 by copying a given one.
            /// </summary>
            /// <param name="copy">The SEALHeader_3_4 to copy from</param>
            /// <exception cref="ArgumentNullException">if copy is null</exception>
            public SEALHeader_3_4(Serialization.SEALHeader copy)
            {
                if (null == copy)
                    throw new ArgumentNullException(nameof(copy));

                Set(copy);
            }

            /// <summary>Copies a given SEALHeader_3_4 to the current one.</summary>
            /// <param name="assign">The SEALHeader_3_4 to copy from</param>
            /// <exception cref="ArgumentNullException">if assign is null</exception>
            public void Set(SEALHeader_3_4 assign)
            {
                if (null == assign)
                    throw new ArgumentNullException(nameof(assign));

                Magic = assign.Magic;
                ZeroByte = assign.ZeroByte;
                ComprMode = assign.ComprMode;
                Size = assign.Size;
                Reserved = assign.Reserved;
            }

            /// <summary>Copies a given SEALHeader to the current one as a byte array.</summary>
            /// <param name="assign">The SEALHeader to copy from</param>
            /// <exception cref="ArgumentNullException">if assign is null</exception>
            public void Set(Serialization.SEALHeader assign)
            {
                if (null == assign)
                    throw new ArgumentNullException(nameof(assign));

                GCHandle gch = GCHandle.Alloc(this, GCHandleType.Pinned);
                Marshal.StructureToPtr(assign, gch.AddrOfPinnedObject(), false);
                gch.Free();
            }
        };
    }
}
