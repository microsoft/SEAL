// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

using System;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;

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

        /// <summary>Struct to contain header information for serialization.</summary>
        /// <remarks>
        /// Struct to contain header information for serialization. The size of the
        /// header is 16 bytes and it consists of the following fields:
        ///
        /// 1. a magic number identifying this is a SEALHeader struct (2 bytes)
        /// 2. 0x00 (1 byte)
        /// 3. a compr_mode_type indicating whether data after the header is compressed (1 byte)
        /// 4. the size in bytes of the entire serialized object, including the header (4 bytes)
        /// 5. reserved for future use (8 bytes)
        /// </remarks>
        public class SEALHeader
        {
            /// <summary>A magic number identifying this as a SEALHeader struct
            /// (2 bytes)</summary>
            public ushort Magic = SEALMagic;

            /// <summary>0x00 (1 byte)</summary>
            public byte ZeroByte = 0x00;

            /// <summary>A ComprModeType indicating whether data after the header is
            /// compressed (1 byte)</summary>
            public ComprModeType ComprMode = ComprModeDefault;

            /// <summary>The size in bytes of the entire serialized object, including the
            /// header (4 bytes)</summary>
            public uint Size = 0;

            /// <summary>Reserved for future use (8 bytes)</summary>
            public uint Reserved = 0;
        };

        private static bool IsSupportedComprMode(byte comprMode)
        {
            NativeMethods.Serialization_IsSupportedComprMode(comprMode, out bool result);
            return result;
        }

        internal static bool IsSupportedComprMode(ComprModeType comprMode) =>
            IsSupportedComprMode((byte)comprMode);

        internal static bool IsValidHeader(SEALHeader header)
        {
            byte[] headerArray = new byte[16];
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
        /// Saves a SEALHeader to a given stream. The output is in binary format and
        /// not human-readable.
        /// </remarks>
        /// <param name="header">The SEALHeader to save to the stream</param>
        /// <param name="stream">The stream to save the SEALHeader to</param>
        /// <exception cref="ArgumentNullException">if header or stream is null</exception>
        /// <exception cref="ArgumentException">if the stream is closed or does not support
        /// writing</exception>
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
                writer.Write(header.ZeroByte);
                writer.Write((byte)header.ComprMode);
                writer.Write(header.Reserved);
            }
        }

        /// <summary>Loads a SEALHeader from a given stream.</summary>
        /// <param name="stream">The stream to load the SEALHeader from</param>
        /// <param name="header">The SEALHeader to populate with the loaded data</param>
        /// <exception cref="ArgumentNullException">if header or stream is null</exception>
        /// <exception cref="ArgumentException">if the stream is closed or does not support
        /// reading</exception>
        /// <exception cref="InvalidOperationException">if the loaded data is not a valid
        /// SEALHeader or if the loaded compression mode is not supported</exception>
        /// <exception cref="EndOfStreamException">if the stream ended unexpectedly</exception>
        /// <exception cref="IOException">if I/O operations failed</exception>
        public static void LoadHeader(Stream stream, SEALHeader header)
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
                header.ZeroByte = reader.ReadByte();
                header.ComprMode = (ComprModeType)reader.ReadByte();
                header.Size = reader.ReadUInt32();
            }
        }

        internal delegate void SaveDelegate(
            byte[] outptr, ulong size, byte comprMode, out long outBytes);

        internal delegate void LoadDelegate(
            byte[] inptr, ulong size, out long inBytes);

        /// <summary>Saves data to a given binary stream.</summary>
        /// <remarks>
        /// First this function allocates a buffer of size <paramref name="size" />.
        /// The buffer is used by the <paramref name="SaveData"/> delegate that
        /// writes some number of bytes to the buffer and outputs (in out-parameter)
        /// the number of bytes written (less than the size of the buffer). The
        /// contents of the buffer are then written to <paramref name="stream"/> and
        /// the function returns the output value of <paramref name="SaveData"/>.
        /// This function is intended only for internal use.
        /// </remarks>
        /// <param name="SaveData">The delegate that writes some number of bytes to
        /// a given buffer</param>
        /// <param name="size">An upper bound on the number of bytes that
        /// <paramref name="SaveData" /> requires</param>
        /// <param name="comprMode">The desired compression mode</param>
        /// <param name="stream">The destination stream</param>
        /// <exception cref="ArgumentNullException">if SaveData or stream is
        /// null</exception>
        /// <exception cref="ArgumentException">if the stream is closed or does not
        /// support writing, or if size is negative or too large</exception>
        /// <exception cref="IOException">if I/O operations failed</exception>
        /// <exception cref="InvalidOperationException">if the data to be saved is
        /// invalid, if compression mode is not supported, or if compression
        /// failed</exception>
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
                byte[] buffer = new byte[size];
                SaveData(buffer, checked((ulong)size), (byte)comprMode, out long outBytes);
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
        /// This function calls the <see cref="LoadHeader" /> function to first load
        /// a <see cref="SEALHeader" /> object from <paramref name="stream"/>. The
        /// <see cref="SEALHeader.Size"/> is then read from the <see cref="SEALHeader" />
        /// and a buffer of corresponding size is allocated. Next, the buffer is
        /// filled with data read from <paramref name="stream"/> and <paramref name="LoadData"/>
        /// is called with the buffer as input, which outputs (in out-parameter) the
        /// number bytes read from the buffer. This should match exactly the size of
        /// the buffer. Finally, the function returns the output value of
        /// <paramref name="LoadData"/>. This function is intended only for internal
        /// use.
        /// </remarks>
        /// <param name="LoadData">The delegate that reads some number of bytes to
        /// a given buffer</param>
        /// <param name="stream">The input stream</param>
        /// <exception cref="ArgumentNullException">if LoadData or stream is null</exception>
        /// <exception cref="ArgumentException">if the stream is closed or does not
        /// support reading</exception>
        /// <exception cref="EndOfStreamException">if the stream ended unexpectedly</exception>
        /// <exception cref="IOException">if I/O operations failed</exception>
        /// <exception cref="InvalidOperationException">if the loaded data is invalid
        /// or if the loaded compression mode is not supported</exception>
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
                if (!IsSupportedComprMode(header.ComprMode))
                    throw new InvalidOperationException("Unsupported compression mode");
                if (!IsValidHeader(header))
                    throw new InvalidOperationException("Loaded SEALHeader is invalid");

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
}
