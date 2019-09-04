// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

using Microsoft.Research.SEAL.Tools;
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
        none = 0
    }

    /// <summary> 
    /// The compression mode used by default.
    /// </summary>
    ComprModeType comprModeDefault = ComprModeType.None;

    /// <summary>
    /// 
    /// </summary>
    /// <remarks>
    /// <para>
    /// Memory Management
    /// The size of a ciphertext refers to the number of polynomials it contains,
    /// whereas its capacity refers to the number of polynomials that fit in the
    /// current memory allocation. In high-performance applications unnecessary
    /// re-allocations should be avoided by reserving enough memory for the
    /// ciphertext to begin with either by providing the desired capacity to the
    /// constructor as an extra argument, or by calling the reserve function at
    /// any time.
    /// </para>
    /// <para>
    /// Thread Safety
    /// In general, reading from ciphertext is thread-safe as long as no other
    /// thread is concurrently mutating it. This is due to the underlying data
    /// structure storing the ciphertext not being thread-safe.
    /// </para>
    /// </remarks>
    /// <seealso cref="Plaintext">See Plaintext for the class that stores plaintexts.</seealso>
    //public class Ciphertext : NativeObject
    /**
    Class to provide functionality for compressed serialization. Most users of
    the library should never have to call these functions explicitly, as they are
    called internally by functions such as Ciphertext::save and Ciphertext::load.
    */
    public abstract class Serialization
    {
        static System.UInt16 sealMagic = 0x5EA1;

        /**
        Struct to contain header information for serialization. The size of the
        header is 9 bytes and it consists of the following fields:

        1. a magic number 0x5EA1 identifying this is a SEALHeader struct (2 bytes)
        2. a version identifier, possibly 0x0000 (2 bytes)
        3. a compr_mode_type indicating whether data after the header is compressed (1 byte)
        4. the size in bytes of the entire serialized object, including the header (4 bytes)
        */
        struct SEALHeader
        {
            std::uint16_t magic = seal_magic;

            std::uint16_t version = 0x0000;

            compr_mode_type compr_mode;

            std::uint32_t size;
        };

        /**
        Saves a SEALHeader to a given stream. The output is in binary format and
        not human-readable. The output stream must have the "binary" flag set.

        @param[in] header The SEALHeader to save to the stream
        @param[out] stream The stream to save the SEALHeader to
        */
        static void SaveHeader(const SEALHeader &header, std::ostream &stream);

        /**
        Loads a SEALHeader from a given stream.

        @param[in] stream The stream to load the SEALHeader from
        @param[in] header The SEALHeader to populate with the loaded data
        */
        static void LoadHeader(std::istream &stream, SEALHeader &header);
