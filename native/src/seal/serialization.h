// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#pragma once

#include "seal/version.h"
#include "seal/util/defines.h"
#include <cstdint>
#include <cstring>
#include <functional>
#include <iostream>

namespace seal
{
    /**
    A type to describe the compression algorithm applied to serialized data.
    Ciphertext and key data consist of a large number of 64-bit words storing
    integers modulo prime numbers much smaller than the word size, resulting in
    a large number of zero bytes in the output. Any compression algorithm should
    be able to clean up these zero bytes and hence compress both ciphertext and
    key data.
    */
    enum class compr_mode_type : std::uint8_t
    {
        // No compression is used.
        none = 0,
#ifdef SEAL_USE_ZLIB
        // Use ZLIB compression
        zlib = 1,
#endif
#ifdef SEAL_USE_ZSTD
        // Use Zstandard compression
        zstd = 2,
#endif
        // Use bit-packing, which removes the high-order bits, and the low-order bits, that are zero in all 64-bit
        // words of a block of data. It is designed for ciphertext and key data, requires no external library, and
        // performs no integrity checking. Loading requires Microsoft SEAL 4.6 or later.
        bitpack = 3,
    };

    /**
    Class to provide functionality for serialization. Most users of the library
    should never have to call these functions explicitly, as they are called
    internally by functions such as Ciphertext::save and Ciphertext::load.
    */
    class Serialization
    {
    public:
        /**
        The compression mode used by default; prefer Zstandard
        */
#if defined(SEAL_USE_ZSTD)
        static constexpr compr_mode_type compr_mode_default = compr_mode_type::zstd;
#elif defined(SEAL_USE_ZLIB)
        static constexpr compr_mode_type compr_mode_default = compr_mode_type::zlib;
#else
        static constexpr compr_mode_type compr_mode_default = compr_mode_type::none;
#endif
        /**
        The magic value indicating a Microsoft SEAL header.
        */
        static constexpr std::uint16_t seal_magic = 0xA15E;

        /**
        The size in bytes of the SEALHeader.
        */
        static constexpr std::uint8_t seal_header_size = 0x10;

        /**
        The serialization format version written to SEALHeader by default. Rather
        than the library version, SEALHeader records the Microsoft SEAL version that
        introduced the serialization format of the object. Microsoft SEAL 4.4 and
        later load any format up to their own version, and Microsoft SEAL 4.0 loads
        format 4.0; Microsoft SEAL 4.1-4.3 accept only their own version. The format
        is unchanged since Microsoft SEAL 4.0, except that BGV ciphertexts are in NTT
        form since Microsoft SEAL 4.1 and bit-packed objects require Microsoft SEAL
        4.6. Objects that save the members of another type directly, such as keys,
        must be updated whenever that type's format changes.
        */
        static constexpr std::uint8_t format_version_major = 4;

        /**
        The serialization format minor version written to SEALHeader by default.
        */
        static constexpr std::uint8_t format_version_minor = 0;

        /**
        The serialization format minor version written to SEALHeader for NTT-form
        ciphertexts. The scheme is unknown when saving, so every NTT-form ciphertext
        (BGV, CKKS, or BFV transformed to NTT form) uses this version to prevent
        Microsoft SEAL 4.0 from misinterpreting BGV ciphertexts. Keys use
        format_version_minor. Nested headers use format_version_minor, so Microsoft
        SEAL 4.1 cannot load these ciphertexts either.
        */
        static constexpr std::uint8_t format_version_minor_ntt_ciphertext = 1;

        /**
        The serialization format minor version written to SEALHeader for bit-packed
        objects. Earlier Microsoft SEAL 4.x releases do not understand the bit-packed
        wire format and reject these objects as incompatible. Save writes at least
        this version for bit-packed data, and IsValidHeader rejects bit-packed data
        with an older version.
        */
        static constexpr std::uint8_t format_version_minor_bitpack = 6;

        static_assert(format_version_minor_bitpack <= SEAL_VERSION_MINOR, "bitpack format version is too new");

        /**
        Struct to contain metadata for serialization comprising the following fields:

        1. a magic number identifying this is a SEALHeader struct (2 bytes)
        2. size in bytes of the SEALHeader struct (1 byte)
        3. serialization format major version number (1 byte)
        4. serialization format minor version number (1 byte)
        5. a compr_mode_type indicating whether data after the header is compressed (1 byte)
        6. reserved for future use and data alignment (2 bytes)
        7. the size in bytes of the entire serialized object, including the header (8 bytes)

        Microsoft SEAL 4.4.x and earlier wrote the library version number instead
        of the serialization format version number. Bit-packed objects are written
        with format version 4.6.
        */
        struct SEALHeader
        {
            std::uint16_t magic = seal_magic;

            std::uint8_t header_size = seal_header_size;

            std::uint8_t version_major = format_version_major;

            std::uint8_t version_minor = format_version_minor;

            compr_mode_type compr_mode = compr_mode_type::none;

            std::uint16_t reserved = 0;

            std::uint64_t size = 0;
        };

        static_assert(sizeof(SEALHeader) == seal_header_size, "");

        /**
        Returns true if the given byte corresponds to a supported compression mode.

        @param[in] compr_mode The compression mode to validate
        */
        SEAL_NODISCARD static bool IsSupportedComprMode(std::uint8_t compr_mode) noexcept
        {
            switch (compr_mode)
            {
            case static_cast<std::uint8_t>(compr_mode_type::none):
                /* fall through */
#ifdef SEAL_USE_ZLIB
            case static_cast<std::uint8_t>(compr_mode_type::zlib):
                /* fall through */
#endif
#ifdef SEAL_USE_ZSTD
            case static_cast<std::uint8_t>(compr_mode_type::zstd):
                /* fall through */
#endif
            case static_cast<std::uint8_t>(compr_mode_type::bitpack):
                return true;
            }
            return false;
        }

        /**
        Returns true if the given value corresponds to a supported compression mode.

        @param[in] compr_mode The compression mode to validate
        */
        SEAL_NODISCARD static inline bool IsSupportedComprMode(compr_mode_type compr_mode) noexcept
        {
            return IsSupportedComprMode(static_cast<uint8_t>(compr_mode));
        }

        /**
        Returns an upper bound on the output size of data compressed according to
        a given compression mode with given input size. If compr_mode is
        compr_mode_type::none, the return value is exactly in_size.

        @param[in] in_size The input size to a compression algorithm
        @param[in] in_size The compression mode
        @throws std::invalid_argument if the compression mode is not supported
        */
        SEAL_NODISCARD static std::size_t ComprSizeEstimate(std::size_t in_size, compr_mode_type compr_mode);

        /**
        Returns true if the SEALHeader has a version number compatible with this version of Microsoft SEAL.

        @param[in] header The SEALHeader
        */
        SEAL_NODISCARD static bool IsCompatibleVersion(const SEALHeader &header) noexcept
        {
            // Same major version and no newer minor version. A format change uses the
            // version of the release introducing it, so this rejects newer formats and
            // accepts the library versions written by Microsoft SEAL 4.1-4.4.x.
            if (header.version_major == SEAL_VERSION_MAJOR && header.version_minor <= SEAL_VERSION_MINOR)
            {
                return true;
            }

            // Different major versions not supported
            if (header.version_major != SEAL_VERSION_MAJOR && header.version_major != 3)
            {
                return false;
            }

            // Support Microsoft SEAL 3.4 and above
            if (header.version_major == 3 && header.version_minor >= 4)
            {
                return true;
            }

            return false;
        }

        /**
        Returns true if the given SEALHeader is valid for this version of Microsoft SEAL.

        @param[in] header The SEALHeader
        */
        SEAL_NODISCARD static bool IsValidHeader(const SEALHeader &header) noexcept
        {
            if (header.magic != seal_magic)
            {
                return false;
            }
            if (header.header_size != seal_header_size)
            {
                return false;
            }
            if (!IsCompatibleVersion(header))
            {
                return false;
            }
            if (!IsSupportedComprMode(static_cast<uint8_t>(header.compr_mode)))
            {
                return false;
            }
            if (header.compr_mode == compr_mode_type::bitpack &&
                (header.version_major != format_version_major || header.version_minor < format_version_minor_bitpack))
            {
                return false;
            }
            return true;
        }

        /**
        Saves a SEALHeader to a given stream. The output is in binary format and
        not human-readable. The output stream must have the "binary" flag set.

        @param[in] header The SEALHeader to save to the stream
        @param[out] stream The stream to save the SEALHeader to
        @throws std::runtime_error if I/O operations failed
        */
        static std::streamoff SaveHeader(const SEALHeader &header, std::ostream &stream);

        /**
        Loads a SEALHeader from a given stream.

        @param[in] stream The stream to load the SEALHeader from
        @param[in] header The SEALHeader to populate with the loaded data
        @param[in] try_upgrade_if_invalid If the loaded SEALHeader is invalid,
        attempt to identify its format and upgrade to the current SEALHeader version
        @throws std::runtime_error if I/O operations failed
        */
        static std::streamoff LoadHeader(std::istream &stream, SEALHeader &header, bool try_upgrade_if_invalid = true);

        /**
        Saves a SEALHeader to a given memory location. The output is in binary
        format and is not human-readable.

        @param[out] out The memory location to write the SEALHeader to
        @param[in] size The number of bytes available in the given memory location
        @throws std::invalid_argument if out is null or if size is too small to
        contain a SEALHeader
        @throws std::runtime_error if I/O operations failed
        */
        static std::streamoff SaveHeader(const SEALHeader &header, seal_byte *out, std::size_t size);

        /**
        Loads a SEALHeader from a given memory location.

        @param[in] in The memory location to load the SEALHeader from
        @param[in] size The number of bytes available in the given memory location
        @param[in] try_upgrade_if_invalid If the loaded SEALHeader is invalid,
        attempt to identify its format and upgrade to the current SEALHeader version
        @throws std::invalid_argument if in is null or if size is too small to
        contain a SEALHeader
        @throws std::runtime_error if I/O operations failed
        */
        static std::streamoff LoadHeader(
            const seal_byte *in, std::size_t size, SEALHeader &header, bool try_upgrade_if_invalid = true);

        /**
        Evaluates save_members and compresses the output according to the given
        compr_mode_type. The resulting data is written to stream and is prepended
        by the given compr_mode_type and the total size of the data to facilitate
        deserialization. In typical use-cases save_members would be a function
        that serializes the member variables of an object to the given stream.

        For any given compression mode, raw_size must be the exact right size
        (in bytes) of what save_members writes to a stream in the uncompressed
        mode plus the size of SEALHeader. Otherwise the behavior of Save is
        unspecified.

        @param[in] save_members A function taking an std::ostream reference as an
        argument, possibly writing some number of bytes into it
        @param[in] raw_size The exact uncompressed output size of save_members
        plus the size of SEALHeader
        @param[out] stream The stream to write to
        @param[in] compr_mode The desired compression mode
        @param[in] clear_buffers Whether internal buffers should be cleared
        @param[in] version_minor The serialization format minor version to write
        to SEALHeader; bit-packed data is raised to format_version_minor_bitpack
        @throws std::invalid_argument if save_members is invalid
        @throws std::invalid_argument if raw_size is smaller than SEALHeader size
        @throws std::invalid_argument if version_minor is newer than this version
        of Microsoft SEAL
        @throws std::logic_error if the data to be saved is invalid, if compression
        mode is not supported, or if compression failed
        @throws std::runtime_error if I/O operations failed
        */
        static std::streamoff Save(
            std::function<void(std::ostream &)> save_members, std::streamoff raw_size, std::ostream &stream,
            compr_mode_type compr_mode, bool clear_buffers, std::uint8_t version_minor = format_version_minor);

        /**
        Deserializes data from stream that was serialized by Save. Once stream has
        been decompressed (depending on compression mode), load_members is applied
        to the decompressed stream. In typical use-cases load_members would be
        a function that deserializes the member variables of an object from the
        given stream.

        @param[in] load_members A function taking an std::istream reference and
        a SEALVersion struct as arguments, possibly reading some number of bytes
        from the std::istream, possibly depending on the SEALVersion object
        @param[in] stream The stream to read from
        @param[in] clear_buffers Whether internal buffers should be cleared
        @throws std::invalid_argument if load_members is invalid
        @throws std::logic_error if the data cannot be loaded by this version of
        Microsoft SEAL, if the loaded data is invalid, or if decompression failed
        @throws std::runtime_error if I/O operations failed
        */
        static std::streamoff Load(
            std::function<void(std::istream &, SEALVersion)> load_members, std::istream &stream, bool clear_buffers);

        /**
        Evaluates save_members and compresses the output according to the given
        compr_mode_type. The resulting data is written to a given memory location
        and is prepended by the given compr_mode_type and the total size of the
        data to facilitate deserialization. In typical use-cases save_members would
        be a function that serializes the member variables of an object to the
        given stream.

        For any given compression mode, raw_size must be the exact right size
        (in bytes) of what save_members writes to a stream in the uncompressed
        mode plus the size of SEALHeader. Otherwise the behavior of Save is
        unspecified.

        @param[in] save_members A function that takes an std::ostream reference as
        an argument and writes some number of bytes into it
        @param[in] raw_size The exact uncompressed output size of save_members
        plus the size of SEALHeader
        @param[out] out The memory location to write to
        @param[in] size The number of bytes available in the given memory location
        @param[in] compr_mode The desired compression mode
        @param[in] clear_buffers Whether internal buffers should be cleared
        @param[in] version_minor The serialization format minor version to write
        to SEALHeader; bit-packed data is raised to format_version_minor_bitpack
        @throws std::invalid_argument if save_members is invalid, if raw_size or
        size is smaller than SEALHeader size, if out is null, or if version_minor
        is newer than this version of Microsoft SEAL
        @throws std::logic_error if the data to be saved is invalid, if compression
        mode is not supported, or if compression failed
        @throws std::runtime_error if I/O operations failed
        */
        static std::streamoff Save(
            std::function<void(std::ostream &)> save_members, std::streamoff raw_size, seal_byte *out, std::size_t size,
            compr_mode_type compr_mode, bool clear_buffers, std::uint8_t version_minor = format_version_minor);

        /**
        Deserializes data from a memory location that was serialized by Save.
        Once the data has been decompressed (depending on compression mode),
        load_members is applied to the decompressed stream. In typical use-cases
        load_members would be a function that deserializes the member variables
        of an object from the given stream.

        @param[in] load_members A function that takes an std::istream reference as
        a SEALVersion struct as arguments, possibly reading some number of bytes
        from the std::istream, possibly depending on the SEALVersion object
        @param[in] in The memory location to read from
        @param[in] size The number of bytes available in the given memory location
        @param[in] clear_buffers Whether internal buffers should be cleared
        @throws std::invalid_argument if load_members is invalid, if in is null,
        or if size is too small to contain a SEALHeader
        @throws std::logic_error if the data cannot be loaded by this version of
        Microsoft SEAL, if the loaded data is invalid, or if decompression failed
        @throws std::runtime_error if I/O operations failed
        */
        static std::streamoff Load(
            std::function<void(std::istream &, SEALVersion)> load_members, const seal_byte *in, std::size_t size,
            bool clear_buffers);

    private:
        Serialization() = delete;

        friend class KSwitchKeys;

        // The following overloads of Load are the same as the public ones, except that if bounded_expansion is true,
        // compressed data is rejected if it expands far more than valid key data can, and objects nested in the data
        // must not be compressed.
        static std::streamoff Load(
            std::function<void(std::istream &, SEALVersion)> load_members, std::istream &stream, bool clear_buffers,
            bool bounded_expansion);

        static std::streamoff Load(
            std::function<void(std::istream &, SEALVersion)> load_members, const seal_byte *in, std::size_t size,
            bool clear_buffers, bool bounded_expansion);
    };

    namespace legacy_headers
    {
        /**
        Struct to enable compatibility with Microsoft SEAL 3.4 headers.
        */
        struct SEALHeader_3_4
        {
            std::uint16_t magic = Serialization::seal_magic;

            std::uint8_t zero_byte = 0x00;

            compr_mode_type compr_mode = compr_mode_type::none;

            std::uint32_t size = 0;

            std::uint64_t reserved = 0;

            SEALHeader_3_4 &operator=(const Serialization::SEALHeader assign)
            {
                std::memcpy(this, &assign, Serialization::seal_header_size);
                return *this;
            }

            SEALHeader_3_4() = default;

            SEALHeader_3_4(const Serialization::SEALHeader &copy)
            {
                operator=(copy);
            }
        };
    } // namespace legacy_headers
} // namespace seal
