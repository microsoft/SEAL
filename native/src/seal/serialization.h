// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#pragma once

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
        // Use Deflate compression
        deflate = 1,
#endif
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
        The compression mode used by default.
        */
#ifdef SEAL_USE_ZLIB
        static constexpr compr_mode_type compr_mode_default = compr_mode_type::deflate;
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
        Struct to contain metadata for serialization comprising the following fields:

        1. a magic number identifying this is a SEALHeader struct (2 bytes)
        2. size in bytes of the SEALHeader struct (1 byte)
        3. Microsoft SEAL's major version number (1 byte)
        4. Microsoft SEAL's minor version number (1 byte)
        5. a compr_mode_type indicating whether data after the header is compressed (1 byte)
        6. reserved for future use and data alignment (2 bytes)
        7. the size in bytes of the entire serialized object, including the header (8 bytes)
        */
        struct SEALHeader
        {
            std::uint16_t magic = seal_magic;

            std::uint8_t header_size = seal_header_size;

            std::uint8_t version_major = static_cast<std::uint8_t>(SEAL_VERSION_MAJOR);

            std::uint8_t version_minor = static_cast<std::uint8_t>(SEAL_VERSION_MINOR);

            compr_mode_type compr_mode = compr_mode_type::none;

            std::uint16_t reserved = 0;

            std::uint64_t size = 0;
        };

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
            case static_cast<std::uint8_t>(compr_mode_type::deflate):
#endif
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
            return (header.version_major == SEAL_VERSION_MAJOR && header.version_minor == SEAL_VERSION_MINOR);
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
        static std::streamoff SaveHeader(const SEALHeader &header, SEAL_BYTE *out, std::size_t size);

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
            const SEAL_BYTE *in, std::size_t size, SEALHeader &header, bool try_upgrade_if_invalid = true);

        /**
        Evaluates save_members and compresses the output according to the given
        compr_mode_type. The resulting data is written to stream and is prepended
        by the given compr_mode_type and the total size of the data to facilitate
        deserialization. In typical use-cases save_members would be a function
        that serializes the member variables of an object to the given stream.

        For any given compression mode, raw_size must be the exact right size
        (in bytes) of what save_members writes to a stream in the uncompressed
        mode. Otherwise the behavior of Save is unspecified.

        @param[in] save_members A function taking an std::ostream reference as an
        argument, possibly writing some number of bytes into it
        @param[in] raw_size The exact uncompressed output size of save_members
        @param[out] stream The stream to write to
        @param[in] compr_mode The desired compression mode
        @throws std::invalid_argument if save_members is invalid
        @throws std::invalid_argument if raw_size is smaller than SEALHeader size
        @throws std::logic_error if the data to be saved is invalid, if compression
        mode is not supported, or if compression failed
        @throws std::runtime_error if I/O operations failed
        */
        static std::streamoff Save(
            std::function<void(std::ostream &stream)> save_members, std::streamoff raw_size, std::ostream &stream,
            compr_mode_type compr_mode, bool clear_on_destruction = false);

        /**
        Deserializes data from stream that was serialized by Save. Once stream has
        been decompressed (depending on compression mode), load_members is applied
        to the decompressed stream. In typical use-cases load_members would be
        a function that deserializes the member variables of an object from the
        given stream.

        @param[in] load_members A function taking an std::istream reference as an
        argument, possibly reading some number of bytes from it
        @param[in] stream The stream to read from
        @throws std::invalid_argument if load_members is invalid
        @throws std::logic_error if the data cannot be loaded by this version of
        Microsoft SEAL, if the loaded data is invalid, or if decompression failed
        @throws std::runtime_error if I/O operations failed
        */
        static std::streamoff Load(
            std::function<void(std::istream &stream)> load_members, std::istream &stream,
            bool clear_on_destruction = false);

        /**
        Evaluates save_members and compresses the output according to the given
        compr_mode_type. The resulting data is written to a given memory location
        and is prepended by the given compr_mode_type and the total size of the
        data to facilitate deserialization. In typical use-cases save_members would
        be a function that serializes the member variables of an object to the
        given stream.

        For any given compression mode, raw_size must be the exact right size
        (in bytes) of what save_members writes to a stream in the uncompressed
        mode. Otherwise the behavior of Save is unspecified.

        @param[in] save_members A function that takes an std::ostream reference as
        an argument and writes some number of bytes into it
        @param[in] raw_size The exact uncompressed output size of save_members
        @param[out] out The memory location to write to
        @param[in] size The number of bytes available in the given memory location
        @param[in] compr_mode The desired compression mode
        @throws std::invalid_argument if save_members is invalid, if raw_size or
        size is smaller than SEALHeader size, or if out is null
        @throws std::logic_error if the data to be saved is invalid, if compression
        mode is not supported, or if compression failed
        @throws std::runtime_error if I/O operations failed
        */
        static std::streamoff Save(
            std::function<void(std::ostream &stream)> save_members, std::streamoff raw_size, SEAL_BYTE *out,
            std::size_t size, compr_mode_type compr_mode, bool clear_on_destruction = false);

        /**
        Deserializes data from a memory location that was serialized by Save.
        Once the data has been decompressed (depending on compression mode),
        load_members is applied to the decompressed stream. In typical use-cases
        load_members would be a function that deserializes the member variables
        of an object from the given stream.

        @param[in] load_members A function that takes an std::istream reference as
        an argument and reads some number of bytes from it
        @param[in] in The memory location to read from
        @param[in] size The number of bytes available in the given memory location
        @throws std::invalid_argument if load_members is invalid, if in is null,
        or if size is too small to contain a SEALHeader
        @throws std::logic_error if the data cannot be loaded by this version of
        Microsoft SEAL, if the loaded data is invalid, or if decompression failed
        @throws std::runtime_error if I/O operations failed
        */
        static std::streamoff Load(
            std::function<void(std::istream &stream)> load_members, const SEAL_BYTE *in, std::size_t size,
            bool clear_on_destruction = false);

    private:
        Serialization() = delete;
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
                std::memcpy(this, &assign, sizeof(Serialization::SEALHeader));
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
