// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#pragma once

#include "seal/dynarray.h"
#include "seal/memorymanager.h"
#include "seal/util/common.h"
#include "seal/util/defines.h"
#include "seal/util/pointer.h"
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <ios>
#include <iostream>
#include <memory>
#include <streambuf>

namespace seal
{
    namespace util
    {
        namespace bitpack
        {
            /**
            The functions in this namespace implement the compr_mode_type::bitpack encoding of a serialized byte
            stream. This can be thought of as a compression algorithm designed specifically for the types of byte
            streams SEAL will most often be serializing.

            The vast majority of data serialized / deserialized by SEAL will be arrays of uint64_t representing
            polynomial coefficients in RNS form. Each of the uint64_ts in a single array will be residues modulo
            some prime q, where q < 2^61. Thus, some number of high-order bits of these values will always be zero,
            while the lower-order bits will (when serializing any cryptographic data) have high entropy, unless an
            application has cleared some of them: some applications clear the low-order bits of ciphertext
            coefficients that decryption does not need, to make the ciphertexts they send smaller. Standard
            compression algorithms like zlib are designed to operate on whole bytes, so they will fail to compress any
            zero bits that do not appear as a whole byte, and the high-entropy cryptographic bits are incompressible.

            The optimal way to compress these arrays of polynomial coefficients would be to simply use knowledge
            of q to append one coefficient after another with no padding bits in between. However, SEAL's serialization
            API deliberately hides details of the payload's schema from the serializer, which just sees a raw byte
            stream. While the majority of that byte stream will usually contain these uint64_t arrays, each array
            may have a different value of q, and the stream may be interspersed with other small data structures such
            as metadata, parms_ids, etc.

            The bitpack compression scheme works by breaking the byte stream up into blocks of bitpack_block_bytes
            (1024) bytes, and attempting to compress each block as if it contains a section of a uint64_t array of
            polynomial coefficients modulo some q, using the strategy described below. On blocks that really do
            contain such data, it achieves near-optimal compression; on blocks that contain any other kind of data
            it will probably not compress the data at all, but such blocks are rare enough that the overall
            performance when applied to real SEAL payloads is closer to optimal than standard compression algorithms
            can achieve.

            The structure of the output of bitpack compression is as follows. It begins with a 9-byte header,
            consisting of the original size of the byte array pre-compression (8 bytes, little-endian), and the log of
            the block size used for the stream (1 byte). Serialization format version 4.6
            (Serialization::format_version_minor_bitpack) requires the block size to be 2^bitpack_block_log2 = 1024
            bytes; a later format version may allow other block sizes. The remainder of the output is a series of
            compressed blocks, one for each block of the input; the last block may be shorter than 1024 bytes.

            +---------------+------------+---------+---------+--   --+---------+
            | original size | block size | block 0 | block 1 |  ...  | block k |
            |   (8 bytes)   |   (log2,   |         |         |       |         |
            |               |   1 byte)  |         |         |       |         |
            +---------------+------------+---------+---------+--   --+---------+

            The compression algorithm for each block works independently, as follows. The algorithm assumes that
            the input block contains a series of uint64_t values, each stored as 8 consecutive bytes in little-endian
            order, with some number of high bits, and possibly some number of low bits, that are consistently 0;
            however, the first uint64_t value may start some number of bytes after the start of the block. Those bytes
            may hold the end of a value that started in the previous block, or other data, such as the metadata of a
            ciphertext. They are called the "prefix" and are stored verbatim. The compression algorithm simply tries
            all prefix lengths from 0 to bitpack_prefix_max (255) bytes (at most the block length) and proceeds with
            the one that yields the smallest compressed block, choosing the shortest such prefix.

            An example input block might begin like the following. (The annotations below the figure represent where
            the data came from.)

             00  00  00  00  00  25  EB  79  2B  00  00  00  00  14  AC  2D  27  00  00  00 ...
            +-------------------+-------------------------------+---------------------------+
            | metadata tail     |         coefficient 0         |       coefficient 1       |
            | (from prev block) |     0x2B79EB25 -> 30 bits     |     0x272DAC14 -> 30 bits |
            +-------------------+-------------------------------+---------------------------+

            Here we can see that the optimal prefix will be 5 bytes, since this stream does actually contain an array
            of uint64_t values and they start on the sixth byte. The algorithm will then read the remainder of the
            block as little-endian uint64_ts, bitwise-OR those values together, and record the position of the
            highest-order 1 bit (counting from 1) and the number of low-order 0 bits. The number of uint64_ts in the
            array is the value of "words". If removing the low-order 0 bits from every word makes the block smaller
            despite the extra byte needed to record their number, that number is the "shift"; otherwise the shift is
            0. The "width" is the position of the highest-order 1 bit minus the shift: the number of bits stored for
            each word. (The width plus the shift is the algorithm's best guess at the bit size of the coefficient
            modulus.) The compressed block is then:

            +-----------+-----------+~~~~~~~~~~~~~+~~~~~~~~~~~~~+--------------------------------+~~~~~~~~~~~~~+
            | width     | prefix    |  shift      |  verbatim   |          packed words          |  verbatim   |
            | (1 byte:  | (1 byte,  |  (1 byte,   |  (prefix    |  (ceil(words * width / 8)      |  (tail      |
            | max 64,   | max 255)  |  1 to 63;   |  bytes)     |  bytes)                        |  bytes)     |
            | bit 7 set |           |  only if    |             |                                |             |
            | if shift) |           |  shift > 0) |             |                                |             |
            +-----------+-----------+~~~~~~~~~~~~~+~~~~~~~~~~~~~+--------------------------------+~~~~~~~~~~~~~+

            The width byte holds the width in its low 7 bits, and its bit 7 is set if the shift byte follows the
            prefix byte. The width plus the shift is at most 64. The packed words are written one after another,
            starting from the least significant bit: bit k of the packed words is bit (k mod 8) of byte floor(k / 8),
            and each word contributes its "width" bits after shifting it right by "shift" bits; decoding shifts the
            words back. The "verbatim" bytes before the packed words simply contain the raw data before the first
            word, and those after the packed words contain the raw data that remains when the rest of the block does
            not fill a whole uint64_t.

            For the example block above, the compressed block looks like this:

                1E      05     00 00 00 00 00   25 EB 79 2B 05 6B CB ...           xx xx xx
            +-------+--------+~~~~~~~~~~~~~~~~+----------------------------------+~~~~~~~~~~~+
            | width | prefix |  verbatim      |          packed words            |  verbatim |
            |  1 B  |  1 B   |     5 B        |  127 words x 30 bits -> 477 B    |   3 B     |
            +-------+--------+~~~~~~~~~~~~~~~~+----------------------------------+~~~~~~~~~~~+

            The packed words are not aligned to bytes. Coefficient 0 fills bits 0 to 29, so coefficient 1 starts at
            bit 30: its two low bits (00) complete the byte 2B, and its remaining bits follow as 05 6B CB, since
            0x272DAC14 >> 2 = 0x09CB6B05. The trailing xx bytes are the start of a coefficient that no longer fit
            in a whole uint64_t before the block ended; they are carried verbatim, and being the low-order bytes of
            a coefficient they are high-entropy rather than zero. The total size of the compressed block in this
            example would be 487 bytes. The coefficients have no low-order 0 bits in common, so there is no shift.
            If an application had cleared the low 15 bits of every coefficient, a shift would remove those bits from
            every word, and the block would pack 127 words x 15 bits into 239 bytes, for a total of 250 bytes.

            Two other scenarios are worth mentioning. First, when the input stream contains something other than the
            expected content (e.g. metadata) beyond what a prefix can hold, generally this algorithm will not find any
            value for "width" below 64, and the prefix will default to 0, meaning the "compressed" output will be two
            bytes carrying the width (64) and prefix (0), followed by the raw input block. Second, if a block contains
            only 0-bits and its length is a multiple of 8 bytes (as for any full block), the computed width and prefix
            will both be 0, with no shift, so the compressed output will simply be two bytes containing 0s. A block of
            1024 bytes is never encoded in fewer than these two bytes, so decoding expands the data by at most 512:1.

            Unlike ZLIB, bit-packing performs no integrity checking of the data.
            */

            // Base-2 logarithm of the fixed block size accepted by Microsoft SEAL 4.6 bit-packed payloads.
            constexpr int bitpack_block_log2 = 10;

            // Number of original bytes encoded in each bit-packed block.
            constexpr std::size_t bitpack_block_bytes = std::size_t(1) << bitpack_block_log2;

            static_assert(bitpack_block_bytes == 1024, "bitpack_block_bytes must be 1024");

            // Largest number of bytes a bit-packed block may store verbatim before its words.
            constexpr std::size_t bitpack_prefix_max = 255;

            // Bit of a bit-packed block's width byte indicating that a shift byte follows the prefix byte.
            constexpr unsigned char bitpack_shift_flag = 0x80;

            // The bit-packed format is little-endian, as is every platform Microsoft SEAL supports (see
            // seal/util/defines.h), so words are loaded and stored in the platform's byte order.
            SEAL_NODISCARD inline std::uint64_t load_uint64_le(const unsigned char *src) noexcept
            {
                std::uint64_t result = 0;
                std::memcpy(&result, src, sizeof(result));
                return result;
            }

            inline void store_uint64_le(unsigned char *dst, std::uint64_t value) noexcept
            {
                std::memcpy(dst, &value, sizeof(value));
            }

            /**
            Bit-packs data in the given buffer, completes the given SEALHeader by writing in the size of the output
            and setting the compression mode to compr_mode_type::bitpack and finally writes the SEALHeader followed
            by the bit-packed data in the given stream.

            @param[in] in The buffer to bit-pack
            @param[out] header_ptr A pointer to a SEALHeader instance matching the output of the encoding
            @param[out] out_stream The stream to write to
            @param[in] pool The MemoryPoolHandle pointing to a valid memory pool
            @throws std::invalid_argument if pool is uninitialized
            @throws std::runtime_error if I/O operations failed
            */
            void bitpack_write_header_pack_buffer(
                const DynArray<seal_byte> &in, void *header_ptr, std::ostream &out_stream, MemoryPoolHandle pool);

            /**
            A get-only stream buffer that unpacks bit-packed data from an underlying input stream on demand, one
            block at a time, instead of decoding the entire payload up front into a single growing buffer. Because
            the parser only pulls as many bytes as its (validated) parameters require, this bounds the memory used
            during deserialization to the size of the object actually being read, defending against hostile size
            claims in the encoded data.
            The buffer is forward-only: it reports the current read position (so tellg() works, which nested loads
            rely on) but does not support repositioning.
            */
            class BitUnpackGetBuffer final : public std::streambuf
            {
            public:
                BitUnpackGetBuffer(std::istream &in_stream, std::streamoff in_size, MemoryPoolHandle pool);

                ~BitUnpackGetBuffer() override;

                BitUnpackGetBuffer(const BitUnpackGetBuffer &copy) = delete;

                BitUnpackGetBuffer &operator=(const BitUnpackGetBuffer &assign) = delete;

                // True if malformed or truncated input was encountered while pulling data.
                SEAL_NODISCARD bool failed() const noexcept
                {
                    return failed_;
                }

                // Number of packed bytes from the bound that have not yet been read from the underlying stream.
                SEAL_NODISCARD std::streamoff remaining() const noexcept
                {
                    return in_remaining_;
                }

                // Makes unpacking fail once the output exceeds free_bytes plus max_ratio times the packed input read
                // so far. A max_ratio of zero means no limit.
                void set_expansion_limit(std::uint64_t free_bytes, std::uint64_t max_ratio) noexcept
                {
                    expansion_free_bytes_ = free_bytes;
                    expansion_max_ratio_ = max_ratio;
                }

            private:
                // Unpacks the next block into out_buf_, returning the number of bytes produced. Sets finished_ when
                // all of the original bytes have been produced and failed_ on malformed or truncated input.
                std::size_t unpack_block();

                // Reads up to count packed bytes from the underlying stream, capped by the remaining bound. Returns
                // the number of bytes actually read.
                std::streamsize read_packed(unsigned char *dst, std::streamsize count);

                int_type underflow() override;

                std::streamsize xsgetn(char_type *s, std::streamsize count) override;

                // Supports only tellg() (a no-op seek to the current input position); any other seek fails. This is
                // enough for the nested loads that verify their size via tellg().
                pos_type seekoff(
                    off_type off, std::ios_base::seekdir dir,
                    std::ios_base::openmode which = std::ios_base::in | std::ios_base::out) override;

                // True if producing a total of produced bytes would exceed the expansion limit.
                SEAL_NODISCARD bool expansion_exceeded(std::uint64_t produced) const noexcept;

                MemoryPoolHandle pool_;

                // Allocated once the block size has been read from the packed data.
                Pointer<unsigned char> in_buf_;

                Pointer<unsigned char> out_buf_;

                std::istream &in_stream_;

                std::streamoff in_remaining_;

                std::ios_base::iostate in_stream_except_mask_;

                // Number of original bytes that remain to be produced; valid once started_ is set.
                std::uint64_t raw_remaining_ = 0;

                // Block size read from the packed data; valid once started_ is set.
                std::size_t block_bytes_ = 0;

                bool started_ = false;

                bool failed_ = false;

                bool finished_ = false;

                // Total unpacked bytes handed to the get area so far; used to report the read position.
                std::streamoff total_produced_ = 0;

                // Total packed bytes read from the underlying stream.
                std::uint64_t in_read_ = 0;

                std::uint64_t expansion_free_bytes_ = 0;

                std::uint64_t expansion_max_ratio_ = 0;
            };

            // Creates a streambuf that unpacks in_size bytes of bit-packed data from in_stream on demand.
            std::unique_ptr<BitUnpackGetBuffer> make_bitpack_unpack_buffer(
                std::istream &in_stream, std::streamoff in_size, MemoryPoolHandle pool);

            template <typename SizeT>
            SEAL_NODISCARD SizeT bitpack_size_bound(SizeT in_size)
            {
                // 9 bytes for the original size and the block size, and two bytes per block of
                // bitpack_block_bytes = 1024 original bytes (plus rounding up): an encoded block never exceeds its
                // original size by more than its width and prefix bytes, because the encoder adds a shift byte only
                // when that makes the block smaller.
                return util::add_safe<SizeT>(in_size, in_size >> 9, SizeT(17));
            }
        } // namespace bitpack
    } // namespace util
} // namespace seal
