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
            some prime q, where q <= 2^60. Thus, some number of high-order bits of these values will always be zero,
            while the lower-order bits will (when serializing any cryptographic data) have high entropy. Standard
            compression algorithms like zlib are designed to operate on whole bytes, so they will fail to compress
            any zero bits that do not appear as a whole byte, and the high-entropy cryptographic bits are
            incompressible.

            The optimal way to compress these arrays of polynomial coefficients would be to simply use knowledge
            of q to append one coefficient after another with no zero-bits inbetween. However, SEAL's serialization
            API deliberately hides details of the payload's schema from the serializer, which just sees a raw byte
            stream. While the majority of that byte stream will usually contain these uint64_t arrays, each array
            may have a different value of q, and the stream may be interspersed with other small data structures such
            as metadata, parms_ids, etc.

            The bitpack compression scheme works by breaking the byte stream up into blocks of size
            bitpack_block_bytes (currently 1024), and attempting to compress each block as if it contains a section
            of a uint64_t array of polynomial coefficients modulo some q, using the strategy described below.
            On blocks that really do contain such data, it achieves near-optimal compression; on blocks that contain
            any other kind of data it will probably not compress the data at all, but such blocks are rare enough
            that the overall performance when applied to real SEAL payloads is closer to optimal than standard
            compression algorithms can achieve.

            The structure of the output of bitpack compression is as follows. It begins with a 9-byte header,
            consisting of the original size of the byte array pre-compression (8 bytes), and the log of
            bitpack_block_bytes used for the stream (1 byte). The remainder of the output is a series of compressed
            blocks.

            +---------------+------------+---------+---------+--   --+---------+
            | original size | block size | block 0 | block 1 |  ...  | block k |
            |   (8 bytes)   |   (log2,   |         |         |       |         |
            |               |   1 byte)  |         |         |       |         |
            +---------------+------------+---------+---------+--   --+---------+

            The compression algorithm for each block works independently, as follows. The algorithm assumes that
            the input block contains a series of uint64_t values with some number of high bits that are consistently 0,
            however the start of the first uint64_t value may be offset from the start of the stream by some unknown
            number of bytes between 0 and 7 (this misalignment can be caused by interleaved metadata earlier in the
            stream, for example). This offset is called the "phase," and the compression algorithm simply tries all
            possible phase values between 0 and 7 and proceeds with the one that yields the smallest compressed block.

            An example input stream might look like the following. (The annotations below the figure represent where
            the data came from.)

             00  00  00  00  00  25  EB  79  2B  00  00  00  00  14  AC  2D  26  00  00  00 ...
            +-------------------+-------------------------------+---------------------------+
            | metadata tail     |         coefficient 0         |       coefficient 1       |
            | (from prev block) |     0x2B79EB25 -> 30 bits     |     0x272DAC14 -> 29 bits |
            +-------------------+-------------------------------+---------------------------+

            Here we can see that the optimal value of "phase" will be 5, since this stream does actually contain an
            array of uint64_t values and they start on the sixth byte. The algorithm will then cast the remainder of the
            stream as uint64_ts, bitwise-OR those values together, and record the position of the highest-order 1 bit.
            This is the "width," and the number of uint64_ts in the array is the value of "words". (The width is the
            algorithm's best guess at the bit size of the coefficient modulus.) The final output of compression is
            then:

            +-----------+-----------+~~~~~~~~~~~~~+--------------------------------+~~~~~~~~~~~~~+
            | width     | phase     |  verbatim   |          packed words          |  verbatim   |
            | (1 byte,  | (1 byte,  |  (phase     |  (ceil(words * width / 8)      |  (tail      |
            | max 64)   | max 7)    |  bytes)     |  bytes)                        |  bytes)     |
            +-----------+-----------+~~~~~~~~~~~~~+--------------------------------+~~~~~~~~~~~~~+

            Here, the "verbatim" blocks before and after the packed words simply contain the raw data from the array
            before the packed stream started and after it ends, if the phase value was not 0.

            For the example stream above, this would look like:

                1C     05     00 00 00 00 00   25 EB 79 2B 05 6B CB ...           00 00 00
            +-------+-------+~~~~~~~~~~~~~~~~+----------------------------------+~~~~~~~~~~~+
            | width | phase |  verbatim      |          packed words            |  verbatim |
            |  1 B  |  1 B  |     5 B        |  127 words x 30 bits -> 477 B    |   3 B     |
            +-------+-------+~~~~~~~~~~~~~~~~+----------------------------------+~~~~~~~~~~~+

            The total size of the compressed block in this example would be 487 bytes.

            Two other scenarios are worth mentioning. First, when the input stream contains something other than the
            expected content (e.g. metadata), generally this algorithm will not find any value for "width" below 64,
            and phase will default to 0, meaning the "compressed" output will be the raw input block plus two
            additional bytes carrying the width (64) and phase (0). Second, if the input contains all 0-bits for
            whatever reason, the computed width and phase will both be 0, so the compressed output will simply be two
            bytes containing 0s.
            */

            // Bounds for the base-2 logarithm of the block size accepted when unpacking.
            constexpr int bitpack_block_log2_min = 6;

            constexpr int bitpack_block_log2_max = 16;

            // Number of original bytes encoded in each bit-packed block by this encoder.
            constexpr std::size_t bitpack_block_bytes = 1024;

            static_assert(
                (bitpack_block_bytes & (bitpack_block_bytes - 1)) == 0 &&
                    bitpack_block_bytes >= (std::size_t(1) << bitpack_block_log2_min) &&
                    bitpack_block_bytes <= (std::size_t(1) << bitpack_block_log2_max),
                "bitpack_block_bytes must be a power of two within the accepted range");

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
            during deserialization to a small constant, defending against hostile size claims in the encoded data.
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
            };

            // Creates a streambuf that unpacks in_size bytes of bit-packed data from in_stream on demand.
            std::unique_ptr<BitUnpackGetBuffer> make_bitpack_unpack_buffer(
                std::istream &in_stream, std::streamoff in_size, MemoryPoolHandle pool);

            template <typename SizeT>
            SEAL_NODISCARD SizeT bitpack_size_bound(SizeT in_size)
            {
                // 9 bytes for the original size and the block size, and a width and a phase byte per block of
                // bitpack_block_bytes = 1024 original bytes (plus rounding up); the blocks themselves never
                // exceed their original size.
                return util::add_safe<SizeT>(in_size, in_size >> 9, SizeT(17));
            }
        } // namespace bitpack
    } // namespace util
} // namespace seal
