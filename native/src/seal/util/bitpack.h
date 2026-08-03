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
            stream. The stream is split into blocks of bitpack_block_bytes bytes; in each block, a run of 64-bit
            words is re-encoded using only as many bits per word as the largest word in the run requires, so each
            word begins immediately after the last significant bit of the previous one, even in the middle of a
            byte. Since ciphertext and key data consist of words storing integers modulo primes much smaller than
            the word size, and the significant bits are high-entropy, this discards exactly the always-zero high
            bits that a general-purpose compressor cannot improve upon.

            Serialized metadata is not always a multiple of eight bytes, so the word data in the stream need not
            fall on the stream's own word grid. Each block therefore carries a phase: the number of initial bytes
            (0 to 7) stored verbatim before the packed run, chosen by the encoder to minimize the encoded size of
            the block. Bytes after the last whole word in the block are likewise stored verbatim.

            The encoded format is, in order:

            1. the size in bytes of the original byte stream (8 bytes)
            2. for each block of block_len = min(bitpack_block_bytes, bytes remaining) original bytes:
               a. the bit width used for the packed words (1 byte, at most 64)
               b. the phase (1 byte, at most min(7, block_len))
               c. phase verbatim bytes
               d. the (block_len - phase) / 8 words packed consecutively starting from the least significant bit
               e. the remaining (block_len - phase) % 8 bytes verbatim

            A width of zero denotes words that are all zero, packed into no bytes at all. Like the rest of the
            serialized data, the encoding is in the byte order of the host.
            */

            // Number of original bytes encoded in each bit-packed block.
            constexpr std::size_t bitpack_block_bytes = 4096;

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

                Pointer<unsigned char> in_buf_;

                Pointer<unsigned char> out_buf_;

                std::istream &in_stream_;

                std::streamoff in_remaining_;

                std::ios_base::iostate in_stream_except_mask_;

                // Number of original bytes that remain to be produced; valid once started_ is set.
                std::uint64_t raw_remaining_ = 0;

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
                // 8 bytes for the original size and a width and a phase byte per block of bitpack_block_bytes =
                // 4096 original bytes (plus rounding up); the blocks themselves never exceed their original size.
                return util::add_safe<SizeT>(in_size, in_size >> 11, SizeT(17));
            }
        } // namespace bitpack
    } // namespace util
} // namespace seal
