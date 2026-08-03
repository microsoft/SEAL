// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include "seal/serialization.h"
#include "seal/util/bitpack.h"
#include "seal/util/common.h"
#include <algorithm>
#include <cstring>

using namespace std;

namespace seal
{
    namespace util
    {
        namespace bitpack
        {
            namespace
            {
                // Size in bytes of the 64-bit words being packed.
                constexpr size_t bytes_per_word = sizeof(uint64_t);

                // Slack allowing the packing and unpacking loops to address words through whole-uint64_t reads and
                // writes near the end of a block without stepping out of bounds.
                constexpr size_t block_slack = bytes_per_word;

                // Number of whole 64-bit words in a block of block_len bytes read at the given phase.
                SEAL_NODISCARD inline size_t block_word_count(size_t block_len, size_t phase) noexcept
                {
                    return (block_len - phase) / bytes_per_word;
                }

                // Encoded size in bytes of the body of a block of block_len bytes read at the given phase: the
                // verbatim phase bytes, the packed words, and the verbatim tail bytes.
                SEAL_NODISCARD inline size_t block_body_size(size_t block_len, size_t phase, int width) noexcept
                {
                    size_t words = block_word_count(block_len, phase);
                    size_t packed_bytes = (words * static_cast<size_t>(width) + size_t(7)) >> 3;
                    return block_len - words * bytes_per_word + packed_bytes;
                }
            } // namespace

            void bitpack_write_header_pack_buffer(
                const DynArray<seal_byte> &in, void *header_ptr, ostream &out_stream, MemoryPoolHandle pool)
            {
                if (!pool)
                {
                    throw invalid_argument("pool is uninitialized");
                }

                Serialization::SEALHeader &header = *reinterpret_cast<Serialization::SEALHeader *>(header_ptr);

                size_t in_size = in.size();
                const unsigned char *in_data = reinterpret_cast<const unsigned char *>(in.cbegin());

                // The whole-uint64_t writes below rely on the output being zero-filled (DynArray zero-fills) and on
                // block_slack bytes of headroom past the size bound.
                DynArray<seal_byte> out(add_safe(bitpack_size_bound(in_size), block_slack), pool);
                unsigned char *out_data = reinterpret_cast<unsigned char *>(out.begin());

                // Write the original byte count and the block size
                uint64_t in_size64 = static_cast<uint64_t>(in_size);
                memcpy(out_data, &in_size64, bytes_per_word);
                size_t out_pos = bytes_per_word;
                out_data[out_pos++] = static_cast<unsigned char>(get_significant_bit_count(bitpack_block_bytes) - 1);

                for (size_t block_start = 0; block_start < in_size;)
                {
                    size_t block_len = min(bitpack_block_bytes, in_size - block_start);
                    const unsigned char *block_in = in_data + block_start;

                    // The word data in the stream need not fall on the stream's own word grid (serialized metadata
                    // is not always a multiple of eight bytes), so choose the phase that minimizes the encoded size
                    // of the block.
                    size_t phase = 0;
                    int width = 0;
                    size_t body_size = block_len;
                    for (size_t p = 0; p <= min<size_t>(size_t(7), block_len); p++)
                    {
                        size_t words = block_word_count(block_len, p);
                        uint64_t block_or = 0;
                        for (size_t i = 0; i < words; i++)
                        {
                            uint64_t word = 0;
                            memcpy(&word, block_in + p + i * bytes_per_word, bytes_per_word);
                            block_or |= word;
                        }
                        int p_width = get_significant_bit_count(block_or);
                        size_t p_body_size = block_body_size(block_len, p, p_width);
                        if (p == 0 || p_body_size < body_size)
                        {
                            phase = p;
                            width = p_width;
                            body_size = p_body_size;
                        }
                    }
                    size_t words = block_word_count(block_len, phase);

                    out_data[out_pos++] = static_cast<unsigned char>(width);
                    out_data[out_pos++] = static_cast<unsigned char>(phase);

                    // Verbatim phase bytes
                    memcpy(out_data + out_pos, block_in, phase);
                    out_pos += phase;

                    // Pack the words consecutively starting from the least significant bit. Each word carries at
                    // most width significant bits, so nothing is lost; the read-modify-write below only ever ORs
                    // significant bits into the zero-filled output.
                    unsigned char *packed_out = out_data + out_pos;
                    size_t bit_pos = 0;
                    for (size_t i = 0; i < words; i++)
                    {
                        uint64_t word = 0;
                        memcpy(&word, block_in + phase + i * bytes_per_word, bytes_per_word);
                        size_t byte_index = bit_pos >> 3;
                        int shift = static_cast<int>(bit_pos & size_t(7));
                        uint64_t low_word = 0;
                        memcpy(&low_word, packed_out + byte_index, bytes_per_word);
                        low_word |= word << shift;
                        memcpy(packed_out + byte_index, &low_word, bytes_per_word);
                        if (shift && width > bits_per_uint64 - shift)
                        {
                            packed_out[byte_index + bytes_per_word] =
                                static_cast<unsigned char>(word >> (bits_per_uint64 - shift));
                        }
                        bit_pos += static_cast<size_t>(width);
                    }
                    out_pos += (words * static_cast<size_t>(width) + size_t(7)) >> 3;

                    // Verbatim tail bytes
                    size_t tail = block_len - phase - words * bytes_per_word;
                    memcpy(out_data + out_pos, block_in + block_len - tail, tail);
                    out_pos += tail;

                    block_start += block_len;
                }

                // Populate the header
                header.compr_mode = compr_mode_type::bitpack;
                header.size = static_cast<uint64_t>(add_safe(sizeof(Serialization::SEALHeader), out_pos));

                auto old_except_mask = out_stream.exceptions();
                try
                {
                    // Throw exceptions on ios_base::badbit and ios_base::failbit
                    out_stream.exceptions(ios_base::badbit | ios_base::failbit);

                    // Write the header and the data
                    out_stream.write(reinterpret_cast<const char *>(&header), sizeof(Serialization::SEALHeader));
                    out_stream.write(reinterpret_cast<const char *>(out_data), safe_cast<streamsize>(out_pos));
                }
                catch (...)
                {
                    out_stream.exceptions(old_except_mask);
                    throw;
                }

                out_stream.exceptions(old_except_mask);
            }

            BitUnpackGetBuffer::BitUnpackGetBuffer(istream &in_stream, streamoff in_size, MemoryPoolHandle pool)
                : pool_(std::move(pool)), in_stream_(in_stream), in_remaining_(in_size),
                  in_stream_except_mask_(in_stream.exceptions())
            {
                if (!pool_)
                {
                    throw invalid_argument("pool is uninitialized");
                }

                // Unpacking reports failure through failed_ rather than stream exceptions, so clear the mask while
                // we read; it is restored in the destructor.
                in_stream_.exceptions(ios_base::goodbit);

                // Start with an empty get area so that the first read triggers underflow(); the buffers are
                // allocated once the block size has been read from the packed data.
                setg(nullptr, nullptr, nullptr);
            }

            BitUnpackGetBuffer::~BitUnpackGetBuffer()
            {
                in_stream_.exceptions(in_stream_except_mask_);
            }

            streamsize BitUnpackGetBuffer::read_packed(unsigned char *dst, streamsize count)
            {
                streamsize to_read = min<streamsize>(count, in_remaining_);
                if (to_read <= 0)
                {
                    return 0;
                }
                in_stream_.read(reinterpret_cast<char *>(dst), to_read);
                streamsize got = in_stream_.gcount();
                in_remaining_ -= got;
                return got;
            }

            size_t BitUnpackGetBuffer::unpack_block()
            {
                if (finished_)
                {
                    return 0;
                }

                if (!started_)
                {
                    // The packed data begins with the original byte count and the block size
                    unsigned char prologue[bytes_per_word + 1];
                    if (read_packed(prologue, static_cast<streamsize>(sizeof(prologue))) !=
                        static_cast<streamsize>(sizeof(prologue)))
                    {
                        failed_ = true;
                        return 0;
                    }
                    memcpy(&raw_remaining_, prologue, bytes_per_word);
                    int block_log2 = static_cast<int>(prologue[bytes_per_word]);
                    if (block_log2 < bitpack_block_log2_min || block_log2 > bitpack_block_log2_max)
                    {
                        failed_ = true;
                        return 0;
                    }
                    block_bytes_ = size_t(1) << block_log2;
                    in_buf_ = allocate<unsigned char>(block_bytes_ + block_slack, pool_);
                    out_buf_ = allocate<unsigned char>(block_bytes_, pool_);
                    started_ = true;
                    if (!raw_remaining_)
                    {
                        finished_ = true;
                        return 0;
                    }
                }

                size_t block_len =
                    static_cast<size_t>(min<uint64_t>(static_cast<uint64_t>(block_bytes_), raw_remaining_));

                unsigned char block_header[2];
                if (read_packed(block_header, 2) != 2)
                {
                    failed_ = true;
                    return 0;
                }
                int width = static_cast<int>(block_header[0]);
                size_t phase = static_cast<size_t>(block_header[1]);
                if (width > bits_per_uint64 || phase > min<size_t>(size_t(7), block_len))
                {
                    failed_ = true;
                    return 0;
                }
                size_t words = block_word_count(block_len, phase);
                size_t packed_bytes = (words * static_cast<size_t>(width) + size_t(7)) >> 3;
                size_t tail = block_len - phase - words * bytes_per_word;

                // Verbatim phase bytes
                if (read_packed(out_buf_.get(), safe_cast<streamsize>(phase)) != safe_cast<streamsize>(phase))
                {
                    failed_ = true;
                    return 0;
                }

                if (read_packed(in_buf_.get(), safe_cast<streamsize>(packed_bytes)) !=
                    safe_cast<streamsize>(packed_bytes))
                {
                    failed_ = true;
                    return 0;
                }

                // Unpack the words. The whole-uint64_t reads may pick up bits past the packed data (block_slack
                // bytes of headroom make them safe); the mask discards everything above the significant bits.
                uint64_t mask = (width == bits_per_uint64) ? ~uint64_t(0) : ((uint64_t(1) << width) - 1);
                size_t bit_pos = 0;
                for (size_t i = 0; i < words; i++)
                {
                    size_t byte_index = bit_pos >> 3;
                    int shift = static_cast<int>(bit_pos & size_t(7));
                    uint64_t low_word = 0;
                    memcpy(&low_word, in_buf_.get() + byte_index, bytes_per_word);
                    low_word >>= shift;
                    if (shift && width > bits_per_uint64 - shift)
                    {
                        uint64_t high_byte = in_buf_.get()[byte_index + bytes_per_word];
                        low_word |= high_byte << (bits_per_uint64 - shift);
                    }
                    uint64_t word = low_word & mask;
                    memcpy(out_buf_.get() + phase + i * bytes_per_word, &word, bytes_per_word);
                    bit_pos += static_cast<size_t>(width);
                }

                // Verbatim tail bytes
                if (read_packed(out_buf_.get() + block_len - tail, safe_cast<streamsize>(tail)) !=
                    safe_cast<streamsize>(tail))
                {
                    failed_ = true;
                    return 0;
                }

                raw_remaining_ -= block_len;
                if (!raw_remaining_)
                {
                    finished_ = true;
                }
                return block_len;
            }

            BitUnpackGetBuffer::int_type BitUnpackGetBuffer::underflow()
            {
                if (gptr() < egptr())
                {
                    return traits_type::to_int_type(*gptr());
                }

                // Pull and unpack blocks until we produce output, reach the end of the data, or fail. unpack_block()
                // guarantees progress: whenever it makes none it sets failed_ or finished_, so this loop always
                // terminates.
                while (!failed_)
                {
                    size_t produced = unpack_block();
                    if (failed_)
                    {
                        break;
                    }
                    if (produced)
                    {
                        char_type *base = reinterpret_cast<char_type *>(out_buf_.get());
                        setg(base, base, base + produced);
                        total_produced_ += static_cast<streamoff>(produced);
                        return traits_type::to_int_type(*gptr());
                    }
                    if (finished_)
                    {
                        return traits_type::eof();
                    }
                }
                return traits_type::eof();
            }

            streamsize BitUnpackGetBuffer::xsgetn(char_type *s, streamsize count)
            {
                streamsize total = 0;
                while (total < count)
                {
                    if (gptr() == egptr() && traits_type::eq_int_type(underflow(), traits_type::eof()))
                    {
                        break;
                    }
                    streamsize avail = min<streamsize>(count - total, static_cast<streamsize>(egptr() - gptr()));
                    copy_n(gptr(), avail, s + total);

                    // avail is at most the block size (at most 64 KB), which is well within the range of int.
                    gbump(static_cast<int>(avail));
                    total += avail;
                }
                return total;
            }

            BitUnpackGetBuffer::pos_type BitUnpackGetBuffer::seekoff(
                off_type off, ios_base::seekdir dir, ios_base::openmode which)
            {
                // Only a no-op seek to the current input position is supported, i.e. tellg(). The position is the
                // number of unpacked bytes already consumed from the get area.
                if (off == 0 && dir == ios_base::cur && (which & ios_base::in))
                {
                    return pos_type(total_produced_ - static_cast<off_type>(egptr() - gptr()));
                }
                return pos_type(off_type(-1));
            }

            unique_ptr<BitUnpackGetBuffer> make_bitpack_unpack_buffer(
                istream &in_stream, streamoff in_size, MemoryPoolHandle pool)
            {
                return make_unique<BitUnpackGetBuffer>(in_stream, in_size, std::move(pool));
            }
        } // namespace bitpack
    } // namespace util
} // namespace seal
