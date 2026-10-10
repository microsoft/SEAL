// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include "seal/serialization.h"
#include "seal/util/bitpack.h"
#include "seal/util/common.h"
#include <algorithm>
#include <cstring>
#include <limits>

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

                // Number of whole 64-bit words in a block of block_len bytes after a verbatim prefix of the given
                // length.
                SEAL_NODISCARD inline size_t block_word_count(size_t block_len, size_t prefix) noexcept
                {
                    return (block_len - prefix) / bytes_per_word;
                }

                // Size in bytes of the encoding of a block of block_len bytes with the given prefix length, width,
                // and shift: the width and prefix bytes, the shift byte if the shift is nonzero, the verbatim
                // prefix, the packed words, and the verbatim tail.
                SEAL_NODISCARD inline size_t block_encoded_size(size_t block_len, size_t prefix, int width, int shift)
                {
                    size_t words = block_word_count(block_len, prefix);
                    size_t packed_bytes = (words * static_cast<size_t>(width) + size_t(7)) >> 3;
                    return size_t(shift ? 3 : 2) + block_len - words * bytes_per_word + packed_bytes;
                }

                // Number of low-order zero bits of a nonzero value.
                SEAL_NODISCARD inline int trailing_zero_count(uint64_t value)
                {
                    return get_significant_bit_count(value & (~value + 1)) - 1;
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

                // Allocates a zero-filled array with block_slack bytes of extra headroom past the size bound.
                DynArray<seal_byte> out(add_safe(bitpack_size_bound(in_size), block_slack), pool);
                unsigned char *out_data = reinterpret_cast<unsigned char *>(out.begin());

                // Write the 9-byte stream header: the original byte count and the base-2 log of the block size.
                store_uint64_le(out_data, static_cast<uint64_t>(in_size));
                size_t out_pos = bytes_per_word;
                out_data[out_pos++] = static_cast<unsigned char>(bitpack_block_log2);

                for (size_t block_start = 0; block_start < in_size;)
                {
                    size_t block_len = min(bitpack_block_bytes, in_size - block_start);
                    const unsigned char *block_in = in_data + block_start;

                    // Choose the smallest encoding of the block. Its words follow a verbatim prefix: the word data
                    // need not fall on the stream's own word grid (serialized metadata is not always a multiple of
                    // eight bytes), and a block may begin with bytes that are not word data at all, such as the
                    // metadata of a ciphertext. For each phase of the word grid, every prefix on that grid of at
                    // most bitpack_prefix_max bytes is considered, and the OR of the words after the prefix gives
                    // the width and the low-order zero bits that can be shifted out. A phase of bytes_per_word would
                    // reproduce the grid of phase zero, so only smaller phases need to be considered. The clamp to
                    // block_len keeps the word count from underflowing on a block shorter than a word; for such a
                    // block every candidate has the same size, and the tie-break settles on an empty prefix.
                    size_t prefix = 0;
                    int width = 0;
                    int shift = 0;
                    size_t encoded_size = numeric_limits<size_t>::max();
                    uint64_t suffix_or[bitpack_prefix_max / bytes_per_word + 1];
                    for (size_t phase = 0; phase <= min<size_t>(bytes_per_word - 1, block_len); phase++)
                    {
                        // A prefix on this grid holds at most max_k words
                        size_t phase_words = block_word_count(block_len, phase);
                        size_t max_k = min(phase_words, (bitpack_prefix_max - phase) / bytes_per_word);
                        uint64_t head_or = 0;
                        for (size_t i = 0; i < max_k; i++)
                        {
                            head_or |= load_uint64_le(block_in + phase + i * bytes_per_word);
                        }
                        uint64_t words_or = 0;
                        for (size_t i = max_k; i < phase_words; i++)
                        {
                            words_or |= load_uint64_le(block_in + phase + i * bytes_per_word);
                        }

                        // Moving a word into the prefix without changing the OR adds 8 verbatim bytes and saves at
                        // most 8 packed bytes, so it cannot make the block smaller. In particular, if the words that a
                        // prefix can hold add no bits to the OR of the words after them, no prefix on this grid beats
                        // the shortest one. Otherwise, for k up to max_k, suffix_or[k] is the OR of the words on this
                        // grid from the k-th word on.
                        size_t k_end = 0;
                        suffix_or[0] = words_or;
                        if (head_or & ~words_or)
                        {
                            k_end = max_k;
                            suffix_or[max_k] = words_or;
                            for (size_t k = max_k; k > 0; k--)
                            {
                                suffix_or[k - 1] =
                                    suffix_or[k] | load_uint64_le(block_in + phase + (k - 1) * bytes_per_word);
                            }
                        }

                        for (size_t k = 0; k <= k_end; k++)
                        {
                            if (k && suffix_or[k] == suffix_or[k - 1])
                            {
                                continue;
                            }
                            size_t k_prefix = phase + k * bytes_per_word;
                            int k_width = get_significant_bit_count(suffix_or[k]);
                            int k_shift = 0;
                            size_t k_size = block_encoded_size(block_len, k_prefix, k_width, 0);

                            // Shift out the low-order bits that are zero in every word if that makes the block
                            // smaller despite the shift byte.
                            if (suffix_or[k] && !(suffix_or[k] & 1))
                            {
                                int zero_bits = trailing_zero_count(suffix_or[k]);
                                size_t shifted_size =
                                    block_encoded_size(block_len, k_prefix, k_width - zero_bits, zero_bits);
                                if (shifted_size < k_size)
                                {
                                    k_shift = zero_bits;
                                    k_size = shifted_size;
                                }
                            }

                            // Among equally small encodings, choose the one with the shortest prefix
                            if (k_size < encoded_size || (k_size == encoded_size && k_prefix < prefix))
                            {
                                prefix = k_prefix;
                                width = k_width - k_shift;
                                shift = k_shift;
                                encoded_size = k_size;
                            }
                        }
                    }
                    size_t words = block_word_count(block_len, prefix);

                    out_data[out_pos++] = static_cast<unsigned char>(width | (shift ? bitpack_shift_flag : 0));
                    out_data[out_pos++] = static_cast<unsigned char>(prefix);
                    if (shift)
                    {
                        out_data[out_pos++] = static_cast<unsigned char>(shift);
                    }

                    // Verbatim prefix bytes
                    memcpy(out_data + out_pos, block_in, prefix);
                    out_pos += prefix;

                    // Pack the words, without their shifted-out low-order bits, consecutively starting from the least
                    // significant bit. Each shifted word carries at most width significant bits, so nothing is lost;
                    // the read-modify-write below only ever ORs significant bits into the zero-filled output.
                    unsigned char *packed_out = out_data + out_pos;
                    size_t bit_pos = 0;
                    for (size_t i = 0; i < words; i++)
                    {
                        uint64_t word = load_uint64_le(block_in + prefix + i * bytes_per_word) >> shift;
                        size_t byte_index = bit_pos >> 3;
                        int bit_offset = static_cast<int>(bit_pos & size_t(7));
                        uint64_t low_word = load_uint64_le(packed_out + byte_index);
                        low_word |= word << bit_offset;
                        store_uint64_le(packed_out + byte_index, low_word);
                        if (bit_offset && width > bits_per_uint64 - bit_offset)
                        {
                            packed_out[byte_index + bytes_per_word] =
                                static_cast<unsigned char>(word >> (bits_per_uint64 - bit_offset));
                        }
                        bit_pos += static_cast<size_t>(width);
                    }
                    out_pos += (words * static_cast<size_t>(width) + size_t(7)) >> 3;

                    // Verbatim tail bytes
                    size_t tail = block_len - prefix - words * bytes_per_word;
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
                // Restoring the mask throws if truncated input left the stream in a failed state, but a destructor
                // must not throw. The mask is restored anyway, and the stream keeps its error state for the caller.
                try
                {
                    in_stream_.exceptions(in_stream_except_mask_);
                }
                catch (...)
                {}
            }

            streamsize BitUnpackGetBuffer::read_packed(unsigned char *dst, streamsize count)
            {
                streamsize to_read = static_cast<streamsize>(min<streamoff>(count, in_remaining_));
                if (to_read <= 0)
                {
                    return 0;
                }
                in_stream_.read(reinterpret_cast<char *>(dst), to_read);
                streamsize got = in_stream_.gcount();
                in_remaining_ -= got;
                in_read_ += static_cast<uint64_t>(got);
                return got;
            }

            bool BitUnpackGetBuffer::expansion_exceeded(uint64_t produced) const noexcept
            {
                if (!expansion_max_ratio_ || produced <= expansion_free_bytes_)
                {
                    return false;
                }

                // The comparison is produced - free_bytes > max_ratio * in_read_, rearranged to avoid overflow.
                return (produced - expansion_free_bytes_ - 1) / expansion_max_ratio_ >= in_read_;
            }

            size_t BitUnpackGetBuffer::unpack_block()
            {
                if (finished_)
                {
                    return 0;
                }

                if (!started_)
                {
                    // The compressed stream begins with its 9-byte header: the original byte count and the base-2
                    // log of the block size
                    unsigned char prologue[bytes_per_word + 1];
                    if (read_packed(prologue, static_cast<streamsize>(sizeof(prologue))) !=
                        static_cast<streamsize>(sizeof(prologue)))
                    {
                        failed_ = true;
                        return 0;
                    }
                    raw_remaining_ = load_uint64_le(prologue);
                    int block_log2 = static_cast<int>(prologue[bytes_per_word]);
                    uint64_t block_count =
                        raw_remaining_ / bitpack_block_bytes + (raw_remaining_ % bitpack_block_bytes != 0);
                    if (raw_remaining_ > static_cast<uint64_t>(numeric_limits<streamoff>::max()) ||
                        block_log2 != bitpack_block_log2 || block_count > static_cast<uint64_t>(in_remaining_) / 2)
                    {
                        failed_ = true;
                        return 0;
                    }
                    block_bytes_ = bitpack_block_bytes;
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
                int width = static_cast<int>(block_header[0] & static_cast<unsigned char>(~bitpack_shift_flag));
                bool has_shift = (block_header[0] & bitpack_shift_flag) != 0;
                size_t prefix = static_cast<size_t>(block_header[1]);
                if (width > bits_per_uint64 || prefix > block_len)
                {
                    failed_ = true;
                    return 0;
                }
                int shift = 0;
                if (has_shift)
                {
                    unsigned char shift_byte = 0;
                    if (read_packed(&shift_byte, 1) != 1)
                    {
                        failed_ = true;
                        return 0;
                    }
                    shift = static_cast<int>(shift_byte);

                    // A shift applies to words with stored bits, and the restored words must fit in 64 bits
                    if (!shift || !width || width + shift > bits_per_uint64)
                    {
                        failed_ = true;
                        return 0;
                    }
                }
                size_t words = block_word_count(block_len, prefix);
                size_t packed_bytes = (words * static_cast<size_t>(width) + size_t(7)) >> 3;
                size_t tail = block_len - prefix - words * bytes_per_word;

                // Verbatim prefix bytes
                if (read_packed(out_buf_.get(), safe_cast<streamsize>(prefix)) != safe_cast<streamsize>(prefix))
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

                fill_n(in_buf_.get() + packed_bytes, block_slack, uint8_t(0));

                // Unpack the words and restore their shifted-out low-order zero bits. The whole-uint64_t reads may
                // pick up bits past the packed data (block_slack bytes of headroom make them safe); the mask discards
                // everything above the stored bits.
                uint64_t mask = (width == bits_per_uint64) ? ~uint64_t(0) : ((uint64_t(1) << width) - 1);
                size_t bit_pos = 0;
                for (size_t i = 0; i < words; i++)
                {
                    size_t byte_index = bit_pos >> 3;
                    int bit_offset = static_cast<int>(bit_pos & size_t(7));
                    uint64_t low_word = load_uint64_le(in_buf_.get() + byte_index);
                    low_word >>= bit_offset;
                    if (bit_offset && width > bits_per_uint64 - bit_offset)
                    {
                        uint64_t high_byte = in_buf_.get()[byte_index + bytes_per_word];
                        low_word |= high_byte << (bits_per_uint64 - bit_offset);
                    }
                    uint64_t word = (low_word & mask) << shift;
                    store_uint64_le(out_buf_.get() + prefix + i * bytes_per_word, word);
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
                        if (expansion_exceeded(static_cast<uint64_t>(total_produced_) + produced))
                        {
                            failed_ = true;
                            break;
                        }
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

                    // avail is at most bitpack_block_bytes, which is well within the range of int.
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
