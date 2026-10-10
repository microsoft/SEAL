// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#pragma once

#include "seal/util/defines.h"

#if defined(SEAL_USE_ZLIB) || defined(SEAL_USE_ZSTD)
#include "seal/dynarray.h"
#include "seal/memorymanager.h"
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
        namespace ztools
        {
            /**
            Compresses data in the given buffer, completes the given SEALHeader by writing in the size of the output and
            setting the compression mode to compr_mode_type::zlib and finally writes the SEALHeader followed by the
            compressed data in the given stream.

            @param[in] in The buffer to compress
            @param[in] in_size The size of the buffer to compress in bytes
            @param[out] header A pointer to a SEALHeader instance matching the output of the compression
            @param[out] out_stream The stream to write to
            @param[in] pool The MemoryPoolHandle pointing to a valid memory pool
            @throws std::invalid_argument if pool is uninitialized
            @throws std::logic_error if compression failed
            */
            void zlib_write_header_deflate_buffer(
                DynArray<seal_byte> &in, void *header_ptr, std::ostream &out_stream, MemoryPoolHandle pool);

            int zlib_deflate_array_inplace(DynArray<seal_byte> &in, MemoryPoolHandle pool);

            /**
            Compresses data in the given buffer, completes the given SEALHeader by writing in the size of the output and
            setting the compression mode to compr_mode_type::zstd and finally writes the SEALHeader followed by the
            compressed data in the given stream.

            @param[in] in The buffer to compress
            @param[in] in_size The size of the buffer to compress in bytes
            @param[out] header A pointer to a SEALHeader instance matching the output of the compression
            @param[out] out_stream The stream to write to
            @param[in] pool The MemoryPoolHandle pointing to a valid memory pool
            @throws std::invalid_argument if pool is uninitialized
            @throws std::logic_error if compression failed
            */
            void zstd_write_header_deflate_buffer(
                DynArray<seal_byte> &in, void *header_ptr, std::ostream &out_stream, MemoryPoolHandle pool);

            unsigned zstd_deflate_array_inplace(DynArray<seal_byte> &in, MemoryPoolHandle pool);

            /**
            A get-only stream buffer that inflates zlib/zstd-compressed data from an underlying input stream on demand,
            instead of decompressing the entire payload up front into a single growing buffer. Because the parser only
            pulls as many bytes as its (validated) parameters require, this bounds the memory used during
            deserialization to the size of the object actually being read, defending against decompression bombs. The
            buffer is forward-only: it reports the current read position (so tellg() works, which nested loads rely on)
            but does not support repositioning.
            */
            class InflateGetBuffer : public std::streambuf
            {
            public:
                InflateGetBuffer(std::istream &in_stream, std::streamoff in_size, MemoryPoolHandle pool);

                ~InflateGetBuffer() override;

                InflateGetBuffer(const InflateGetBuffer &copy) = delete;

                InflateGetBuffer &operator=(const InflateGetBuffer &assign) = delete;

                // True if a decompression error or truncated input was encountered while pulling data.
                SEAL_NODISCARD bool failed() const noexcept
                {
                    return failed_;
                }

                // Number of compressed bytes from the bound that have not yet been read from the underlying stream.
                SEAL_NODISCARD std::streamoff remaining() const noexcept
                {
                    return in_remaining_;
                }

                // Makes decompression fail once the output exceeds free_bytes plus max_ratio times the compressed
                // input consumed so far. A max_ratio of zero means no limit.
                void set_expansion_limit(std::uint64_t free_bytes, std::uint64_t max_ratio) noexcept
                {
                    expansion_free_bytes_ = free_bytes;
                    expansion_max_ratio_ = max_ratio;
                }

            protected:
                // Inflates the next chunk into out_buf_, returning the number of bytes produced. Sets finished_ at the
                // end of the compressed stream and failed_ on a decompression error or truncated input. Implemented per
                // compression algorithm.
                virtual std::size_t inflate_chunk() = 0;

                // Reads up to count compressed bytes from the underlying stream, capped by the remaining bound. Returns
                // the number of bytes actually read.
                std::streamsize read_compressed(unsigned char *dst, std::streamsize count);

                Pointer<unsigned char> in_buf_;
                Pointer<unsigned char> out_buf_;
                unsigned char *in_next_ = nullptr;
                std::size_t in_avail_ = 0;
                bool failed_ = false;
                bool finished_ = false;

            private:
                int_type underflow() override;

                std::streamsize xsgetn(char_type *s, std::streamsize count) override;

                // Supports only tellg() (a no-op seek to the current input position); any other seek fails. This is
                // enough for the nested loads that verify their size via tellg().
                pos_type seekoff(
                    off_type off, std::ios_base::seekdir dir,
                    std::ios_base::openmode which = std::ios_base::in | std::ios_base::out) override;

                // True if producing a total of produced bytes would exceed the expansion limit.
                SEAL_NODISCARD bool expansion_exceeded(std::uint64_t produced) const noexcept;

                std::istream &in_stream_;
                std::streamoff in_remaining_;
                std::ios_base::iostate in_stream_except_mask_;

                // Total decompressed bytes handed to the get area so far; used to report the read position.
                std::streamoff total_produced_ = 0;

                // Total compressed bytes read from the underlying stream, including any not yet consumed.
                std::uint64_t in_read_ = 0;

                std::uint64_t expansion_free_bytes_ = 0;

                std::uint64_t expansion_max_ratio_ = 0;
            };

#ifdef SEAL_USE_ZLIB
            // Creates a streambuf that inflates in_size bytes of zlib-compressed data from in_stream on demand.
            std::unique_ptr<InflateGetBuffer> make_zlib_inflate_buffer(
                std::istream &in_stream, std::streamoff in_size, MemoryPoolHandle pool);
#endif
#ifdef SEAL_USE_ZSTD
            // Creates a streambuf that inflates in_size bytes of Zstandard-compressed data from in_stream on demand.
            std::unique_ptr<InflateGetBuffer> make_zstd_inflate_buffer(
                std::istream &in_stream, std::streamoff in_size, MemoryPoolHandle pool);
#endif

            template <typename SizeT>
            SEAL_NODISCARD SizeT zlib_deflate_size_bound(SizeT in_size)
            {
                return util::add_safe<SizeT>(in_size, in_size >> 12, in_size >> 14, in_size >> 25, SizeT(17));
            }

            template <typename SizeT>
            SEAL_NODISCARD SizeT zstd_deflate_size_bound(SizeT in_size)
            {
                return util::add_safe<SizeT>(
                    in_size, in_size >> 8,
                    (in_size < (SizeT(128) << 10)) ? (((SizeT(128) << 10) - in_size) >> 11) : SizeT(0));
            }
        } // namespace ztools
    } // namespace util
} // namespace seal

#endif
