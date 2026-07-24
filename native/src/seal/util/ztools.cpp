// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include "seal/util/defines.h"

#if defined(SEAL_USE_ZLIB) || defined(SEAL_USE_ZSTD)

#include "seal/dynarray.h"
#include "seal/memorymanager.h"
#include "seal/serialization.h"
#include "seal/util/pointer.h"
#include "seal/util/ztools.h"
#include <algorithm>
#include <cstddef>
#include <cstring>
#include <ios>
#include <iostream>
#include <limits>
#include <memory>
#include <sstream>
#include <unordered_map>

using namespace std;

namespace seal
{
    namespace util
    {
        namespace ztools
        {
            namespace
            {
                // Size for an internal buffer allocated for inflate and deflate
                constexpr size_t buffer_size = 256 * 1024;

                class PointerStorage
                {
                public:
                    PointerStorage(MemoryPoolHandle pool) : pool_(std::move(pool))
                    {}

                    void *allocate(size_t size)
                    {
                        auto ptr = util::allocate<seal_byte>(size, pool_);
                        void *addr = reinterpret_cast<void *>(ptr.get());
                        ptr_storage_[addr] = std::move(ptr);
                        return addr;
                    }

                    void free(void *addr)
                    {
                        ptr_storage_.erase(addr);
                    }

                private:
                    MemoryPoolHandle pool_;

                    unordered_map<void *, Pointer<seal_byte>> ptr_storage_;
                };
            } // namespace

            InflateGetBuffer::InflateGetBuffer(istream &in_stream, streamoff in_size, MemoryPoolHandle pool)
                : in_buf_(allocate<unsigned char>(buffer_size, pool)),
                  out_buf_(allocate<unsigned char>(buffer_size, pool)), in_stream_(in_stream), in_remaining_(in_size),
                  in_stream_except_mask_(in_stream.exceptions())
            {
                // Decompression reports failure through failed_ rather than stream exceptions, so clear the mask while
                // we read; it is restored in the destructor.
                in_stream_.exceptions(ios_base::goodbit);

                // Start with an empty get area so that the first read triggers underflow().
                char_type *base = reinterpret_cast<char_type *>(out_buf_.get());
                setg(base, base, base);
            }

            InflateGetBuffer::~InflateGetBuffer()
            {
                in_stream_.exceptions(in_stream_except_mask_);
            }

            streamsize InflateGetBuffer::read_compressed(unsigned char *dst, streamsize count)
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

            InflateGetBuffer::int_type InflateGetBuffer::underflow()
            {
                if (gptr() < egptr())
                {
                    return traits_type::to_int_type(*gptr());
                }

                // Pull and inflate until we produce output, reach the end of the stream, or fail. inflate_chunk()
                // guarantees progress: it sets failed_ when it can make none (e.g., truncated input), so this loop
                // always terminates.
                while (!failed_)
                {
                    size_t produced = inflate_chunk();
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

            streamsize InflateGetBuffer::xsgetn(char_type *s, streamsize count)
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

                    // avail is at most buffer_size, which is well within the range of int.
                    gbump(static_cast<int>(avail));
                    total += avail;
                }
                return total;
            }

            InflateGetBuffer::pos_type InflateGetBuffer::seekoff(
                off_type off, ios_base::seekdir dir, ios_base::openmode which)
            {
                // Only a no-op seek to the current input position is supported, i.e. tellg(). The position is the
                // number of decompressed bytes already consumed from the get area.
                if (off == 0 && dir == ios_base::cur && (which & ios_base::in))
                {
                    return pos_type(total_produced_ - static_cast<off_type>(egptr() - gptr()));
                }
                return pos_type(off_type(-1));
            }
        } // namespace ztools
    } // namespace util
} // namespace seal

#endif

#ifdef SEAL_USE_ZLIB

#include "zlib.h"

namespace seal
{
    namespace util
    {
        namespace ztools
        {
            namespace
            {
                // The output size in a single deflate round cannot exceed 4 GB so we need to invert the deflateBound
                // inequality to find an upper bound for the input size.
                constexpr size_t zlib_process_bytes_out_max = static_cast<size_t>(numeric_limits<uInt>::max());

                // If input size is at most zlib_process_bytes_in_max, we can complete the deflate algorithm in a single
                // call to deflate (deflateBound(zlib_process_bytes_in_max) is at most 4 GB).
                constexpr size_t zlib_process_bytes_in_max =
                    zlib_process_bytes_out_max - (zlib_process_bytes_out_max >> 10) - 17;

                // Custom allocator for ZLIB
                void *zlib_alloc_impl(voidpf ptr_storage, uInt items, uInt size)
                {
                    try
                    {
                        size_t total_size = safe_cast<size_t>(mul_safe(items, size));
                        return reinterpret_cast<PointerStorage *>(ptr_storage)->allocate(total_size);
                    }
                    catch (const invalid_argument &)
                    {
                        // Allocation failed due to too large allocation size
                        return Z_NULL;
                    }
                    catch (const bad_alloc &)
                    {
                        // Allocation failed due to out of memory error
                        return Z_NULL;
                    }
                    catch (const logic_error &)
                    {
                        // Allocation failed due to data type overflow
                        return Z_NULL;
                    }
                    catch (const runtime_error &)
                    {
                        // Allocation failed due to too many pools allocated
                        return Z_NULL;
                    }
                }

                // Custom free implementation for ZLIB
                void zlib_free_impl(voidpf ptr_storage, void *addr)
                {
                    reinterpret_cast<PointerStorage *>(ptr_storage)->free(addr);
                }

                // Inflating stream buffer specialization for ZLIB.
                class ZlibInflateGetBuffer : public InflateGetBuffer
                {
                public:
                    ZlibInflateGetBuffer(istream &in_stream, streamoff in_size, MemoryPoolHandle pool)
                        : InflateGetBuffer(in_stream, in_size, pool), ptr_storage_(pool)
                    {
                        zstream_.data_type = Z_BINARY;
                        zstream_.zalloc = zlib_alloc_impl;
                        zstream_.zfree = zlib_free_impl;
                        zstream_.opaque = reinterpret_cast<voidpf>(&ptr_storage_);
                        zstream_.avail_in = 0;
                        zstream_.next_in = Z_NULL;
                        if (inflateInit(&zstream_) != Z_OK)
                        {
                            failed_ = true;
                        }
                        else
                        {
                            inited_ = true;
                        }
                    }

                    ~ZlibInflateGetBuffer() override
                    {
                        if (inited_)
                        {
                            inflateEnd(&zstream_);
                        }
                    }

                protected:
                    size_t inflate_chunk() override
                    {
                        if (finished_)
                        {
                            return 0;
                        }

                        // Refill the compressed input if the decompressor has consumed all of it.
                        if (!in_avail_)
                        {
                            in_avail_ = static_cast<size_t>(read_compressed(in_buf_.get(), buffer_size));
                            in_next_ = in_buf_.get();
                            if (!in_avail_)
                            {
                                // No more compressed input but the stream did not end: truncated input.
                                failed_ = true;
                                return 0;
                            }
                        }

                        zstream_.next_in = in_next_;
                        zstream_.avail_in = static_cast<uInt>(in_avail_);
                        zstream_.next_out = out_buf_.get();
                        zstream_.avail_out = static_cast<uInt>(buffer_size);

                        int result = inflate(&zstream_, Z_NO_FLUSH);
                        if (result == Z_NEED_DICT || result == Z_DATA_ERROR || result == Z_MEM_ERROR ||
                            result == Z_STREAM_ERROR)
                        {
                            failed_ = true;
                            return 0;
                        }

                        size_t consumed = in_avail_ - static_cast<size_t>(zstream_.avail_in);
                        in_next_ += consumed;
                        in_avail_ = static_cast<size_t>(zstream_.avail_in);
                        if (result == Z_STREAM_END)
                        {
                            finished_ = true;
                        }
                        return buffer_size - static_cast<size_t>(zstream_.avail_out);
                    }

                private:
                    PointerStorage ptr_storage_;
                    z_stream zstream_;
                    bool inited_ = false;
                };
            } // namespace

            unique_ptr<InflateGetBuffer> make_zlib_inflate_buffer(
                istream &in_stream, streamoff in_size, MemoryPoolHandle pool)
            {
                return make_unique<ZlibInflateGetBuffer>(in_stream, in_size, std::move(pool));
            }

            int zlib_deflate_array_inplace(DynArray<seal_byte> &in, MemoryPoolHandle pool)
            {
                if (!pool)
                {
                    throw invalid_argument("pool is uninitialized");
                }

                // We need size_t to be at least as large as uInt
                static_assert(numeric_limits<uInt>::max() <= numeric_limits<size_t>::max(), "");

                int result, flush;
                int level = Z_DEFAULT_COMPRESSION;

                int pending_bits;
                unsigned pending_bytes;

                z_stream zstream;
                zstream.data_type = Z_BINARY;

                PointerStorage ptr_storage(pool);
                zstream.zalloc = zlib_alloc_impl;
                zstream.zfree = zlib_free_impl;
                zstream.opaque = reinterpret_cast<voidpf>(&ptr_storage);

                result = deflateInit(&zstream, level);
                if (result != Z_OK)
                {
                    deflateEnd(&zstream);
                    return result;
                }

                // How much data was finally produced
                size_t bytes_written_to_in = 0;
                size_t bytes_read_from_in = 0;

                // Allocate a temporary buffer for output
                auto temp_out = DynArray<seal_byte>(buffer_size, pool);

                // Where we are writing output now; start writing to the temporary buffer
                seal_byte *out_head = temp_out.begin();

                // How much of input do we have left to process
                size_t in_size = in.size();

                // Size of the current output buffer
                size_t out_size = buffer_size;

                // Are we overwriting in at this time?
                bool out_is_in = false;

                // Set the input and output pointers for the initial block
                zstream.next_in = reinterpret_cast<unsigned char *>(const_cast<seal_byte *>(in.cbegin()));
                zstream.next_out = reinterpret_cast<unsigned char *>(out_head);

                do
                {
                    // The number of bytes we can read at a time is capped by process_bytes_in_max
                    size_t process_bytes_in = min<size_t>(in_size, zlib_process_bytes_in_max);
                    zstream.avail_in = static_cast<uInt>(process_bytes_in);

                    // Number of bytes left after this round; if we are at the end set flush accordingly
                    in_size -= process_bytes_in;
                    flush = in_size ? Z_NO_FLUSH : Z_FINISH;

                    // Loop while we have input left
                    do
                    {
                        // First ensure we have output space
                        while (!out_size)
                        {
                            // We are out of output buffer
                            if (!out_is_in)
                            {
                                // If we have been writing to the temporary buffer, then see if we can copy to in
                                size_t temp_out_size = temp_out.size();
                                if (bytes_read_from_in >= bytes_written_to_in + temp_out_size)
                                {
                                    // All is good; we can copy over the buffer to in
                                    out_head = in.begin() + bytes_written_to_in;
                                    memcpy(out_head, temp_out.cbegin(), temp_out_size);
                                    out_head += temp_out_size;
                                    bytes_written_to_in += temp_out_size;

                                    // For next writes, try to write to in
                                    out_is_in = true;

                                    // Reset out_size
                                    out_size = bytes_read_from_in - bytes_written_to_in;

                                    // Reset temp_out to have size buffer_size
                                    temp_out.resize(buffer_size, false);
                                }
                                else
                                {
                                    // We don't have enough room to copy to in; instead, resize temp_out and continue
                                    // using it, hoping that the situation will change
                                    out_size = temp_out_size + buffer_size;
                                    temp_out.resize(out_size, false);
                                    out_size = buffer_size;
                                    out_head = temp_out.begin() + temp_out_size;
                                }
                            }
                            else
                            {
                                // We are writing to in but are out of space; switch to temp_out for the moment
                                out_is_in = false;

                                // Set size and pointer
                                out_size = temp_out.size();
                                out_head = temp_out.begin();
                            }
                        }

                        // Set the stream output
                        zstream.next_out = reinterpret_cast<unsigned char *>(out_head);

                        // Cap the out size to zlib_process_bytes_out_max
                        size_t process_bytes_out = min<size_t>(out_size, zlib_process_bytes_out_max);
                        zstream.avail_out = static_cast<uInt>(process_bytes_out);

                        result = deflate(&zstream, flush);
#ifdef SEAL_DEBUG
                        // Intermediate rounds should return Z_OK and last should return Z_STREAM_END
                        if (result != Z_OK && result != Z_STREAM_END)
                        {
                            // Something went wrong so finish up here
                            deflateEnd(&zstream);
                            return result;
                        }
#endif
                        // True number of bytes written
                        process_bytes_out =
                            static_cast<size_t>(reinterpret_cast<seal_byte *>(zstream.next_out) - out_head);
                        out_size -= process_bytes_out;
                        out_head += process_bytes_out;

                        // Number of bytes read
                        bytes_read_from_in += process_bytes_in - zstream.avail_in;

                        if (out_is_in)
                        {
                            // Update number of bytes written to in
                            bytes_written_to_in += process_bytes_out;
                        }

                        // Is there pending output in the internal buffers? If so, we need to call deflate again
                        deflatePending(&zstream, &pending_bytes, &pending_bits);
                    } while ((flush == Z_FINISH && result == Z_OK) ||
                             (!zstream.avail_out && (pending_bits || pending_bytes)));
                } while (in_size);

                if (!out_is_in)
                {
                    // We are done but the last writes were to temp_out
                    size_t bytes_in_temp_out = temp_out.size() - out_size;

                    // Resize in to fit the remaining data
                    in.resize(bytes_written_to_in + bytes_in_temp_out);

                    // Copy over the buffer to in
                    out_head = in.begin() + bytes_written_to_in;
                    memcpy(out_head, temp_out.cbegin(), bytes_in_temp_out);
                    bytes_written_to_in += bytes_in_temp_out;
                }
                else
                {
                    // Just resize in to the right size
                    in.resize(bytes_written_to_in);
                }

                deflateEnd(&zstream);
                return Z_OK;
            }

            void zlib_write_header_deflate_buffer(
                DynArray<seal_byte> &in, void *header_ptr, ostream &out_stream, MemoryPoolHandle pool)
            {
                Serialization::SEALHeader &header = *reinterpret_cast<Serialization::SEALHeader *>(header_ptr);

                auto ret = zlib_deflate_array_inplace(in, std::move(pool));
                if (Z_OK != ret)
                {
                    stringstream ss;
                    ss << "ZLIB compression failed with error code ";
                    ss << ret;
                    throw logic_error(ss.str());
                }

                // Populate the header
                header.compr_mode = compr_mode_type::zlib;
                header.size = static_cast<uint64_t>(add_safe(sizeof(Serialization::SEALHeader), in.size()));

                auto old_except_mask = out_stream.exceptions();
                try
                {
                    // Throw exceptions on ios_base::badbit and ios_base::failbit
                    out_stream.exceptions(ios_base::badbit | ios_base::failbit);

                    // Write the header and the data
                    out_stream.write(reinterpret_cast<const char *>(&header), sizeof(Serialization::SEALHeader));
                    out_stream.write(reinterpret_cast<const char *>(in.cbegin()), safe_cast<streamsize>(in.size()));
                }
                catch (...)
                {
                    out_stream.exceptions(old_except_mask);
                    throw;
                }

                out_stream.exceptions(old_except_mask);
            }
        } // namespace ztools
    } // namespace util
} // namespace seal

#endif

#ifdef SEAL_USE_ZSTD

#if (SEAL_COMPILER == SEAL_COMPILER_GCC)
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wsign-conversion"
#elif (SEAL_COMPILER == SEAL_COMPILER_CLANG)
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wsign-conversion"
#endif
#define ZSTD_STATIC_LINKING_ONLY
#include "zstd.h"
#include "zstd_errors.h"
#if (SEAL_COMPILER == SEAL_COMPILER_GCC)
#pragma GCC diagnostic pop
#elif (SEAL_COMPILER == SEAL_COMPILER_CLANG)
#pragma clang diagnostic pop
#endif

namespace seal
{
    namespace util
    {
        namespace ztools
        {
            namespace
            {
                // We cap the output size in a single compression round to 4 GB so we need to invert the deflateBound
                // inequality to find an upper bound for the input size. Unlike for ZLIB, for Zstandard this is not
                // a required bound. However, it can help keep the memory footprint smaller when very large objects are
                // compressed.
                constexpr size_t zstd_process_bytes_out_max = static_cast<size_t>(numeric_limits<uint32_t>::max());

                // If input size is at most zstd_process_bytes_in_max, we can complete the deflate algorithm in a single
                // call to deflate (deflateBound(zstd_process_bytes_in_max) is at most 4 GB).
                constexpr size_t zstd_process_bytes_in_max =
                    zstd_process_bytes_out_max - (zstd_process_bytes_out_max >> 8) - 64;

                constexpr int zstd_window_log_max = 23;

                // Custom allocator for Zstandard
                void *zstd_alloc_impl(void *ptr_storage, size_t size)
                {
                    try
                    {
                        return reinterpret_cast<PointerStorage *>(ptr_storage)->allocate(size);
                    }
                    catch (const invalid_argument &)
                    {
                        // Allocation failed due to too large allocation size
                        return nullptr;
                    }
                    catch (const bad_alloc &)
                    {
                        // Allocation failed due to out of memory error
                        return nullptr;
                    }
                    catch (const logic_error &)
                    {
                        // Allocation failed due to data type overflow
                        return nullptr;
                    }
                    catch (const runtime_error &)
                    {
                        // Allocation failed due to too many pools allocated
                        return nullptr;
                    }
                }

                // Custom free implementation for Zstandard
                void zstd_free_impl(void *ptr_storage, void *addr)
                {
                    reinterpret_cast<PointerStorage *>(ptr_storage)->free(addr);
                }

                // Inflating stream buffer specialization for Zstandard.
                class ZstdInflateGetBuffer : public InflateGetBuffer
                {
                public:
                    ZstdInflateGetBuffer(istream &in_stream, streamoff in_size, MemoryPoolHandle pool)
                        : InflateGetBuffer(in_stream, in_size, pool), ptr_storage_(pool)
                    {
                        mem_.customAlloc = zstd_alloc_impl;
                        mem_.customFree = zstd_free_impl;
                        mem_.opaque = &ptr_storage_;
                        dctx_ = ZSTD_createDCtx_advanced(mem_);
                        if (!dctx_)
                        {
                            failed_ = true;
                        }
                        else if (ZSTD_isError(ZSTD_DCtx_setParameter(dctx_, ZSTD_d_windowLogMax, zstd_window_log_max)))
                        {
                            failed_ = true;
                        }
                    }

                    ~ZstdInflateGetBuffer() override
                    {
                        if (dctx_)
                        {
                            ZSTD_freeDCtx(dctx_);
                        }
                    }

                protected:
                    size_t inflate_chunk() override
                    {
                        if (finished_)
                        {
                            return 0;
                        }

                        // Refill the compressed input if the decompressor has consumed all of it.
                        if (!in_avail_)
                        {
                            in_avail_ = static_cast<size_t>(read_compressed(in_buf_.get(), buffer_size));
                            in_next_ = in_buf_.get();
                            if (!in_avail_)
                            {
                                // No more compressed input but the stream did not end: truncated input.
                                failed_ = true;
                                return 0;
                            }
                        }

                        ZSTD_inBuffer input = { in_next_, in_avail_, 0 };
                        ZSTD_outBuffer output = { out_buf_.get(), buffer_size, 0 };

                        size_t ret = ZSTD_decompressStream(dctx_, &output, &input);
                        if (ZSTD_isError(ret))
                        {
                            failed_ = true;
                            return 0;
                        }

                        in_next_ += input.pos;
                        in_avail_ -= input.pos;

                        // A return value of 0 indicates a frame was fully decoded; SEAL writes a single frame, so this
                        // marks the end of the stream.
                        if (ret == 0)
                        {
                            finished_ = true;
                        }
                        return output.pos;
                    }

                private:
                    PointerStorage ptr_storage_;
                    ZSTD_customMem mem_;
                    ZSTD_DCtx *dctx_ = nullptr;
                };
            } // namespace

            unique_ptr<InflateGetBuffer> make_zstd_inflate_buffer(
                istream &in_stream, streamoff in_size, MemoryPoolHandle pool)
            {
                return make_unique<ZstdInflateGetBuffer>(in_stream, in_size, std::move(pool));
            }

            unsigned zstd_deflate_array_inplace(DynArray<seal_byte> &in, MemoryPoolHandle pool)
            {
                if (!pool)
                {
                    throw invalid_argument("pool is uninitialized");
                }

                PointerStorage ptr_storage(pool);

                // Set up the custom allocator
                ZSTD_customMem mem;
                mem.customAlloc = zstd_alloc_impl;
                mem.customFree = zstd_free_impl;
                mem.opaque = &ptr_storage;

                ZSTD_CCtx *cctx = ZSTD_createCCtx_advanced(mem);
                if (!cctx)
                {
                    // Failed to set up the context; there is something wrong with the allocator
                    return ZSTD_error_GENERIC;
                }

                // How much data was finally produced
                size_t bytes_written_to_in = 0;
                size_t bytes_read_from_in = 0;

                // Allocate a temporary buffer for output
                auto temp_out = DynArray<seal_byte>(buffer_size, pool);

                // Where we are writing output now; start writing to the temporary buffer
                seal_byte *out_head = temp_out.begin();

                // How much of input do we have left to process
                size_t in_size = in.size();

                // Size of the current output buffer
                size_t out_size = buffer_size;

                // Are we overwriting in at this time?
                bool out_is_in = false;

                // Holds the return value of the stream compression call. This is either the amount of data that remains
                // to be flushed from internal buffers, or an error code.
                size_t pending = 0;

                do
                {
                    // The number of bytes we can read at a time is capped by zstd_process_bytes_in_max
                    size_t process_bytes_in = min<size_t>(in_size, zstd_process_bytes_in_max);
                    ZSTD_inBuffer input = { in.cbegin() + bytes_read_from_in, process_bytes_in, 0 };
                    size_t prev_pos = 0;

                    // Number of bytes left after this round; if we are at the end set flush accordingly
                    in_size -= process_bytes_in;
                    ZSTD_EndDirective flush = in_size ? ZSTD_e_continue : ZSTD_e_end;

                    // Loop while we have input left
                    do
                    {
                        // First ensure we have output space
                        while (!out_size)
                        {
                            // We are out of output buffer
                            if (!out_is_in)
                            {
                                // If we have been writing to the temporary buffer, then see if we can copy to in
                                size_t temp_out_size = temp_out.size();
                                if (bytes_read_from_in >= bytes_written_to_in + temp_out_size)
                                {
                                    // All is good; we can copy over the buffer to in
                                    out_head = in.begin() + bytes_written_to_in;
                                    memcpy(out_head, temp_out.cbegin(), temp_out_size);
                                    out_head += temp_out_size;
                                    bytes_written_to_in += temp_out_size;

                                    // For next writes, try to write to in
                                    out_is_in = true;

                                    // Reset out_size
                                    out_size = bytes_read_from_in - bytes_written_to_in;

                                    // Reset temp_out to have size buffer_size
                                    temp_out.resize(buffer_size, false);
                                }
                                else
                                {
                                    // We don't have enough room to copy to in; instead, resize temp_out and continue
                                    // using it, hoping that the situation will change
                                    out_size = temp_out_size + buffer_size;
                                    temp_out.resize(out_size, false);
                                    out_size = buffer_size;
                                    out_head = temp_out.begin() + temp_out_size;
                                }
                            }
                            else
                            {
                                // We are writing to in but are out of space; switch to temp_out for the moment
                                out_is_in = false;

                                // Set size and pointer
                                out_size = temp_out.size();
                                out_head = temp_out.begin();
                            }
                        }

                        // Cap the out size to zstd_process_bytes_out_max
                        size_t process_bytes_out = min<size_t>(out_size, zstd_process_bytes_out_max);

                        ZSTD_outBuffer output = { out_head, process_bytes_out, 0 };

                        // Call the stream compression; the return value indicates remaining data in internal buffers,
                        // or an error code, which we need to check.
                        pending = ZSTD_compressStream2(cctx, &output, &input, flush);
                        if (ZSTD_isError(pending))
                        {
                            // Something went wrong; return the error code
                            return static_cast<unsigned>(pending);
                        }

                        // True number of bytes written
                        process_bytes_out = output.pos;
                        out_size -= process_bytes_out;
                        out_head += process_bytes_out;

                        // Number of bytes read
                        bytes_read_from_in += input.pos - prev_pos;
                        prev_pos = input.pos;

                        if (out_is_in)
                        {
                            // Update number of bytes written to in
                            bytes_written_to_in += process_bytes_out;
                        }

                        // Continue while not all input has been read, or while there is data pending in the internal
                        // buffers
                    } while (pending || (input.pos != input.size));
                } while (in_size);

                if (!out_is_in)
                {
                    // We are done but the last writes were to temp_out
                    size_t bytes_in_temp_out = temp_out.size() - out_size;

                    // Resize in to fit the remaining data
                    in.resize(bytes_written_to_in + bytes_in_temp_out);

                    // Copy over the buffer to in
                    out_head = in.begin() + bytes_written_to_in;
                    memcpy(out_head, temp_out.cbegin(), bytes_in_temp_out);
                    bytes_written_to_in += bytes_in_temp_out;
                }
                else
                {
                    // Just resize in to the right size
                    in.resize(bytes_written_to_in);
                }

                ZSTD_freeCCtx(cctx);

                return ZSTD_error_no_error;
            }

            void zstd_write_header_deflate_buffer(
                DynArray<seal_byte> &in, void *header_ptr, ostream &out_stream, MemoryPoolHandle pool)
            {
                Serialization::SEALHeader &header = *reinterpret_cast<Serialization::SEALHeader *>(header_ptr);

                auto ret = zstd_deflate_array_inplace(in, std::move(pool));
                if (ZSTD_error_no_error != ret)
                {
                    stringstream ss;
                    ss << "Zstandard compression failed with error code ";
                    ss << ret;
                    ss << " (" << ZSTD_getErrorName(ret) << ")";
                    throw logic_error(ss.str());
                }

                // Populate the header
                header.compr_mode = compr_mode_type::zstd;
                header.size = static_cast<uint64_t>(add_safe(sizeof(Serialization::SEALHeader), in.size()));

                auto old_except_mask = out_stream.exceptions();
                try
                {
                    // Throw exceptions on ios_base::badbit and ios_base::failbit
                    out_stream.exceptions(ios_base::badbit | ios_base::failbit);

                    // Write the header and the data
                    out_stream.write(reinterpret_cast<const char *>(&header), sizeof(Serialization::SEALHeader));
                    out_stream.write(reinterpret_cast<const char *>(in.cbegin()), safe_cast<streamsize>(in.size()));
                }
                catch (...)
                {
                    out_stream.exceptions(old_except_mask);
                    throw;
                }

                out_stream.exceptions(old_except_mask);
            }
        } // namespace ztools
    } // namespace util
} // namespace seal

#endif
