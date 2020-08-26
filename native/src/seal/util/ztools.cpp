// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include "seal/util/defines.h"

#if defined(SEAL_USE_ZLIB) || defined(SEAL_USE_ZSTD)

#include "seal/serialization.h"
#include "seal/util/pointer.h"
#include "seal/util/ztools.h"
#include <cmath>
#include <cstddef>
#include <cstring>
#include <limits>
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
                    PointerStorage(MemoryPoolHandle pool) : pool_(pool)
                    {}

                    void *allocate(size_t size)
                    {
                        auto ptr = util::allocate<SEAL_BYTE>(size, pool_);
                        void *addr = reinterpret_cast<void *>(ptr.get());
                        ptr_storage_[addr] = move(ptr);
                        return addr;
                    }

                    void free(void *addr)
                    {
                        ptr_storage_.erase(addr);
                    }

                private:
                    MemoryPoolHandle pool_;

                    unordered_map<void *, Pointer<SEAL_BYTE>> ptr_storage_;
                };
            } // namespace
        }     // namespace ztools
    }         // namespace util
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

                // If input size is at most process_bytes_in_max, we can complete the deflate algorithm in a single call
                // to deflate (deflateBound(process_bytes_in_max) is at most 4 GB).
                constexpr size_t zlib_process_bytes_in_max =
                    zlib_process_bytes_out_max - (zlib_process_bytes_out_max >> 10) - 17;

                // Custom implementation for zlib zalloc
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

                // Custom implementation for zlib zfree
                void zlib_free_impl(voidpf ptr_storage, void *addr)
                {
                    reinterpret_cast<PointerStorage *>(ptr_storage)->free(addr);
                }
            } // namespace

            int zlib_deflate_array_inplace(IntArray<SEAL_BYTE> &in, MemoryPoolHandle pool)
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
                auto temp_out = IntArray<SEAL_BYTE>(buffer_size, pool);

                // Where we are writing output now; start writing to the temporary buffer
                SEAL_BYTE *out_head = temp_out.begin();

                // How much of input do we have left to process
                size_t in_size = in.size();

                // Size of the current output buffer
                size_t out_size = buffer_size;

                // Are we overwriting in at this time?
                bool out_is_in = false;

                // Set the input and output pointers for the initial block
                zstream.next_in = reinterpret_cast<unsigned char *>(const_cast<SEAL_BYTE *>(in.cbegin()));
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

                        // Cap the out size to process_bytes_out_max
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
                            static_cast<size_t>(reinterpret_cast<SEAL_BYTE *>(zstream.next_out) - out_head);
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

            int zlib_inflate_stream(istream &in_stream, streamoff in_size, ostream &out_stream, MemoryPoolHandle pool)
            {
                // Clear the exception masks; this function returns an error code
                // on failure rather than throws an IO exception.
                auto in_stream_except_mask = in_stream.exceptions();
                in_stream.exceptions(ios_base::goodbit);
                auto out_stream_except_mask = out_stream.exceptions();
                out_stream.exceptions(ios_base::goodbit);

                auto in_stream_start_pos = in_stream.tellg();
                auto in_stream_end_pos = in_stream_start_pos + in_size;

                int result;
                size_t have;

                auto in(allocate<unsigned char>(buffer_size, pool));
                auto out(allocate<unsigned char>(buffer_size, pool));

                z_stream zstream;
                zstream.data_type = Z_BINARY;

                PointerStorage ptr_storage(pool);
                zstream.zalloc = zlib_alloc_impl;
                zstream.zfree = zlib_free_impl;
                zstream.opaque = reinterpret_cast<voidpf>(&ptr_storage);

                zstream.avail_in = 0;
                zstream.next_in = Z_NULL;
                result = inflateInit(&zstream);
                if (result != Z_OK)
                {
                    in_stream.exceptions(in_stream_except_mask);
                    out_stream.exceptions(out_stream_except_mask);
                    return result;
                }

                do
                {
                    if (!in_stream.read(
                            reinterpret_cast<char *>(in.get()),
                            min(static_cast<streamoff>(buffer_size), in_stream_end_pos - in_stream.tellg())))
                    {
                        inflateEnd(&zstream);
                        in_stream.exceptions(in_stream_except_mask);
                        out_stream.exceptions(out_stream_except_mask);
                        return Z_ERRNO;
                    }
                    if (!(zstream.avail_in = static_cast<decltype(zstream.avail_in)>(in_stream.gcount())))
                    {
                        break;
                    }
                    zstream.next_in = in.get();

                    do
                    {
                        zstream.avail_out = buffer_size;
                        zstream.next_out = out.get();
                        result = inflate(&zstream, Z_NO_FLUSH);

                        switch (result)
                        {
                        case Z_NEED_DICT:
                            result = Z_DATA_ERROR;
                            /* fall through */

                        case Z_DATA_ERROR:
                            /* fall through */

                        case Z_MEM_ERROR:
                            inflateEnd(&zstream);
                            in_stream.exceptions(in_stream_except_mask);
                            out_stream.exceptions(out_stream_except_mask);
                            return result;
                        }

                        have = buffer_size - static_cast<size_t>(zstream.avail_out);

                        if (!out_stream.write(reinterpret_cast<const char *>(out.get()), static_cast<streamsize>(have)))
                        {
                            inflateEnd(&zstream);
                            in_stream.exceptions(in_stream_except_mask);
                            out_stream.exceptions(out_stream_except_mask);
                            return Z_ERRNO;
                        }
                    } while (!zstream.avail_out);
                } while (result != Z_STREAM_END);

                inflateEnd(&zstream);
                in_stream.exceptions(in_stream_except_mask);
                out_stream.exceptions(out_stream_except_mask);
                return result == Z_STREAM_END ? Z_OK : Z_DATA_ERROR;
            }

            void zlib_write_header_deflate_buffer(
                IntArray<SEAL_BYTE> &in, void *header_ptr, ostream &out_stream, MemoryPoolHandle pool)
            {
                Serialization::SEALHeader &header = *reinterpret_cast<Serialization::SEALHeader *>(header_ptr);

                auto ret = zlib_deflate_array_inplace(in, move(pool));
                if (Z_OK != ret)
                {
                    throw logic_error("zlib compression failed");
                }

                // Populate the header
                header.compr_mode = compr_mode_type::ZLIB;
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
    }     // namespace util
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
#include "common/zstd_internal.h"
#include "zstd.h"
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
                // inequality to find an upper bound for the input size.
                constexpr size_t zstd_process_bytes_out_max = static_cast<size_t>(numeric_limits<uint32_t>::max());

                // If input size is at most process_bytes_in_max, we can complete the deflate algorithm in a single call
                // to deflate (deflateBound(process_bytes_in_max) is at most 4 GB).
                constexpr size_t zstd_process_bytes_in_max =
                    zstd_process_bytes_out_max - (zstd_process_bytes_out_max >> 8) - 64;

                // Custom implementation for Zstandard
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

                // Custom implementation for zlib zfree
                void zstd_free_impl(void *ptr_storage, void *addr)
                {
                    reinterpret_cast<PointerStorage *>(ptr_storage)->free(addr);
                }
            } // namespace

            int zstd_deflate_array_inplace(IntArray<SEAL_BYTE> &in, MemoryPoolHandle pool)
            {
                if (!pool)
                {
                    throw invalid_argument("pool is uninitialized");
                }

                // int result;
                // int level = Z_DEFAULT_COMPRESSION;

                size_t pending = 0;

                // z_stream zstream;
                // zstream.data_type = Z_BINARY;

                PointerStorage ptr_storage(pool);

                ZSTD_customMem mem;
                mem.customAlloc = zstd_alloc_impl;
                mem.customFree = zstd_free_impl;
                mem.opaque = &ptr_storage;

                // zstream.zalloc = alloc_impl;
                // zstream.zfree = free_impl;
                // zstream.opaque = reinterpret_cast<voidpf>(&ptr_storage);

                // result = deflateInit(&zstream, level);
                ZSTD_CCtx *cctx = ZSTD_createCCtx_advanced(mem);

                // ZSTD_CCtx_setParameter(cctx, ZSTD_c_compressionLevel, 1);
                // ZSTD_CCtx_setParameter(cctx, ZSTD_c_checksumFlag, 1);

                // if (result != Z_OK)
                //{
                // deflateEnd(&zstream);
                // return result;
                //}

                // How much data was finally produced
                size_t bytes_written_to_in = 0;
                size_t bytes_read_from_in = 0;

                // Allocate a temporary buffer for output
                auto temp_out = IntArray<SEAL_BYTE>(buffer_size, pool);

                // Where we are writing output now; start writing to the temporary buffer
                SEAL_BYTE *out_head = temp_out.begin();

                // How much of input do we have left to process
                size_t in_size = in.size();

                // Size of the current output buffer
                size_t out_size = buffer_size;

                // Are we overwriting in at this time?
                bool out_is_in = false;

                // Set the input and output pointers for the initial block
                // zstream.next_in = reinterpret_cast<unsigned char *>(const_cast<SEAL_BYTE *>(in.cbegin()));
                // zstream.next_out = reinterpret_cast<unsigned char *>(out_head);

                do
                {
                    // The number of bytes we can read at a time is capped by zstd_process_bytes_in_max
                    size_t process_bytes_in = min<size_t>(in_size, zstd_process_bytes_in_max);
                    ZSTD_inBuffer input = { in.cbegin() + bytes_read_from_in, process_bytes_in, 0 };
                    // input.size = process_bytes_in;

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

                        // Set the stream output
                        // zstream.next_out = reinterpret_cast<unsigned char *>(out_head);
                        // output.dst = out_head;

                        // Cap the out size to process_bytes_out_max
                        size_t process_bytes_out = min<size_t>(out_size, zstd_process_bytes_out_max);
                        // zstream.avail_out = static_cast<uInt>(process_bytes_out);

                        ZSTD_outBuffer output = { out_head, process_bytes_out, 0 };

                        // result = deflate(&zstream, flush);

                        pending = ZSTD_compressStream2(cctx, &output, &input, flush);

                        // True number of bytes written
                        process_bytes_out = output.pos;
                        out_size -= process_bytes_out;
                        out_head += process_bytes_out;

                        if (out_is_in)
                        {
                            // Update number of bytes written to in
                            bytes_written_to_in += process_bytes_out;
                        }

                        // Continue while not all input has been read, or while there is data pending in the internal
                        // buffers
                    } while (pending || (input.pos != input.size));
                    //} while (((flush == ZSTD_e_end) && pending) || (input.pos != input.size));

                    // Number of bytes read
                    bytes_read_from_in += process_bytes_in;
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

                return 0;
            }

            int zstd_inflate_stream(istream &in_stream, streamoff in_size, ostream &out_stream, MemoryPoolHandle pool)
            {
                // Clear the exception masks; this function returns an error code
                // on failure rather than throws an IO exception.
                auto in_stream_except_mask = in_stream.exceptions();
                in_stream.exceptions(ios_base::goodbit);
                auto out_stream_except_mask = out_stream.exceptions();
                out_stream.exceptions(ios_base::goodbit);

                auto in_stream_start_pos = in_stream.tellg();
                auto in_stream_end_pos = in_stream_start_pos + in_size;

                auto in(allocate<unsigned char>(buffer_size, pool));
                auto out(allocate<unsigned char>(buffer_size, pool));

                size_t pending = 0;

                PointerStorage ptr_storage(pool);
                ZSTD_customMem mem;
                mem.customAlloc = zstd_alloc_impl;
                mem.customFree = zstd_free_impl;
                mem.opaque = &ptr_storage;

                // z_stream zstream;
                // zstream.data_type = Z_BINARY;
                ZSTD_DCtx *dctx = ZSTD_createDCtx_advanced(mem);

                // zstream.zalloc = alloc_impl;
                // zstream.zfree = free_impl;
                // zstream.opaque = reinterpret_cast<voidpf>(&ptr_storage);

                // zstream.avail_in = 0;
                // zstream.next_in = Z_NULL;
                // result = inflateInit(&zstream);
                // if (result != Z_OK)
                //{
                // in_stream.exceptions(in_stream_except_mask);
                // out_stream.exceptions(out_stream_except_mask);
                // return result;
                //}

                while (true)
                {
                    if (!in_stream.read(
                            reinterpret_cast<char *>(in.get()),
                            min(static_cast<streamoff>(buffer_size), in_stream_end_pos - in_stream.tellg())))
                    {
                        // inflateEnd(&zstream);
                        in_stream.exceptions(in_stream_except_mask);
                        out_stream.exceptions(out_stream_except_mask);

                        // Failed to read from stream
                        return -1;
                    }

                    ZSTD_inBuffer input = { in.get(), static_cast<size_t>(in_stream.gcount()), 0 };
                    if (!input.size)
                    {
                        break;
                    }

                    while (input.pos < input.size)
                    {
                        ZSTD_outBuffer output = { out.get(), buffer_size, 0 };
                        pending = ZSTD_decompressStream(dctx, &output, &input);

                        // zstream.avail_out = buffer_size;
                        // zstream.next_out = out.get();
                        // result = inflate(&zstream, Z_NO_FLUSH);

                        // switch (result)
                        //{
                        // case Z_NEED_DICT:
                        // result = Z_DATA_ERROR;
                        //[> fall through <]

                        // case Z_DATA_ERROR:
                        //[> fall through <]

                        // case Z_MEM_ERROR:
                        // inflateEnd(&zstream);
                        // in_stream.exceptions(in_stream_except_mask);
                        // out_stream.exceptions(out_stream_except_mask);
                        // return result;
                        //}

                        // in_stream.exceptions(in_stream_except_mask);
                        // out_stream.exceptions(out_stream_except_mask);
                        // return result;

                        if (!out_stream.write(
                                reinterpret_cast<const char *>(out.get()), static_cast<streamsize>(output.pos)))
                        {
                            // inflateEnd(&zstream);
                            in_stream.exceptions(in_stream_except_mask);
                            out_stream.exceptions(out_stream_except_mask);
                            return -1;
                        }
                    }
                }
                //} while (result != Z_STREAM_END);

                ZSTD_freeDCtx(dctx);
                // inflateEnd(&zstream);

                in_stream.exceptions(in_stream_except_mask);
                out_stream.exceptions(out_stream_except_mask);
                return 0;
                // return result == Z_STREAM_END ? Z_OK : Z_DATA_ERROR;
            }

            void zstd_write_header_deflate_buffer(
                IntArray<SEAL_BYTE> &in, void *header_ptr, ostream &out_stream, MemoryPoolHandle pool)
            {
                Serialization::SEALHeader &header = *reinterpret_cast<Serialization::SEALHeader *>(header_ptr);

                auto ret = zstd_deflate_array_inplace(in, move(pool));
                if (ret)
                {
                    throw logic_error("zstd compression failed");
                }

                // Populate the header
                header.compr_mode = compr_mode_type::ZSTD;
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
    }     // namespace util
} // namespace seal

#endif
