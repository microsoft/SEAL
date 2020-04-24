// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include "seal/util/defines.h"

#ifdef SEAL_USE_ZLIB

#include "seal/serialization.h"
#include "seal/util/pointer.h"
#include "seal/util/ztools.h"
#include <cmath>
#include <cstddef>
#include <limits>
#include <unordered_map>
#include <zlib.h>

using namespace std;

namespace seal
{
    namespace util
    {
        namespace ztools
        {
            namespace
            {
                constexpr size_t inflate_buffer_size = 256 * 1024;

                constexpr double deflate_buffer_expansion_factor = 1.3;

                // The output size in a single deflate round cannot exceed 4 GB so we need to invert the deflateBound
                // inequality to find an upper bound for the input size.
                constexpr size_t process_bytes_out_max = static_cast<size_t>(numeric_limits<uInt>::max());

                // If input size is at most process_bytes_in_max, we can complete the deflate algorithm in a single call
                // to deflate (deflateBound(process_bytes_in_max) is at most 4 GB).
                constexpr size_t process_bytes_in_max = process_bytes_out_max - (process_bytes_out_max >> 10) - 17;

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

                // Custom implementation for zlib zalloc
                void *alloc_impl(voidpf ptr_storage, uInt items, uInt size)
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
                void free_impl(voidpf ptr_storage, void *addr)
                {
                    reinterpret_cast<PointerStorage *>(ptr_storage)->free(addr);
                }
            } // namespace

            size_t deflate_size_bound(size_t in_size)
            {
                return util::add_safe(in_size, in_size >> 12, in_size >> 14, in_size >> 25, std::size_t(17));
            }

            int deflate_array(const IntArray<SEAL_BYTE> &in, IntArray<SEAL_BYTE> &out, MemoryPoolHandle pool)
            {
                if (!pool)
                {
                    throw invalid_argument("pool is uninitialized");
                }

                // We need size_t to be at least as large as uInt
                static_assert(numeric_limits<uInt>::max() <= numeric_limits<size_t>::max(), "");

                size_t in_size = in.size();
                int result, flush;
                int level = Z_DEFAULT_COMPRESSION;

                int pending_bits;
                unsigned pending_bytes;

                z_stream zstream;
                zstream.data_type = Z_BINARY;

                PointerStorage ptr_storage(pool);
                zstream.zalloc = alloc_impl;
                zstream.zfree = free_impl;
                zstream.opaque = reinterpret_cast<voidpf>(&ptr_storage);

                result = deflateInit(&zstream, level);
                if (result != Z_OK)
                {
                    deflateEnd(&zstream);
                    return result;
                }

                // Set the output buffer size fo the deflate size bound; for small input buffers this will guarantee
                // deflate to immediately return Z_STREAM_END
                size_t out_size = deflate_size_bound(in_size);
                out.resize(out_size, false);

                // How much data was finally produced
                size_t final_out_size = 0;

                // Set the input and output pointers; deflate moves these automatically
                zstream.next_in = reinterpret_cast<unsigned char *>(const_cast<SEAL_BYTE *>(in.cbegin()));
                zstream.next_out = reinterpret_cast<unsigned char *>(out.begin());

                do
                {
                    size_t process_bytes_in = min<size_t>(in_size, process_bytes_in_max);
                    zstream.avail_in = static_cast<uInt>(process_bytes_in);

                    // Number of bytes left after this round; if we are at the end set flush accordingly
                    in_size -= process_bytes_in;
                    flush = in_size ? Z_NO_FLUSH : Z_FINISH;

                    do
                    {
                        // If out_size is zero, then we need to reallocate and increase the size
                        if (!out_size)
                        {
                            out_size = safe_cast<size_t>(
                                ceil(safe_cast<double>(out.size()) * deflate_buffer_expansion_factor));
                            out.resize(out_size, false);

                            // Set the next_out pointer correctly to the new allocation and shift by the number of bytes
                            // already written
                            zstream.next_out = reinterpret_cast<unsigned char *>(out.begin()) + final_out_size;
                            out_size -= final_out_size;
                        }

                        size_t process_bytes_out = min<size_t>(out_size, process_bytes_out_max);
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
                        // Update out_size
                        process_bytes_out -= static_cast<size_t>(zstream.avail_out);
                        out_size -= process_bytes_out;
                        final_out_size += process_bytes_out;

                        // Is there pending output in the internal buffers? If so, we need to call deflate again
                        deflatePending(&zstream, &pending_bytes, &pending_bits);
                    } while (!zstream.avail_out && (pending_bits || pending_bytes));
                } while (in_size);

                // Now resize out to the right size
                out.resize(final_out_size);

                deflateEnd(&zstream);
                return Z_OK;
            }

            int inflate_stream(istream &in_stream, streamoff in_size, ostream &out_stream, MemoryPoolHandle pool)
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

                auto in(allocate<unsigned char>(inflate_buffer_size, pool));
                auto out(allocate<unsigned char>(inflate_buffer_size, pool));

                z_stream zstream;
                zstream.data_type = Z_BINARY;

                PointerStorage ptr_storage(pool);
                zstream.zalloc = alloc_impl;
                zstream.zfree = free_impl;
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
                            min(static_cast<streamoff>(inflate_buffer_size), in_stream_end_pos - in_stream.tellg())))
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
                        zstream.avail_out = inflate_buffer_size;
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

                        have = inflate_buffer_size - static_cast<size_t>(zstream.avail_out);

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

            void write_header_deflate_buffer(
                const IntArray<SEAL_BYTE> &in, void *header_ptr, ostream &out_stream, MemoryPoolHandle pool)
            {
                Serialization::SEALHeader &header = *reinterpret_cast<Serialization::SEALHeader *>(header_ptr);

                IntArray<SEAL_BYTE> out_array(pool);
                auto ret = deflate_array(in, out_array, move(pool));
                if (Z_OK != ret)
                {
                    throw logic_error("deflate failed");
                }

                // Populate the header
                header.compr_mode = compr_mode_type::deflate;
                header.size = static_cast<uint64_t>(add_safe(sizeof(Serialization::SEALHeader), out_array.size()));

                auto old_except_mask = out_stream.exceptions();
                try
                {
                    // Throw exceptions on ios_base::badbit and ios_base::failbit
                    out_stream.exceptions(ios_base::badbit | ios_base::failbit);

                    // Write the header and the data
                    out_stream.write(reinterpret_cast<const char *>(&header), sizeof(Serialization::SEALHeader));
                    out_stream.write(
                        reinterpret_cast<const char *>(out_array.cbegin()), safe_cast<streamsize>(out_array.size()));
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
