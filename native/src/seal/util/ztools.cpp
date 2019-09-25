// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include "seal/util/defines.h"

#ifdef SEAL_USE_ZLIB

#include <cstddef>
#include <zlib.h>
#include <unordered_map>
#include "seal/util/ztools.h"
#include "seal/util/pointer.h"

using namespace std;

namespace seal
{
    namespace util
    {
        namespace ztools
        {
            namespace
            {
                class PointerStorage
                {
                public:
                    PointerStorage(MemoryPoolHandle pool) : pool_(pool)
                    {
                    }

                    void *allocate(size_t size)
                    {
                        auto ptr = util::allocate<SEAL_BYTE>(size, pool_);
                        void *addr = reinterpret_cast<void*>(ptr.get());
                        ptr_storage_[addr] = move(ptr);
                        return addr;
                    }

                    void free(void *addr)
                    {
                        ptr_storage_.erase(addr);
                    }

                private:
                    MemoryPoolHandle pool_;

                    unordered_map<void*, Pointer<SEAL_BYTE>> ptr_storage_;
                };

                // Custom implementation for zlib zalloc
                void *alloc_impl(voidpf ptr_storage, uInt items, uInt size)
                {
                    try
                    {
                        size_t total_size = safe_cast<size_t>(mul_safe(items, size));
                        return reinterpret_cast<PointerStorage*>(ptr_storage)->allocate(total_size);
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
                    reinterpret_cast<PointerStorage*>(ptr_storage)->free(addr);
                }
            }

            size_t deflate_size_bound(size_t in_size) noexcept
            {
                return util::add_safe(
                    in_size,
                    in_size >> 12,
                    in_size >> 14,
                    in_size >> 25,
                    std::size_t(13));
            }

            int deflate_stream(istream &in_stream,
                streamoff in_size, ostream &out_stream,
                MemoryPoolHandle pool)
            {
                // Clear the exception masks; this function returns an error code
                // on failure rather than throws an IO exception.
                auto in_stream_except_mask = in_stream.exceptions();
                in_stream.exceptions(ios_base::goodbit);
                auto out_stream_except_mask = out_stream.exceptions();
                out_stream.exceptions(ios_base::goodbit);

                try
                {
                    auto in_stream_start_pos = in_stream.tellg();
                    in_stream.seekg(0, in_stream.end);
                    auto in_stream_end_pos = in_stream.tellg();
                    if (in_stream_end_pos - in_stream_start_pos < in_size)
                    {
                        in_stream.exceptions(in_stream_except_mask);
                        out_stream.exceptions(out_stream_except_mask);
                        return Z_ERRNO;
                    }
                    in_stream.seekg(in_stream_start_pos);
                    in_stream.seekg(in_size, in_stream.cur);
                    in_stream_end_pos = in_stream.tellg();
                    in_stream.seekg(in_stream_start_pos);

                    int result, flush;
                    int level = Z_DEFAULT_COMPRESSION;

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
                        in_stream.exceptions(in_stream_except_mask);
                        out_stream.exceptions(out_stream_except_mask);
                        return result;
                    }

                    flush = Z_FINISH;
                    auto in(allocate<unsigned char>(safe_cast<size_t>(in_size), pool));
                    size_t out_size = safe_cast<size_t>(
                        deflateBound(&zstream, safe_cast<uLong>(in_size)));
                    auto out(allocate<unsigned char>(out_size, pool));

                    if (!in_stream.read(reinterpret_cast<char*>(in.get()), in_size))
                    {
                        deflateEnd(&zstream);
                        in_stream.exceptions(in_stream_except_mask);
                        out_stream.exceptions(out_stream_except_mask);
                        return Z_ERRNO;
                    }

                    zstream.avail_in = safe_cast<uInt>(in_size);
                    zstream.next_in = in.get();
                    zstream.avail_out = safe_cast<uInt>(out_size);
                    zstream.next_out = out.get();

                    result = deflate(&zstream, flush);
                    if (result != Z_STREAM_END)
                    {
                        deflateEnd(&zstream);
                        in_stream.exceptions(in_stream_except_mask);
                        out_stream.exceptions(out_stream_except_mask);
                        return result;
                    }

                    if (!out_stream.write(reinterpret_cast<const char*>(out.get()),
                        safe_cast<streamsize>(
                            static_cast<uInt>(out_size) - zstream.avail_out)))
                    {
                        deflateEnd(&zstream);
                        in_stream.exceptions(in_stream_except_mask);
                        out_stream.exceptions(out_stream_except_mask);
                        return Z_ERRNO;
                    }

                    deflateEnd(&zstream);
                    in_stream.exceptions(in_stream_except_mask);
                    out_stream.exceptions(out_stream_except_mask);
                    return Z_OK;
                }
                catch (const logic_error &)
                {
                    in_stream.exceptions(in_stream_except_mask);
                    out_stream.exceptions(out_stream_except_mask);
                    throw;
                }
            }

            int inflate_stream(istream &in_stream,
                streamoff in_size, ostream &out_stream,
                MemoryPoolHandle pool)
            {
                // Clear the exception masks; this function returns an error code
                // on failure rather than throws an IO exception.
                auto in_stream_except_mask = in_stream.exceptions();
                in_stream.exceptions(ios_base::goodbit);
                auto out_stream_except_mask = out_stream.exceptions();
                out_stream.exceptions(ios_base::goodbit);

                auto in_stream_start_pos = in_stream.tellg();
                in_stream.seekg(0, in_stream.end);
                auto in_stream_end_pos = in_stream.tellg();
                if (in_stream_end_pos - in_stream_start_pos < in_size)
                {
                    in_stream.exceptions(in_stream_except_mask);
                    out_stream.exceptions(out_stream_except_mask);
                    return Z_ERRNO;
                }
                in_stream.seekg(in_stream_start_pos);
                in_stream.seekg(in_size, in_stream.cur);
                in_stream_end_pos = in_stream.tellg();
                in_stream.seekg(in_stream_start_pos);

                int result;
                size_t have;

                auto in(allocate<unsigned char>(buf_size, pool));
                auto out(allocate<unsigned char>(buf_size, pool));

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
                    if (!in_stream.read(reinterpret_cast<char*>(in.get()),
                        min(static_cast<streamoff>(buf_size),
                            in_stream_end_pos - in_stream.tellg())))
                    {
                        inflateEnd(&zstream);
                        in_stream.exceptions(in_stream_except_mask);
                        out_stream.exceptions(out_stream_except_mask);
                        return Z_ERRNO;
                    }
                    if (!(zstream.avail_in =
                        static_cast<decltype(zstream.avail_in)>(in_stream.gcount())))
                    {
                        break;
                    }
                    zstream.next_in = in.get();

                    do
                    {
                        zstream.avail_out = buf_size;
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

                        have = buf_size - static_cast<size_t>(zstream.avail_out);

                        if (!out_stream.write(reinterpret_cast<const char*>(out.get()),
                            static_cast<streamsize>(have)))
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
        }
    }
}

#else

#include "seal/util/defines.h"
#include "seal/util/common.h"

using namespace std;

namespace seal
{
    namespace util
    {
        namespace ztools
        {
            size_t deflate_size_bound(size_t in_size) noexcept
            {
                return in_size;
            }
        }
    }
}

#endif
