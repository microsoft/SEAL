// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include "seal/util/defines.h"

#ifdef SEAL_USE_ZLIB

#include <cstddef>
#include <zlib.h>
#include "seal/util/ztools.h"
#include "seal/util/pointer.h"

using namespace std;

namespace seal
{
    namespace util
    {
        namespace ztools
        {
            int deflate_stream(istream &in_stream,
                streamoff in_size, ostream &out_stream,
                MemoryPoolHandle pool)
            {
                auto in_stream_start_pos = in_stream.tellg();
                in_stream.seekg(0, in_stream.end);
                auto in_stream_end_pos = in_stream.tellg();
                if (in_stream_end_pos - in_stream_start_pos < in_size)
                {
                    return Z_ERRNO;
                }
                in_stream.seekg(in_stream_start_pos);
                in_stream.seekg(in_size, in_stream.cur);
                in_stream_end_pos = in_stream.tellg();
                in_stream.seekg(in_stream_start_pos);

                int result, flush;
                int level = Z_DEFAULT_COMPRESSION;
                size_t have;

                auto in(allocate<unsigned char>(buf_size, pool));
                auto out(allocate<unsigned char>(buf_size, pool));

                z_stream zstream;
                zstream.zalloc = Z_NULL;
                zstream.zfree = Z_NULL;
                zstream.opaque = Z_NULL;
                result = deflateInit(&zstream, level);
                if (result != Z_OK)
                {
                    return result;
                }

                do
                {
                    if (!in_stream.read(reinterpret_cast<char*>(in.get()),
                        min(static_cast<streamoff>(buf_size),
                            in_stream_end_pos - in_stream.tellg())))
                    {
                        deflateEnd(&zstream);
                        return Z_ERRNO;
                    }
                    zstream.avail_in =
                        static_cast<decltype(zstream.avail_in)>(in_stream.gcount());
                    flush = (in_stream.tellg() == in_stream_end_pos) ? Z_FINISH : Z_NO_FLUSH;
                    zstream.next_in = in.get();

                    do
                    {
                        zstream.avail_out = buf_size;
                        zstream.next_out = out.get();
                        result = deflate(&zstream, flush);
                        have = buf_size - static_cast<size_t>(zstream.avail_out);

                        if (!out_stream.write(reinterpret_cast<const char*>(out.get()),
                            static_cast<streamsize>(have)))
                        {
                            deflateEnd(&zstream);
                            return Z_ERRNO;
                        }
                    } while (!zstream.avail_out);
                } while (flush != Z_FINISH);

                deflateEnd(&zstream);
                return Z_OK;
            }

            int inflate_stream(istream &in_stream,
                streamoff in_size, ostream &out_stream,
                MemoryPoolHandle pool)
            {
                auto in_stream_start_pos = in_stream.tellg();
                in_stream.seekg(0, in_stream.end);
                auto in_stream_end_pos = in_stream.tellg();
                if (in_stream_end_pos - in_stream_start_pos < in_size)
                {
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
                zstream.zalloc = Z_NULL;
                zstream.zfree = Z_NULL;
                zstream.opaque = Z_NULL;
                zstream.avail_in = 0;
                zstream.next_in = Z_NULL;
                result = inflateInit(&zstream);
                if (result != Z_OK)
                {
                    return result;
                }

                do
                {
                    if (!in_stream.read(reinterpret_cast<char*>(in.get()),
                        min(static_cast<streamoff>(buf_size),
                            in_stream_end_pos - in_stream.tellg())))
                    {
                        inflateEnd(&zstream);
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
                            return result;
                        }

                        have = buf_size - static_cast<size_t>(zstream.avail_out);

                        if (!out_stream.write(reinterpret_cast<const char*>(out.get()),
                            static_cast<streamsize>(have)))
                        {
                            inflateEnd(&zstream);
                            return Z_ERRNO;
                        }
                    } while (!zstream.avail_out);
                } while (result != Z_STREAM_END);

                inflateEnd(&zstream);
                return result == Z_STREAM_END ? Z_OK : Z_DATA_ERROR;
            }
        }
    }
}

#endif
