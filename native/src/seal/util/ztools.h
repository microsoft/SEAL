// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#pragma once

#include <cstdint>
#include <cstddef>
#include <iostream>
#include <stdexcept>
#include <zlib.h>

namespace seal
{
    namespace util
    {
        namespace ztools
        {
            constexpr std::size_t buf_size = 16384;

            int z_deflate_stream(std::istream &in_stream,
                std::istream::off_type in_size, std::ostream &out_stream)
            {
                auto in_stream_start_pos = in_stream.tellg();
                auto in_stream_end_pos = in_stream.seekg(0, in_stream.end);
                if (in_stream_end_pos - in_stream_start_pos < in_size)
                {
                    return Z_ERRNO;
                }
                in_stream.seekg(in_stream_start_pos);
                in_stream_end_pos = in_stream.seekg(in_size, in_stream.cur);

                int result, flush;
                int level = Z_DEFAULT_COMPRESSION; 
                unsigned have;

                unsigned char in[buf_size];
                unsigned char out[buf_size];

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
                    if (!in_stream.read(reinterpret_cast<char*>(in),
                        std::max(buf_size, in_stream_end_pos - in_stream.tellg())))
                    {
                        deflateEnd(&zstream);
                        return Z_ERRNO;
                    }
                    zstream.avail_in = 
                        static_cast<decltype(zstream.avail_in)>(in_stream.gcount());
                    flush = (in_stream.tellg() == in_stream.end) ? Z_FINISH : Z_NO_FLUSH;
                    zstream.next_in = in;

                    do
                    {
                        zstream.avail_out = buf_size;
                        zstream.next_out = out;
                        result = deflate(&zstream, flush);
                        have = buf_size - zstream.avail_out;

                        if (!out_stream.write(reinterpret_cast<const char*>(out), have))
                        {
                            deflateEnd(&zstream);
                            return Z_ERRNO;
                        }
                    }
                    while (!zstream.avail_out);
                }
                while(flush != Z_FINISH);

                deflateEnd(&zstream);
                return Z_OK;
            }

            int z_inflate_stream(std::istream &in_stream,
                std::istream::off_type in_size, std::ostream &out_stream)
            {
                auto in_stream_start_pos = in_stream.tellg();
                auto in_stream_end_pos = in_stream.seekg(0, in_stream.end);
                if (in_stream_end_pos - in_stream_start_pos < in_size)
                {
                    return Z_ERRNO;
                }
                in_stream.seekg(in_stream_start_pos);
                in_stream_end_pos = in_stream.seekg(in_size, in_stream.cur);

                int result;
                unsigned have;

                unsigned char in[buf_size];
                unsigned char out[buf_size];

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
                    if (!in_stream.read(reinterpret_cast<char*>(in),
                        std::max(buf_size, in_stream_end_pos - in_stream.tellg())))
                    {
                        inflateEnd(&zstream);
                        return Z_ERRNO;
                    }
                    if (!(zstream.avail_in = 
                        static_cast<decltype(zstream.avail_in)>(in_stream.gcount())))
                    {
                        break;
                    }
                    zstream.next_in = in;

                    do
                    {
                        zstream.avail_out = buf_size;
                        zstream.next_out = out;
                        result = inflate(&zstream, Z_NO_FLUSH);

                        switch (result)
                        {
                        case Z_NEED_DICT:
                            result = Z_DATA_ERROR;

                        case Z_DATA_ERROR:

                        case Z_MEM_ERROR:
                            inflateEnd(&zstream);
                            return result;
                        }

                        have = buf_size - zstream.avail_out;

                        if (!out_stream.write(reinterpret_cast<const char*>(out), have))
                        {
                            inflateEnd(&zstream);
                            return Z_ERRNO;
                        }
                    }
                    while (!zstream.avail_out);
                }
                while(result != Z_STREAM_END);

                inflateEnd(&zstream);
                return result == Z_STREAM_END ? Z_OK : Z_DATA_ERROR;
            }
        }
    }
}
