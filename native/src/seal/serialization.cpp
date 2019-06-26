// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stdexcept>
#include <cstdint>
#include <sstream>
#include <type_traits>
#include <utility>
#include <algorithm>
#include "seal/context.h"
#include "seal/serialization.h"
#include "seal/memorymanager.h"
#include "seal/util/defines.h"
#include "seal/util/common.h"
#include "seal/util/ztools.h"

using namespace std;
using namespace seal::util;

namespace seal
{
    streamoff Serialization::Save(
        function<void(ostream &stream)> save_members,
        ostream &stream,
        compr_mode_type compr_mode)
    {
        streamoff out_size = 0;

        auto old_except_mask = stream.exceptions();
        try
        {
            // Throw exceptions on ios_base::badbit and ios_base::failbit
            stream.exceptions(ios_base::badbit | ios_base::failbit);

            // Save the starting position
            auto stream_start_pos = stream.tellp();

            // First write the compression mode
            uint32_t compr_mode32 = static_cast<uint32_t>(compr_mode);
            stream.write(reinterpret_cast<const char*>(&compr_mode32), sizeof(uint32_t));

            // Save the position where size should be stored and write zero for now
            auto stream_size_pos = stream.tellp();
            uint32_t stream_size32 = 0;
            stream.write(reinterpret_cast<const char*>(&stream_size32), sizeof(uint32_t));

            switch (compr_mode)
            {
            case compr_mode_type::none:
                // Write rest of the data
                save_members(stream);
                break;
#ifdef SEAL_USE_ZLIB
            case compr_mode_type::zlib:
                {
                    constexpr int Z_OK = 0;
                    stringstream temp_stream;
                    temp_stream.exceptions(ios_base::badbit | ios_base::failbit);
                    save_members(temp_stream);
                    if (ztools::deflate_stream(
                        temp_stream, temp_stream.tellp(), stream,
                        MemoryManager::GetPool(mm_prof_opt::FORCE_NEW, true)) != Z_OK)
                    {
                        throw runtime_error("stream deflate failed");
                    }
                    break;
                }
#endif
            default:
                throw invalid_argument("unsupported compression mode");
            }

            // Compute how many bytes were written
            auto stream_end_pos = stream.tellp();
            out_size = stream_end_pos - stream_start_pos;
            stream_size32 = safe_cast<uint32_t>(out_size);

            // Go back to write the size
            stream.seekp(stream_size_pos);
            stream.write(reinterpret_cast<const char*>(&stream_size32), sizeof(uint32_t));

            // Go back to end
            stream.seekp(stream_end_pos);
        }
        catch (const exception &)
        {
            stream.exceptions(old_except_mask);
            throw;
        }

        stream.exceptions(old_except_mask);

        return out_size;
    }

    streamoff Serialization::Save(
        function<void(ostream &stream)> save_members,
        SEAL_BYTE *out,
        compr_mode_type compr_mode)
    {
        stringstream temp_stream;
        temp_stream.exceptions(ios_base::badbit | ios_base::failbit);
        auto out_size = Save(save_members, temp_stream, compr_mode);
        temp_stream.seekg(0, temp_stream.beg);
        if (out)
        {
            temp_stream.rdbuf()->sgetn(reinterpret_cast<char*>(out), out_size);
        }
        return out_size;
    }

    streamoff Serialization::Load(
        function<void(istream &stream)> load_members,
        istream &stream)
    {
        streamoff in_size = 0;

        auto old_except_mask = stream.exceptions();
        try
        {
            // Throw exceptions on ios_base::badbit and ios_base::failbit
            stream.exceptions(ios_base::badbit | ios_base::failbit);

            // Save the starting position
            auto stream_start_pos = stream.tellg();

            // First read the compression mode
            uint32_t compr_mode32 = 0;
            stream.read(reinterpret_cast<char*>(&compr_mode32), sizeof(uint32_t));
            if (compr_mode32 >> (sizeof(compr_mode_type) * bits_per_byte))
            {
                throw logic_error("invalid compression mode header");
            }
            compr_mode_type compr_mode = static_cast<compr_mode_type>(compr_mode32); 

            // Next read the stream size
            uint32_t stream_size32 = 0;
            stream.read(reinterpret_cast<char*>(&stream_size32), sizeof(uint32_t));
            auto stream_size = safe_cast<streamoff>(stream_size32);

            switch (compr_mode)
            {
            case compr_mode_type::none:
                // Read rest of the data
                load_members(stream);
                if (stream_size != stream.tellg() - stream_start_pos)
                {
                    throw logic_error("invalid data size");
                }
                break;
#ifdef SEAL_USE_ZLIB
            case compr_mode_type::zlib:
                {
                    constexpr int Z_OK = 0;
                    auto compr_size = stream_size - (stream.tellg() - stream_start_pos);
                    stringstream temp_stream;
                    temp_stream.exceptions(ios_base::badbit | ios_base::failbit);
                    if (ztools::inflate_stream(
                        stream, compr_size, temp_stream,
                        MemoryManager::GetPool(mm_prof_opt::FORCE_NEW, true)) != Z_OK)
                    {
                        throw runtime_error("stream deflate failed");
                    }
                    load_members(temp_stream);
                    break;
                }
#endif
            default:
                throw invalid_argument("unsupported compression mode");
            }
            
            in_size = stream_size;
        }
        catch (const exception &)
        {
            stream.exceptions(old_except_mask);
            throw;
        }

        stream.exceptions(old_except_mask);

        return in_size;
    }

    streamoff Serialization::Load(
        function<void(istream &stream)> load_members,
        const SEAL_BYTE *in)
    {
        if (!in)
        {
            throw invalid_argument("in cannot be null");
        }

        streamoff in_size = 0;

        try
        {
            // Save the starting position
            auto stream_start_pos = in;

            // First read the compression mode
            uint32_t compr_mode32 = 0;
            copy_n(in, sizeof(uint32_t), reinterpret_cast<SEAL_BYTE*>(&compr_mode32));
            in += sizeof(uint32_t);
            if (compr_mode32 >> (sizeof(compr_mode_type) * bits_per_byte))
            {
                throw logic_error("invalid compression mode header");
            }
            compr_mode_type compr_mode = static_cast<compr_mode_type>(compr_mode32); 

            // Next read the stream size
            uint32_t stream_size32 = 0;
            copy_n(in, sizeof(uint32_t), reinterpret_cast<SEAL_BYTE*>(&stream_size32));
            in += sizeof(uint32_t);
            auto stream_size = safe_cast<streamoff>(stream_size32);

            auto compr_size = stream_size - static_cast<streamoff>(in - stream_start_pos);
            switch (compr_mode)
            {
            case compr_mode_type::none:
                {
                    // Read rest of the data
                    stringstream temp_stream;
                    temp_stream.exceptions(ios_base::badbit | ios_base::failbit);
                    temp_stream.write(reinterpret_cast<const char*>(in), compr_size);
                    load_members(temp_stream);
                    break;
                }
#ifdef SEAL_USE_ZLIB
            case compr_mode_type::zlib:
                {
                    constexpr int Z_OK = 0;
                    stringstream compr_temp_stream, temp_stream;
                    compr_temp_stream.exceptions(ios_base::badbit | ios_base::failbit);
                    temp_stream.exceptions(ios_base::badbit | ios_base::failbit);
                    compr_temp_stream.write(reinterpret_cast<const char*>(in), compr_size);
                    if (ztools::inflate_stream(
                        compr_temp_stream, compr_size, temp_stream,
                        MemoryManager::GetPool(mm_prof_opt::FORCE_NEW, true)) != Z_OK)
                    {
                        throw runtime_error("stream deflate failed");
                    }
                    load_members(temp_stream);
                    break;
                }
#endif
            default:
                throw invalid_argument("unsupported compression mode");
            }
            
            in_size = stream_size;
        }
        catch (const exception &)
        {
            throw;
        }

        return in_size;
    }
}
