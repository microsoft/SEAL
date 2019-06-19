// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#pragma once

#include <stdexcept>
#include <cstdint>
#include <sstream>
#include <iostream>
#include <type_traits>
#include <memory>
#include "seal/context.h"
#include "seal/ciphertext.h"
#include "seal/util/defines.h"
#include "seal/util/common.h"
#ifdef SEAL_USE_ZLIB
#include "seal/util/ztools.h"
#endif

namespace seal
{
    enum class compr_mode_type : std::uint8_t
    {
        none = 0,
#ifdef SEAL_USE_ZLIB
        zlib = 1
#endif
    };
    
    class Serialization
    {
    public:
        template<class T>
        static std::streamoff Save(const T &in, std::ostream &stream,
            compr_mode_type compr_mode = compr_mode_type::none)
        {
            std::streamoff out_size = 0;

            auto old_except_mask = stream.exceptions();
            try
            {
                // Throw exceptions on std::ios_base::badbit and std::ios_base::failbit
                stream.exceptions(std::ios_base::badbit | std::ios_base::failbit);

                // Save the starting position
                auto stream_start_pos = stream.tellp();

                // First write the compression mode
                stream.write(reinterpret_cast<const char*>(&compr_mode), sizeof(compr_mode_type));

                // Save the position where size should be stored and write zero for now
                auto stream_size_pos = stream.tellp();
                std::uint32_t stream_size32 = 0;
                stream.write(reinterpret_cast<const char*>(&stream_size32), sizeof(std::uint32_t));

                switch (compr_mode)
                {
                case compr_mode_type::none:
                    // Write rest of the data
                    in.save(stream);
                    break;
#ifdef SEAL_USE_ZLIB
                case compr_mode_type::zlib:
                    {
                        std::stringstream temp_stream;
                        in.save(temp_stream);
                        temp_stream.flush();
                        if (util::ztools::z_deflate_stream(
                            temp_stream, temp_stream.tellp(), stream) != Z_OK)
                        {
                            throw std::runtime_error("stream deflate failed");
                        }
                        break;
                    }
#endif
                default:
                    throw std::invalid_argument("unsupported compression mode");
                }

                // Compute how many bytes were written
                auto stream_end_pos = stream.tellp();
                out_size = stream_end_pos - stream_start_pos;
                stream_size32 = util::safe_cast<std::uint32_t>(out_size);

                // Go back to write the size
                stream.seekp(stream_size_pos);
                stream.write(reinterpret_cast<const char*>(&stream_size32), sizeof(std::uint32_t));

                // Go back to end
                stream.seekp(stream_end_pos);
            }
            catch (const std::exception &)
            {
                stream.exceptions(old_except_mask);
                throw;
            }

            stream.exceptions(old_except_mask);

            return out_size;
        }

        template<class T>
        static std::streamoff UnsafeLoad(std::istream &stream, T &out)
        {
            std::streamoff in_size = 0;

            auto old_except_mask = stream.exceptions();
            try
            {
                // Throw exceptions on std::ios_base::badbit and std::ios_base::failbit
                stream.exceptions(std::ios_base::badbit | std::ios_base::failbit);

                // Save the starting position
                auto stream_start_pos = stream.tellg();

                // First read the compression mode
                compr_mode_type compr_mode = compr_mode_type::none;
                stream.read(reinterpret_cast<char*>(&compr_mode), sizeof(compr_mode_type));

                // Next read the stream size
                std::uint32_t stream_size32 = 0;
                stream.read(reinterpret_cast<char*>(&stream_size32), sizeof(std::uint32_t));
                std::streamoff stream_size =
                    util::safe_cast<std::streamoff>(stream_size32);

                switch (compr_mode)
                {
                case compr_mode_type::none:
                    // Read rest of the data
                    out.unsafe_load(stream);
                    if (stream_size != stream.tellg() - stream_start_pos)
                    {
                        throw std::logic_error("invalid data size");
                    }
                    break;
#ifdef SEAL_USE_ZLIB
                case compr_mode_type::zlib:
                    {
                        std::streamoff compr_size =
                            stream_size - (stream.tellg() - stream_start_pos);
                        std::stringstream temp_stream;
                        if (util::ztools::z_inflate_stream(
                            stream, compr_size, temp_stream) != Z_OK)
                        {
                            throw std::runtime_error("stream deflate failed");
                        }
                        out.unsafe_load(temp_stream);
                        break;
                    }
#endif
                default:
                    throw std::invalid_argument("unsupported compression mode");
                }
                
                in_size = stream_size;
            }
            catch (const std::exception &)
            {
                stream.exceptions(old_except_mask);
                throw;
            }

            stream.exceptions(old_except_mask);

            return in_size;
        }

        template<class T>
        static std::streamoff Load(std::shared_ptr<SEALContext> context,
            std::istream &stream, T &out)
        {
            T new_object;
            std::streamoff in_size = UnsafeLoad(stream, new_object);
            if (!is_valid_for(new_object, std::move(context)))
            {
                throw std::invalid_argument("loaded object is invalid");
            }
            std::swap(out, new_object);

            return in_size;
        }

    private:
        Serialization() = delete;
    };
}
