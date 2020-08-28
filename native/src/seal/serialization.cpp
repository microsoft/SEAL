// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include "seal/context.h"
#include "seal/intarray.h"
#include "seal/memorymanager.h"
#include "seal/serialization.h"
#include "seal/util/common.h"
#include "seal/util/streambuf.h"
#include "seal/util/ztools.h"
#include <algorithm>
#include <stdexcept>
#include <type_traits>
#include <typeinfo>
#include <utility>

using namespace std;
using namespace seal::util;

namespace seal
{
    // Required for C++14 compliance: static constexpr member variables are not necessarily inlined so need to ensure
    // symbol is created.
    constexpr compr_mode_type Serialization::compr_mode_default;

    // Required for C++14 compliance: static constexpr member variables are not necessarily inlined so need to ensure
    // symbol is created.
    constexpr uint16_t Serialization::seal_magic;

    // Required for C++14 compliance: static constexpr member variables are not necessarily inlined so need to ensure
    // symbol is created.
    constexpr uint8_t Serialization::seal_header_size;

    namespace
    {
        [[noreturn]] void expressive_rethrow_on_ios_base_failure(const ostream &stream)
        {
            if (!stream.rdbuf())
            {
                throw runtime_error("I/O error: output stream has no associated buffer");
            }

            // Use RTTI to determine if this is an ArrayPutBuffer
            auto &rdbuf_ref = *stream.rdbuf();
            if (typeid(rdbuf_ref).hash_code() == typeid(ArrayPutBuffer).hash_code())
            {
                auto buffer = reinterpret_cast<ArrayPutBuffer *>(stream.rdbuf());

                // Determine if write overflow occurred
                if (buffer->at_end())
                {
                    // Return a more expressive error
                    throw runtime_error("I/O error: insufficient output buffer");
                }
            }

            // Generic message
            throw runtime_error("I/O error");
        }

        [[noreturn]] void expressive_rethrow_on_ios_base_failure(const istream &stream)
        {
            if (!stream.rdbuf())
            {
                throw runtime_error("I/O error: input stream has no associated buffer");
            }

            // Use RTTI to determine if this is an ArrayGetBuffer
            if (stream.eof())
            {
                auto &rdbuf_ref = *stream.rdbuf();
                if (typeid(rdbuf_ref).hash_code() == typeid(ArrayGetBuffer).hash_code())
                {
                    // Report buffer underflow
                    throw runtime_error("I/O error: input buffer ended unexpectedly");
                }
                else
                {
                    // Report generic underflow
                    throw runtime_error("I/O error: input stream ended unexpectedly");
                }
            }

            // Generic message
            throw runtime_error("I/O error");
        }
    } // namespace

    size_t Serialization::ComprSizeEstimate(size_t in_size, compr_mode_type compr_mode)
    {
        if (!IsSupportedComprMode(compr_mode))
        {
            throw invalid_argument("unsupported compression mode");
        }

        switch (compr_mode)
        {
#ifdef SEAL_USE_ZLIB
        case compr_mode_type::deflate:
            return ztools::deflate_size_bound(in_size);
#endif
        case compr_mode_type::none:
            // No compression
            return in_size;

        default:
            throw invalid_argument("unsupported compression mode");
        }
    }

    streamoff Serialization::SaveHeader(const SEALHeader &header, ostream &stream)
    {
        auto old_except_mask = stream.exceptions();
        try
        {
            // Throw exceptions on ios_base::badbit and ios_base::failbit
            stream.exceptions(ios_base::badbit | ios_base::failbit);

            stream.write(reinterpret_cast<const char *>(&header), sizeof(SEALHeader));
        }
        catch (const ios_base::failure &)
        {
            stream.exceptions(old_except_mask);
            expressive_rethrow_on_ios_base_failure(stream);
        }
        catch (...)
        {
            stream.exceptions(old_except_mask);
            throw;
        }
        stream.exceptions(old_except_mask);

        // Return the size of the SEALHeader
        return static_cast<streamoff>(sizeof(SEALHeader));
    }

    streamoff Serialization::LoadHeader(istream &stream, SEALHeader &header, bool try_upgrade_if_invalid)
    {
        auto old_except_mask = stream.exceptions();
        try
        {
            // Throw exceptions on ios_base::badbit and ios_base::failbit
            stream.exceptions(ios_base::badbit | ios_base::failbit);

            stream.read(reinterpret_cast<char *>(&header), sizeof(SEALHeader));

            // If header is invalid this may be an older header and we can try to automatically upgrade it
            if (try_upgrade_if_invalid && !IsValidHeader(header))
            {
                // Try interpret the data as a Microsoft SEAL 3.4 header
                legacy_headers::SEALHeader_3_4 header_3_4(header);

                SEALHeader new_header;
                // Copy over the fields; of course the result may not be valid depending on whether the input was a
                // valid version 3.4 header
                new_header.compr_mode = header_3_4.compr_mode;
                new_header.size = header_3_4.size;

                // Now validate the new header and discard if still not valid; something else is probably wrong
                if (IsValidHeader(new_header))
                {
                    header = new_header;
                }
            }
        }
        catch (const ios_base::failure &)
        {
            stream.exceptions(old_except_mask);
            expressive_rethrow_on_ios_base_failure(stream);
        }
        catch (...)
        {
            stream.exceptions(old_except_mask);
            throw;
        }
        stream.exceptions(old_except_mask);

        // Return the size of the SEALHeader
        return static_cast<streamoff>(sizeof(SEALHeader));
    }

    streamoff Serialization::SaveHeader(const SEALHeader &header, SEAL_BYTE *out, size_t size)
    {
        if (!out)
        {
            throw invalid_argument("out cannot be null");
        }
        if (size < sizeof(SEALHeader))
        {
            throw invalid_argument("insufficient size");
        }
        if (!fits_in<streamsize>(size))
        {
            throw invalid_argument("size is too large");
        }
        ArrayPutBuffer apbuf(reinterpret_cast<char *>(out), static_cast<streamsize>(size));
        ostream stream(&apbuf);
        return SaveHeader(header, stream);
    }

    streamoff Serialization::LoadHeader(
        const SEAL_BYTE *in, size_t size, SEALHeader &header, bool try_upgrade_if_invalid)
    {
        if (!in)
        {
            throw invalid_argument("in cannot be null");
        }
        if (size < sizeof(SEALHeader))
        {
            throw invalid_argument("insufficient size");
        }
        if (!fits_in<streamsize>(size))
        {
            throw invalid_argument("size is too large");
        }
        ArrayGetBuffer agbuf(reinterpret_cast<const char *>(in), static_cast<streamsize>(size));
        istream stream(&agbuf);
        return LoadHeader(stream, header, try_upgrade_if_invalid);
    }

    streamoff Serialization::Save(
        function<void(ostream &stream)> save_members, streamoff raw_size, ostream &stream, compr_mode_type compr_mode,
        bool clear_on_destruction)
    {
        if (!save_members)
        {
            throw invalid_argument("save_members is invalid");
        }
        if (raw_size < static_cast<streamoff>(sizeof(SEALHeader)))
        {
            throw invalid_argument("raw_size is too small");
        }
        if (!IsSupportedComprMode(compr_mode))
        {
            throw invalid_argument("unsupported compression mode");
        }

        streamoff out_size = 0;

        auto old_except_mask = stream.exceptions();
        try
        {
            // Throw exceptions on ios_base::badbit and ios_base::failbit
            stream.exceptions(ios_base::badbit | ios_base::failbit);

            // Save the starting position
            auto stream_start_pos = stream.tellp();

            // Create the header
            SEALHeader header;

            switch (compr_mode)
            {
            case compr_mode_type::none:
                // We set the compression mode and size here, and save the header
                header.compr_mode = compr_mode;
                header.size = safe_cast<uint64_t>(raw_size);
                SaveHeader(header, stream);

                // Write rest of the data
                save_members(stream);
                break;
#ifdef SEAL_USE_ZLIB
            case compr_mode_type::deflate:
            {
                // First save_members to a temporary byte stream; set the size
                // of the temporary stream to be right from the start to avoid
                // extra reallocs.
                SafeByteBuffer safe_buffer(
                    ztools::deflate_size_bound(raw_size - static_cast<streamoff>(sizeof(SEALHeader))),
                    clear_on_destruction);
                iostream temp_stream(&safe_buffer);
                temp_stream.exceptions(ios_base::badbit | ios_base::failbit);
                save_members(temp_stream);

                auto safe_pool(MemoryManager::GetPool(mm_prof_opt::FORCE_NEW, clear_on_destruction));

                // Create temporary aliasing IntArray to wrap safe_buffer
                IntArray<SEAL_BYTE> safe_buffer_array(
                    Pointer<SEAL_BYTE>::Aliasing(safe_buffer.data()), safe_buffer.size(),
                    static_cast<size_t>(temp_stream.tellp()), false, safe_pool);

                // After compression, write_header_deflate_buffer will write the
                // final size to the given header and write the header to stream,
                // before writing the compressed output.
                ztools::write_header_deflate_buffer(
                    safe_buffer_array, reinterpret_cast<void *>(&header), stream, safe_pool);
                break;
            }
#endif
            default:
                throw invalid_argument("unsupported compression mode");
            }

            // Compute how many bytes were written
            auto stream_end_pos = stream.tellp();
            out_size = stream_end_pos - stream_start_pos;
        }
        catch (const ios_base::failure &)
        {
            stream.exceptions(old_except_mask);
            expressive_rethrow_on_ios_base_failure(stream);
        }
        catch (...)
        {
            stream.exceptions(old_except_mask);
            throw;
        }
        stream.exceptions(old_except_mask);

        return out_size;
    }

    streamoff Serialization::Load(
        function<void(istream &stream)> load_members, istream &stream, bool clear_on_destruction)
    {
        if (!load_members)
        {
            throw invalid_argument("load_members is invalid");
        }

        streamoff in_size = 0;
        SEALHeader header;

        auto old_except_mask = stream.exceptions();
        try
        {
            // Throw exceptions on ios_base::badbit and ios_base::failbit
            stream.exceptions(ios_base::badbit | ios_base::failbit);

            // Save the starting position
            auto stream_start_pos = stream.tellg();

            // First read the header
            LoadHeader(stream, header);
            if (!IsCompatibleVersion(header))
            {
                throw logic_error("incompatible version");
            }
            if (!IsValidHeader(header))
            {
                throw logic_error("loaded SEALHeader is invalid");
            }

            switch (header.compr_mode)
            {
            case compr_mode_type::none:
                // Read rest of the data
                load_members(stream);
                if (header.size != safe_cast<uint64_t>(stream.tellg() - stream_start_pos))
                {
                    throw logic_error("invalid data size");
                }
                break;
#ifdef SEAL_USE_ZLIB
            case compr_mode_type::deflate:
            {
                auto compr_size = header.size - safe_cast<uint64_t>(stream.tellg() - stream_start_pos);

                // We don't know the decompressed size, but use compr_size as
                // starting point for the buffer.
                SafeByteBuffer safe_buffer(safe_cast<streamsize>(compr_size), clear_on_destruction);

                iostream temp_stream(&safe_buffer);
                temp_stream.exceptions(ios_base::badbit | ios_base::failbit);

                constexpr int Z_OK = 0;
                if (ztools::inflate_stream(
                        stream, safe_cast<streamoff>(compr_size), temp_stream,
                        MemoryManager::GetPool(mm_prof_opt::FORCE_NEW, clear_on_destruction)) != Z_OK)
                {
                    throw logic_error("stream inflate failed");
                }
                load_members(temp_stream);
                break;
            }
#endif
            default:
                throw invalid_argument("unsupported compression mode");
            }

            in_size = safe_cast<streamoff>(header.size);
        }
        catch (const ios_base::failure &)
        {
            stream.exceptions(old_except_mask);
            expressive_rethrow_on_ios_base_failure(stream);
        }
        catch (...)
        {
            stream.exceptions(old_except_mask);
            throw;
        }
        stream.exceptions(old_except_mask);

        return in_size;
    }

    streamoff Serialization::Save(
        function<void(ostream &stream)> save_members, streamoff raw_size, SEAL_BYTE *out, size_t size,
        compr_mode_type compr_mode, bool clear_on_destruction)
    {
        if (!out)
        {
            throw invalid_argument("out cannot be null");
        }
        if (size < sizeof(SEALHeader))
        {
            throw invalid_argument("insufficient size");
        }
        if (!fits_in<streamsize>(size))
        {
            throw invalid_argument("size is too large");
        }
        ArrayPutBuffer apbuf(reinterpret_cast<char *>(out), static_cast<streamsize>(size));
        ostream stream(&apbuf);
        return Save(save_members, raw_size, stream, compr_mode, clear_on_destruction);
    }

    streamoff Serialization::Load(
        function<void(istream &stream)> load_members, const SEAL_BYTE *in, size_t size, bool clear_on_destruction)
    {
        if (!in)
        {
            throw invalid_argument("in cannot be null");
        }
        if (size < sizeof(SEALHeader))
        {
            throw invalid_argument("insufficient size");
        }
        if (!fits_in<streamsize>(size))
        {
            throw invalid_argument("size is too large");
        }
        ArrayGetBuffer agbuf(reinterpret_cast<const char *>(in), static_cast<streamsize>(size));
        istream stream(&agbuf);
        return Load(load_members, stream, clear_on_destruction);
    }
} // namespace seal
