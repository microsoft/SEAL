// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stdexcept>
#include <cstdint>
#include <sstream>
#include <streambuf>
#include <type_traits>
#include <utility>
#include <algorithm>
#include "seal/context.h"
#include "seal/intarray.h"
#include "seal/serialization.h"
#include "seal/memorymanager.h"
#include "seal/util/common.h"
#include "seal/util/ztools.h"

using namespace std;
using namespace seal::util;

namespace seal
{
    namespace
    {
        class SafeByteBuffer final : public streambuf
        {
        public:
            SafeByteBuffer(streamsize size = 1) : size_(size)
            {
                if (!fits_in<int>(add_safe(size_, streamsize(1))))
                {
                    throw invalid_argument("size is too large");
                }
                buf_.resize(static_cast<size_t>(size_ + 1));
                setp(buf_.begin(), buf_.begin() + size_);
                setg(buf_.begin(), buf_.begin(), buf_.begin() + size_);
            }

            ~SafeByteBuffer() override = default;

            SafeByteBuffer(const SafeByteBuffer &copy) = delete;

            SafeByteBuffer &operator =(const SafeByteBuffer &assign) = delete;

            SEAL_NODISCARD const SEAL_BYTE *data() const noexcept
            {
                return reinterpret_cast<const SEAL_BYTE*>(buf_.cbegin());
            }

            SEAL_NODISCARD SEAL_BYTE *data() noexcept
            {
                return reinterpret_cast<SEAL_BYTE*>(buf_.begin());
            }

        private:
            int_type underflow() override
            {
                if (gptr() == egptr())
                {
                    return eof_;
                }
                return traits_type::to_int_type(*gptr());
            }

            int_type pbackfail(int_type ch) override
            {
                if (gptr() == eback() || traits_type::eq_int_type(eof_, ch) ||
                    (traits_type::not_eof(ch) && ch != gptr()[-1]))
                {
                    return traits_type::eof();
                }
                gbump(-1);
                return traits_type::to_int_type(*gptr());
            }

            streamsize showmanyc() override
            {
                if (gptr() >= egptr())
                {
                    return -1;
                }
                return distance(gptr(), egptr());
            }

            streamsize xsgetn(char_type *s, streamsize count) override
            {
                streamsize avail =
                    max(streamsize(0), min(
                        count, safe_cast<streamsize>(distance(gptr(), egptr()))));
                copy_n(gptr(), avail, s);
                gbump(safe_cast<int>(avail));
                return avail;
            }

            pos_type seekpos(
                pos_type pos,
                ios_base::openmode which = ios_base::in | ios_base::out) override
            {
                if (pos < 0 || pos > size_)
                {
                    return pos_type(off_type(-1));
                }
                if (which & ios_base::in)
                {
                    setg(eback(), eback() + static_cast<ptrdiff_t>(pos), egptr());
                }
                if (which & ios_base::out)
                {
                    setp(pbase(), epptr());
                    pbump(static_cast<int>(pos));
                }
                return pos;
            }

            pos_type seekoff(
                off_type off,
                ios_base::seekdir dir,
                ios_base::openmode which = ios_base::in | ios_base::out) override
            {
                // Cannot seek relative to current position for both input and
                // output heads if they are in different positions.
                if (which == (ios_base::in | ios_base::out) &&
                    dir == ios_base::cur && gptr() != pptr())
                {
                    return pos_type(off_type(-1));
                }

                // We are guaranteed to have only a single absolute offset
                off_type newoff = off;
                switch (dir)
                {
                case ios_base::beg:
                    break;

                case ios_base::cur:
                    if (which == ios_base::in)
                    {
                        newoff = add_safe(newoff,
                            safe_cast<streamoff>(distance(eback(), gptr())));
                    }
                    else
                    {
                        newoff = add_safe(newoff,
                            safe_cast<streamoff>(distance(pbase(), pptr())));
                    }
                    break;

                case ios_base::end:
                    newoff = add_safe(newoff, safe_cast<off_type>(size_));
                    break;

                default:
                    return pos_type(off_type(-1));
                }
                return seekpos(pos_type(newoff), which);
            }

            void expand_size()
            {
                // Compute expanded size
                size_ = safe_cast<streamsize>(
                    ceil(safe_cast<double>(buf_.size()) * expansion_factor_));

                // Store the old offsets for both put and get heads
                streamsize old_poff = distance(pbase(), pptr());
                streamsize old_goff = distance(eback(), gptr());

                // Copy entire buffer to new location and reserve extra byte
                buf_.resize(safe_cast<size_t>(
                    add_safe<streamsize>(size_, streamsize(1))));

                // Set the get and put pointers appropriately
                setp(buf_.begin(), buf_.begin() + size_);
                pbump(safe_cast<int>(old_poff));
                setg(buf_.begin(), buf_.begin() + old_goff, buf_.begin() + size_);
            }

            int_type overflow(int_type ch = traits_type::eof()) override
            {
                if (traits_type::eq_int_type(eof_, ch) || !fits_in<int>(
                    ceil(static_cast<double>(buf_.size()) * expansion_factor_) + 1))
                {
                    return eof_;
                }

                // Output ch to the buffer (there is one byte left of space) and overflow
                *pptr() = traits_type::to_char_type(ch);
                pbump(1);

                // Expand the size of the buffer
                expand_size();

                return ch;
            }

            streamsize xsputn(const char_type *s, streamsize count) override
            {
                streamsize remaining = count;
                while (remaining)
                {
                    if (pptr() == epptr())
                    {
                        expand_size();
                    }
                    streamsize avail = max(streamsize(0), min(
                        remaining, safe_cast<streamsize>(distance(pptr(), epptr()))));
                    copy_n(s, avail, pptr());
                    pbump(safe_cast<int>(avail));
                    remaining -= avail;
                    s += avail;
                }
                return count;
            }

            IntArray<char> buf_{ MemoryManager::GetPool(mm_prof_opt::FORCE_NEW, true) };

            streamsize size_;

            static constexpr double expansion_factor_ = 1.3;

            int_type eof_ = traits_type::eof();
        };

        class ArrayGetBuffer final : public streambuf
        {
        public:
            ArrayGetBuffer(const char_type *buf, streamsize size) :
                buf_(buf),
                size_(size)
            {
                if (!buf)
                {
                    throw invalid_argument("buf cannot be null");
                }
                if (size <= 0)
                {
                    throw invalid_argument("size must be positive");
                }
                begin_ = buf_;
                end_ = buf_ + size_;
                head_ = begin_;
            }

            ~ArrayGetBuffer() override = default;

            ArrayGetBuffer(const ArrayGetBuffer &copy) = delete;

            ArrayGetBuffer &operator =(const ArrayGetBuffer &assign) = delete;

        private:
            int_type underflow() override
            {
                if (head_ == end_)
                {
                    return eof_;
                }
                return traits_type::to_int_type(*head_);
            }

            int_type uflow() override
            {
                if (head_ == end_)
                {
                    return eof_;
                }
                return traits_type::to_int_type(*head_++);
            }

            int_type pbackfail(int_type ch) override
            {
                if (head_ == begin_ || traits_type::eq_int_type(eof_, ch) ||
                    (traits_type::not_eof(ch) && ch != head_[-1]))
                {
                    return traits_type::eof();
                }
                return traits_type::to_int_type(*--head_);
            }

            streamsize showmanyc() override
            {
                if (head_ >= end_)
                {
                    return -1;
                }
                return distance(head_, end_);
            }

            streamsize xsgetn(char_type *s, streamsize count) override
            {
                streamsize avail = max(streamsize(0),
                    min(count, safe_cast<streamsize>(distance(head_, end_))));
                copy_n(head_, avail, s);
                advance(head_, avail);
                return avail;
            }

            pos_type seekpos(
                pos_type pos,
                ios_base::openmode which = ios_base::in) override
            {
                if (which != ios_base::in)
                {
                    return pos_type(off_type(-1));
                }
                if (pos < 0 || pos > pos_type(size_))
                {
                    return pos_type(off_type(-1));
                }

                head_ = begin_ + static_cast<ptrdiff_t>(pos);
                return pos;
            }

            pos_type seekoff(
                off_type off,
                ios_base::seekdir dir,
                ios_base::openmode which = ios_base::in) override
            {
                off_type newoff = off;
                switch (dir)
                {
                case ios_base::beg:
                    break;

                case ios_base::cur:
                    newoff = add_safe(newoff,
                        safe_cast<off_type>(distance(begin_, head_)));
                    break;

                case ios_base::end:
                    newoff = add_safe(newoff, off_type(size_));
                    break;

                default:
                    return pos_type(off_type(-1));
                }
                return seekpos(pos_type(newoff), which);
            }

            const char_type *buf_;

            streamsize size_;

            using iterator_type = const char_type *;

            int_type eof_ = traits_type::eof();

            iterator_type begin_;

            iterator_type end_;

            iterator_type head_;
        };

        class ArrayPutBuffer final : public streambuf
        {
        public:
            ArrayPutBuffer(char_type *buf, streamsize size) :
                buf_(buf),
                size_(size)
            {
                if (!buf)
                {
                    throw invalid_argument("buf cannot be null");
                }
                if (size <= 0)
                {
                    throw invalid_argument("size must be positive");
                }
                begin_ = buf_;
                end_ = buf_ + size_;
                head_ = begin_;
            }

            ~ArrayPutBuffer() override = default;

            ArrayPutBuffer(const ArrayPutBuffer &copy) = delete;

            ArrayPutBuffer &operator =(const ArrayPutBuffer &assign) = delete;

        private:
            int_type overflow(int_type ch = traits_type::eof()) override
            {
                if (head_ == end_ || traits_type::eq_int_type(eof_, ch))
                {
                    return eof_;
                }
                *head_++ = traits_type::to_char_type(ch);
                return ch;
            }

            streamsize xsputn(const char_type *s, streamsize count) override
            {
                streamsize avail =
                    max(streamsize(0), min(
                        count, safe_cast<streamsize>(distance(head_, end_))));
                copy_n(s, avail, head_);
                advance(head_, avail);
                return avail;
            }

            pos_type seekpos(
                pos_type pos,
                ios_base::openmode which = ios_base::out) override
            {
                if (which != ios_base::out)
                {
                    return pos_type(off_type(-1));
                }
                if (pos < 0 || pos > pos_type(size_))
                {
                    return pos_type(off_type(-1));
                }

                head_ = begin_ + static_cast<ptrdiff_t>(pos);
                return pos;
            }

            pos_type seekoff(
                off_type off,
                ios_base::seekdir dir,
                ios_base::openmode which = ios_base::out) override
            {
                off_type newoff = off;
                switch (dir)
                {
                case ios_base::beg:
                    break;

                case ios_base::cur:
                    newoff = add_safe(newoff,
                        safe_cast<off_type>(distance(begin_, head_)));
                    break;

                case ios_base::end:
                    newoff = add_safe(newoff, off_type(size_));
                    break;

                default:
                    return pos_type(off_type(-1));
                }
                return seekpos(pos_type(newoff), which);
            }

            char_type *buf_;

            streamsize size_;

            using iterator_type = char_type *;

            int_type eof_ = traits_type::eof();

            iterator_type begin_;

            iterator_type end_;

            iterator_type head_;
        };
    }

    size_t Serialization::ComprSizeEstimate(
        size_t in_size, compr_mode_type compr_mode)
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
            throw logic_error("unsupported compression mode");
        }
    }

    void Serialization::SaveHeader(const SEALHeader &header, ostream &stream)
    {
        auto old_except_mask = stream.exceptions();
        try
        {
            // Throw exceptions on ios_base::badbit and ios_base::failbit
            stream.exceptions(ios_base::badbit | ios_base::failbit);

            stream.write(reinterpret_cast<const char*>(&header), sizeof(SEALHeader));
        }
        catch (const ios_base::failure &)
        {
            stream.exceptions(old_except_mask);
            throw runtime_error("I/O error");
        }
        catch (...)
        {
            stream.exceptions(old_except_mask);
            throw;
        }
        stream.exceptions(old_except_mask);
    }

    void Serialization::LoadHeader(istream &stream, SEALHeader &header)
    {
        auto old_except_mask = stream.exceptions();
        try
        {
            // Throw exceptions on ios_base::badbit and ios_base::failbit
            stream.exceptions(ios_base::badbit | ios_base::failbit);

            stream.read(reinterpret_cast<char*>(&header), sizeof(SEALHeader));
        }
        catch (const ios_base::failure &)
        {
            stream.exceptions(old_except_mask);
            throw runtime_error("I/O error");
        }
        catch (...)
        {
            stream.exceptions(old_except_mask);
            throw;
        }
        stream.exceptions(old_except_mask);
    }

    streamoff Serialization::Save(
        function<void(ostream &stream)> save_members,
        streamoff raw_size,
        ostream &stream,
        compr_mode_type compr_mode)
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
            throw logic_error("unsupported compression mode");
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
                header.size = safe_cast<uint32_t>(raw_size);
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
                        raw_size - static_cast<streamoff>(sizeof(SEALHeader)));
                    iostream temp_stream(&safe_buffer);
                    temp_stream.exceptions(ios_base::badbit | ios_base::failbit);
                    save_members(temp_stream);

                    auto safe_pool(MemoryManager::GetPool(mm_prof_opt::FORCE_NEW, true));

                    // Create temporary aliasing IntArray to wrap safe_buffer
                    IntArray<SEAL_BYTE> safe_buffer_array(
                        Pointer<SEAL_BYTE>::Aliasing(safe_buffer.data()),
                        static_cast<size_t>(temp_stream.tellp()), false, safe_pool);

                    // After compression, write_header_deflate_buffer will write the
                    // final size to the given header and write the header to stream,
                    // before writing the compressed output.
                    ztools::write_header_deflate_buffer(safe_buffer_array,
                        reinterpret_cast<void*>(&header), stream, safe_pool);
                    break;
                }
#endif
            default:
                throw logic_error("unsupported compression mode");
            }

            // Compute how many bytes were written
            auto stream_end_pos = stream.tellp();
            out_size = stream_end_pos - stream_start_pos;
        }
        catch (const ios_base::failure &)
        {
            stream.exceptions(old_except_mask);
            throw runtime_error("I/O error");
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
        function<void(istream &stream)> load_members,
        istream &stream)
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
            if (!IsValidHeader(header))
            {
                throw logic_error("loaded SEALHeader is invalid");
            }

            switch (header.compr_mode)
            {
            case compr_mode_type::none:
                // Read rest of the data
                load_members(stream);
                if (header.size != stream.tellg() - stream_start_pos)
                {
                    throw logic_error("invalid data size");
                }
                break;
#ifdef SEAL_USE_ZLIB
            case compr_mode_type::deflate:
                {
                    auto compr_size = header.size - (stream.tellg() - stream_start_pos);

                    // We don't know the decompressed size, but use compr_size as
                    // starting point for the buffer.
                    SafeByteBuffer safe_buffer(safe_cast<streamsize>(compr_size));

                    iostream temp_stream(&safe_buffer);
                    temp_stream.exceptions(ios_base::badbit | ios_base::failbit);

                    constexpr int Z_OK = 0;
                    if (ztools::inflate_stream(
                        stream, compr_size, temp_stream,
                        MemoryManager::GetPool(mm_prof_opt::FORCE_NEW, true)) != Z_OK)
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
            throw runtime_error("I/O error");
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
        function<void(ostream &stream)> save_members,
        streamoff raw_size,
        SEAL_BYTE *out,
        size_t size,
        compr_mode_type compr_mode)
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
        ArrayPutBuffer apbuf(
            reinterpret_cast<char*>(out),
            static_cast<streamsize>(size));
        ostream stream(&apbuf);
        return Save(save_members, raw_size, stream, compr_mode);
    }

    streamoff Serialization::Load(
        function<void(istream &stream)> load_members,
        const SEAL_BYTE *in,
        size_t size)
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
        ArrayGetBuffer agbuf(
            reinterpret_cast<const char*>(in),
            static_cast<streamsize>(size));
        istream stream(&agbuf);
        return Load(load_members, stream);
    }
}
