// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#pragma once

#include "seal/intarray.h"
#include "seal/memorymanager.h"
#include "seal/util/common.h"
#include "seal/util/defines.h"
#include <algorithm>
#include <cstddef>
#include <ios>
#include <iterator>
#include <stdexcept>
#include <streambuf>

namespace seal
{
    namespace util
    {
        class SafeByteBuffer final : public std::streambuf
        {
        public:
            SafeByteBuffer(std::streamsize size = 1, bool clear_on_destruction = false)
                : size_(size), clear_on_destruction_(clear_on_destruction)
            {
                if (!fits_in<std::size_t>(add_safe(size_, std::streamsize(1))))
                {
                    throw std::invalid_argument("size is too large");
                }
                buf_.resize(static_cast<std::size_t>(size_ + 1), false);
                setp(buf_.begin(), buf_.begin() + size_);
                setg(buf_.begin(), buf_.begin(), buf_.begin() + size_);
            }

            ~SafeByteBuffer() override = default;

            SafeByteBuffer(const SafeByteBuffer &copy) = delete;

            SafeByteBuffer &operator=(const SafeByteBuffer &assign) = delete;

            SEAL_NODISCARD const SEAL_BYTE *data() const noexcept
            {
                return reinterpret_cast<const SEAL_BYTE *>(buf_.cbegin());
            }

            SEAL_NODISCARD SEAL_BYTE *data() noexcept
            {
                return reinterpret_cast<SEAL_BYTE *>(buf_.begin());
            }

            SEAL_NODISCARD std::size_t size() noexcept
            {
                return buf_.size();
            }

            SEAL_NODISCARD std::size_t capacity() noexcept
            {
                return buf_.capacity();
            }

        private:
            void safe_gbump(std::streamsize count)
            {
                constexpr std::streamsize int_max = static_cast<std::streamsize>(std::numeric_limits<int>::max());
                while (count > int_max)
                {
                    gbump(std::numeric_limits<int>::max());
                    count -= int_max;
                }

                // This is now safe
                gbump(static_cast<int>(count));
            }

            void safe_pbump(std::streamsize count)
            {
                constexpr std::streamsize int_max = static_cast<std::streamsize>(std::numeric_limits<int>::max());
                while (count > int_max)
                {
                    pbump(std::numeric_limits<int>::max());
                    count -= int_max;
                }

                // This is now safe
                pbump(static_cast<int>(count));
            }

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
                safe_gbump(std::streamsize(-1));
                return traits_type::to_int_type(*gptr());
            }

            std::streamsize showmanyc() override
            {
                if (gptr() >= egptr())
                {
                    return -1;
                }
                return std::distance(gptr(), egptr());
            }

            std::streamsize xsgetn(char_type *s, std::streamsize count) override
            {
                std::streamsize avail = std::max(
                    std::streamsize(0), std::min(count, safe_cast<std::streamsize>(std::distance(gptr(), egptr()))));
                std::copy_n(gptr(), avail, s);
                safe_gbump(avail);
                return avail;
            }

            pos_type seekpos(
                pos_type pos, std::ios_base::openmode which = std::ios_base::in | std::ios_base::out) override
            {
                if (pos < 0 || pos > size_)
                {
                    return pos_type(off_type(-1));
                }
                if (which & std::ios_base::in)
                {
                    setg(eback(), eback() + static_cast<std::ptrdiff_t>(pos), egptr());
                }
                if (which & std::ios_base::out)
                {
                    setp(pbase(), epptr());
                    safe_pbump(static_cast<std::streamsize>(pos));
                }
                return pos;
            }

            pos_type seekoff(
                off_type off, std::ios_base::seekdir dir,
                std::ios_base::openmode which = std::ios_base::in | std::ios_base::out) override
            {
                // Cannot seek relative to current position for both input and
                // output heads if they are in different positions.
                if (which == (std::ios_base::in | std::ios_base::out) && dir == std::ios_base::cur && gptr() != pptr())
                {
                    return pos_type(off_type(-1));
                }

                // We are guaranteed to have only a single absolute offset
                off_type newoff = off;
                switch (dir)
                {
                case std::ios_base::beg:
                    break;

                case std::ios_base::cur:
                    if (which == std::ios_base::in)
                    {
                        newoff = add_safe(newoff, safe_cast<std::streamoff>(std::distance(eback(), gptr())));
                    }
                    else
                    {
                        newoff = add_safe(newoff, safe_cast<std::streamoff>(std::distance(pbase(), pptr())));
                    }
                    break;

                case std::ios_base::end:
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
                size_ = safe_cast<std::streamsize>(ceil(safe_cast<double>(buf_.size()) * expansion_factor_));

                // Store the old offsets for both put and get heads
                std::streamsize old_poff = std::distance(pbase(), pptr());
                std::streamsize old_goff = std::distance(eback(), gptr());

                // Copy entire buffer to new location and reserve extra byte
                buf_.resize(safe_cast<std::size_t>(add_safe<std::streamsize>(size_, std::streamsize(1))), false);

                // Set the get and put pointers appropriately
                setp(buf_.begin(), buf_.begin() + size_);
                safe_pbump(old_poff);
                setg(buf_.begin(), buf_.begin() + old_goff, buf_.begin() + size_);
            }

            int_type overflow(int_type ch = traits_type::eof()) override
            {
                if (traits_type::eq_int_type(eof_, ch) ||
                    !fits_in<std::size_t>(ceil(static_cast<double>(buf_.size()) * expansion_factor_) + 1))
                {
                    return eof_;
                }

                // Output ch to the buffer (there is one byte left of space) and overflow
                *pptr() = traits_type::to_char_type(ch);
                safe_pbump(std::streamsize(1));

                // Expand the size of the buffer
                expand_size();

                return ch;
            }

            std::streamsize xsputn(const char_type *s, std::streamsize count) override
            {
                std::streamsize remaining = count;
                while (remaining)
                {
                    if (pptr() == epptr())
                    {
                        expand_size();
                    }
                    std::streamsize avail = std::max(
                        std::streamsize(0),
                        std::min(remaining, safe_cast<std::streamsize>(std::distance(pptr(), epptr()))));
                    std::copy_n(s, avail, pptr());
                    safe_pbump(avail);
                    remaining -= avail;
                    s += avail;
                }
                return count;
            }

            IntArray<char> buf_{ MemoryManager::GetPool(mm_prof_opt::FORCE_NEW, clear_on_destruction_) };

            std::streamsize size_;

            bool clear_on_destruction_;

            static constexpr double expansion_factor_ = 1.3;

            int_type eof_ = traits_type::eof();
        };

        class ArrayGetBuffer final : public std::streambuf
        {
        public:
            ArrayGetBuffer(const char_type *buf, std::streamsize size) : buf_(buf), size_(size)
            {
                if (!buf)
                {
                    throw std::invalid_argument("buf cannot be null");
                }
                if (size <= 0)
                {
                    throw std::invalid_argument("size must be positive");
                }
                begin_ = buf_;
                end_ = buf_ + size_;
                head_ = begin_;
            }

            ~ArrayGetBuffer() override = default;

            ArrayGetBuffer(const ArrayGetBuffer &copy) = delete;

            ArrayGetBuffer &operator=(const ArrayGetBuffer &assign) = delete;

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

            std::streamsize showmanyc() override
            {
                if (head_ >= end_)
                {
                    return -1;
                }
                return std::distance(head_, end_);
            }

            std::streamsize xsgetn(char_type *s, std::streamsize count) override
            {
                std::streamsize avail = std::max(
                    std::streamsize(0), std::min(count, safe_cast<std::streamsize>(std::distance(head_, end_))));
                std::copy_n(head_, avail, s);
                std::advance(head_, avail);
                return avail;
            }

            pos_type seekpos(pos_type pos, std::ios_base::openmode which = std::ios_base::in) override
            {
                if (which != std::ios_base::in)
                {
                    return pos_type(off_type(-1));
                }
                if (pos < 0 || pos > pos_type(size_))
                {
                    return pos_type(off_type(-1));
                }

                head_ = begin_ + static_cast<std::ptrdiff_t>(pos);
                return pos;
            }

            pos_type seekoff(
                off_type off, std::ios_base::seekdir dir, std::ios_base::openmode which = std::ios_base::in) override
            {
                off_type newoff = off;
                switch (dir)
                {
                case std::ios_base::beg:
                    break;

                case std::ios_base::cur:
                    newoff = add_safe(newoff, safe_cast<off_type>(std::distance(begin_, head_)));
                    break;

                case std::ios_base::end:
                    newoff = add_safe(newoff, off_type(size_));
                    break;

                default:
                    return pos_type(off_type(-1));
                }
                return seekpos(pos_type(newoff), which);
            }

            const char_type *buf_;

            std::streamsize size_;

            using iterator_type = const char_type *;

            int_type eof_ = traits_type::eof();

            iterator_type begin_;

            iterator_type end_;

            iterator_type head_;
        };

        class ArrayPutBuffer final : public std::streambuf
        {
        public:
            ArrayPutBuffer(char_type *buf, std::streamsize size) : buf_(buf), size_(size)
            {
                if (!buf)
                {
                    throw std::invalid_argument("buf cannot be null");
                }
                if (size <= 0)
                {
                    throw std::invalid_argument("size must be positive");
                }
                begin_ = buf_;
                end_ = buf_ + size_;
                head_ = begin_;
            }

            ~ArrayPutBuffer() override = default;

            ArrayPutBuffer(const ArrayPutBuffer &copy) = delete;

            ArrayPutBuffer &operator=(const ArrayPutBuffer &assign) = delete;

            SEAL_NODISCARD bool at_end() const noexcept
            {
                return head_ == end_;
            }

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

            std::streamsize xsputn(const char_type *s, std::streamsize count) override
            {
                std::streamsize avail = std::max(
                    std::streamsize(0), std::min(count, safe_cast<std::streamsize>(std::distance(head_, end_))));
                std::copy_n(s, avail, head_);
                std::advance(head_, avail);
                return avail;
            }

            pos_type seekpos(pos_type pos, std::ios_base::openmode which = std::ios_base::out) override
            {
                if (which != std::ios_base::out)
                {
                    return pos_type(off_type(-1));
                }
                if (pos < 0 || pos > pos_type(size_))
                {
                    return pos_type(off_type(-1));
                }

                head_ = begin_ + static_cast<std::ptrdiff_t>(pos);
                return pos;
            }

            pos_type seekoff(
                off_type off, std::ios_base::seekdir dir, std::ios_base::openmode which = std::ios_base::out) override
            {
                off_type newoff = off;
                switch (dir)
                {
                case std::ios_base::beg:
                    break;

                case std::ios_base::cur:
                    newoff = add_safe(newoff, safe_cast<off_type>(std::distance(begin_, head_)));
                    break;

                case std::ios_base::end:
                    newoff = add_safe(newoff, off_type(size_));
                    break;

                default:
                    return pos_type(off_type(-1));
                }
                return seekpos(pos_type(newoff), which);
            }

            char_type *buf_;

            std::streamsize size_;

            using iterator_type = char_type *;

            int_type eof_ = traits_type::eof();

            iterator_type begin_;

            iterator_type end_;

            iterator_type head_;
        };
    } // namespace util
} // namespace seal
