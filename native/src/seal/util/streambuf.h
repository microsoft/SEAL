// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#pragma once

#include "seal/dynarray.h"
#include "seal/util/defines.h"
#include <cstddef>
#include <ios>
#include <streambuf>

namespace seal
{
    namespace util
    {
        class SafeByteBuffer final : public std::streambuf
        {
        public:
            SafeByteBuffer(std::streamsize size = 1, bool clear_buffers = true);

            ~SafeByteBuffer() override = default;

            SafeByteBuffer(const SafeByteBuffer &copy) = delete;

            SafeByteBuffer &operator=(const SafeByteBuffer &assign) = delete;

            SEAL_NODISCARD inline const seal_byte *data() const noexcept
            {
                return reinterpret_cast<const seal_byte *>(buf_.cbegin());
            }

            SEAL_NODISCARD inline seal_byte *data() noexcept
            {
                return reinterpret_cast<seal_byte *>(buf_.begin());
            }

            SEAL_NODISCARD inline std::size_t size() noexcept
            {
                return buf_.size();
            }

            SEAL_NODISCARD inline std::size_t capacity() noexcept
            {
                return buf_.capacity();
            }

        private:
            void safe_gbump(std::streamsize count);

            void safe_pbump(std::streamsize count);

            int_type underflow() override;

            int_type pbackfail(int_type ch) override;

            std::streamsize showmanyc() override;

            std::streamsize xsgetn(char_type *s, std::streamsize count) override;

            pos_type seekpos(
                pos_type pos, std::ios_base::openmode which = std::ios_base::in | std::ios_base::out) override;

            pos_type seekoff(
                off_type off, std::ios_base::seekdir dir,
                std::ios_base::openmode which = std::ios_base::in | std::ios_base::out) override;

            void expand_size();

            int_type overflow(int_type ch = traits_type::eof()) override;

            std::streamsize xsputn(const char_type *s, std::streamsize count) override;

            std::streamsize size_;

            const bool clear_buffers_;

            DynArray<char> buf_;

            static constexpr double expansion_factor_ = 1.3;

            int_type eof_ = traits_type::eof();
        };

        class ArrayGetBuffer final : public std::streambuf
        {
        public:
            ArrayGetBuffer(const char_type *buf, std::streamsize size);

            ~ArrayGetBuffer() override = default;

            ArrayGetBuffer(const ArrayGetBuffer &copy) = delete;

            ArrayGetBuffer &operator=(const ArrayGetBuffer &assign) = delete;

        private:
            int_type underflow() override;

            int_type uflow() override;

            int_type pbackfail(int_type ch) override;

            std::streamsize showmanyc() override;

            std::streamsize xsgetn(char_type *s, std::streamsize count) override;

            pos_type seekpos(pos_type pos, std::ios_base::openmode which = std::ios_base::in) override;

            pos_type seekoff(
                off_type off, std::ios_base::seekdir dir, std::ios_base::openmode which = std::ios_base::in) override;

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
            ArrayPutBuffer(char_type *buf, std::streamsize size);

            ~ArrayPutBuffer() override = default;

            ArrayPutBuffer(const ArrayPutBuffer &copy) = delete;

            ArrayPutBuffer &operator=(const ArrayPutBuffer &assign) = delete;

            SEAL_NODISCARD inline bool at_end() const noexcept
            {
                return head_ == end_;
            }

        private:
            int_type overflow(int_type ch = traits_type::eof()) override;

            std::streamsize xsputn(const char_type *s, std::streamsize count) override;

            pos_type seekpos(pos_type pos, std::ios_base::openmode which = std::ios_base::out) override;

            pos_type seekoff(
                off_type off, std::ios_base::seekdir dir, std::ios_base::openmode which = std::ios_base::out) override;

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
