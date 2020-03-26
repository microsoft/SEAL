// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#pragma once

#include "seal/util/defines.h"
#include "seal/util/common.h"
#include "seal/ciphertext.h"
#include "seal/plaintext.h"
#include <iterator>
#include <cstdint>
#include <cstddef>

namespace seal
{
    namespace util
    {
        template<class SelfT, typename ValueT>
        class array_iterator_base
        {
        public:
            using self_type = SelfT;
            using value_type = ValueT;
            using pointer = void;
            using reference = void;

            using iterator_category = std::bidirectional_iterator_tag;
            using difference_type = std::ptrdiff_t;

            array_iterator_base(value_type ptr, std::size_t step_size) : ptr_(ptr), step_size_(step_size)
            {}

            array_iterator_base(const array_iterator_base &copy) = default; 

            array_iterator_base &operator=(const array_iterator_base &assign) = default;

            SEAL_NODISCARD inline value_type operator*() noexcept
            {
                return ptr_;
            }

            SEAL_NODISCARD inline bool operator==(const self_type &compare) const noexcept
            {
                return (ptr_ == compare.ptr_);
            }

            SEAL_NODISCARD inline bool operator!=(const self_type &compare) const noexcept
            {
                return !(*this == compare);
            }

        protected:
            value_type ptr_;

            const std::size_t step_size_;
        };

        class poly_iterator : public array_iterator_base<poly_iterator, std::uint64_t*>
        {
        public:
            poly_iterator(const poly_iterator &copy) = default;

            poly_iterator &operator=(const poly_iterator &assign) = default;

            inline auto &operator++() noexcept
            {
                ptr_ += step_size_;
                return *this;
            }

            inline auto operator++(int) noexcept
            {
                self_type result(*this);
                ptr_ += step_size_;
                return result;
            }

            inline auto &operator--() noexcept
            {
                ptr_ -= step_size_;
                return *this;
            }

            inline auto operator--(int) noexcept
            {
                self_type result(*this);
                ptr_ -= step_size_;
                return result;
            }

            static inline poly_iterator begin(
                    value_type ptr,
                    std::size_t poly_modulus_degree,
                    std::size_t coeff_modulus_count)
            {
                return poly_iterator(ptr, poly_modulus_degree, coeff_modulus_count);
            }

            static inline poly_iterator end(
                    value_type ptr,
                    std::size_t poly_modulus_degree,
                    std::size_t coeff_modulus_count,
                    std::size_t size)
            {
                poly_iterator end_iter(ptr, poly_modulus_degree, coeff_modulus_count);
                end_iter.ptr_ += size * end_iter.step_size_;
                return end_iter;
            }

            static inline poly_iterator begin(Ciphertext &ct)
            {
                return begin(ct.data(), ct.poly_modulus_degree(), ct.coeff_modulus_count());
            }

            static inline poly_iterator end(Ciphertext &ct)
            {
                return end(ct.data(), ct.poly_modulus_degree(), ct.coeff_modulus_count(), ct.size());
            }

            SEAL_NODISCARD inline std::size_t poly_modulus_degree() const noexcept
            {
                return poly_modulus_degree_;
            }

            SEAL_NODISCARD inline std::size_t coeff_modulus_count() const noexcept
            {
                return coeff_modulus_count_;
            }

        private:
            poly_iterator(value_type ptr, std::size_t poly_modulus_degree, std::size_t coeff_modulus_count) :
                array_iterator_base<poly_iterator, value_type>(
                        ptr,
                        mul_safe(poly_modulus_degree, coeff_modulus_count)),
                poly_modulus_degree_(poly_modulus_degree),
                coeff_modulus_count_(coeff_modulus_count)
            {}

            std::size_t poly_modulus_degree_;

            std::size_t coeff_modulus_count_;
        };

        class const_poly_iterator : public array_iterator_base<const_poly_iterator, const std::uint64_t*>
        {
        public:
            const_poly_iterator(const const_poly_iterator &copy) = default;

            const_poly_iterator &operator=(const const_poly_iterator &assign) = default;

            inline auto &operator++() noexcept
            {
                ptr_ += step_size_;
                return *this;
            }

            inline auto operator++(int) noexcept
            {
                self_type result(*this);
                ptr_ += step_size_;
                return result;
            }

            inline auto &operator--() noexcept
            {
                ptr_ -= step_size_;
                return *this;
            }

            inline auto operator--(int) noexcept
            {
                self_type result(*this);
                ptr_ -= step_size_;
                return result;
            }

            static inline const_poly_iterator begin(
                    value_type ptr,
                    std::size_t poly_modulus_degree,
                    std::size_t coeff_modulus_count)
            {
                return const_poly_iterator(ptr, poly_modulus_degree, coeff_modulus_count);
            }

            static inline const_poly_iterator end(
                    value_type ptr,
                    std::size_t poly_modulus_degree,
                    std::size_t coeff_modulus_count,
                    std::size_t size)
            {
                const_poly_iterator end_iter(ptr, poly_modulus_degree, coeff_modulus_count);
                end_iter.ptr_ += size * end_iter.step_size_;
                return end_iter;
            }

            static inline const_poly_iterator begin(const Ciphertext &ct)
            {
                return begin(ct.data(), ct.poly_modulus_degree(), ct.coeff_modulus_count());
            }

            static inline const_poly_iterator end(const Ciphertext &ct)
            {
                return end(ct.data(), ct.poly_modulus_degree(), ct.coeff_modulus_count(), ct.size());
            }

            SEAL_NODISCARD inline std::size_t poly_modulus_degree() const noexcept
            {
                return poly_modulus_degree_;
            }

            SEAL_NODISCARD inline std::size_t coeff_modulus_count() const noexcept
            {
                return coeff_modulus_count_;
            }

        private:
            const_poly_iterator(value_type ptr, std::size_t poly_modulus_degree, std::size_t coeff_modulus_count) :
                array_iterator_base<const_poly_iterator, value_type>(
                        ptr,
                        mul_safe(poly_modulus_degree, coeff_modulus_count)),
                poly_modulus_degree_(poly_modulus_degree),
                coeff_modulus_count_(coeff_modulus_count)
            {}

            std::size_t poly_modulus_degree_;

            std::size_t coeff_modulus_count_;
        };

        class rns_iterator : public array_iterator_base<rns_iterator, std::uint64_t*>
        {
        public:
            rns_iterator(const rns_iterator &copy) = default;

            rns_iterator &operator=(const rns_iterator &assign) = default;

            inline auto &operator++() noexcept
            {
                ptr_ += step_size_;
                return *this;
            }

            inline auto operator++(int) noexcept
            {
                self_type result(*this);
                ptr_ += step_size_;
                return result;
            }

            inline auto &operator--() noexcept
            {
                ptr_ -= step_size_;
                return *this;
            }

            inline auto operator--(int) noexcept
            {
                self_type result(*this);
                ptr_ -= step_size_;
                return result;
            }

            static inline rns_iterator begin(value_type ptr, std::size_t poly_modulus_degree)
            {
                return rns_iterator(ptr, poly_modulus_degree);
            }

            static inline rns_iterator end(
                    value_type ptr,
                    std::size_t poly_modulus_degree,
                    std::size_t coeff_modulus_count)
            {
                rns_iterator end_iter(ptr, poly_modulus_degree);
                end_iter.ptr_ += coeff_modulus_count * end_iter.step_size_;
                return end_iter;
            }

            static inline rns_iterator begin(poly_iterator &poly_iter)
            {
                return begin(*poly_iter, poly_iter.poly_modulus_degree());
            }

            static inline rns_iterator end(poly_iterator &poly_iter)
            {
                return end(*poly_iter, poly_iter.poly_modulus_degree(), poly_iter.coeff_modulus_count());
            }

            SEAL_NODISCARD inline std::size_t poly_modulus_degree() const noexcept
            {
                return poly_modulus_degree_;
            }

        private:
            rns_iterator(value_type ptr, std::size_t poly_modulus_degree) :
                array_iterator_base<rns_iterator, value_type>(ptr, poly_modulus_degree),
                poly_modulus_degree_(poly_modulus_degree)
            {}

            std::size_t poly_modulus_degree_;
        };

        class const_rns_iterator : public array_iterator_base<const_rns_iterator, const std::uint64_t*>
        {
        public:
            const_rns_iterator(const const_rns_iterator &copy) = default;

            const_rns_iterator &operator=(const const_rns_iterator &assign) = default;

            inline auto &operator++() noexcept
            {
                ptr_ += step_size_;
                return *this;
            }

            inline auto operator++(int) noexcept
            {
                self_type result(*this);
                ptr_ += step_size_;
                return result;
            }

            inline auto &operator--() noexcept
            {
                ptr_ -= step_size_;
                return *this;
            }

            inline auto operator--(int) noexcept
            {
                self_type result(*this);
                ptr_ -= step_size_;
                return result;
            }

            static inline const_rns_iterator begin(value_type ptr, std::size_t poly_modulus_degree)
            {
                return const_rns_iterator(ptr, poly_modulus_degree);
            }

            static inline const_rns_iterator end(
                    value_type ptr,
                    std::size_t poly_modulus_degree,
                    std::size_t coeff_modulus_count)
            {
                const_rns_iterator end_iter(ptr, poly_modulus_degree);
                end_iter.ptr_ += coeff_modulus_count * end_iter.step_size_;
                return end_iter;
            }

            static inline const_rns_iterator begin(const_poly_iterator &poly_iter)
            {
                return begin(*poly_iter, poly_iter.poly_modulus_degree());
            }

            static inline const_rns_iterator end(const_poly_iterator &poly_iter)
            {
                return end(*poly_iter, poly_iter.poly_modulus_degree(), poly_iter.coeff_modulus_count());
            }

            static inline const_rns_iterator begin(poly_iterator &poly_iter)
            {
                return begin(*poly_iter, poly_iter.poly_modulus_degree());
            }

            static inline const_rns_iterator end(poly_iterator &poly_iter)
            {
                return end(*poly_iter, poly_iter.poly_modulus_degree(), poly_iter.coeff_modulus_count());
            }

            SEAL_NODISCARD inline std::size_t poly_modulus_degree() const noexcept
            {
                return poly_modulus_degree_;
            }

        private:
            const_rns_iterator(value_type ptr, std::size_t poly_modulus_degree) :
                array_iterator_base<const_rns_iterator, value_type>(ptr, poly_modulus_degree),
                poly_modulus_degree_(poly_modulus_degree)
            {}

            std::size_t poly_modulus_degree_;
        };

        class coeff_iterator
        {
        public:
            using self_type = coeff_iterator;
            using value_type = std::uint64_t;
            using pointer = std::uint64_t*;
            using reference = std::uint64_t&;

            using iterator_category = std::bidirectional_iterator_tag;
            using difference_type = std::ptrdiff_t;

            coeff_iterator(pointer ptr) : ptr_(ptr)
            {}

            coeff_iterator(const coeff_iterator &copy) = default;

            coeff_iterator &operator=(const coeff_iterator &assign) = default;

            inline auto &operator++() noexcept
            {
                ptr_++;
                return *this;
            }

            inline auto operator++(int) noexcept
            {
                self_type result(ptr_);
                ptr_++;
                return result;
            }

            inline auto &operator--() noexcept
            {
                ptr_--;
                return *this;
            }

            inline auto operator--(int) noexcept
            {
                self_type result(ptr_);
                ptr_--;
                return result;
            }

            SEAL_NODISCARD inline value_type operator*() noexcept
            {
                return *ptr_;
            }

            SEAL_NODISCARD inline bool operator==(const self_type &compare) const noexcept
            {
                return (ptr_ == compare.ptr_);
            }

            SEAL_NODISCARD inline bool operator!=(const self_type &compare) const noexcept
            {
                return !(*this == compare);
            }

            static inline coeff_iterator begin(rns_iterator &rns_iter)
            {
                return coeff_iterator(*rns_iter);
            }

            static inline coeff_iterator end(rns_iterator &rns_iter)
            {
                coeff_iterator end_iter(*rns_iter);
                end_iter.ptr_ += rns_iter.poly_modulus_degree();
                return end_iter;
            }

        private:
            pointer ptr_;
        };

        class const_coeff_iterator
        {
        public:
            using self_type = const_coeff_iterator;
            using value_type = std::uint64_t;
            using pointer = const std::uint64_t*;
            using reference = const std::uint64_t&;

            using iterator_category = std::bidirectional_iterator_tag;
            using difference_type = std::ptrdiff_t;

            const_coeff_iterator(pointer ptr) : ptr_(ptr)
            {}

            const_coeff_iterator(const const_coeff_iterator &copy) = default;

            const_coeff_iterator &operator=(const const_coeff_iterator &assign) = default;

            inline auto &operator++() noexcept
            {
                ptr_++;
                return *this;
            }

            inline auto operator++(int) noexcept
            {
                self_type result(ptr_);
                ptr_++;
                return result;
            }

            inline auto &operator--() noexcept
            {
                ptr_--;
                return *this;
            }

            inline auto operator--(int) noexcept
            {
                self_type result(ptr_);
                ptr_--;
                return result;
            }

            SEAL_NODISCARD inline value_type operator*() noexcept
            {
                return *ptr_;
            }

            SEAL_NODISCARD inline bool operator==(const self_type &compare) const noexcept
            {
                return (ptr_ == compare.ptr_);
            }

            SEAL_NODISCARD inline bool operator!=(const self_type &compare) const noexcept
            {
                return !(*this == compare);
            }

            static inline const_coeff_iterator begin(const_rns_iterator &rns_iter)
            {
                return const_coeff_iterator(*rns_iter);
            }

            static inline const_coeff_iterator end(const_rns_iterator &rns_iter)
            {
                const_coeff_iterator end_iter(*rns_iter);
                end_iter.ptr_ += rns_iter.poly_modulus_degree();
                return end_iter;
            }

            static inline const_coeff_iterator begin(rns_iterator &rns_iter)
            {
                return const_coeff_iterator(*rns_iter);
            }

            static inline const_coeff_iterator end(rns_iterator &rns_iter)
            {
                const_coeff_iterator end_iter(*rns_iter);
                end_iter.ptr_ += rns_iter.poly_modulus_degree();
                return end_iter;
            }

        private:
            pointer ptr_;
        };
    }
}
