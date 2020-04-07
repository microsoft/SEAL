// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#pragma once

#include "seal/ciphertext.h"
#include "seal/plaintext.h"
#include "seal/util/common.h"
#include "seal/util/defines.h"
#include <cstddef>
#include <cstdint>
#include <iterator>
#include <type_traits>

namespace seal
{
    namespace util
    {
        class coeff_iterator;

        class const_coeff_iterator;

        class rns_iterator;

        class const_rns_iterator;

        class poly_iterator;

        class const_poly_iterator;

        class coeff_iterator
        {
        public:
            friend rns_iterator;

            using self_type = coeff_iterator;
            using value_type = std::uint64_t;
            using pointer = std::uint64_t *;
            using reference = std::uint64_t &;

            using iterator_category = std::bidirectional_iterator_tag;
            using difference_type = std::ptrdiff_t;

            using is_deref_to_iterator_type = std::false_type;

            coeff_iterator(pointer ptr) : ptr_(ptr)
            {}

            coeff_iterator(Ciphertext &ct) : coeff_iterator(ct.data())
            {}

            coeff_iterator(const coeff_iterator &copy) = default;

            coeff_iterator &operator=(const coeff_iterator &assign) = default;

            SEAL_NODISCARD inline auto ptr() const noexcept
            {
                return ptr_;
            }

            SEAL_NODISCARD operator std::uint64_t *() const noexcept
            {
                return ptr();
            }

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

            SEAL_NODISCARD inline reference operator*() const noexcept
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

        private:
            pointer ptr_;
        };

        class const_coeff_iterator
        {
        public:
            friend const_rns_iterator;

            using self_type = const_coeff_iterator;
            using value_type = std::uint64_t;
            using pointer = const std::uint64_t *;
            using reference = const std::uint64_t &;

            using iterator_category = std::bidirectional_iterator_tag;
            using difference_type = std::ptrdiff_t;

            using is_deref_to_iterator_type = std::false_type;

            const_coeff_iterator(pointer ptr) : ptr_(ptr)
            {}

            const_coeff_iterator(const Ciphertext &ct) : const_coeff_iterator(ct.data())
            {}

            const_coeff_iterator(const const_coeff_iterator &copy) = default;

            const_coeff_iterator &operator=(const const_coeff_iterator &assign) = default;

            SEAL_NODISCARD inline auto ptr() const noexcept
            {
                return ptr_;
            }

            SEAL_NODISCARD operator const std::uint64_t *() const noexcept
            {
                return ptr();
            }

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

            SEAL_NODISCARD inline reference operator*() const noexcept
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

        private:
            pointer ptr_;
        };

        class rns_iterator
        {
        public:
            friend class poly_iterator;

            using self_type = rns_iterator;
            using value_type = coeff_iterator;
            using pointer = void;
            using reference = void;

            using iterator_category = std::bidirectional_iterator_tag;
            using difference_type = std::ptrdiff_t;

            using is_deref_to_iterator_type = std::true_type;

            rns_iterator(std::uint64_t *ptr, std::size_t poly_modulus_degree)
                : ptr_(ptr), step_size_(poly_modulus_degree)
            {}

            rns_iterator(Ciphertext &ct) : rns_iterator(ct.data(), ct.poly_modulus_degree())
            {}

            rns_iterator(const rns_iterator &copy) = default;

            rns_iterator &operator=(const rns_iterator &assign) = default;

            SEAL_NODISCARD inline auto ptr() const noexcept
            {
                return ptr_;
            }

            SEAL_NODISCARD operator std::uint64_t *() const noexcept
            {
                return ptr();
            }

            SEAL_NODISCARD inline value_type operator*() const noexcept
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

            SEAL_NODISCARD inline std::size_t poly_modulus_degree() const noexcept
            {
                return step_size_;
            }

        private:
            std::uint64_t *ptr_;

            std::size_t step_size_;
        };

        class const_rns_iterator
        {
        public:
            friend class const_poly_iterator;

            using self_type = const_rns_iterator;
            using value_type = const_coeff_iterator;
            using pointer = void;
            using reference = void;

            using iterator_category = std::bidirectional_iterator_tag;
            using difference_type = std::ptrdiff_t;

            using is_deref_to_iterator_type = std::true_type;

            const_rns_iterator(const Ciphertext &ct) : const_rns_iterator(ct.data(), ct.poly_modulus_degree())
            {}

            const_rns_iterator(const std::uint64_t *ptr, std::size_t poly_modulus_degree)
                : ptr_(ptr), step_size_(poly_modulus_degree)
            {}

            const_rns_iterator(const const_rns_iterator &copy) = default;

            const_rns_iterator &operator=(const const_rns_iterator &assign) = default;

            SEAL_NODISCARD inline auto ptr() const noexcept
            {
                return ptr_;
            }

            SEAL_NODISCARD operator const std::uint64_t *() const noexcept
            {
                return ptr();
            }

            SEAL_NODISCARD inline value_type operator*() const noexcept
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

            SEAL_NODISCARD inline std::size_t poly_modulus_degree() const noexcept
            {
                return step_size_;
            }

        private:
            const std::uint64_t *ptr_;

            std::size_t step_size_;
        };

        class poly_iterator
        {
        public:
            using self_type = poly_iterator;
            using value_type = rns_iterator;
            using pointer = void;
            using reference = void;

            using iterator_category = std::bidirectional_iterator_tag;
            using difference_type = std::ptrdiff_t;

            using is_deref_to_iterator_type = std::true_type;

            poly_iterator(std::uint64_t *ptr, std::size_t poly_modulus_degree, std::size_t coeff_modulus_count)
                : ptr_(ptr), step_size_(mul_safe(poly_modulus_degree, coeff_modulus_count)),
                  poly_modulus_degree_(poly_modulus_degree), coeff_modulus_count_(coeff_modulus_count)
            {}

            poly_iterator(Ciphertext &ct) : poly_iterator(ct.data(), ct.poly_modulus_degree(), ct.coeff_modulus_count())
            {}

            poly_iterator(const poly_iterator &copy) = default;

            poly_iterator &operator=(const poly_iterator &assign) = default;

            SEAL_NODISCARD inline auto ptr() const noexcept
            {
                return ptr_;
            }

            SEAL_NODISCARD operator std::uint64_t *() const noexcept
            {
                return ptr();
            }

            SEAL_NODISCARD inline value_type operator*() const noexcept
            {
                return value_type(ptr_, poly_modulus_degree_);
            }

            SEAL_NODISCARD inline bool operator==(const self_type &compare) const noexcept
            {
                return (ptr_ == compare.ptr_);
            }

            SEAL_NODISCARD inline bool operator!=(const self_type &compare) const noexcept
            {
                return !(*this == compare);
            }

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

            SEAL_NODISCARD inline std::size_t poly_modulus_degree() const noexcept
            {
                return poly_modulus_degree_;
            }

            SEAL_NODISCARD inline std::size_t coeff_modulus_count() const noexcept
            {
                return coeff_modulus_count_;
            }

        private:
            std::uint64_t *ptr_;

            std::size_t step_size_;

            std::size_t poly_modulus_degree_;

            std::size_t coeff_modulus_count_;
        };

        class const_poly_iterator
        {
        public:
            using self_type = const_poly_iterator;
            using value_type = const_rns_iterator;
            using pointer = void;
            using reference = void;

            using iterator_category = std::bidirectional_iterator_tag;
            using difference_type = std::ptrdiff_t;

            using is_deref_to_iterator_type = std::true_type;

            const_poly_iterator(
                const std::uint64_t *ptr, std::size_t poly_modulus_degree, std::size_t coeff_modulus_count)
                : ptr_(ptr), step_size_(mul_safe(poly_modulus_degree, coeff_modulus_count)),
                  poly_modulus_degree_(poly_modulus_degree), coeff_modulus_count_(coeff_modulus_count)
            {}

            const_poly_iterator(const Ciphertext &ct)
                : const_poly_iterator(ct.data(), ct.poly_modulus_degree(), ct.coeff_modulus_count())
            {}

            const_poly_iterator(const const_poly_iterator &copy) = default;

            const_poly_iterator &operator=(const const_poly_iterator &assign) = default;

            SEAL_NODISCARD inline auto ptr() const noexcept
            {
                return ptr_;
            }

            SEAL_NODISCARD operator const std::uint64_t *() const noexcept
            {
                return ptr();
            }

            SEAL_NODISCARD inline value_type operator*() const noexcept
            {
                return value_type(ptr_, poly_modulus_degree_);
            }

            SEAL_NODISCARD inline bool operator==(const self_type &compare) const noexcept
            {
                return (ptr_ == compare.ptr_);
            }

            SEAL_NODISCARD inline bool operator!=(const self_type &compare) const noexcept
            {
                return !(*this == compare);
            }

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

            SEAL_NODISCARD inline std::size_t poly_modulus_degree() const noexcept
            {
                return poly_modulus_degree_;
            }

            SEAL_NODISCARD inline std::size_t coeff_modulus_count() const noexcept
            {
                return coeff_modulus_count_;
            }

        private:
            const std::uint64_t *ptr_;

            std::size_t step_size_;

            std::size_t poly_modulus_degree_;

            std::size_t coeff_modulus_count_;
        };

        template <class PtrT>
        class iterator_wrapper
        {
        public:
            using self_type = iterator_wrapper<PtrT>;
            using value_type = PtrT;
            using pointer = void;
            using reference = void;

            using iterator_category = std::bidirectional_iterator_tag;
            using difference_type = std::ptrdiff_t;

            using is_deref_to_iterator_type = std::false_type;

            iterator_wrapper(PtrT ptr) : ptr_(ptr)
            {}

            iterator_wrapper(const iterator_wrapper &copy) = default;

            iterator_wrapper &operator=(const iterator_wrapper &assign) = default;

            SEAL_NODISCARD inline value_type operator*() const noexcept
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

            inline auto &operator++() noexcept
            {
                ptr_++;
                return *this;
            }

            inline auto operator++(int) noexcept
            {
                self_type result(*this);
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
                self_type result(*this);
                ptr_--;
                return result;
            }

        private:
            value_type ptr_;
        };

        template <class It1, class It2>
        class iterator_tuple_2
        {
        public:
            using value_type_1 = std::conditional_t<
                It1::is_deref_to_iterator_type::value, typename std::iterator_traits<It1>::value_type,
                iterator_wrapper<typename std::iterator_traits<It1>::value_type>>;
            using value_type_2 = std::conditional_t<
                It2::is_deref_to_iterator_type::value, typename std::iterator_traits<It2>::value_type,
                iterator_wrapper<typename std::iterator_traits<It2>::value_type>>;

            using is_deref_to_iterator_type = std::conditional_t<
                It1::is_deref_to_iterator_type::value && It2::is_deref_to_iterator_type::value, std::true_type,
                std::false_type>;

            using self_type = iterator_tuple_2<It1, It2>;
            using value_type = iterator_tuple_2<value_type_1, value_type_2>;
            using pointer = void;
            using reference = void;

            using iterator_category = std::bidirectional_iterator_tag;
            using difference_type = std::ptrdiff_t;

            self_type(const It1 &it1, const It2 &it2) : it1_(it1), it2_(it2)
            {}

            self_type(const self_type &copy) = default;

            self_type &operator=(const self_type &assign) = default;

            SEAL_NODISCARD inline const It1 &it1() const noexcept
            {
                return it1_;
            }

            SEAL_NODISCARD inline const It2 &it2() const noexcept
            {
                return it2_;
            }

            SEAL_NODISCARD inline value_type operator*() const noexcept
            {
                return { *it1_, *it2_ };
            }

            SEAL_NODISCARD inline bool operator==(const self_type &compare) const noexcept
            {
                return (it1_ == compare.it1_ && it2_ == compare.it2_);
            }

            SEAL_NODISCARD inline bool operator!=(const self_type &compare) const noexcept
            {
                return !(*this == compare);
            }

            inline auto &operator++() noexcept
            {
                it1_++;
                it2_++;
                return *this;
            }

            inline auto operator++(int) noexcept
            {
                self_type result(*this);
                it1_++;
                it2_++;
                return result;
            }

            inline auto &operator--() noexcept
            {
                it1_--;
                it2_--;
                return *this;
            }

            inline auto operator--(int) noexcept
            {
                self_type result(*this);
                it1_--;
                it2_--;
                return result;
            }

        private:
            It1 it1_;

            It2 it2_;
        };

        template <class It1, class It2, class It3>
        class iterator_tuple_3
        {
        public:
            using value_type_1 = std::conditional_t<
                It1::is_deref_to_iterator_type::value, typename std::iterator_traits<It1>::value_type,
                iterator_wrapper<typename std::iterator_traits<It1>::value_type>>;
            using value_type_2 = std::conditional_t<
                It2::is_deref_to_iterator_type::value, typename std::iterator_traits<It2>::value_type,
                iterator_wrapper<typename std::iterator_traits<It2>::value_type>>;
            using value_type_3 = std::conditional_t<
                It3::is_deref_to_iterator_type::value, typename std::iterator_traits<It3>::value_type,
                iterator_wrapper<typename std::iterator_traits<It3>::value_type>>;

            using is_deref_to_iterator_type = std::conditional_t<
                It1::is_deref_to_iterator_type::value && It2::is_deref_to_iterator_type::value &&
                    It3::is_deref_to_iterator_type::value,
                std::true_type, std::false_type>;

            using self_type = iterator_tuple_3<It1, It2, It3>;
            using value_type = iterator_tuple_3<value_type_1, value_type_2, value_type_3>;
            using pointer = void;
            using reference = void;

            using iterator_category = std::bidirectional_iterator_tag;
            using difference_type = std::ptrdiff_t;

            self_type(const It1 &it1, const It2 &it2, const It3 &it3) : it1_(it1), it2_(it2), it3_(it3)
            {}

            self_type(const self_type &copy) = default;

            self_type &operator=(const self_type &assign) = default;

            SEAL_NODISCARD inline const It1 &it1() const noexcept
            {
                return it1_;
            }

            SEAL_NODISCARD inline const It2 &it2() const noexcept
            {
                return it2_;
            }

            SEAL_NODISCARD inline const It3 &it3() const noexcept
            {
                return it3_;
            }

            SEAL_NODISCARD inline value_type operator*() const noexcept
            {
                return { *it1_, *it2_, *it3_ };
            }

            SEAL_NODISCARD inline bool operator==(const self_type &compare) const noexcept
            {
                return (it1_ == compare.it1_ && it2_ == compare.it2_ && it3_ == compare.it3_);
            }

            SEAL_NODISCARD inline bool operator!=(const self_type &compare) const noexcept
            {
                return !(*this == compare);
            }

            inline auto &operator++() noexcept
            {
                it1_++;
                it2_++;
                it3_++;
                return *this;
            }

            inline auto operator++(int) noexcept
            {
                self_type result(*this);
                it1_++;
                it2_++;
                it3_++;
                return result;
            }

            inline auto &operator--() noexcept
            {
                it1_--;
                it2_--;
                it3_--;
                return *this;
            }

            inline auto operator--(int) noexcept
            {
                self_type result(*this);
                it1_--;
                it2_--;
                it3_--;
                return result;
            }

        private:
            It1 it1_;

            It2 it2_;

            It3 it3_;
        };

        template <class It1, class It2, class It3, class It4>
        class iterator_tuple_4
        {
        public:
            using value_type_1 = std::conditional_t<
                It1::is_deref_to_iterator_type::value, typename std::iterator_traits<It1>::value_type,
                iterator_wrapper<typename std::iterator_traits<It1>::value_type>>;
            using value_type_2 = std::conditional_t<
                It2::is_deref_to_iterator_type::value, typename std::iterator_traits<It2>::value_type,
                iterator_wrapper<typename std::iterator_traits<It2>::value_type>>;
            using value_type_3 = std::conditional_t<
                It3::is_deref_to_iterator_type::value, typename std::iterator_traits<It3>::value_type,
                iterator_wrapper<typename std::iterator_traits<It3>::value_type>>;
            using value_type_4 = std::conditional_t<
                It4::is_deref_to_iterator_type::value, typename std::iterator_traits<It4>::value_type,
                iterator_wrapper<typename std::iterator_traits<It4>::value_type>>;

            using is_deref_to_iterator_type = std::conditional_t<
                It1::is_deref_to_iterator_type::value && It2::is_deref_to_iterator_type::value &&
                    It3::is_deref_to_iterator_type::value && It4::is_deref_to_iterator_type::value,
                std::true_type, std::false_type>;

            using self_type = iterator_tuple_4<It1, It2, It3, It4>;
            using value_type = iterator_tuple_4<value_type_1, value_type_2, value_type_3, value_type_4>;
            using pointer = void;
            using reference = void;

            using iterator_category = std::bidirectional_iterator_tag;
            using difference_type = std::ptrdiff_t;

            self_type(const It1 &it1, const It2 &it2, const It3 &it3, const It4 &it4)
                : it1_(it1), it2_(it2), it3_(it3), it4_(it4)
            {}

            self_type(const self_type &copy) = default;

            self_type &operator=(const self_type &assign) = default;

            SEAL_NODISCARD inline const It1 &it1() const noexcept
            {
                return it1_;
            }

            SEAL_NODISCARD inline const It2 &it2() const noexcept
            {
                return it2_;
            }

            SEAL_NODISCARD inline const It3 &it3() const noexcept
            {
                return it3_;
            }

            SEAL_NODISCARD inline const It4 &it4() const noexcept
            {
                return it4_;
            }

            SEAL_NODISCARD inline value_type operator*() const noexcept
            {
                return { *it1_, *it2_, *it3_, *it4_ };
            }

            SEAL_NODISCARD inline bool operator==(const self_type &compare) const noexcept
            {
                return (it1_ == compare.it1_ && it2_ == compare.it2_ && it3_ == compare.it3_ && it4_ == compare.it4_);
            }

            SEAL_NODISCARD inline bool operator!=(const self_type &compare) const noexcept
            {
                return !(*this == compare);
            }

            inline auto &operator++() noexcept
            {
                it1_++;
                it2_++;
                it3_++;
                it4_++;
                return *this;
            }

            inline auto operator++(int) noexcept
            {
                self_type result(*this);
                it1_++;
                it2_++;
                it3_++;
                it4_++;
                return result;
            }

            inline auto &operator--() noexcept
            {
                it1_--;
                it2_--;
                it3_--;
                it4_--;
                return *this;
            }

            inline auto operator--(int) noexcept
            {
                self_type result(*this);
                it1_--;
                it2_--;
                it3_--;
                it4_--;
                return result;
            }

        private:
            It1 it1_;

            It2 it2_;

            It3 it3_;

            It4 it4_;
        };

        template <class It>
        class reverse_iterator : public It
        {
        public:
            using self_type = reverse_iterator<It>;

            self_type(const It &copy) : It(copy)
            {}

            self_type &operator=(const self_type &assign) = default;

            inline auto &operator++() noexcept
            {
                return It::operator--();
            }

            inline auto operator++(int) noexcept
            {
                return It::operator--(0);
            }

            inline auto &operator--() noexcept
            {
                return It::operator++();
            }

            inline auto operator--(int) noexcept
            {
                return It::operator++(0);
            }
        };
    } // namespace util
} // namespace seal
