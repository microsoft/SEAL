// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#pragma once

#include "seal/ciphertext.h"
#include "seal/plaintext.h"
#include "seal/util/common.h"
#include "seal/util/defines.h"
#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <iterator>
#include <type_traits>

namespace seal
{
    namespace util
    {
#ifndef SEAL_USE_STD_FOR_EACH_N
        // C++14 does not have for_each_n so we define a custom version here.
        template <typename ForwardIt, typename Size, typename Func>
        InputIt for_each_n(ForwardIt first, Size size, Func func)
        {
            for (; size--; (void)++first)
            {
                func(*first);
            }
            return first;
        }
#endif
        class CoeffIterator;

        class ConstCoeffIterator;

        class RNSIterator;

        class ConstRNSIterator;

        class PolyIterator;

        class ConstPolyIterator;

        class CoeffIterator
        {
        public:
            friend class RNSIterator;
            friend class PolyIterator;

            using self_type = CoeffIterator;
            using is_deref_to_iterator_type = std::false_type;

            // Standard iterator typedefs
            using value_type = std::uint64_t *;
            using pointer = void;
            using reference = const value_type &;
            using iterator_category = std::bidirectional_iterator_tag;
            using difference_type = std::ptrdiff_t;

            CoeffIterator() : ptr_(nullptr)
            {}

            CoeffIterator(value_type ptr) : ptr_(ptr)
            {}

            CoeffIterator(const self_type &copy) = default;

            self_type &operator=(const self_type &assign) = default;

            CoeffIterator(self_type &&source) = default;

            self_type &operator=(self_type &&assign) = default;

            SEAL_NODISCARD inline reference operator*() const noexcept
            {
                return ptr_;
            }

            inline self_type &operator++() noexcept
            {
                ptr_++;
                return *this;
            }

            inline self_type operator++(int) noexcept
            {
                self_type result(ptr_);
                ptr_++;
                return result;
            }

            inline self_type &operator--() noexcept
            {
                ptr_--;
                return *this;
            }

            inline self_type operator--(int) noexcept
            {
                self_type result(ptr_);
                ptr_--;
                return result;
            }

            SEAL_NODISCARD inline bool operator==(const self_type &compare) const noexcept
            {
                return (ptr_ == compare.ptr_);
            }

            SEAL_NODISCARD inline bool operator!=(const self_type &compare) const noexcept
            {
                return !(*this == compare);
            }

            SEAL_NODISCARD inline operator std::uint64_t *() const noexcept
            {
                return ptr_;
            }

        private:
            value_type ptr_;
        };

        class ConstCoeffIterator
        {
        public:
            friend class ConstRNSIterator;
            friend class ConstPolyIterator;

            using self_type = ConstCoeffIterator;
            using is_deref_to_iterator_type = std::false_type;

            // Standard iterator typedefs
            using value_type = const std::uint64_t *;
            using pointer = void;
            using reference = const value_type &;
            using iterator_category = std::bidirectional_iterator_tag;
            using difference_type = std::ptrdiff_t;

            ConstCoeffIterator() : ptr_(nullptr)
            {}

            ConstCoeffIterator(value_type ptr) : ptr_(ptr)
            {}

            ConstCoeffIterator(const self_type &copy) = default;

            self_type &operator=(const self_type &assign) = default;

            ConstCoeffIterator(self_type &&source) = default;

            self_type &operator=(self_type &&assign) = default;

            ConstCoeffIterator(const CoeffIterator &copy) : ptr_(static_cast<const std::uint64_t *>(copy))
            {}

            SEAL_NODISCARD inline reference operator*() const noexcept
            {
                return ptr_;
            }

            inline self_type &operator++() noexcept
            {
                ptr_++;
                return *this;
            }

            inline self_type operator++(int) noexcept
            {
                self_type result(ptr_);
                ptr_++;
                return result;
            }

            inline self_type &operator--() noexcept
            {
                ptr_--;
                return *this;
            }

            inline self_type operator--(int) noexcept
            {
                self_type result(ptr_);
                ptr_--;
                return result;
            }

            SEAL_NODISCARD inline bool operator==(const self_type &compare) const noexcept
            {
                return (ptr_ == compare.ptr_);
            }

            SEAL_NODISCARD inline bool operator!=(const self_type &compare) const noexcept
            {
                return !(*this == compare);
            }

            SEAL_NODISCARD inline operator const std::uint64_t *() const noexcept
            {
                return ptr_;
            }

        private:
            value_type ptr_;
        };

        class RNSIterator
        {
        public:
            friend class PolyIterator;

            using self_type = RNSIterator;
            using is_deref_to_iterator_type = std::true_type;

            // Standard iterator typedefs
            using value_type = CoeffIterator;
            using pointer = void;
            using reference = const value_type &;
            using iterator_category = std::bidirectional_iterator_tag;
            using difference_type = std::ptrdiff_t;

            RNSIterator() : coeff_it_(nullptr), step_size_(0)
            {}

            RNSIterator(std::uint64_t *ptr, std::size_t poly_modulus_degree)
                : coeff_it_(ptr), step_size_(poly_modulus_degree)
            {}

            RNSIterator(const self_type &copy) = default;

            self_type &operator=(const self_type &assign) = default;

            RNSIterator(self_type &&source) = default;

            self_type &operator=(self_type &&assign) = default;

            SEAL_NODISCARD inline reference operator*() const noexcept
            {
                return coeff_it_;
            }

            inline self_type &operator++() noexcept
            {
                coeff_it_.ptr_ += step_size_;
                return *this;
            }

            inline self_type operator++(int) noexcept
            {
                self_type result(*this);
                coeff_it_.ptr_ += step_size_;
                return result;
            }

            inline self_type &operator--() noexcept
            {
                coeff_it_.ptr_ -= step_size_;
                return *this;
            }

            inline self_type operator--(int) noexcept
            {
                self_type result(*this);
                coeff_it_.ptr_ -= step_size_;
                return result;
            }

            SEAL_NODISCARD inline bool operator==(const self_type &compare) const noexcept
            {
                return (coeff_it_ == compare.coeff_it_) && (step_size_ == compare.step_size_);
            }

            SEAL_NODISCARD inline bool operator!=(const self_type &compare) const noexcept
            {
                return !(*this == compare);
            }

            SEAL_NODISCARD inline operator std::uint64_t *() const noexcept
            {
                return coeff_it_;
            }

            SEAL_NODISCARD inline value_type operator->() const noexcept
            {
                return **this;
            }

            SEAL_NODISCARD inline std::size_t poly_modulus_degree() const noexcept
            {
                return step_size_;
            }

        private:
            CoeffIterator coeff_it_;

            std::size_t step_size_;
        };

        class ConstRNSIterator
        {
        public:
            friend class ConstPolyIterator;

            using self_type = ConstRNSIterator;
            using is_deref_to_iterator_type = std::true_type;

            // Standard iterator typedefs
            using value_type = ConstCoeffIterator;
            using pointer = void;
            using reference = const value_type &;
            using iterator_category = std::bidirectional_iterator_tag;
            using difference_type = std::ptrdiff_t;

            ConstRNSIterator() : coeff_it_(nullptr), step_size_(0)
            {}

            ConstRNSIterator(const std::uint64_t *ptr, std::size_t poly_modulus_degree)
                : coeff_it_(ptr), step_size_(poly_modulus_degree)
            {}

            ConstRNSIterator(const self_type &copy) = default;

            self_type &operator=(const self_type &assign) = default;

            ConstRNSIterator(self_type &&source) = default;

            self_type &operator=(self_type &&assign) = default;

            ConstRNSIterator(const RNSIterator &copy)
                : coeff_it_(static_cast<const std::uint64_t *>(copy)), step_size_(copy.poly_modulus_degree())
            {}

            SEAL_NODISCARD inline reference operator*() const noexcept
            {
                return coeff_it_;
            }

            inline self_type &operator++() noexcept
            {
                coeff_it_.ptr_ += step_size_;
                return *this;
            }

            inline self_type operator++(int) noexcept
            {
                self_type result(*this);
                coeff_it_.ptr_ += step_size_;
                return result;
            }

            inline self_type &operator--() noexcept
            {
                coeff_it_.ptr_ -= step_size_;
                return *this;
            }

            inline self_type operator--(int) noexcept
            {
                self_type result(*this);
                coeff_it_.ptr_ -= step_size_;
                return result;
            }

            SEAL_NODISCARD inline bool operator==(const self_type &compare) const noexcept
            {
                return (coeff_it_ == compare.coeff_it_) && (step_size_ == compare.step_size_);
            }

            SEAL_NODISCARD inline bool operator!=(const self_type &compare) const noexcept
            {
                return !(*this == compare);
            }

            SEAL_NODISCARD inline operator const std::uint64_t *() const noexcept
            {
                return coeff_it_;
            }

            SEAL_NODISCARD inline value_type operator->() const noexcept
            {
                return **this;
            }

            SEAL_NODISCARD inline std::size_t poly_modulus_degree() const noexcept
            {
                return step_size_;
            }

        private:
            ConstCoeffIterator coeff_it_;

            std::size_t step_size_;
        };

        class PolyIterator
        {
        public:
            using self_type = PolyIterator;
            using is_deref_to_iterator_type = std::true_type;

            // Standard iterator typedefs
            using value_type = RNSIterator;
            using pointer = void;
            using reference = const value_type &;
            using iterator_category = std::bidirectional_iterator_tag;
            using difference_type = std::ptrdiff_t;

            PolyIterator() : rns_it_(nullptr, 0), coeff_modulus_count_(0), step_size_(0)
            {}

            PolyIterator(std::uint64_t *ptr, std::size_t poly_modulus_degree, std::size_t coeff_modulus_count)
                : rns_it_(ptr, poly_modulus_degree), coeff_modulus_count_(coeff_modulus_count),
                  step_size_(mul_safe(poly_modulus_degree, coeff_modulus_count_))
            {}

            PolyIterator(Ciphertext &ct) : self_type(ct.data(), ct.poly_modulus_degree(), ct.coeff_modulus_count())
            {}

            PolyIterator(const self_type &copy) = default;

            self_type &operator=(const self_type &assign) = default;

            PolyIterator(self_type &&source) = default;

            self_type &operator=(self_type &&assign) = default;

            SEAL_NODISCARD inline reference operator*() const noexcept
            {
                return rns_it_;
            }

            inline self_type &operator++() noexcept
            {
                rns_it_.coeff_it_.ptr_ += step_size_;
                return *this;
            }

            inline self_type operator++(int) noexcept
            {
                self_type result(*this);
                rns_it_.coeff_it_.ptr_ += step_size_;
                return result;
            }

            inline self_type &operator--() noexcept
            {
                rns_it_.coeff_it_.ptr_ -= step_size_;
                return *this;
            }

            inline self_type operator--(int) noexcept
            {
                self_type result(*this);
                rns_it_.coeff_it_.ptr_ -= step_size_;
                return result;
            }

            SEAL_NODISCARD inline bool operator==(const self_type &compare) const noexcept
            {
                return (rns_it_ == compare.rns_it_) && (coeff_modulus_count_ == compare.coeff_modulus_count_);
            }

            SEAL_NODISCARD inline bool operator!=(const self_type &compare) const noexcept
            {
                return !(*this == compare);
            }

            SEAL_NODISCARD inline operator std::uint64_t *() const noexcept
            {
                return rns_it_;
            }

            SEAL_NODISCARD inline value_type operator->() const noexcept
            {
                return **this;
            }

            SEAL_NODISCARD inline std::size_t poly_modulus_degree() const noexcept
            {
                return rns_it_.step_size_;
            }

            SEAL_NODISCARD inline std::size_t coeff_modulus_count() const noexcept
            {
                return coeff_modulus_count_;
            }

        private:
            RNSIterator rns_it_;

            std::size_t coeff_modulus_count_;

            std::size_t step_size_;
        };

        class ConstPolyIterator
        {
        public:
            using self_type = ConstPolyIterator;
            using is_deref_to_iterator_type = std::true_type;

            // Standard iterator typedefs
            using value_type = ConstRNSIterator;
            using pointer = void;
            using reference = const value_type &;
            using iterator_category = std::bidirectional_iterator_tag;
            using difference_type = std::ptrdiff_t;

            ConstPolyIterator() : rns_it_(nullptr, 0), coeff_modulus_count_(0), step_size_(0)
            {}

            ConstPolyIterator(
                const std::uint64_t *ptr, std::size_t poly_modulus_degree, std::size_t coeff_modulus_count)
                : rns_it_(ptr, poly_modulus_degree), coeff_modulus_count_(coeff_modulus_count),
                  step_size_(mul_safe(poly_modulus_degree, coeff_modulus_count_))
            {}

            ConstPolyIterator(const Ciphertext &ct)
                : self_type(ct.data(), ct.poly_modulus_degree(), ct.coeff_modulus_count())
            {}

            ConstPolyIterator(const self_type &copy) = default;

            self_type &operator=(const self_type &assign) = default;

            ConstPolyIterator(self_type &&source) = default;

            self_type &operator=(self_type &&assign) = default;

            ConstPolyIterator(const PolyIterator &copy)
                : rns_it_(static_cast<const std::uint64_t *>(copy), copy.poly_modulus_degree()),
                  coeff_modulus_count_(copy.coeff_modulus_count()),
                  step_size_(mul_safe(rns_it_.step_size_, coeff_modulus_count_))
            {}

            SEAL_NODISCARD inline reference operator*() const noexcept
            {
                return rns_it_;
            }

            inline self_type &operator++() noexcept
            {
                rns_it_.coeff_it_.ptr_ += step_size_;
                return *this;
            }

            inline self_type operator++(int) noexcept
            {
                self_type result(*this);
                rns_it_.coeff_it_.ptr_ += step_size_;
                return result;
            }

            inline self_type &operator--() noexcept
            {
                rns_it_.coeff_it_.ptr_ -= step_size_;
                return *this;
            }

            inline self_type operator--(int) noexcept
            {
                self_type result(*this);
                rns_it_.coeff_it_.ptr_ -= step_size_;
                return result;
            }

            SEAL_NODISCARD inline bool operator==(const self_type &compare) const noexcept
            {
                return (rns_it_ == compare.rns_it_) && (coeff_modulus_count_ == compare.coeff_modulus_count_);
            }

            SEAL_NODISCARD inline bool operator!=(const self_type &compare) const noexcept
            {
                return !(*this == compare);
            }

            SEAL_NODISCARD inline operator const std::uint64_t *() const noexcept
            {
                return rns_it_;
            }

            SEAL_NODISCARD inline value_type operator->() const noexcept
            {
                return **this;
            }

            SEAL_NODISCARD inline std::size_t poly_modulus_degree() const noexcept
            {
                return rns_it_.step_size_;
            }

            SEAL_NODISCARD inline std::size_t coeff_modulus_count() const noexcept
            {
                return coeff_modulus_count_;
            }

        private:
            ConstRNSIterator rns_it_;

            std::size_t coeff_modulus_count_;

            std::size_t step_size_;
        };

        template <typename PtrT>
        class IteratorWrapper
        {
        public:
            using self_type = typename IteratorWrapper<PtrT>;
            using is_deref_to_iterator_type = std::false_type;

            // Standard iterator typedefs
            using value_type = PtrT;
            using pointer = void;
            using reference = const value_type &;
            using iterator_category = std::bidirectional_iterator_tag;
            using difference_type = std::ptrdiff_t;

            IteratorWrapper() : ptr_(nullptr)
            {}

            IteratorWrapper(value_type ptr) : ptr_(ptr)
            {}

            IteratorWrapper(const self_type &copy) = default;

            self_type &operator=(const self_type &assign) = default;

            IteratorWrapper(self_type &&source) = default;

            self_type &operator=(self_type &&assign) = default;

            SEAL_NODISCARD inline reference operator*() const noexcept
            {
                return ptr_;
            }

            inline self_type &operator++() noexcept
            {
                ptr_++;
                return *this;
            }

            inline self_type operator++(int) noexcept
            {
                self_type result(ptr_);
                ptr_++;
                return result;
            }

            inline self_type &operator--() noexcept
            {
                ptr_--;
                return *this;
            }

            inline self_type operator--(int) noexcept
            {
                self_type result(ptr_);
                ptr_--;
                return result;
            }

            SEAL_NODISCARD inline bool operator==(const self_type &compare) const noexcept
            {
                return (ptr_ == compare.ptr_);
            }

            SEAL_NODISCARD inline bool operator!=(const self_type &compare) const noexcept
            {
                return !(*this == compare);
            }

            SEAL_NODISCARD inline operator value_type *() const noexcept
            {
                return ptr_;
            }

            SEAL_NODISCARD inline value_type operator->() const noexcept
            {
                return **this;
            }

        private:
            value_type ptr_;
        };

        template <typename BidirIt>
        class ReverseIterator : public BidirIt
        {
        public:
            using self_type = ReverseIterator<BidirIt>;

            ReverseIterator() : BidirIt()
            {}

            ReverseIterator(const BidirIt &copy) : BidirIt(copy)
            {}

            ReverseIterator(BidirIt &&source) : BidirIt(source)
            {}

            ReverseIterator(const self_type &copy) = default;

            self_type &operator=(const self_type &assign) = default;

            ReverseIterator(self_type &&source) = default;

            self_type &operator=(self_type &&assign) = default;

            inline self_type &operator++() noexcept
            {
                BidirIt::operator--();
                return *this;
            }

            inline self_type operator++(int) noexcept
            {
                self_type result(*this);
                BidirIt::operator--();
                return result;
            }

            inline self_type &operator--() noexcept
            {
                BidirIt::operator++();
                return *this;
            }

            inline self_type operator--(int) noexcept
            {
                self_type result(*this);
                BidirIt::operator++();
                return result;
            }
        };

        template <typename It1, typename It2>
        class IteratorTuple2
        {
        public:
            using value_type_1 = std::conditional_t<
                It1::is_deref_to_iterator_type::value, typename std::iterator_traits<It1>::value_type,
                IteratorWrapper<typename std::iterator_traits<It1>::value_type>>;
            using value_type_2 = std::conditional_t<
                It2::is_deref_to_iterator_type::value, typename std::iterator_traits<It2>::value_type,
                IteratorWrapper<typename std::iterator_traits<It2>::value_type>>;

            using is_deref_to_iterator_type = std::conditional_t<
                It1::is_deref_to_iterator_type::value && It2::is_deref_to_iterator_type::value, std::true_type,
                std::false_type>;

            using self_type = IteratorTuple2<It1, It2>;
            using value_type = IteratorTuple2<value_type_1, value_type_2>;
            using pointer = void;
            using reference = void;

            using iterator_category = std::bidirectional_iterator_tag;
            using difference_type = std::ptrdiff_t;

            IteratorTuple2(const It1 &it1, const It2 &it2) : it1_(it1), it2_(it2)
            {}

            IteratorTuple2(const self_type &copy) = default;

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

        template <typename It1, typename It2, typename It3>
        class IteratorTuple3
        {
        public:
            using value_type_1 = std::conditional_t<
                It1::is_deref_to_iterator_type::value, typename std::iterator_traits<It1>::value_type,
                IteratorWrapper<typename std::iterator_traits<It1>::value_type>>;
            using value_type_2 = std::conditional_t<
                It2::is_deref_to_iterator_type::value, typename std::iterator_traits<It2>::value_type,
                IteratorWrapper<typename std::iterator_traits<It2>::value_type>>;
            using value_type_3 = std::conditional_t<
                It3::is_deref_to_iterator_type::value, typename std::iterator_traits<It3>::value_type,
                IteratorWrapper<typename std::iterator_traits<It3>::value_type>>;

            using is_deref_to_iterator_type = std::conditional_t<
                It1::is_deref_to_iterator_type::value && It2::is_deref_to_iterator_type::value &&
                    It3::is_deref_to_iterator_type::value,
                std::true_type, std::false_type>;

            using self_type = IteratorTuple3<It1, It2, It3>;
            using value_type = IteratorTuple3<value_type_1, value_type_2, value_type_3>;
            using pointer = void;
            using reference = void;

            using iterator_category = std::bidirectional_iterator_tag;
            using difference_type = std::ptrdiff_t;

            IteratorTuple3(const It1 &it1, const It2 &it2, const It3 &it3) : it1_(it1), it2_(it2), it3_(it3)
            {}

            IteratorTuple3(const self_type &copy) = default;

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

        template <typename It1, typename It2, typename It3, typename It4>
        class IteratorTuple4
        {
        public:
            using value_type_1 = std::conditional_t<
                It1::is_deref_to_iterator_type::value, typename std::iterator_traits<It1>::value_type,
                IteratorWrapper<typename std::iterator_traits<It1>::value_type>>;
            using value_type_2 = std::conditional_t<
                It2::is_deref_to_iterator_type::value, typename std::iterator_traits<It2>::value_type,
                IteratorWrapper<typename std::iterator_traits<It2>::value_type>>;
            using value_type_3 = std::conditional_t<
                It3::is_deref_to_iterator_type::value, typename std::iterator_traits<It3>::value_type,
                IteratorWrapper<typename std::iterator_traits<It3>::value_type>>;
            using value_type_4 = std::conditional_t<
                It4::is_deref_to_iterator_type::value, typename std::iterator_traits<It4>::value_type,
                IteratorWrapper<typename std::iterator_traits<It4>::value_type>>;

            using is_deref_to_iterator_type = std::conditional_t<
                It1::is_deref_to_iterator_type::value && It2::is_deref_to_iterator_type::value &&
                    It3::is_deref_to_iterator_type::value && It4::is_deref_to_iterator_type::value,
                std::true_type, std::false_type>;

            using self_type = IteratorTuple4<It1, It2, It3, It4>;
            using value_type = IteratorTuple4<value_type_1, value_type_2, value_type_3, value_type_4>;
            using pointer = void;
            using reference = void;

            using iterator_category = std::bidirectional_iterator_tag;
            using difference_type = std::ptrdiff_t;

            IteratorTuple4(const It1 &it1, const It2 &it2, const It3 &it3, const It4 &it4)
                : it1_(it1), it2_(it2), it3_(it3), it4_(it4)
            {}

            IteratorTuple4(const self_type &copy) = default;

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
    } // namespace util
} // namespace seal
