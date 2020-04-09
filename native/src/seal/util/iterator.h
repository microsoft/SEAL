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
        class CoeffIterator;

        class ConstCoeffIterator;

        class RNSIterator;

        class ConstRNSIterator;

        class PolyIterator;

        class ConstPolyIterator;

        class CoeffIterator
        {
        public:
            using self_type = CoeffIterator;
            using value_type = std::uint64_t *;
            using pointer = void;
            using reference = void;

            using iterator_category = std::bidirectional_iterator_tag;
            using difference_type = std::ptrdiff_t;

            using is_deref_to_iterator_type = std::false_type;

            CoeffIterator(value_type ptr) : ptr_(ptr)
            {}

            CoeffIterator(const CoeffIterator &copy) = default;

            CoeffIterator &operator=(const CoeffIterator &assign) = default;

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

        private:
            value_type ptr_;
        };

        class ConstCoeffIterator
        {
        public:
            using self_type = ConstCoeffIterator;
            using value_type = const std::uint64_t *;
            using pointer = void;
            using reference = void;

            using iterator_category = std::bidirectional_iterator_tag;
            using difference_type = std::ptrdiff_t;

            using is_deref_to_iterator_type = std::false_type;

            ConstCoeffIterator(value_type ptr) : ptr_(ptr)
            {}

            ConstCoeffIterator(const ConstCoeffIterator &copy) = default;

            ConstCoeffIterator &operator=(const ConstCoeffIterator &assign) = default;

            ConstCoeffIterator(const CoeffIterator &copy) : ptr_(copy.ptr())
            {}

            ConstCoeffIterator &operator=(const CoeffIterator &assign)
            {
                ptr_ = assign.ptr();
                return *this;
            }

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

        private:
            value_type ptr_;
        };

        class RNSIterator
        {
        public:
            using self_type = RNSIterator;
            using value_type = CoeffIterator;
            using pointer = void;
            using reference = void;

            using iterator_category = std::bidirectional_iterator_tag;
            using difference_type = std::ptrdiff_t;

            using is_deref_to_iterator_type = std::true_type;

            RNSIterator(std::uint64_t *ptr, std::size_t poly_modulus_degree)
                : ptr_(ptr), step_size_(poly_modulus_degree)
            {}

            RNSIterator(const RNSIterator &copy) = default;

            RNSIterator &operator=(const RNSIterator &assign) = default;

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

        class ConstRNSIterator
        {
        public:
            using self_type = ConstRNSIterator;
            using value_type = ConstCoeffIterator;
            using pointer = void;
            using reference = void;

            using iterator_category = std::bidirectional_iterator_tag;
            using difference_type = std::ptrdiff_t;

            using is_deref_to_iterator_type = std::true_type;

            ConstRNSIterator(const std::uint64_t *ptr, std::size_t poly_modulus_degree)
                : ptr_(ptr), step_size_(poly_modulus_degree)
            {}

            ConstRNSIterator(const ConstRNSIterator &copy) = default;

            ConstRNSIterator &operator=(const ConstRNSIterator &assign) = default;

            ConstRNSIterator(const RNSIterator &copy) : ptr_(copy.ptr()), step_size_(copy.poly_modulus_degree())
            {}

            ConstRNSIterator &operator=(const RNSIterator &assign)
            {
                ptr_ = assign.ptr();
                step_size_ = assign.poly_modulus_degree();
                return *this;
            }

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

        class PolyIterator
        {
        public:
            using self_type = PolyIterator;
            using value_type = RNSIterator;
            using pointer = void;
            using reference = void;

            using iterator_category = std::bidirectional_iterator_tag;
            using difference_type = std::ptrdiff_t;

            using is_deref_to_iterator_type = std::true_type;

            PolyIterator(std::uint64_t *ptr, std::size_t poly_modulus_degree, std::size_t coeff_modulus_count)
                : ptr_(ptr), step_size_(mul_safe(poly_modulus_degree, coeff_modulus_count)),
                  poly_modulus_degree_(poly_modulus_degree), coeff_modulus_count_(coeff_modulus_count)
            {}

            PolyIterator(Ciphertext &ct) : PolyIterator(ct.data(), ct.poly_modulus_degree(), ct.coeff_modulus_count())
            {}

            PolyIterator(const PolyIterator &copy) = default;

            PolyIterator &operator=(const PolyIterator &assign) = default;

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

        class ConstPolyIterator
        {
        public:
            using self_type = ConstPolyIterator;
            using value_type = ConstRNSIterator;
            using pointer = void;
            using reference = void;

            using iterator_category = std::bidirectional_iterator_tag;
            using difference_type = std::ptrdiff_t;

            using is_deref_to_iterator_type = std::true_type;

            ConstPolyIterator(
                const std::uint64_t *ptr, std::size_t poly_modulus_degree, std::size_t coeff_modulus_count)
                : ptr_(ptr), step_size_(mul_safe(poly_modulus_degree, coeff_modulus_count)),
                  poly_modulus_degree_(poly_modulus_degree), coeff_modulus_count_(coeff_modulus_count)
            {}

            ConstPolyIterator(const Ciphertext &ct)
                : ConstPolyIterator(ct.data(), ct.poly_modulus_degree(), ct.coeff_modulus_count())
            {}

            ConstPolyIterator(const ConstPolyIterator &copy) = default;

            ConstPolyIterator &operator=(const ConstPolyIterator &assign) = default;

            ConstPolyIterator(const PolyIterator &copy)
                : ptr_(copy.ptr()), step_size_(copy.poly_modulus_degree() * copy.coeff_modulus_count()),
                  poly_modulus_degree_(copy.poly_modulus_degree()), coeff_modulus_count_(copy.coeff_modulus_count())
            {}

            ConstPolyIterator &operator=(const PolyIterator &assign)
            {
                ptr_ = assign.ptr();
                step_size_ = assign.poly_modulus_degree() * assign.coeff_modulus_count();
                poly_modulus_degree_ = assign.poly_modulus_degree();
                coeff_modulus_count_ = assign.coeff_modulus_count();
                return *this;
            }

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
        class IteratorWrapper
        {
        public:
            using self_type = IteratorWrapper<PtrT>;
            using value_type = PtrT;
            using pointer = void;
            using reference = void;

            using iterator_category = std::bidirectional_iterator_tag;
            using difference_type = std::ptrdiff_t;

            using is_deref_to_iterator_type = std::false_type;

            IteratorWrapper(PtrT ptr) : ptr_(ptr)
            {}

            IteratorWrapper(const IteratorWrapper &copy) = default;

            IteratorWrapper &operator=(const IteratorWrapper &assign) = default;

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

        template <class It>
        class ReverseIterator : public It
        {
        public:
            using self_type = ReverseIterator<It>;

            ReverseIterator(const It &copy) : It(copy)
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

        template <class It1, class It2>
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

        template <class It1, class It2, class It3>
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

        template <class It1, class It2, class It3, class It4>
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
