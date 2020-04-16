// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#pragma once

#include "seal/ciphertext.h"
#include "seal/plaintext.h"
#include "seal/util/common.h"
#include "seal/util/defines.h"
#include "seal/util/pointer.h"
#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <iterator>
#include <type_traits>
#include <utility>
#include <vector>

namespace seal
{
    namespace util
    {
        /*
        In this file we define a set of custom iterator classes ("SEAL iterators") that are used throughout Microsoft
        SEAL for easier iteration over ciphertext polynomials, their RNS components, and the coefficients in the RNS
        components. All SEAL iterators satisfy the C++ LegacyBidirectionalIterator requirements. Please note that they
        are *not* random access iterators. The SEAL iterators are very helpful when used with std::for_each_n in C++17.
        For C++14 compilers we have defined our own implementation of for_each_n below.

        The SEAL iterator classes behave as illustrated by the following diagram:

        +-------------------+
        |    Pointer & Size |  Construct  +---------------------+
        | or Ciphertext     +------------>+ (Const)PolyIterator |  Iterates over RNS polynomials in a ciphertext
        +-------------------+             +---------------------+  (coeff_modulus_count-many RNS components)
                                                    |
                                                    |
                                                    | Dereference
                                                    |
                                                    |
                                                    v
         +----------------+  Construct   +--------------------+
         | Pointer & Size +------------->+ (Const)RNSIterator |  Iterates over RNS components in an RNS polynomial
         +----------------+              +--------------------+  (poly_modulus_degree-many coefficients)
                                                    |
                                                    |
                                                    | Dereference
                                                    |
                                                    |
                                                    v
        +----------------+  Construct  +----------------------+
        | Pointer & Size +------------>+ (Const)CoeffIterator |  Iterates over coefficients (std::uint64_t) in a single
        +----------------+             +----------------------+  RNS polynomial component
                                                    |
                                                    |
                                                    | Dereference
                                                    |
                                                    |
                                                    v
                                       +------------------------+  Construct  +-----------------------+
                                       | (const) std::uint64_t* +------------>+ IteratorWrapper<PtrT> | Simple wrapper
                                       +------------------------+             +-----------------------+ for raw pointers
                                                                                ^      |
                            +---------+  Construct                              |      |
                            | MyType* +-----------------------------------------+      | Dereference
                            +---------+                                                |
                                                                                       |
                                                                                       v
                                                                                   +------+
                                                                                   | PtrT |  Unusual dereference to PtrT
                                                                                   +------+

        In addition to the types above, we define a ReverseIterator<SEALIter> that reverses the direction of iteration.

        An extremely useful template class is the (variadic) IteratorTuple<...> that allows multiple SEAL iterators to
        be zipped together. The IteratorTuple is itself a SEAL iterator and nested IteratorTuple instances are used
        commonly in the library. One critically important aspect of the IteratorTuple is that dereferencing yields
        another valid IteratorTuple, with each component dereferenced individually. When one of the components is not
        immediately dereferenceable to a SEAL iterator (but instead to a raw pointer), the result is wrapped inside an
        IteratorWrapper object to produce a valid tuple of SEAL iterators. As a curiosity, an IteratorTuple wrapping an
        IteratorWrapper<PtrT> can be dereferenced indefinitely, always yielding the same IteratorTuple. The individual
        components of an IteratorTuple can be accessed with the seal::util::get<i>(...) functions. The behavior of
        IteratorTuple is summarized in the following diagram:

                  +---------------------------------------------------------+
                  | IteratorTuple<PolyIterator, RNSIterator, CoeffIterator> |
                  +-----------------------------+---------------------------+
                                                |
                                                |
                                                | Dereference
                                                |
                                                |
                                                v
        +---------------------------------------+------------------------------------+
        | IteratorTuple<RNSIterator, CoeffIterator, IteratorWrapper<std::uint64_t*>> |
        +-----------------+---------------------+----------------------+-------------+
                          |                     |                      |
                          |                     |                      |
                          | get<0>              | get<1>               | get<2>
                          |                     |                      |
                          |                     |                      |
                          v                     v                      v
                   +------+------+      +-------+-------+   +----------+----------------------+
                   | RNSIterator |      | CoeffIterator |   | IteratorWrapper<std::uint64_t*> |
                   +-------------+      +---------------+   +---------------------------------+

        Each SEAL iterator class defines a type called value_type_is_seal_iterator_type, which is equal to either
        std::true_type or std::false_type, and signals whether instances of that particular SEAL iterator class, when
        dereferenced, produce an instance of another SEAL iterator class. For example, CoeffIterator dereferences to
        a raw pointer, so CoeffIterator::value_type_is_seal_iterator_type is equal to std::false_type. This type is
        used mainly internally by the SEAL iterators and is unlikely to be useful elsewhere.

        As an example, the following snippet from Evaluator::negate_inplace iterates over the polynomials in an input
        ciphertext, and for each polynomial iterates over the RNS components, and for each RNS component negates the
        polynomial coefficients modulo a SmallModulus element corresponding to the RNS component:

                for_each_n(PolyIterator(encrypted), encrypted.size(), [&](auto I) {
                    for_each_n(
                        IteratorTuple<RNSIterator, IteratorWrapper<const SmallModulus *>>(I, coeff_modulus),
                        coeff_modulus_count,
                        [&](auto J) { negate_poly_coeffmod(get<0>(J), coeff_count, **get<1>(J), get<0>(J)); });
                });

        Here coeff_modulus is a std::vector<SmallModulus>, and IteratorWrapper<const SmallModulus *> was constructed
        directly from it. IteratorWrapper provides a similar constructor from a SEAL Pointer type. Note also how we had
        to dereference get<1>(J) twice in the innermost lambda function to access the value (SmallNTTTables). This is
        because get<1>(J) is itself an IteratorWrapper<const SmallNTTTables *> as explained above; it dereferences to a
        raw pointer to SmallNTTTables, which must be dereferenced to access the value.

        There are two important coding conventions in the above code snippet that are to be observed:

            1. Always explicitly write the class template arguments. This is important for C++14 compatibility, and can
               help avoid confusing bugs resulting from mistakes in iterator types in nested for_each_n calls.
            2. Use I, J, K, ... for the lambda function parameters representing SEAL iterators. This is compact and
               makes it very clear that the objects in question are SEAL iterators since such variable names should not
               be used in SEAL in any other context.
        */
#ifndef SEAL_USE_STD_FOR_EACH_N
        // C++14 does not have for_each_n so we define a custom version here.
        template <typename ForwardIt, typename Size, typename Func>
        ForwardIt for_each_n(ForwardIt first, Size size, Func func)
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
            using value_type_is_seal_iterator_type = std::false_type;

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
            using value_type_is_seal_iterator_type = std::false_type;

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
            using value_type_is_seal_iterator_type = std::true_type;

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
            using value_type_is_seal_iterator_type = std::true_type;

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
            using value_type_is_seal_iterator_type = std::true_type;

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
            using value_type_is_seal_iterator_type = std::true_type;

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

            ConstPolyIterator(Ciphertext &ct) : self_type(ct.data(), ct.poly_modulus_degree(), ct.coeff_modulus_count())
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
            using self_type = IteratorWrapper<PtrT>;
            using value_type_is_seal_iterator_type = std::false_type;

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

            IteratorWrapper(const std::vector<std::remove_cv_t<std::remove_pointer_t<PtrT>>> &arr)
                : IteratorWrapper(arr.data())
            {}

            IteratorWrapper(const Pointer<std::remove_cv_t<std::remove_pointer_t<PtrT>>> &arr)
                : IteratorWrapper(arr.get())
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

        template <typename SEALIter>
        class ReverseIterator : public SEALIter
        {
        public:
            using self_type = ReverseIterator<SEALIter>;

            ReverseIterator() : SEALIter()
            {}

            ReverseIterator(const SEALIter &copy) : SEALIter(copy)
            {}

            ReverseIterator(SEALIter &&source) : SEALIter(source)
            {}

            ReverseIterator(const self_type &copy) = default;

            self_type &operator=(const self_type &assign) = default;

            ReverseIterator(self_type &&source) = default;

            self_type &operator=(self_type &&assign) = default;

            inline self_type &operator++() noexcept
            {
                SEALIter::operator--();
                return *this;
            }

            inline self_type operator++(int) noexcept
            {
                self_type result(*this);
                SEALIter::operator--();
                return result;
            }

            inline self_type &operator--() noexcept
            {
                SEALIter::operator++();
                return *this;
            }

            inline self_type operator--(int) noexcept
            {
                self_type result(*this);
                SEALIter::operator++();
                return result;
            }
        };

        template <typename... SEALIters>
        class IteratorTuple;

        template <typename SEALIter, typename... Rest>
        class IteratorTuple<SEALIter, Rest...>
        {
        public:
            using self_type = IteratorTuple<SEALIter, Rest...>;
            using value_type_is_seal_iterator_type = std::true_type;

            // Standard iterator typedefs
            using value_type_first = std::conditional_t<
                SEALIter::value_type_is_seal_iterator_type::value, typename std::iterator_traits<SEALIter>::value_type,
                IteratorWrapper<typename std::iterator_traits<SEALIter>::value_type>>;
            using value_type =
                IteratorTuple<value_type_first, typename std::iterator_traits<IteratorTuple<Rest>>::value_type...>;
            using pointer = void;
            using reference = const value_type &;
            using iterator_category = std::bidirectional_iterator_tag;
            using difference_type = std::ptrdiff_t;

            IteratorTuple() = default;

            IteratorTuple(SEALIter first, IteratorTuple<Rest...> rest) : first_(first), rest_(rest){};

            IteratorTuple(SEALIter first, Rest... rest) : first_(first), rest_(rest...)
            {}

            IteratorTuple(const self_type &copy) = default;

            self_type &operator=(const self_type &assign) = default;

            IteratorTuple(self_type &&source) = default;

            self_type &operator=(self_type &&assign) = default;

            SEAL_NODISCARD inline value_type operator*() const noexcept
            {
                return { *first_, *rest_ };
            }

            inline self_type &operator++() noexcept
            {
                first_++;
                rest_++;
                return *this;
            }

            inline self_type operator++(int) noexcept
            {
                self_type result(*this);
                first_++;
                rest_++;
                return result;
            }

            inline self_type &operator--() noexcept
            {
                first_--;
                rest_--;
                return *this;
            }

            inline self_type operator--(int) noexcept
            {
                self_type result(*this);
                first_--;
                rest_--;
                return result;
            }

            SEAL_NODISCARD inline bool operator==(const self_type &compare) const noexcept
            {
                return (first_ == compare.first_) && (rest_ == compare.rest_);
            }

            SEAL_NODISCARD inline bool operator!=(const self_type &compare) const noexcept
            {
                return !(*this == compare);
            }

            SEAL_NODISCARD inline value_type operator->() const noexcept
            {
                return **this;
            }

            SEAL_NODISCARD inline const SEALIter &first() const noexcept
            {
                return first_;
            }

            SEAL_NODISCARD inline const IteratorTuple<Rest...> &rest() const noexcept
            {
                return rest_;
            }

        private:
            SEALIter first_;

            IteratorTuple<Rest...> rest_;
        };

        template <typename SEALIter>
        class IteratorTuple<SEALIter>
        {
        public:
            using self_type = IteratorTuple<SEALIter>;
            using value_type_is_seal_iterator_type = std::true_type;

            // Standard iterator typedefs
            using value_type = std::conditional_t<
                SEALIter::value_type_is_seal_iterator_type::value, typename std::iterator_traits<SEALIter>::value_type,
                IteratorWrapper<typename std::iterator_traits<SEALIter>::value_type>>;
            using pointer = void;
            using reference = const value_type &;
            using iterator_category = std::bidirectional_iterator_tag;
            using difference_type = std::ptrdiff_t;

            IteratorTuple(){};

            IteratorTuple(SEALIter first) : first_(first)
            {}

            IteratorTuple(const self_type &copy) = default;

            self_type &operator=(const self_type &assign) = default;

            IteratorTuple(self_type &&source) = default;

            self_type &operator=(self_type &&assign) = default;

            SEAL_NODISCARD inline value_type operator*() const noexcept
            {
                return *first_;
            }

            inline self_type &operator++() noexcept
            {
                first_++;
                return *this;
            }

            inline self_type operator++(int) noexcept
            {
                self_type result(*this);
                first_++;
                return result;
            }

            inline self_type &operator--() noexcept
            {
                first_--;
                return *this;
            }

            inline self_type operator--(int) noexcept
            {
                self_type result(*this);
                first_--;
                return result;
            }

            SEAL_NODISCARD inline bool operator==(const self_type &compare) const noexcept
            {
                return first_ == compare.first_;
            }

            SEAL_NODISCARD inline bool operator!=(const self_type &compare) const noexcept
            {
                return !(*this == compare);
            }

            SEAL_NODISCARD inline value_type operator->() const noexcept
            {
                return **this;
            }

            SEAL_NODISCARD inline const SEALIter &first() const noexcept
            {
                return first_;
            }

        private:
            SEALIter first_;
        };

        namespace iterator_tuple_internal
        {
            template <std::size_t N>
            struct GetHelperStruct
            {
                template <typename SEALIter, typename... Rest>
                static auto apply(const IteratorTuple<SEALIter, Rest...> &it)
                {
                    return GetHelperStruct<N - 1>::apply(it.rest());
                }
            };

            template <>
            struct GetHelperStruct<0>
            {
                template <typename SEALIter, typename... Rest>
                static auto apply(const IteratorTuple<SEALIter, Rest...> &it)
                {
                    return it.first();
                }
            };
        }; // namespace iterator_tuple_internal

        template <std::size_t N, typename... SEALIters>
        auto get(const IteratorTuple<SEALIters...> &it)
        {
            return iterator_tuple_internal::GetHelperStruct<N>::apply(it);
        }
    } // namespace util
} // namespace seal
