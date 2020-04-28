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
#include <stdexcept>
#include <type_traits>
#include <utility>
#include <vector>

namespace seal
{
    namespace util
    {
        /**
        In this file we define a set of custom iterator classes ("SEAL iterators") that are used throughout Microsoft
        SEAL for easier iteration over ciphertext polynomials, their RNS components, and the coefficients in the RNS
        components. All SEAL iterators satisfy the C++ LegacyBidirectionalIterator requirements. Please note that they
        are *not* random access iterators. The SEAL iterators are very helpful when used with std::for_each_n in C++17.
        For C++14 compilers we have defined our own implementation of for_each_n below.

        The SEAL iterator classes behave as illustrated by the following diagram:

        +-------------------+
        |    Pointer & Size |  Construct  +-----------------+
        | or Ciphertext     +------------>+ (Const)PolyIter |  Iterates over RNS polynomials in a ciphertext
        +-------------------+             +-----------------+  (coeff_modulus_size-many RNS components)
                                                   |
                                                   |
                                                   | Dereference
                                                   |
                                                   |
                                                   v
           +----------------+  Construct   +----------------+
           | Pointer & Size +------------->+ (Const)RNSIter |  Iterates over RNS components in an RNS polynomial
           +----------------+              +----------------+  (poly_modulus_degree-many coefficients)
                                                   |
                                                   |
                                                   | Dereference
                                                   |
                                                   |
                                                   v
          +----------------+  Construct  +------------------+
          | Pointer & Size +------------>+ (Const)CoeffIter |  Iterates over coefficients (std::uint64_t) in a single
          +----------------+             +------------------+  RNS polynomial component
                                                   |
                                                   |
                                                   | Dereference
                                                   |
                                                   |
                                                   v
                                       +------------------------+  Construct  +---------------+
                                       | (const) std::uint64_t* +------------>+ PtrIter<PtrT> |  Simple wrapper
                                       +------------------------+             +---------------+  for raw pointers
                                                                                ^     |
                            +---------+  Construct                              |     |
                            | MyType* +-----------------------------------------+     | Dereference
                            +---------+                                               |
                                                                                      |
                                                                                      v
                                                                                  +------+
                                                                                  | PtrT |  Unusual dereference to PtrT
                                                                                  +------+

        In addition to the types above, we define a ReverseIter<SEALIter> that reverses the direction of iteration.
        However, ReverseIter<SEALIter> dereferences to the same type as SEALIter: for example, dereferencing
        ReverseIter<RNSIter> results in CoeffIter, not ReverseIter<CoeffIter>.

        An extremely useful template class is the (variadic) IterTuple<...> that allows multiple SEAL iterators to be
        zipped together. An IterTuple is itself a SEAL iterator and nested IterTuple types are used commonly in the
        library. Dereferencing an IterTuple always yields another valid IterTuple, with each component dereferenced
        individually. An IterTuple can in fact also hold raw pointers as its components, but such an IterTuple cannot
        be dereferenced. Instead, the raw pointer must be first wrapped into a PtrIter object. Dereferencing a PtrIter
        yields the wrapped raw pointer; hence, an IterTuple holding PtrIter objects can be dereferenced only once.

        The individual components of an IterTuple can be accessed with the seal::util::get<i>(...) functions. The
        behavior of IterTuple is summarized in the following diagram:

                 +-----------------------------------------+
                 | IterTuple<PolyIter, RNSIter, CoeffIter> |
                 +--------------------+--------------------+
                                      |
                                      |
                                      | Dereference
                                      |
                                      |
                                      v
        +-----------------------------+--------------------------+
        | IterTuple<RNSIter, CoeffIter, PtrIter<std::uint64_t*>> |
        +------+----------------------+----------------------+---+
               |                      |                      |
               |                      |                      |
               | get<0>               | get<1>               | get<2>
               |                      |                      |
               |                      |                      |
               v                      v                      v
        +------+------+       +-------+-------+      +-------------------------+
        |   RNSIter   |       |   CoeffIter   |      | PtrIter<std::uint64_t*> |
        +-------------+       +---------------+      +-------------------------+

        As an example, the following snippet from Evaluator::negate_inplace iterates over the polynomials in an input
        ciphertext, and for each polynomial iterates over the RNS components, and for each RNS component negates the
        polynomial coefficients modulo a Modulus element corresponding to the RNS component:

        for_each_n(PolyIter(encrypted), encrypted_size, [&](auto I) {
            for_each_n(
                IterTuple<RNSIter, PtrIter<const Modulus *>>(I, coeff_modulus), coeff_modulus_size,
                [&](auto J) { negate_poly_coeffmod(get<0>(J), coeff_count, *get<1>(J), get<0>(J)); });
        });

        Here coeff_modulus is a std::vector<Modulus>, and PtrIter<const Modulus *> was constructed directly
        from it. PtrIter provides a similar constructor from a seal::util::Pointer type. Note also how we had to
        dereference get<1>(J) in the innermost lambda function to access the value (NTTTables). This is because
        get<1>(J) is const NTTTables *, as was discussed above.

        There are two important coding conventions in the above code snippet that are to be observed:

            1. Always explicitly write the class template arguments. This is important for C++14 compatibility, and can
               help avoid confusing bugs resulting from mistakes in iterator types in nested for_each_n calls.
            2. Use I, J, K, ... for the lambda function parameters representing SEAL iterators. This is compact and
               makes it very clear that the objects in question are SEAL iterators since such variable names should not
               be used in SEAL in any other context.
            3. Always pass SEAL iterators by value to the lambda function.

        It is not unusual to have multiple nested for_each_n calls operating on multiple/nested IterTuple objects.
        It can become very difficult to keep track of what exactly the different iterators are pointing to, and what
        their types are (the above convention of using I, J, K, ... does not reveal the type). Hence we sometimes
        annotate the code and check that the types match what we expect them to be using the SEAL_ASSERT_TYPE macro.
        For example, the above code snippet would be annotated as follows:

        for_each_n(PolyIter(encrypted), encrypted_size, [&](auto I) {
            SEAL_ASSERT_TYPE(I, RNSIter, "encrypted");
            for_each_n(
                IterTuple<RNSIter, PtrIter<const Modulus *>>(I, coeff_modulus), coeff_modulus_size, [&](auto J) {
                    SEAL_ASSERT_TYPE(get<0>(J), CoeffIter, "encrypted");
                    SEAL_ASSERT_TYPE(get<1>(J), const Modulus *, "coeff_modulus");
                    negate_poly_coeffmod(get<0>(J), coeff_count, *get<1>(J), get<0>(J));
                });
        });

        Note how SEAL_ASSERT_TYPE makes it explicit what type the different iterators are, and includes a string that
        describes what object is iterated over. We use this convention in particularly complex functions to make the
        code easier to follow and less error-prone. The code will fail to compile if the type of the object in the first
        parameter does not match the type in the second parameter of the macro.

        In the future we hope to use the parallel version of std::for_each_n, introduced in C++17. For this to work,
        be mindful of how you use heap allocations in the lambda functions. Specifically, in heavy lambda functions it
        is probably a good idea to call seal::util::allocate inside the lambda function for any allocations needed,
        rather than using allocations captured from outside the lambda function.
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
        class CoeffIter;

        class ConstCoeffIter;

        class RNSIter;

        class ConstRNSIter;

        class PolyIter;

        class ConstPolyIter;

        class CoeffIter
        {
        public:
            friend class RNSIter;
            friend class PolyIter;

            using self_type = CoeffIter;

            // Standard iterator typedefs
            using value_type = std::uint64_t *;
            using pointer = void;
            using reference = const value_type &;
            using iterator_category = std::random_access_iterator_tag;
            using difference_type = std::ptrdiff_t;

            CoeffIter() : ptr_(nullptr)
            {}

            CoeffIter(value_type ptr) : ptr_(ptr)
            {}

            CoeffIter(const self_type &copy) = default;

            self_type &operator=(const self_type &assign) = default;

            CoeffIter(self_type &&source) = default;

            self_type &operator=(self_type &&assign) = default;

            SEAL_NODISCARD inline reference operator*() const noexcept
            {
                return ptr_;
            }

            template <typename SizeT>
            SEAL_NODISCARD inline value_type operator[](SizeT n) const noexcept
            {
                return ptr_ + n;
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

            template <typename SizeT>
            inline self_type &operator+=(SizeT n) noexcept
            {
                ptr_ += n;
                return *this;
            }

            template <typename SizeT>
            SEAL_NODISCARD inline self_type operator+(SizeT n) const noexcept
            {
                return ptr_ + n;
            }

            template <typename SizeT>
            inline self_type &operator-=(SizeT n) noexcept
            {
                ptr_ -= n;
                return *this;
            }

            template <typename SizeT>
            SEAL_NODISCARD inline self_type operator-(SizeT n) const noexcept
            {
                return ptr_ - n;
            }

            SEAL_NODISCARD inline difference_type operator-(const self_type &b) const noexcept
            {
                return ptr_ - b.ptr_;
            }

            SEAL_NODISCARD inline bool operator==(const self_type &compare) const noexcept
            {
                return ptr_ == compare.ptr_;
            }

            SEAL_NODISCARD inline bool operator!=(const self_type &compare) const noexcept
            {
                return !(*this == compare);
            }

            SEAL_NODISCARD inline bool operator<(const self_type &compare) const noexcept
            {
                return ptr_ < compare.ptr_;
            }

            SEAL_NODISCARD inline bool operator>(const self_type &compare) const noexcept
            {
                return ptr_ > compare.ptr_;
            }

            SEAL_NODISCARD inline bool operator<=(const self_type &compare) const noexcept
            {
                return !(ptr_ > compare.ptr_);
            }

            SEAL_NODISCARD inline bool operator>=(const self_type &compare) const noexcept
            {
                return !(ptr_ < compare.ptr_);
            }

            SEAL_NODISCARD inline operator std::uint64_t *() const noexcept
            {
                return ptr_;
            }

            SEAL_NODISCARD explicit inline operator bool() const noexcept
            {
                return nullptr != ptr_;
            }

        private:
            value_type ptr_;
        };

        // Out-of-class definitions
        template <typename SizeT>
        SEAL_NODISCARD inline CoeffIter operator+(SizeT n, const CoeffIter &it) noexcept
        {
            return it + n;
        }

        class ConstCoeffIter
        {
        public:
            friend class ConstRNSIter;
            friend class ConstPolyIter;

            using self_type = ConstCoeffIter;

            // Standard iterator typedefs
            using value_type = const std::uint64_t *;
            using pointer = void;
            using reference = const value_type &;
            using iterator_category = std::random_access_iterator_tag;
            using difference_type = std::ptrdiff_t;

            ConstCoeffIter() : ptr_(nullptr)
            {}

            ConstCoeffIter(value_type ptr) : ptr_(ptr)
            {}

            ConstCoeffIter(const self_type &copy) = default;

            self_type &operator=(const self_type &assign) = default;

            ConstCoeffIter(self_type &&source) = default;

            self_type &operator=(self_type &&assign) = default;

            ConstCoeffIter(const CoeffIter &copy) : ptr_(static_cast<const std::uint64_t *>(copy))
            {}

            SEAL_NODISCARD inline reference operator*() const noexcept
            {
                return ptr_;
            }

            template <typename SizeT>
            SEAL_NODISCARD inline value_type operator[](SizeT n) const noexcept
            {
                return ptr_ + n;
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

            template <typename SizeT>
            inline self_type &operator+=(SizeT n) noexcept
            {
                ptr_ += n;
                return *this;
            }

            template <typename SizeT>
            SEAL_NODISCARD inline self_type operator+(SizeT n) const noexcept
            {
                return ptr_ + n;
            }

            template <typename SizeT>
            inline self_type &operator-=(SizeT n) noexcept
            {
                ptr_ -= n;
                return *this;
            }

            template <typename SizeT>
            SEAL_NODISCARD inline self_type operator-(SizeT n) const noexcept
            {
                return ptr_ - n;
            }

            SEAL_NODISCARD inline difference_type operator-(const self_type &b) const noexcept
            {
                return ptr_ - b.ptr_;
            }

            SEAL_NODISCARD inline bool operator==(const self_type &compare) const noexcept
            {
                return ptr_ == compare.ptr_;
            }

            SEAL_NODISCARD inline bool operator!=(const self_type &compare) const noexcept
            {
                return !(*this == compare);
            }

            SEAL_NODISCARD inline bool operator<(const self_type &compare) const noexcept
            {
                return ptr_ < compare.ptr_;
            }

            SEAL_NODISCARD inline bool operator>(const self_type &compare) const noexcept
            {
                return ptr_ > compare.ptr_;
            }

            SEAL_NODISCARD inline bool operator<=(const self_type &compare) const noexcept
            {
                return !(ptr_ > compare.ptr_);
            }

            SEAL_NODISCARD inline bool operator>=(const self_type &compare) const noexcept
            {
                return !(ptr_ < compare.ptr_);
            }

            SEAL_NODISCARD inline operator const std::uint64_t *() const noexcept
            {
                return ptr_;
            }

            SEAL_NODISCARD explicit inline operator bool() const noexcept
            {
                return nullptr != ptr_;
            }

        private:
            value_type ptr_;
        };

        // Out-of-class definitions
        template <typename SizeT>
        SEAL_NODISCARD inline ConstCoeffIter operator+(SizeT n, const ConstCoeffIter &it) noexcept
        {
            return it + n;
        }

        class RNSIter
        {
        public:
            friend class PolyIter;

            using self_type = RNSIter;

            // Standard iterator typedefs
            using value_type = CoeffIter;
            using pointer = void;
            using reference = const value_type &;
            using iterator_category = std::random_access_iterator_tag;
            using difference_type = std::ptrdiff_t;

            RNSIter() : coeff_it_(nullptr), step_size_(0)
            {}

            RNSIter(std::uint64_t *ptr, std::size_t poly_modulus_degree)
                : coeff_it_(ptr), step_size_(poly_modulus_degree)
            {}

            RNSIter(const self_type &copy) = default;

            self_type &operator=(const self_type &assign) = default;

            RNSIter(self_type &&source) = default;

            self_type &operator=(self_type &&assign) = default;

            SEAL_NODISCARD inline reference operator*() const noexcept
            {
                return coeff_it_;
            }

            template <typename SizeT>
            SEAL_NODISCARD inline value_type operator[](SizeT n) const noexcept
            {
                self_type result(*this);
                result += static_cast<difference_type>(n);
                return *result;
            }

            inline self_type &operator++() noexcept
            {
                coeff_it_ += static_cast<std::ptrdiff_t>(step_size_);
                return *this;
            }

            inline self_type operator++(int) noexcept
            {
                self_type result(*this);
                coeff_it_ += static_cast<std::ptrdiff_t>(step_size_);
                return result;
            }

            inline self_type &operator--() noexcept
            {
                coeff_it_ -= static_cast<std::ptrdiff_t>(step_size_);
                return *this;
            }

            inline self_type operator--(int) noexcept
            {
                self_type result(*this);
                coeff_it_ -= static_cast<std::ptrdiff_t>(step_size_);
                return result;
            }

            template <typename SizeT>
            inline self_type &operator+=(SizeT n) noexcept
            {
                coeff_it_ += n * static_cast<std::ptrdiff_t>(step_size_);
                return *this;
            }

            template <typename SizeT>
            SEAL_NODISCARD inline self_type operator+(SizeT n) const noexcept
            {
                self_type result(*this);
                result.coeff_it_ += static_cast<difference_type>(n) * static_cast<std::ptrdiff_t>(step_size_);
                return result;
            }

            template <typename SizeT>
            inline self_type &operator-=(SizeT n) noexcept
            {
                coeff_it_ -= static_cast<difference_type>(n) * static_cast<std::ptrdiff_t>(step_size_);
                return *this;
            }

            template <typename SizeT>
            SEAL_NODISCARD inline self_type operator-(SizeT n) const noexcept
            {
                return *this + (-static_cast<difference_type>(n));
            }

            SEAL_NODISCARD inline difference_type operator-(const self_type &b) const
            {
#ifdef SEAL_DEBUG
                if (!step_size_)
                {
                    throw std::logic_error("step_size cannot be zero");
                }
                if (step_size_ != b.step_size_)
                {
                    throw std::invalid_argument("incompatible iterators");
                }
#endif
                return (coeff_it_ - b.coeff_it_) / static_cast<std::ptrdiff_t>(step_size_);
            }

            SEAL_NODISCARD inline bool operator==(const self_type &compare) const noexcept
            {
                return coeff_it_ == compare.coeff_it_;
            }

            SEAL_NODISCARD inline bool operator!=(const self_type &compare) const noexcept
            {
                return !(*this == compare);
            }

            SEAL_NODISCARD inline bool operator<(const self_type &compare) const noexcept
            {
                return coeff_it_ < compare.coeff_it_;
            }

            SEAL_NODISCARD inline bool operator>(const self_type &compare) const noexcept
            {
                return coeff_it_ > compare.coeff_it_;
            }

            SEAL_NODISCARD inline bool operator<=(const self_type &compare) const noexcept
            {
                return !(coeff_it_ > compare.coeff_it_);
            }

            SEAL_NODISCARD inline bool operator>=(const self_type &compare) const noexcept
            {
                return !(coeff_it_ < compare.coeff_it_);
            }

            SEAL_NODISCARD inline operator std::uint64_t *() const noexcept
            {
                return static_cast<std::uint64_t *>(coeff_it_);
            }

            SEAL_NODISCARD explicit inline operator bool() const noexcept
            {
                return static_cast<bool>(coeff_it_);
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
            CoeffIter coeff_it_;

            std::size_t step_size_;
        };

        // Out-of-class definitions
        template <typename SizeT>
        SEAL_NODISCARD inline RNSIter operator+(SizeT n, RNSIter it) noexcept
        {
            return it + n;
        }

        class ConstRNSIter
        {
        public:
            friend class ConstPolyIter;

            using self_type = ConstRNSIter;

            // Standard iterator typedefs
            using value_type = ConstCoeffIter;
            using pointer = void;
            using reference = const value_type &;
            using iterator_category = std::bidirectional_iterator_tag;
            using difference_type = std::ptrdiff_t;

            ConstRNSIter() : coeff_it_(nullptr), step_size_(0)
            {}

            ConstRNSIter(const std::uint64_t *ptr, std::size_t poly_modulus_degree)
                : coeff_it_(ptr), step_size_(poly_modulus_degree)
            {}

            ConstRNSIter(const self_type &copy) = default;

            self_type &operator=(const self_type &assign) = default;

            ConstRNSIter(self_type &&source) = default;

            self_type &operator=(self_type &&assign) = default;

            ConstRNSIter(const RNSIter &copy)
                : coeff_it_(static_cast<const std::uint64_t *>(copy)), step_size_(copy.poly_modulus_degree())
            {}

            SEAL_NODISCARD inline reference operator*() const noexcept
            {
                return coeff_it_;
            }

            template <typename SizeT>
            SEAL_NODISCARD inline value_type operator[](SizeT n) const noexcept
            {
                self_type result(*this);
                result += static_cast<difference_type>(n);
                return *result;
            }

            inline self_type &operator++() noexcept
            {
                coeff_it_ += static_cast<std::ptrdiff_t>(step_size_);
                return *this;
            }

            inline self_type operator++(int) noexcept
            {
                self_type result(*this);
                coeff_it_ += static_cast<std::ptrdiff_t>(step_size_);
                return result;
            }

            inline self_type &operator--() noexcept
            {
                coeff_it_ -= static_cast<std::ptrdiff_t>(step_size_);
                return *this;
            }

            inline self_type operator--(int) noexcept
            {
                self_type result(*this);
                coeff_it_ -= static_cast<std::ptrdiff_t>(step_size_);
                return result;
            }

            template <typename SizeT>
            inline self_type &operator+=(SizeT n) noexcept
            {
                coeff_it_ += static_cast<difference_type>(n) * static_cast<std::ptrdiff_t>(step_size_);
                return *this;
            }

            template <typename SizeT>
            SEAL_NODISCARD inline self_type operator+(SizeT n) const noexcept
            {
                self_type result(*this);
                result.coeff_it_ += static_cast<difference_type>(n) * static_cast<std::ptrdiff_t>(step_size_);
                return result;
            }

            template <typename SizeT>
            inline self_type &operator-=(SizeT n) noexcept
            {
                coeff_it_ -= static_cast<difference_type>(n) * static_cast<std::ptrdiff_t>(step_size_);
                return *this;
            }

            template <typename SizeT>
            SEAL_NODISCARD inline self_type operator-(SizeT n) const noexcept
            {
                return *this + (-static_cast<difference_type>(n));
            }

            SEAL_NODISCARD inline difference_type operator-(const self_type &b) const
            {
#ifdef SEAL_DEBUG
                if (!step_size_)
                {
                    throw std::logic_error("step_size cannot be zero");
                }
                if (step_size_ != b.step_size_)
                {
                    throw std::invalid_argument("incompatible iterators");
                }
#endif
                return (coeff_it_ - b.coeff_it_) / static_cast<std::ptrdiff_t>(step_size_);
            }

            SEAL_NODISCARD inline bool operator==(const self_type &compare) const noexcept
            {
                return coeff_it_ == compare.coeff_it_;
            }

            SEAL_NODISCARD inline bool operator!=(const self_type &compare) const noexcept
            {
                return !(*this == compare);
            }

            SEAL_NODISCARD inline bool operator<(const self_type &compare) const noexcept
            {
                return coeff_it_ < compare.coeff_it_;
            }

            SEAL_NODISCARD inline bool operator>(const self_type &compare) const noexcept
            {
                return coeff_it_ > compare.coeff_it_;
            }

            SEAL_NODISCARD inline bool operator<=(const self_type &compare) const noexcept
            {
                return !(coeff_it_ > compare.coeff_it_);
            }

            SEAL_NODISCARD inline bool operator>=(const self_type &compare) const noexcept
            {
                return !(coeff_it_ < compare.coeff_it_);
            }

            SEAL_NODISCARD inline operator const std::uint64_t *() const noexcept
            {
                return static_cast<const std::uint64_t *>(coeff_it_);
            }

            SEAL_NODISCARD explicit inline operator bool() const noexcept
            {
                return static_cast<bool>(coeff_it_);
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
            ConstCoeffIter coeff_it_;

            std::size_t step_size_;
        };

        // Out-of-class definitions
        template <typename SizeT>
        SEAL_NODISCARD inline ConstRNSIter operator+(SizeT n, ConstRNSIter it) noexcept
        {
            return it + n;
        }

        class PolyIter
        {
        public:
            using self_type = PolyIter;

            // Standard iterator typedefs
            using value_type = RNSIter;
            using pointer = void;
            using reference = const value_type &;
            using iterator_category = std::random_access_iterator_tag;
            using difference_type = std::ptrdiff_t;

            PolyIter() : rns_it_(nullptr, 0), coeff_modulus_size_(0), step_size_(0)
            {}

            PolyIter(std::uint64_t *ptr, std::size_t poly_modulus_degree, std::size_t coeff_modulus_size)
                : rns_it_(ptr, poly_modulus_degree), coeff_modulus_size_(coeff_modulus_size),
                  step_size_(mul_safe(poly_modulus_degree, coeff_modulus_size_))
            {}

            PolyIter(Ciphertext &ct) : self_type(ct.data(), ct.poly_modulus_degree(), ct.coeff_modulus_size())
            {}

            PolyIter(const self_type &copy) = default;

            self_type &operator=(const self_type &assign) = default;

            PolyIter(self_type &&source) = default;

            self_type &operator=(self_type &&assign) = default;

            SEAL_NODISCARD inline reference operator*() const noexcept
            {
                return rns_it_;
            }

            template <typename SizeT>
            SEAL_NODISCARD inline value_type operator[](SizeT n) const noexcept
            {
                self_type result(*this);
                result += static_cast<difference_type>(n);
                return *result;
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

            template <typename SizeT>
            inline self_type &operator+=(SizeT n) noexcept
            {
                rns_it_.coeff_it_ += static_cast<difference_type>(n) * static_cast<std::ptrdiff_t>(step_size_);
                return *this;
            }

            template <typename SizeT>
            SEAL_NODISCARD inline self_type operator+(SizeT n) const noexcept
            {
                self_type result(*this);
                result.rns_it_.coeff_it_ += static_cast<difference_type>(n) * static_cast<std::ptrdiff_t>(step_size_);
                return result;
            }

            template <typename SizeT>
            inline self_type &operator-=(SizeT n) noexcept
            {
                rns_it_.coeff_it_ -= static_cast<difference_type>(n) * static_cast<std::ptrdiff_t>(step_size_);
                return *this;
            }

            template <typename SizeT>
            SEAL_NODISCARD inline self_type operator-(SizeT n) const noexcept
            {
                return *this + (-static_cast<difference_type>(n));
            }

            SEAL_NODISCARD inline difference_type operator-(const self_type &b) const
            {
#ifdef SEAL_DEBUG
                if (!step_size_)
                {
                    throw std::logic_error("step_size cannot be zero");
                }
                if (step_size_ != b.step_size_)
                {
                    throw std::invalid_argument("incompatible iterators");
                }
                if (coeff_modulus_size_ != b.coeff_modulus_size_)
                {
                    throw std::invalid_argument("incompatible iterators");
                }
#endif
                return (rns_it_.coeff_it_ - b.rns_it_.coeff_it_) / static_cast<std::ptrdiff_t>(step_size_);
            }

            SEAL_NODISCARD inline bool operator==(const self_type &compare) const noexcept
            {
                return rns_it_ == compare.rns_it_;
            }

            SEAL_NODISCARD inline bool operator!=(const self_type &compare) const noexcept
            {
                return !(*this == compare);
            }

            SEAL_NODISCARD inline bool operator<(const self_type &compare) const noexcept
            {
                return rns_it_ < compare.rns_it_;
            }

            SEAL_NODISCARD inline bool operator>(const self_type &compare) const noexcept
            {
                return rns_it_ > compare.rns_it_;
            }

            SEAL_NODISCARD inline bool operator<=(const self_type &compare) const noexcept
            {
                return !(rns_it_ > compare.rns_it_);
            }

            SEAL_NODISCARD inline bool operator>=(const self_type &compare) const noexcept
            {
                return !(rns_it_ < compare.rns_it_);
            }

            SEAL_NODISCARD inline operator std::uint64_t *() const noexcept
            {
                return rns_it_;
            }

            SEAL_NODISCARD explicit inline operator bool() const noexcept
            {
                return static_cast<bool>(rns_it_);
            }

            SEAL_NODISCARD inline value_type operator->() const noexcept
            {
                return **this;
            }

            SEAL_NODISCARD inline std::size_t poly_modulus_degree() const noexcept
            {
                return rns_it_.step_size_;
            }

            SEAL_NODISCARD inline std::size_t coeff_modulus_size() const noexcept
            {
                return coeff_modulus_size_;
            }

        private:
            RNSIter rns_it_;

            std::size_t coeff_modulus_size_;

            std::size_t step_size_;
        };

        // Out-of-class definitions
        template <typename SizeT>
        SEAL_NODISCARD inline PolyIter operator+(SizeT n, PolyIter it) noexcept
        {
            return it + n;
        }

        class ConstPolyIter
        {
        public:
            using self_type = ConstPolyIter;

            // Standard iterator typedefs
            using value_type = ConstRNSIter;
            using pointer = void;
            using reference = const value_type &;
            using iterator_category = std::random_access_iterator_tag;
            using difference_type = std::ptrdiff_t;

            ConstPolyIter() : rns_it_(nullptr, 0), coeff_modulus_size_(0), step_size_(0)
            {}

            ConstPolyIter(const std::uint64_t *ptr, std::size_t poly_modulus_degree, std::size_t coeff_modulus_size)
                : rns_it_(ptr, poly_modulus_degree), coeff_modulus_size_(coeff_modulus_size),
                  step_size_(mul_safe(poly_modulus_degree, coeff_modulus_size_))
            {}

            ConstPolyIter(const Ciphertext &ct)
                : self_type(ct.data(), ct.poly_modulus_degree(), ct.coeff_modulus_size())
            {}

            ConstPolyIter(Ciphertext &ct) : self_type(ct.data(), ct.poly_modulus_degree(), ct.coeff_modulus_size())
            {}

            ConstPolyIter(const self_type &copy) = default;

            self_type &operator=(const self_type &assign) = default;

            ConstPolyIter(self_type &&source) = default;

            self_type &operator=(self_type &&assign) = default;

            ConstPolyIter(const PolyIter &copy)
                : rns_it_(static_cast<const std::uint64_t *>(copy), copy.poly_modulus_degree()),
                  coeff_modulus_size_(copy.coeff_modulus_size()),
                  step_size_(mul_safe(rns_it_.step_size_, coeff_modulus_size_))
            {}

            SEAL_NODISCARD inline reference operator*() const noexcept
            {
                return rns_it_;
            }

            template <typename SizeT>
            SEAL_NODISCARD inline value_type operator[](SizeT n) const noexcept
            {
                self_type result(*this);
                result += static_cast<difference_type>(n);
                return *result;
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

            template <typename SizeT>
            inline self_type &operator+=(SizeT n) noexcept
            {
                rns_it_.coeff_it_ += static_cast<difference_type>(n) * static_cast<std::ptrdiff_t>(step_size_);
                return *this;
            }

            template <typename SizeT>
            SEAL_NODISCARD inline self_type operator+(SizeT n) const noexcept
            {
                self_type result(*this);
                result.rns_it_.coeff_it_ += static_cast<difference_type>(n) * static_cast<std::ptrdiff_t>(step_size_);
                return result;
            }

            template <typename SizeT>
            inline self_type &operator-=(SizeT n) noexcept
            {
                rns_it_.coeff_it_ -= static_cast<difference_type>(n) * static_cast<std::ptrdiff_t>(step_size_);
                return *this;
            }

            template <typename SizeT>
            SEAL_NODISCARD inline self_type operator-(SizeT n) const noexcept
            {
                return *this + (-static_cast<difference_type>(n));
            }

            SEAL_NODISCARD inline difference_type operator-(const self_type &b) const
            {
#ifdef SEAL_DEBUG
                if (!step_size_)
                {
                    throw std::logic_error("step_size cannot be zero");
                }
                if (step_size_ != b.step_size_)
                {
                    throw std::invalid_argument("incompatible iterators");
                }
                if (coeff_modulus_size_ != b.coeff_modulus_size_)
                {
                    throw std::invalid_argument("incompatible iterators");
                }
#endif
                return (rns_it_.coeff_it_ - b.rns_it_.coeff_it_) / static_cast<std::ptrdiff_t>(step_size_);
            }

            SEAL_NODISCARD inline bool operator==(const self_type &compare) const noexcept
            {
                return rns_it_ == compare.rns_it_;
            }

            SEAL_NODISCARD inline bool operator!=(const self_type &compare) const noexcept
            {
                return !(*this == compare);
            }

            SEAL_NODISCARD inline bool operator<(const self_type &compare) const noexcept
            {
                return rns_it_ < compare.rns_it_;
            }

            SEAL_NODISCARD inline bool operator>(const self_type &compare) const noexcept
            {
                return rns_it_ > compare.rns_it_;
            }

            SEAL_NODISCARD inline bool operator<=(const self_type &compare) const noexcept
            {
                return !(rns_it_ > compare.rns_it_);
            }

            SEAL_NODISCARD inline bool operator>=(const self_type &compare) const noexcept
            {
                return !(rns_it_ < compare.rns_it_);
            }

            SEAL_NODISCARD inline operator const std::uint64_t *() const noexcept
            {
                return rns_it_;
            }

            SEAL_NODISCARD explicit inline operator bool() const noexcept
            {
                return static_cast<bool>(rns_it_);
            }

            SEAL_NODISCARD inline value_type operator->() const noexcept
            {
                return **this;
            }

            SEAL_NODISCARD inline std::size_t poly_modulus_degree() const noexcept
            {
                return rns_it_.step_size_;
            }

            SEAL_NODISCARD inline std::size_t coeff_modulus_size() const noexcept
            {
                return coeff_modulus_size_;
            }

        private:
            ConstRNSIter rns_it_;

            std::size_t coeff_modulus_size_;

            std::size_t step_size_;
        };

        // Out-of-class definitions
        template <typename SizeT>
        SEAL_NODISCARD inline ConstPolyIter operator+(SizeT n, ConstPolyIter it) noexcept
        {
            return it + n;
        }

        template <typename PtrT>
        class PtrIter
        {
        public:
            using self_type = PtrIter<PtrT>;

            // Standard iterator typedefs
            using value_type = PtrT;
            using pointer = void;
            using reference = const value_type &;
            using iterator_category = std::random_access_iterator_tag;
            using difference_type = std::ptrdiff_t;

            PtrIter() : ptr_(nullptr)
            {}

            PtrIter(value_type ptr) : ptr_(ptr)
            {}

            PtrIter(const std::vector<std::remove_cv_t<std::remove_pointer_t<PtrT>>> &arr) : PtrIter(arr.data())
            {}

            PtrIter(const Pointer<std::remove_cv_t<std::remove_pointer_t<PtrT>>> &arr) : PtrIter(arr.get())
            {}

            PtrIter(const self_type &copy) = default;

            self_type &operator=(const self_type &assign) = default;

            PtrIter(self_type &&source) = default;

            self_type &operator=(self_type &&assign) = default;

            SEAL_NODISCARD inline reference operator*() const noexcept
            {
                return ptr_;
            }

            template <typename SizeT>
            SEAL_NODISCARD inline value_type operator[](SizeT n) const noexcept
            {
                return ptr_ + n;
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

            template <typename SizeT>
            inline self_type &operator+=(SizeT n) noexcept
            {
                ptr_ += n;
                return *this;
            }

            template <typename SizeT>
            SEAL_NODISCARD inline self_type operator+(SizeT n) const noexcept
            {
                return ptr_ + n;
            }

            template <typename SizeT>
            inline self_type &operator-=(SizeT n) noexcept
            {
                ptr_ -= n;
                return *this;
            }

            template <typename SizeT>
            SEAL_NODISCARD inline self_type operator-(SizeT n) const noexcept
            {
                return ptr_ - n;
            }

            SEAL_NODISCARD inline difference_type operator-(const self_type &b) const noexcept
            {
                return std::distance(ptr_, b.ptr_);
            }

            SEAL_NODISCARD inline bool operator==(const self_type &compare) const noexcept
            {
                return ptr_ == compare.ptr_;
            }

            SEAL_NODISCARD inline bool operator!=(const self_type &compare) const noexcept
            {
                return !(*this == compare);
            }

            SEAL_NODISCARD inline bool operator<(const self_type &compare) const noexcept
            {
                return ptr_ < compare.ptr_;
            }

            SEAL_NODISCARD inline bool operator>(const self_type &compare) const noexcept
            {
                return ptr_ > compare.ptr_;
            }

            SEAL_NODISCARD inline bool operator<=(const self_type &compare) const noexcept
            {
                return !(ptr_ > compare.ptr_);
            }

            SEAL_NODISCARD inline bool operator>=(const self_type &compare) const noexcept
            {
                return !(ptr_ < compare.ptr_);
            }

            SEAL_NODISCARD inline operator value_type *() const noexcept
            {
                return ptr_;
            }

            SEAL_NODISCARD explicit inline operator bool() const noexcept
            {
                return nullptr != ptr_;
            }

            SEAL_NODISCARD inline value_type operator->() const noexcept
            {
                return **this;
            }

        private:
            value_type ptr_;
        };

        // Out-of-class definitions
        template <typename PtrT, typename SizeT>
        SEAL_NODISCARD inline PtrIter<PtrT> operator+(SizeT n, const PtrIter<PtrT> &it) noexcept
        {
            return it + n;
        }

        template <typename SEALIter>
        class ReverseIter : public SEALIter
        {
        public:
            using self_type = ReverseIter<SEALIter>;

            // Standard iterator typedefs
            using value_type = typename std::iterator_traits<SEALIter>::value_type;
            using pointer = typename std::iterator_traits<SEALIter>::pointer;
            using reference = typename std::iterator_traits<SEALIter>::reference;
            using iterator_category = typename std::iterator_traits<SEALIter>::iterator_category;
            using difference_type = typename std::iterator_traits<SEALIter>::difference_type;

            ReverseIter() : SEALIter()
            {}

            ReverseIter(const SEALIter &copy) : SEALIter(copy)
            {}

            ReverseIter(SEALIter &&source) : SEALIter(source)
            {}

            ReverseIter(const self_type &copy) = default;

            self_type &operator=(const self_type &assign) = default;

            ReverseIter(self_type &&source) = default;

            self_type &operator=(self_type &&assign) = default;

            template <typename SizeT, typename Ignore = value_type>
            SEAL_NODISCARD inline auto operator[](SizeT n) const noexcept
                -> std::enable_if_t<std::is_same<iterator_category, std::random_access_iterator_tag>::value, Ignore>
            {
                self_type result(*this);
                result += static_cast<difference_type>(n);
                return *result;
            }

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

            template <typename SizeT, typename Ignore = typename std::add_lvalue_reference<self_type>::type>
            inline auto operator+=(SizeT n) noexcept
                -> std::enable_if_t<std::is_same<iterator_category, std::random_access_iterator_tag>::value, Ignore>
            {
                SEALIter::operator-=(n);
                return *this;
            }

            template <typename SizeT, typename Ignore = self_type>
            SEAL_NODISCARD inline auto operator+(SizeT n) const noexcept
                -> std::enable_if_t<std::is_same<iterator_category, std::random_access_iterator_tag>::value, Ignore>
            {
                self_type result(*this);
                result += n;
                return result;
            }

            template <typename SizeT, typename Ignore = typename std::add_lvalue_reference<self_type>::type>
            inline auto operator-=(SizeT n) noexcept
                -> std::enable_if_t<std::is_same<iterator_category, std::random_access_iterator_tag>::value, Ignore>
            {
                SEALIter::operator+=(n);
                return *this;
            }

            template <typename SizeT, typename Ignore = self_type>
            SEAL_NODISCARD inline auto operator-(SizeT n) const noexcept
                -> std::enable_if_t<std::is_same<iterator_category, std::random_access_iterator_tag>::value, Ignore>
            {
                return *this + (-static_cast<difference_type>(n));
            }

            template <typename Ignore = difference_type>
            SEAL_NODISCARD inline auto operator-(const self_type &b) const
                -> std::enable_if_t<std::is_same<iterator_category, std::random_access_iterator_tag>::value, Ignore>
            {
                return static_cast<SEALIter>(*this) - static_cast<SEALIter>(*b);
            }

            template <typename Ignore = bool>
            SEAL_NODISCARD inline auto operator<(const self_type &compare) const noexcept
                -> std::enable_if_t<std::is_same<iterator_category, std::random_access_iterator_tag>::value, Ignore>
            {
                return static_cast<SEALIter>(*this) > static_cast<SEALIter>(*compare);
            }

            template <typename Ignore = bool>
            SEAL_NODISCARD inline auto operator>(const self_type &compare) const noexcept
                -> std::enable_if_t<std::is_same<iterator_category, std::random_access_iterator_tag>::value, Ignore>
            {
                return static_cast<SEALIter>(*this) < static_cast<SEALIter>(*compare);
            }

            template <typename Ignore = bool>
            SEAL_NODISCARD inline auto operator<=(const self_type &compare) const noexcept
                -> std::enable_if_t<std::is_same<iterator_category, std::random_access_iterator_tag>::value, Ignore>
            {
                return !(*this > compare);
            }

            template <typename Ignore = bool>
            SEAL_NODISCARD inline auto operator>=(const self_type &compare) const noexcept
                -> std::enable_if_t<std::is_same<iterator_category, std::random_access_iterator_tag>::value, Ignore>
            {
                return !(*this < compare);
            }
        };

        // Out-of-class definitions
        template <
            typename SizeT, typename SEALIter,
            typename = std::enable_if_t<std::is_same<
                typename std::iterator_traits<SEALIter>::iterator_category, std::random_access_iterator_tag>::value>>
        SEAL_NODISCARD inline ReverseIter<SEALIter> operator+(SizeT n, const ReverseIter<SEALIter> &it) noexcept
        {
            return it + n;
        }

        template <typename... SEALIters>
        class IterTuple;

        template <typename SEALIter, typename... Rest>
        class IterTuple<SEALIter, Rest...>
        {
        public:
            using self_type = IterTuple<SEALIter, Rest...>;

            // Standard iterator typedefs
            using value_type = IterTuple<
                typename std::iterator_traits<SEALIter>::value_type,
                typename std::iterator_traits<IterTuple<Rest>>::value_type...>;
            using pointer = void;
            using reference = const value_type &;
            using iterator_category = std::bidirectional_iterator_tag;
            using difference_type = std::ptrdiff_t;

            IterTuple() = default;

            IterTuple(SEALIter first, IterTuple<Rest...> rest) : first_(first), rest_(rest){};

            IterTuple(SEALIter first, Rest... rest) : first_(first), rest_(rest...)
            {}

            IterTuple(const self_type &copy) = default;

            self_type &operator=(const self_type &assign) = default;

            IterTuple(self_type &&source) = default;

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

            SEAL_NODISCARD explicit inline operator bool() const noexcept
            {
                return static_cast<bool>(first_) && static_cast<bool>(rest_);
            }

            SEAL_NODISCARD inline const SEALIter &first() const noexcept
            {
                return first_;
            }

            SEAL_NODISCARD inline const IterTuple<Rest...> &rest() const noexcept
            {
                return rest_;
            }

        private:
            SEALIter first_;

            IterTuple<Rest...> rest_;
        };

        template <typename SEALIter>
        class IterTuple<SEALIter>
        {
        public:
            using self_type = IterTuple<SEALIter>;

            // Standard iterator typedefs
            using value_type = typename std::iterator_traits<SEALIter>::value_type;
            using pointer = void;
            using reference = const value_type &;
            using iterator_category = std::bidirectional_iterator_tag;
            using difference_type = std::ptrdiff_t;

            IterTuple(){};

            IterTuple(SEALIter first) : first_(first)
            {}

            IterTuple(const self_type &copy) = default;

            self_type &operator=(const self_type &assign) = default;

            IterTuple(self_type &&source) = default;

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

            SEAL_NODISCARD explicit inline operator bool() const noexcept
            {
                return static_cast<bool>(first_);
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
                static auto apply(const IterTuple<SEALIter, Rest...> &it)
                {
                    return GetHelperStruct<N - 1>::apply(it.rest());
                }
            };

            template <>
            struct GetHelperStruct<0>
            {
                template <typename SEALIter, typename... Rest>
                static auto apply(const IterTuple<SEALIter, Rest...> &it)
                {
                    return it.first();
                }
            };
        } // namespace iterator_tuple_internal

        template <std::size_t N, typename... SEALIters>
        auto get(const IterTuple<SEALIters...> &it)
        {
            return iterator_tuple_internal::GetHelperStruct<N>::apply(it);
        }
    } // namespace util
} // namespace seal
