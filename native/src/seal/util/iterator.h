// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#pragma once

#include "seal/util/common.h"
#include "seal/util/defines.h"
#include "seal/util/pointer.h"
#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <iostream>
#include <iterator>
#include <stdexcept>
#include <type_traits>
#include <utility>
#include <vector>

namespace seal
{
    class Ciphertext;

    namespace util
    {
        class NTTTables;

        /**
        @par PolyIter, RNSIter, and CoeffIter
        In this file we define a set of custom iterator classes ("SEAL iterators") that are used throughout Microsoft
        SEAL for easier iteration over ciphertext polynomials, their RNS components, and the coefficients in the RNS
        components. All SEAL iterators satisfy the C++ LegacyRandomAccessIterator requirements. SEAL iterators are ideal
        to use with the SEAL_ITERATE macro, which expands to std::for_each_n in C++17 and to seal::util::seal_for_each_n
        in C++14. All SEAL iterators derive from SEALIterBase.

        The SEAL iterator classes behave as illustrated by the following diagram:

        +-------------------+
        |    Pointer & Size |  Construct  +-----------------+
        | or Ciphertext     |------------>| (Const)PolyIter |  Iterates over RNS polynomials in a ciphertext
        +-------------------+             +--------+--------+  (coeff_modulus_size-many RNS components)
                                                   |
                                                   |
                                                   | Dereference
                                                   |
                                                   |
                                                   v
           +----------------+  Construct   +----------------+
           | Pointer & Size |------------->| (Const)RNSIter |  Iterates over RNS components in an RNS polynomial
           +----------------+              +-------+--------+  (poly_modulus_degree-many coefficients)
                                                   |
                                                   |
                                                   | Dereference
                                                   |
                                                   |
                                                   v
          +----------------+  Construct  +------------------+
          | Pointer & Size |------------>| (Const)CoeffIter |  Iterates over coefficients (std::uint64_t) in a single
          +----------------+             +---------+--------+  RNS polynomial component
                                                   |
                                                   |
                                                   | Dereference
                                                   |
                                                   |
                                                   v
                                       +------------------------+  Construct  +---------------+
                                       | (const) std::uint64_t* |------------>| PtrIter<PtrT> |  Simple wrapper
                                       +------------------------+             +-------+-------+  for raw pointers
                                                                                ^     |
                            +---------+  Construct                              |     |
                            | MyType* |-----------------------------------------+     | Dereference
                            +---------+                                               |
                                                                                      |
                                                                                      v
                                                                                  +------+
                                                                                  | PtrT |  Unusual dereference to PtrT
                                                                                  +------+

        @par IterTuple
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
        +-------------+       +---------------+      +-------------------------+
        |   RNSIter   |       |   CoeffIter   |      | PtrIter<std::uint64_t*> |
        +-------------+       +---------------+      +-------------------------+

        Sometimes we have to use multiple nested iterator tuples. In this case accessing the nested iterators can be
        tedious with nested get<...> calls. Consider the following, where encrypted1 and encrypted2 are Ciphertexts
        and destination is either a Ciphertext or a PolyIter:

        IterTuple<PolyIter, PolyIter> I(encrypted1, encrypted2);
        IterTuple<decltype(I), PolyIter> J(I, destination);
        auto encrypted1_iter = get<0>(get<0>(J));
        auto encrypted2_iter = get<1>(get<0>(J));

        An easier way is to use another form of get<...> that accepts multiple indices and accesses the structure in a
        nested manner. For example, in the above we could also write:

        auto encrypted1_iter = get<0, 0>(J));
        auto encrypted2_iter = get<0, 1>(J));

        Note that the innermost tuple index appears first in the list, i.e. the order is reversed from what appears in
        a nested get<...> call. The reason for this reversal is that, when deducing what the iterators are, one first
        examines at the innermost scope, and last the outermost scope, corresponding now to the order of the indices.

        @par Typedefs for common PtrIter types
        It is very common to use the types PtrIter<Modulus *> and PtrIter<NTTTables *>. To simplify the
        notation, we have set up typedefs for these: ModulusIter and NTTTablesIter. There are also constant versions
        ConstModulusIter and ConstNTTTablesIter.

        @par Creating SEAL iterators
        Iterators are easiest to create using the variadic iter function that, when given one or more arguments that can
        naturally be converted to SEAL iterators, outputs an appropriate iterator, or iterator tuple. Consider again the
        code snippet above, and how confusing the template parameters can become to write. Instead, we can simply write:

        auto I = iter(encrypted1, encrypted2);
        auto J = iter(I, destination);
        auto encrypted1_iter = get<0, 0>(J));
        auto encrypted2_iter = get<0, 1>(J));

        @par Reversing direction with ReverseIter
        In addition to the iterator types described above, we provide ReverseIter<SEALIter> that reverses the direction
        of iteration. ReverseIter<SEALIter> dereferences to the same type as SEALIter: for example, dereferencing
        ReverseIter<RNSIter> results in CoeffIter, not ReverseIter<CoeffIter>.

        It is easy to create a ReverseIter from a given SEAL iterator using the function reverse_iter. For example,
        reverse_iter(encrypted) will return a ReverseIter<PolyIter> if encrypted is either a PolyIter, or a Ciphertext.
        When passed multiple arguments, reverse_iter returns an appropriate ReverseIter<IterTuple<...>>. For example,
        reverse_iter(encrypted1, encrypted2) returns ReverseIter<IterTuple<PolyIter, PolyIter>> if encrypted1 and
        encrypted2 are PolyIter or Ciphertext objects.

        @par SEAL_ITERATE
        SEAL iterators are made to be used with the SEAL_ITERATE macro to iterate over a certain number of steps, and
        for each step call a given lambda function. In C++17 SEAL_ITERATE expands to std::for_each_n, and in C++14 it
        expands to seal::util::seal_for_each_n -- a custom implementation. For example, the following snippet appears
        in Evaluator::bfv_multiply:

        SEAL_ITERATE(
            iter(encrypted1, encrypted1_q, encrypted1_Bsk),
            encrypted1_size,
            behz_extend_base_convert_to_ntt);

        Here an IterTuple<PolyIter, PolyIter, PolyIter> is created with the iter function; the argument types are
        Ciphertext (encrypted1), PolyIter (encrypted1_q), and PolyIter (encrypted1_Bsk). The iterator is advanced
        encrypted1_size times, and each time the lambda function behz_extend_base_convert_to_ntt is called with the
        iterator tuple dereferenced. The lambda function starts as follows:

        auto behz_extend_base_convert_to_ntt = [&](auto I) {
            set_poly(get<0>(I), coeff_count, base_q_size, get<1>(I));
            ntt_negacyclic_harvey_lazy(get<1>(I), base_q_size, base_q_ntt_tables);
            ...
        });

        Here the parameter I is of type IterTuple<RNSIter, RNSIter, RNSIter>. Inside the lambda function we first copy
        the RNS polynomial from get<0>(I) (encrypted1) to get<1>(I) (encrypted1_q) and transform it to NTT form. We use
        an overload of ntt_negacyclic_harvey_lazy that takes an RNSIter, size of the RNS base, and ConstNTTTablesIter as
        arguments and converts each RNS component separately. Looking at seal/util/ntt.h we see that the function
        ntt_negacyclic_harvey_lazy is again implemented using SEAL_ITERATE. Specifically, it contains the following:

        SEAL_ITERATE(iter(operand, tables), coeff_modulus_size, [&](auto I) {
            ntt_negacyclic_harvey_lazy(get<0>(I), *get<1>(I));
        });

        Here iter outputs an IterTuple<RNSIter, ConstNTTTablesIter>. In this case the lambda function to be called
        is defined inline. The argument I takes values IterTuple<CoeffIter, const NTTTables *>, and for each step the
        CoeffIter overload of ntt_negacyclic_harvey_lazy is called, with a reference to a matching NTTTables object.

        @par Coding conventions
        There are two important coding conventions in the above code snippets that are to be observed:

            1. Use I, J, K, ... for the lambda function parameters representing SEAL iterators. This is compact and
               makes it very clear that the objects in question are SEAL iterators since such variable names should not
               be used in SEAL in any other context.
            2. Always pass SEAL iterators by value to the lambda function.

        @par Iterator overloads of common functions
        Some functions have overloads that directly take either CoeffIter, RNSIter, or PolyIter inputs, and apply the
        operation in question to the entire structure as indicated by the iterator. For example, the function
        seal::util::negate_poly_coeffmod can negate a single RNS component modulo a given Modulus (CoeffIter overload),
        an entire RNS polynomial modulo an array of matching Modulus elements (RNSIter overload), or an array of RNS
        polynomials (PolyIter overload).

        @par Indexing with SeqIter
        Sometimes inside SEAL_ITERATE lambda functions it is convenient to know the index of the iteration. This can be
        done using a SeqIter<T> iterator. The template parameter is an arithmetic type for the index counter.

        The easiest way to create SeqIter objects is using the seq_iter function. For example, seq_iter(0) returns a
        SeqIter<int> object with initial value 0. Alternatively, the iter function will detect arithmetic types passed
        to it and create SeqIter objects from them. For example, calling iter(0) is equivalent to calling seq_iter(0),
        and this works also for multi-argument calls to iter. Dereferencing a SeqIter object returns a SeqIter object.
        To access the value, call SeqIter<T>::value, or use the implicit conversion to type T. For opposite direction
        indexing, simply wrap a SeqIter into a ReverseIter, or call reverse_iter directly with the start index.

        @par Note on allocations
        In the future we hope to use the parallel version of std::for_each_n, introduced in C++17. For this to work, be
        mindful of how you use heap allocations in the lambda functions. Specifically, in heavy lambda functions it is
        probably a good idea to call seal::util::allocate inside the lambda function for any allocations needed, rather
        than using allocations captured from outside the lambda function.

        @par Iterators to temporary allocations
        In many cases one may want to allocate a temporary buffer and create an iterator pointing to it. However, care
        must be taken to use the correct size parameters now both for the allocation, as well as for setting up the
        iterator. For this reason, we provide a few helpful macros that set up the Pointer and only expose the iterator
        to the function. For example, instead of writing the following error-prone code:

        auto temp_alloc(allocate_poly_array(count, poly_modulus_degree, coeff_modulus_size, pool));
        PolyIter temp(temp_alloc.get(), poly_modulus_degree, coeff_modulus_size);

        we can simply write:

        SEAL_ALLOCATE_GET_POLY_ITER(temp, count, poly_modulus_degree, coeff_modulus_size, pool);

        However, the latter does not expose the name of the allocation itself. There are similar macros for allocating
        buffers and setting up RNSIter and CoeffIter objects as well, and all these macros have versions that set the
        allocated memory to zero, e.g. SEAL_ALLOCATE_ZERO_GET_POLY_ITER.

        @par SEAL_ASSERT_TYPE
        It is not unusual to have multiple nested SEAL_ITERATE calls operating on multiple/nested IterTuple objects. It
        can become very difficult to keep track of what exactly the different iterators are pointing to, and what their
        types are (the above convention of using I, J, K, ... does not reveal the type). Hence we sometimes annotate the
        code and check that the types match what we expect them to be using the SEAL_ASSERT_TYPE macro. For example,
        consider the following annotated code snippet that negates all RNS polynomials in the Ciphertext encrypted:

        SEAL_ITERATE(iter(encrypted), encrypted_size, [&](auto I) {
            SEAL_ASSERT_TYPE(I, RNSIter, "encrypted");
            SEAL_ITERATE(iter(I, coeff_modulus), coeff_modulus_size, [&](auto J) {
                    SEAL_ASSERT_TYPE(get<0>(J), CoeffIter, "encrypted");
                    SEAL_ASSERT_TYPE(get<1>(J), Modulus *, "coeff_modulus");
                    negate_poly_coeffmod(get<0>(J), coeff_count, *get<1>(J), get<0>(J));
                });
        });

        Of course, the above could be done in just one line using the PolyIter overload of negate_poly_coeffmod:

        negate_poly_coeffmod(encrypted, encrypted_size, coeff_modulus, encrypted);

        Nevertheless, note how SEAL_ASSERT_TYPE makes it explicit what type the different iterators are, and includes
        a string that describes what object is iterated over. We use this convention in particularly complex functions
        to make the code easier to follow and less error-prone. The code will fail to compile if the type of the object
        in the first parameter does not match the type in the second parameter of the macro.

        There is one caveat one should be aware of. When calling SEAL_ASSERT_TYPE with a multi-index get<...>(I), an
        extra set of parentheses must be used around the object for the macro arguments to work properly:

        auto I = iter(encrypted1, encrypted2);
        auto J = iter(I, destination);
        SEAL_ASSERT_TYPE((get<0, 0>(J)), PolyIter, "encrypted1");
        */

        // Our custom implementation of std::for_each_n
        template <typename ForwardIt, typename Size, typename Func>
        inline ForwardIt seal_for_each_n(ForwardIt first, Size size, Func func)
        {
            for (; size--; (void)++first)
            {
                func(*first);
            }
            return first;
        }

        class SEALIterBase
        {};

        template <typename T, typename>
        class SeqIter;

        template <typename T>
        class PtrIter;

        class RNSIter;

        class ConstRNSIter;

        class PolyIter;

        class ConstPolyIter;

        template <typename SEALIter>
        class ReverseIter;

        template <typename... SEALIters>
        class IterTuple;

        using CoeffIter = PtrIter<std::uint64_t *>;

        using ConstCoeffIter = PtrIter<const std::uint64_t *>;

        using ConstModulusIter = PtrIter<const Modulus *>;

        using ConstNTTTablesIter = PtrIter<const NTTTables *>;

        using ModulusIter = PtrIter<Modulus *>;

        using NTTTablesIter = PtrIter<NTTTables *>;

        namespace iterator_internal
        {
            template <typename Enable, typename... Ts>
            struct iter_type;

            template <typename T>
            struct iter_type<std::enable_if_t<std::is_arithmetic<T>::value>, T>
            {
                using type = SeqIter<T, void>;
            };

            template <typename T>
            struct iter_type<
                std::enable_if_t<std::is_base_of<SEALIterBase, std::decay_t<T>>::value && !std::is_pointer<T>::value>,
                T>
            {
                using type = std::decay_t<T>;
            };

            template <>
            struct iter_type<void, Ciphertext &>
            {
                using type = PolyIter;
            };

            template <>
            struct iter_type<void, const Ciphertext &>
            {
                using type = ConstPolyIter;
            };

            template <typename T>
            struct iter_type<void, const T *>
            {
                using type = PtrIter<const T *>;
            };

            template <typename T>
            struct iter_type<void, T *>
            {
                using type = PtrIter<T *>;
            };

            template <typename T>
            struct iter_type<void, const T *&>
            {
                using type = PtrIter<const T *>;
            };

            template <typename T>
            struct iter_type<void, T *&>
            {
                using type = PtrIter<T *>;
            };

            template <typename T>
            struct iter_type<void, std::vector<T> &>
            {
                using type = PtrIter<T *>;
            };

            template <typename T>
            struct iter_type<void, const std::vector<T> &>
            {
                using type = PtrIter<const T *>;
            };

            template <typename T>
            struct iter_type<void, Pointer<T> &>
            {
                using type = PtrIter<T *>;
            };

            template <typename T>
            struct iter_type<void, ConstPointer<T> &>
            {
                using type = PtrIter<const T *>;
            };
        } // namespace iterator_internal

        template <typename T, typename = std::enable_if_t<std::is_arithmetic<T>::value>>
        class SeqIter : public SEALIterBase
        {
        public:
            using self_type = SeqIter;

            // Standard iterator typedefs
            using value_type = self_type;
            using pointer = void;
            using reference = const value_type &;
            using iterator_category = std::random_access_iterator_tag;
            using difference_type = std::ptrdiff_t;

            SeqIter() = default;

            SeqIter(T start) : value_(start)
            {}

            SeqIter(const self_type &copy) = default;

            inline self_type &operator=(const self_type &assign) = default;

            SEAL_NODISCARD inline reference operator*() const noexcept
            {
                return *this;
            }

            template <typename SizeT>
            SEAL_NODISCARD inline value_type operator[](SizeT n) const noexcept
            {
                return value_ + static_cast<T>(n);
            }

            inline self_type &operator++() noexcept
            {
                value_++;
                return *this;
            }

            inline self_type operator++(int) noexcept
            {
                self_type result(value_);
                value_++;
                return result;
            }

            inline self_type &operator--() noexcept
            {
                value_--;
                return *this;
            }

            inline self_type operator--(int) noexcept
            {
                self_type result(value_);
                value_--;
                return result;
            }

            template <typename SizeT>
            inline self_type &operator+=(SizeT n) noexcept
            {
                value_ += static_cast<T>(n);
                return *this;
            }

            template <typename SizeT>
            SEAL_NODISCARD inline self_type operator+(SizeT n) const noexcept
            {
                return value_ + static_cast<T>(n);
            }

            template <typename SizeT>
            inline self_type &operator-=(SizeT n) noexcept
            {
                value_ -= static_cast<T>(n);
                return *this;
            }

            template <typename SizeT>
            SEAL_NODISCARD inline self_type operator-(SizeT n) const noexcept
            {
                return value_ - static_cast<T>(n);
            }

            SEAL_NODISCARD inline difference_type operator-(const self_type &b) const noexcept
            {
                return static_cast<difference_type>(value_ - b.value_);
            }

            SEAL_NODISCARD inline bool operator==(const self_type &compare) const noexcept
            {
                return value_ == *compare;
            }

            template <typename S, typename = std::enable_if_t<std::is_arithmetic<S>::value>>
            SEAL_NODISCARD inline bool operator==(S compare) const noexcept
            {
                return value_ == compare;
            }

            SEAL_NODISCARD inline bool operator!=(const self_type &compare) const noexcept
            {
                return !(*this == compare);
            }

            template <typename S, typename = std::enable_if_t<std::is_arithmetic<S>::value>>
            SEAL_NODISCARD inline bool operator!=(S compare) const noexcept
            {
                return !(*this == compare);
            }

            SEAL_NODISCARD inline bool operator<(const self_type &compare) const noexcept
            {
                return value_ < *compare;
            }

            template <typename S, typename = std::enable_if_t<std::is_arithmetic<S>::value>>
            SEAL_NODISCARD inline bool operator<(S compare) const noexcept
            {
                return value_ < compare;
            }

            SEAL_NODISCARD inline bool operator>(const self_type &compare) const noexcept
            {
                return value_ > *compare;
            }

            template <typename S, typename = std::enable_if_t<std::is_arithmetic<S>::value>>
            SEAL_NODISCARD inline bool operator>(S compare) const noexcept
            {
                return value_ > compare;
            }

            SEAL_NODISCARD inline bool operator<=(const self_type &compare) const noexcept
            {
                return !(value_ > *compare);
            }

            template <typename S, typename = std::enable_if_t<std::is_arithmetic<S>::value>>
            SEAL_NODISCARD inline bool operator<=(S compare) const noexcept
            {
                return !(value_ > compare);
            }

            SEAL_NODISCARD inline bool operator>=(const self_type &compare) const noexcept
            {
                return !(value_ < *compare);
            }

            template <typename S, typename = std::enable_if_t<std::is_arithmetic<S>::value>>
            SEAL_NODISCARD inline bool operator>=(S compare) const noexcept
            {
                return !(value_ < compare);
            }

            SEAL_NODISCARD inline T value() const noexcept
            {
                return value_;
            }

            SEAL_NODISCARD inline operator T() const noexcept
            {
                return value();
            }

        private:
            T value_ = 0;
        };

        template <typename T>
        SEAL_NODISCARD inline auto seq_iter(T value = 0) -> SeqIter<T>
        {
            return value;
        }

        template <typename T>
        class PtrIter<T *> : public SEALIterBase
        {
        public:
            using self_type = PtrIter<T *>;

            // Standard iterator typedefs
            using value_type = T *;
            using pointer = void;
            using reference = const value_type &;
            using iterator_category = std::random_access_iterator_tag;
            using difference_type = std::ptrdiff_t;

            PtrIter() = default;

            PtrIter(value_type ptr) noexcept : ptr_(ptr)
            {}

            template <typename S>
            PtrIter(const PtrIter<S *> &copy) noexcept : ptr_(*copy)
            {}

            template <typename S>
            PtrIter(const std::vector<S> &arr) noexcept : PtrIter(arr.data())
            {}

            template <typename S>
            PtrIter(std::vector<S> &arr) noexcept : PtrIter(arr.data())
            {}

            template <typename S>
            PtrIter(const Pointer<S> &arr) noexcept : PtrIter(arr.get())
            {}

            template <typename S>
            inline self_type &operator=(const PtrIter<S *> &assign) noexcept
            {
                ptr_ = *assign;
                return *this;
            }

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

            template <typename S>
            SEAL_NODISCARD inline difference_type operator-(const PtrIter<S *> &b) const noexcept
            {
                return std::distance(*b, ptr_);
            }

            template <typename S>
            SEAL_NODISCARD inline bool operator==(const PtrIter<S *> &compare) const noexcept
            {
                return ptr_ == *compare;
            }

            template <typename S>
            SEAL_NODISCARD inline bool operator!=(const PtrIter<S *> &compare) const noexcept
            {
                return !(*this == compare);
            }

            template <typename S>
            SEAL_NODISCARD inline bool operator<(const PtrIter<S *> &compare) const noexcept
            {
                return ptr_ < *compare;
            }

            template <typename S>
            SEAL_NODISCARD inline bool operator>(const PtrIter<S *> &compare) const noexcept
            {
                return ptr_ > *compare;
            }

            template <typename S>
            SEAL_NODISCARD inline bool operator<=(const PtrIter<S *> &compare) const noexcept
            {
                return !(ptr_ > *compare);
            }

            template <typename S>
            SEAL_NODISCARD inline bool operator>=(const PtrIter<S *> &compare) const noexcept
            {
                return !(ptr_ < *compare);
            }

            SEAL_NODISCARD explicit inline operator bool() const noexcept
            {
                return nullptr != ptr_;
            }

            SEAL_NODISCARD inline reference operator->() const noexcept
            {
                return *this;
            }

            SEAL_NODISCARD inline value_type ptr() const noexcept
            {
                return ptr_;
            }

            SEAL_NODISCARD inline operator value_type() const noexcept
            {
                return ptr();
            }

        private:
            value_type ptr_ = nullptr;
        };

        class RNSIter : public SEALIterBase
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
                coeff_it_ += static_cast<difference_type>(step_size_);
                return *this;
            }

            inline self_type operator++(int) noexcept
            {
                self_type result(*this);
                coeff_it_ += static_cast<difference_type>(step_size_);
                return result;
            }

            inline self_type &operator--() noexcept
            {
                coeff_it_ -= static_cast<difference_type>(step_size_);
                return *this;
            }

            inline self_type operator--(int) noexcept
            {
                self_type result(*this);
                coeff_it_ -= static_cast<difference_type>(step_size_);
                return result;
            }

            template <typename SizeT>
            inline self_type &operator+=(SizeT n) noexcept
            {
                coeff_it_ += n * static_cast<difference_type>(step_size_);
                return *this;
            }

            template <typename SizeT>
            SEAL_NODISCARD inline self_type operator+(SizeT n) const noexcept
            {
                self_type result(*this);
                result.coeff_it_ += static_cast<difference_type>(n) * static_cast<difference_type>(step_size_);
                return result;
            }

            template <typename SizeT>
            inline self_type &operator-=(SizeT n) noexcept
            {
                coeff_it_ -= static_cast<difference_type>(n) * static_cast<difference_type>(step_size_);
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
                return (coeff_it_ - b.coeff_it_) / static_cast<difference_type>(step_size_);
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

        class ConstRNSIter : public SEALIterBase
        {
        public:
            friend class ConstPolyIter;

            using self_type = ConstRNSIter;

            // Standard iterator typedefs
            using value_type = ConstCoeffIter;
            using pointer = void;
            using reference = const value_type &;
            using iterator_category = std::random_access_iterator_tag;
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
                coeff_it_ += static_cast<difference_type>(step_size_);
                return *this;
            }

            inline self_type operator++(int) noexcept
            {
                self_type result(*this);
                coeff_it_ += static_cast<difference_type>(step_size_);
                return result;
            }

            inline self_type &operator--() noexcept
            {
                coeff_it_ -= static_cast<difference_type>(step_size_);
                return *this;
            }

            inline self_type operator--(int) noexcept
            {
                self_type result(*this);
                coeff_it_ -= static_cast<difference_type>(step_size_);
                return result;
            }

            template <typename SizeT>
            inline self_type &operator+=(SizeT n) noexcept
            {
                coeff_it_ += static_cast<difference_type>(n) * static_cast<difference_type>(step_size_);
                return *this;
            }

            template <typename SizeT>
            SEAL_NODISCARD inline self_type operator+(SizeT n) const noexcept
            {
                self_type result(*this);
                result.coeff_it_ += static_cast<difference_type>(n) * static_cast<difference_type>(step_size_);
                return result;
            }

            template <typename SizeT>
            inline self_type &operator-=(SizeT n) noexcept
            {
                coeff_it_ -= static_cast<difference_type>(n) * static_cast<difference_type>(step_size_);
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
                return (coeff_it_ - b.coeff_it_) / static_cast<difference_type>(step_size_);
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

        class PolyIter : public SEALIterBase
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

            PolyIter(Ciphertext &ct);

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
                rns_it_.coeff_it_ += step_size_;
                return *this;
            }

            inline self_type operator++(int) noexcept
            {
                self_type result(*this);
                rns_it_.coeff_it_ += step_size_;
                return result;
            }

            inline self_type &operator--() noexcept
            {
                rns_it_.coeff_it_ -= step_size_;
                return *this;
            }

            inline self_type operator--(int) noexcept
            {
                self_type result(*this);
                rns_it_.coeff_it_ -= step_size_;
                return result;
            }

            template <typename SizeT>
            inline self_type &operator+=(SizeT n) noexcept
            {
                rns_it_.coeff_it_ += static_cast<difference_type>(n) * static_cast<difference_type>(step_size_);
                return *this;
            }

            template <typename SizeT>
            SEAL_NODISCARD inline self_type operator+(SizeT n) const noexcept
            {
                self_type result(*this);
                result.rns_it_.coeff_it_ += static_cast<difference_type>(n) * static_cast<difference_type>(step_size_);
                return result;
            }

            template <typename SizeT>
            inline self_type &operator-=(SizeT n) noexcept
            {
                rns_it_.coeff_it_ -= static_cast<difference_type>(n) * static_cast<difference_type>(step_size_);
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
                return (rns_it_.coeff_it_ - b.rns_it_.coeff_it_) / static_cast<difference_type>(step_size_);
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

        class ConstPolyIter : public SEALIterBase
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

            ConstPolyIter(const Ciphertext &ct);

            ConstPolyIter(Ciphertext &ct);

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
                rns_it_.coeff_it_ += step_size_;
                return *this;
            }

            inline self_type operator++(int) noexcept
            {
                self_type result(*this);
                rns_it_.coeff_it_ += step_size_;
                return result;
            }

            inline self_type &operator--() noexcept
            {
                rns_it_.coeff_it_ -= step_size_;
                return *this;
            }

            inline self_type operator--(int) noexcept
            {
                self_type result(*this);
                rns_it_.coeff_it_ -= step_size_;
                return result;
            }

            template <typename SizeT>
            inline self_type &operator+=(SizeT n) noexcept
            {
                rns_it_.coeff_it_ += static_cast<difference_type>(n) * static_cast<difference_type>(step_size_);
                return *this;
            }

            template <typename SizeT>
            SEAL_NODISCARD inline self_type operator+(SizeT n) const noexcept
            {
                self_type result(*this);
                result.rns_it_.coeff_it_ += static_cast<difference_type>(n) * static_cast<difference_type>(step_size_);
                return result;
            }

            template <typename SizeT>
            inline self_type &operator-=(SizeT n) noexcept
            {
                rns_it_.coeff_it_ -= static_cast<difference_type>(n) * static_cast<difference_type>(step_size_);
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
                return (rns_it_.coeff_it_ - b.rns_it_.coeff_it_) / static_cast<difference_type>(step_size_);
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

        template <typename SEALIter>
        class ReverseIter : public SEALIter
        {
        public:
            static_assert(
                std::is_base_of<SEALIterBase, SEALIter>::value,
                "Template parameter must derive from seal::util::SEALIterBase");

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

            template <typename SizeT>
            SEAL_NODISCARD inline value_type operator[](SizeT n) const noexcept
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

            template <typename SizeT>
            inline self_type &operator+=(SizeT n) noexcept
            {
                SEALIter::operator-=(n);
                return *this;
            }

            template <typename SizeT>
            SEAL_NODISCARD inline self_type operator+(SizeT n) const noexcept
            {
                self_type result(*this);
                result += n;
                return result;
            }

            template <typename SizeT>
            inline self_type &operator-=(SizeT n) noexcept
            {
                SEALIter::operator+=(n);
                return *this;
            }

            template <typename SizeT>
            SEAL_NODISCARD inline self_type operator-(SizeT n) const noexcept
            {
                return *this + (-static_cast<difference_type>(n));
            }

            SEAL_NODISCARD inline difference_type operator-(const self_type &b) const
            {
                // Note the reversed order
                return static_cast<SEALIter>(*b) - static_cast<SEALIter>(*this);
            }

            SEAL_NODISCARD inline bool operator<(const self_type &compare) const noexcept
            {
                // Note the reversed order
                return static_cast<SEALIter>(*this) > static_cast<SEALIter>(*compare);
            }

            SEAL_NODISCARD inline bool operator>(const self_type &compare) const noexcept
            {
                // Note the reversed order
                return static_cast<SEALIter>(*this) < static_cast<SEALIter>(*compare);
            }

            SEAL_NODISCARD inline bool operator<=(const self_type &compare) const noexcept
            {
                // Note the reversed order
                return !(*this > compare);
            }

            SEAL_NODISCARD inline bool operator>=(const self_type &compare) const noexcept
            {
                return !(*this < compare);
            }
        };

        namespace iterator_internal
        {
            template <typename... SEALIters>
            struct extend_iter_tuple;

            template <typename SEALIter, typename... Rest>
            struct extend_iter_tuple<SEALIter, IterTuple<Rest...>>
            {
                using type = IterTuple<SEALIter, Rest...>;
            };

            template <typename SEALIter1, typename SEALIter2>
            struct extend_iter_tuple<SEALIter1, SEALIter2>
            {
                using type = IterTuple<SEALIter1, SEALIter2>;
            };
        }

        template <typename SEALIter, typename... Rest>
        class IterTuple<SEALIter, Rest...> : public SEALIterBase
        {
        public:
            static_assert(
                std::is_base_of<SEALIterBase, SEALIter>::value || std::is_pointer<SEALIter>::value,
                "Template parameter must derive from seal::util::SEALIterBase or be a raw pointer");

            using self_type = IterTuple<SEALIter, Rest...>;

            // Standard iterator typedefs
            using value_type = typename iterator_internal::extend_iter_tuple<
                typename std::iterator_traits<SEALIter>::value_type,
                typename std::iterator_traits<IterTuple<Rest...>>::value_type>::type;
            using pointer = void;
            using reference = const value_type &;
            using iterator_category = std::random_access_iterator_tag;
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

            template <typename SizeT>
            SEAL_NODISCARD inline value_type operator[](SizeT n) const noexcept
            {
                self_type result(*this);
                result += static_cast<difference_type>(n);
                return *result;
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

            template <typename SizeT>
            inline self_type &operator+=(SizeT n) noexcept
            {
                first_ += n;
                rest_ += n;
                return *this;
            }

            template <typename SizeT>
            SEAL_NODISCARD inline self_type operator+(SizeT n) const noexcept
            {
                self_type result(*this);
                result += n;
                return result;
            }

            template <typename SizeT>
            inline self_type &operator-=(SizeT n) noexcept
            {
                first_ -= n;
                rest_ -= n;
                return *this;
            }

            template <typename SizeT>
            SEAL_NODISCARD inline self_type operator-(SizeT n) const noexcept
            {
                return *this + (-static_cast<difference_type>(n));
            }

            SEAL_NODISCARD inline difference_type operator-(const self_type &b) const
            {
                auto first = first_ - b.first_;
#ifdef SEAL_DEBUG
                auto rest = rest_ - b.rest_;
                if (first != rest)
                {
                    throw std::invalid_argument("incompatible iterators");
                }
#endif
                return first;
            }

            SEAL_NODISCARD inline bool operator==(const self_type &compare) const noexcept
            {
                return (first_ == compare.first_) && (rest_ == compare.rest_);
            }

            SEAL_NODISCARD inline bool operator!=(const self_type &compare) const noexcept
            {
                return !(*this == compare);
            }

            SEAL_NODISCARD inline bool operator<(const self_type &compare) const
            {
                auto first = first_ < compare.first_;
#ifdef SEAL_DEBUG
                auto rest = rest_ < compare.rest_;
                if (first != rest)
                {
                    throw std::invalid_argument("incompatible iterators");
                }
#endif
                return first;
            }

            SEAL_NODISCARD inline bool operator>(const self_type &compare) const
            {
                auto first = first_ > compare.first_;
#ifdef SEAL_DEBUG
                auto rest = rest_ > compare.rest_;
                if (first != rest)
                {
                    throw std::invalid_argument("incompatible iterators");
                }
#endif
                return first;
            }

            SEAL_NODISCARD inline bool operator<=(const self_type &compare) const
            {
                auto first = !(first_ > compare.first_);
#ifdef SEAL_DEBUG
                auto rest = !(rest_ > compare.rest_);
                if (first != rest)
                {
                    throw std::invalid_argument("incompatible iterators");
                }
#endif
                return first;
            }

            SEAL_NODISCARD inline bool operator>=(const self_type &compare) const
            {
                auto first = !(first_ < compare.first_);
#ifdef SEAL_DEBUG
                auto rest = !(rest_ < compare.rest_);
                if (first != rest)
                {
                    throw std::invalid_argument("incompatible iterators");
                }
#endif
                return first;
            }

            SEAL_NODISCARD explicit inline operator bool() const noexcept
            {
                return static_cast<bool>(first_) && static_cast<bool>(rest_);
            }

            SEAL_NODISCARD inline value_type operator->() const noexcept
            {
                return **this;
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
        class IterTuple<SEALIter> : public SEALIterBase
        {
        public:
            static_assert(
                std::is_base_of<SEALIterBase, SEALIter>::value || std::is_pointer<SEALIter>::value,
                "Template parameter must derive from seal::util::SEALIterBase or be a raw pointer");

            using self_type = IterTuple<SEALIter>;

            // Standard iterator typedefs
            using value_type = typename std::iterator_traits<SEALIter>::value_type;
            using pointer = void;
            using reference = const value_type &;
            using iterator_category = std::random_access_iterator_tag;
            using difference_type = std::ptrdiff_t;

            IterTuple(){};

            IterTuple(SEALIter first) : first_(first)
            {}

            IterTuple(const self_type &copy) = default;

            self_type &operator=(const self_type &assign) = default;

            IterTuple(self_type &&source) = default;

            self_type &operator=(self_type &&assign) = default;

            SEAL_NODISCARD inline reference operator*() const noexcept
            {
                return *first_;
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

            template <typename SizeT>
            inline self_type &operator+=(SizeT n) noexcept
            {
                first_ += n;
                return *this;
            }

            template <typename SizeT>
            SEAL_NODISCARD inline self_type operator+(SizeT n) const noexcept
            {
                self_type result(*this);
                result += n;
                return result;
            }

            template <typename SizeT>
            inline self_type &operator-=(SizeT n) noexcept
            {
                first_ -= n;
                return *this;
            }

            template <typename SizeT>
            SEAL_NODISCARD inline self_type operator-(SizeT n) const noexcept
            {
                return *this + (-static_cast<difference_type>(n));
            }

            SEAL_NODISCARD inline difference_type operator-(const self_type &b) const
            {
                return first_ - b.first_;
            }

            SEAL_NODISCARD inline bool operator==(const self_type &compare) const noexcept
            {
                return first_ == compare.first_;
            }

            SEAL_NODISCARD inline bool operator!=(const self_type &compare) const noexcept
            {
                return !(*this == compare);
            }

            SEAL_NODISCARD inline bool operator<(const self_type &compare) const noexcept
            {
                return first_ < compare.first_;
            }

            SEAL_NODISCARD inline bool operator>(const self_type &compare) const noexcept
            {
                return first_ > compare.first_;
            }

            SEAL_NODISCARD inline bool operator<=(const self_type &compare) const noexcept
            {
                return !(first_ > compare.first_);
            }

            SEAL_NODISCARD inline bool operator>=(const self_type &compare) const noexcept
            {
                return !(first_ < compare.first_);
            }

            SEAL_NODISCARD explicit inline operator bool() const noexcept
            {
                return static_cast<bool>(first_);
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

        // Out-of-class operator+ for all SEAL iterators
        template <
            typename SizeT, typename SEALIter,
            typename = std::enable_if_t<std::is_base_of<SEALIterBase, SEALIter>::value>>
        SEAL_NODISCARD inline SEALIter operator+(SizeT n, SEALIter it)
        {
            return it + n;
        }

        namespace iterator_internal
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

            template <std::size_t N, typename... SEALIters>
            auto get(const IterTuple<SEALIters...> &it)
            {
                static_assert(N < sizeof...(SEALIters), "IterTuple index out of range");
                return iterator_internal::GetHelperStruct<N>::apply(it);
            }

            template <typename T, typename... Rest>
            struct iter_type<
                std::void_t<
                    std::enable_if_t<(sizeof...(Rest) > 0)>, typename iter_type<void, T>::type,
                    typename iter_type<void, Rest...>::type>,
                T, Rest...>
            {
                using type = typename extend_iter_tuple<
                    typename iter_type<void, T>::type, typename iter_type<void, Rest...>::type>::type;
            };
        } // namespace iterator_internal

        template <
            std::size_t N, std::size_t... Rest, typename... SEALIters, typename = std::enable_if_t<sizeof...(Rest)>>
        SEAL_NODISCARD inline auto get(const IterTuple<SEALIters...> &it)
        {
            return get<Rest...>(iterator_internal::get<N>(it));
        }

        template <std::size_t N, typename... SEALIters>
        SEAL_NODISCARD inline auto get(const IterTuple<SEALIters...> &it)
        {
            return iterator_internal::get<N>(it);
        }

        template <typename... Ts>
        SEAL_NODISCARD inline auto iter(Ts &&... ts) -> typename iterator_internal::iter_type<void, Ts...>::type
        {
            return { std::forward<Ts>(ts)... };
        }

        template <typename... Ts>
        SEAL_NODISCARD inline auto reverse_iter(Ts &&... ts)
            -> ReverseIter<typename iterator_internal::iter_type<void, Ts...>::type>
        {
            return typename iterator_internal::iter_type<void, Ts...>::type(std::forward<Ts>(ts)...);
        }
    } // namespace util
} // namespace seal
