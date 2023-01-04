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
#include <tuple>
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

        The most important SEAL iterator classes behave as illustrated by the following diagram:

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
                                      +-------------------------+
                                      | (const) std::uint64_t & |
                                      +-------------------------+

        @par PtrIter and StrideIter
        PtrIter<T *> and StrideIter<T *> are both templated SEAL iterators that wrap raw pointers. The difference
        between these two types is that advancing PtrIter<T *> always advances the wrapped pointer by one, whereas the
        step size (stride) can be set to be anything for a StrideIter<T *>. CoeffIter is a typedef of
        PtrIter<std::uint64_t *> and and RNSIter is almost the same as StrideIter<std::uint64_t *>, but still a
        different type.

        +----------+  Construct   +-------------------+
        | MyType * |------------->| PtrIter<MyType *> |  Simple wrapper for raw pointers
        +----------+              +----+----------+---+
                                       |          |
                                       |          |
                          Dereference  |          |     PtrIter<MyType *>::ptr()
                                       |          |  or implicit conversion
                                       |          |
                                       v          v
                                +----------+  +----------+
                                | MyType & |  | MyType * |
                                +----------+  +----------+

        +----------+  Construct   +----------------------+
        | MyType * |------------->| StrideIter<MyType *> |  Simple wrapper for raw pointers with custom stride size
        +----------+              +-----+----------+-----+
                                        |          |
                                        |          |
                           Dereference  |          |     StrideIter<MyType *>::ptr()
                                        |          |  or implicit conversion
                                        |          |
                                        v          v
                                 +----------+  +----------+
                                 | MyType & |  | MyType * |
                                 +----------+  +----------+

        @par IterTuple
        An extremely useful template class is the (variadic) IterTuple<...> that allows multiple SEAL iterators to be
        zipped together. An IterTuple is itself a SEAL iterator and nested IterTuple types are used commonly in the
        library. Dereferencing an IterTuple always yields an std::tuple, with each IterTuple element dereferenced.
        Since an IterTuple can be constructed from an std::tuple holding the respective single-parameter constructor
        arguments for each iterator, the dereferenced std::tuple can often be directly passed on to functions expecting
        an IterTuple.

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
        +--------------------------------------------------+
        | std::tuple<RNSIter, CoeffIter, std::uint64_t &>> |
        +------+-------------------+-------------------+---+
               |                   |                   |
               |                   |                   |
               |  std::get<0>      |  std::get<1>      |  std::get<2>
               |                   |                   |
               |                   |                   |
               v                   v                   v
        +-------------+    +---------------+   +-----------------+
        |   RNSIter   |    |   CoeffIter   |   | std::uint64_t & |
        +-------------+    +---------------+   +-----------------+

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
        We have also provided similar functions for nested std::tuple objects, which is necessary when accessing
        the dereferencing of a nested IterTuple.

        @par Typedefs for common PtrIter types
        It is very common to use the types PtrIter<Modulus *> and PtrIter<NTTTables *>. To simplify the
        notation, we have set up typedefs for these: ModulusIter and NTTTablesIter. There are also constant versions
        ConstModulusIter and ConstNTTTablesIter, wrapping pointers to constant Modulus and NTTTables instead.

        @par Creating SEAL iterators
        Iterators are easiest to create using the variadic iter function that, when given one or more arguments that can
        naturally be converted to SEAL iterators, outputs an appropriate iterator, or iterator tuple. Consider again the
        code snippet above, and how confusing the template parameters can become to write. Instead, we can simply write:

        auto I = iter(encrypted1, encrypted2);
        auto J = iter(I, destination);
        auto encrypted1_iter = get<0, 0>(J));
        auto encrypted2_iter = get<0, 1>(J));

        There are three ways to create IterTuples from the iter function. The first way is by passing an IterTuple as
        input, in which case iter outputs a copy of it; there should be no reason to do this. The second way is by
        passing a variadic set of constructor arguments; iter will output an IterTuple consisting of SEAL iterators
        that are compatible with the given constructor arguments. The third way is by passing a std::tuple consisting
        of a variadic set of constructor arguments; the behavior is as in the second way.

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
            ntt_negacyclic_harvey_lazy(get<0>(I), get<1>(I));
        });

        Here iter outputs an IterTuple<RNSIter, ConstNTTTablesIter>. In this case the lambda function to be called
        is defined inline. The argument I takes values IterTuple<CoeffIter, const NTTTables *>, and for each step the
        CoeffIter overload of ntt_negacyclic_harvey_lazy is called, with a reference to a matching NTTTables object.

        @par Coding conventions
        There are two important coding conventions in the above code snippets that are to be observed:

            1. Use I, J, K, ... for the lambda function parameters representing SEAL iterators. This is compact and
               makes it very clear that the objects in question are SEAL iterators since such variable names should not
               be used in SEAL in any other context.
            2. Lambda functions passed to SEAL_ITERATE should almost always (see 3.) take a parameter of type auto. This
               will produce simple looking code that performs well with the expected outcome.
            3. The only exception to 2. is when SEAL_ITERATE operates on a single PtrIter<T *>: dereferencing returns a
               T &, which may be important to forward by reference to the lambda function. For an example of this, see
               seal::util::ntt_negacyclic_harvey in seal/util/ntt.h, where the lambda function parameter is auto &.

               Note: IterTuple<PolyIter, CoeffIter> will dereference to std::tuple<RNSIter, std::uint64_t &>, which can
               safely be passed by value to the lambda function. Hence, a parameter of type auto in the lambda function
               will most likely work as expected.

               Note: Another approach that would always behave correctly is by using a forwarding reference auto && as
               the lambda function parameter. However, we feel that this unnecessarily complicates the code for a minor
               benefit.

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
        and this works also for multi-argument calls to iter. Dereferencing a SeqIter object returns the current value.
        For opposite direction indexing, simply wrap a SeqIter into a ReverseIter, or call reverse_iter directly with
        the start index.

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
        buffers and setting up PtrIter<T *>, StrideIter<T *>, RNSIter, and CoeffIter objects as well.
        */

        class SEALIterBase
        {};

        template <typename T, typename>
        class SeqIter;

        template <typename T>
        class PtrIter;

        template <typename T>
        class StrideIter;

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
            struct IterType;

            template <typename T>
            struct IterType<std::enable_if_t<std::is_arithmetic<T>::value>, T>
            {
                using type = SeqIter<T, void>;
            };

            template <typename T>
            struct IterType<
                std::enable_if_t<std::is_base_of<SEALIterBase, std::decay_t<T>>::value && !std::is_pointer<T>::value>,
                T>
            {
                using type = std::decay_t<T>;
            };

            template <>
            struct IterType<void, Ciphertext &>
            {
                using type = PolyIter;
            };

            template <>
            struct IterType<void, const Ciphertext &>
            {
                using type = ConstPolyIter;
            };

            template <typename T>
            struct IterType<void, const T *>
            {
                using type = PtrIter<const T *>;
            };

            template <typename T>
            struct IterType<void, T *>
            {
                using type = PtrIter<T *>;
            };

            template <typename T>
            struct IterType<void, const T *&>
            {
                using type = PtrIter<const T *>;
            };

            template <typename T>
            struct IterType<void, T *&>
            {
                using type = PtrIter<T *>;
            };

            template <typename T>
            struct IterType<void, std::vector<T> &>
            {
                using type = PtrIter<T *>;
            };

            template <typename T>
            struct IterType<void, const std::vector<T> &>
            {
                using type = PtrIter<const T *>;
            };

            template <typename T>
            struct IterType<void, Pointer<T> &>
            {
                using type = PtrIter<T *>;
            };

            template <typename T>
            struct IterType<void, const Pointer<T> &>
            {
                using type = PtrIter<T *>;
            };

            template <typename T>
            struct IterType<void, ConstPointer<T> &>
            {
                using type = PtrIter<const T *>;
            };

            template <typename T>
            struct IterType<void, const ConstPointer<T> &>
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
            using value_type = T;
            using pointer = void;
            using reference = const value_type &;
            using iterator_category = std::random_access_iterator_tag;
            using difference_type = std::ptrdiff_t;

            SeqIter() = default;

            SeqIter(T start) : value_(start)
            {}

            SeqIter(const self_type &copy) = default;

            self_type &operator=(const self_type &assign) = default;

            SEAL_NODISCARD inline reference operator*() const noexcept
            {
                return value_;
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
                return static_cast<difference_type>(value_) - static_cast<difference_type>(b.value_);
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

            SEAL_NODISCARD inline operator T() const noexcept
            {
                return value_;
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
            using value_type = T &;
            using pointer = T *;
            using reference = value_type;
            using iterator_category = std::random_access_iterator_tag;
            using difference_type = std::ptrdiff_t;

            PtrIter() = default;

            template <typename S>
            PtrIter(S *ptr) noexcept : ptr_(ptr)
            {}

            template <typename S>
            PtrIter(PtrIter<S *> copy) noexcept : ptr_(copy.ptr())
            {}

            template <typename S>
            PtrIter(std::vector<S> &arr) noexcept : PtrIter(arr.data())
            {}

            template <typename S>
            PtrIter(const std::vector<S> &arr) noexcept : PtrIter(arr.data())
            {}

            template <typename S>
            PtrIter(const Pointer<S> &arr) noexcept : PtrIter(arr.get())
            {}

            template <typename S>
            inline self_type &operator=(const PtrIter<S *> &assign) noexcept
            {
                ptr_ = assign.ptr();
                return *this;
            }

            SEAL_NODISCARD inline reference operator*() const noexcept
            {
                return *ptr_;
            }

            template <typename SizeT>
            SEAL_NODISCARD inline reference operator[](SizeT n) const noexcept
            {
                return ptr_[n];
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
                return std::distance(b.ptr(), ptr_);
            }

            template <typename S>
            SEAL_NODISCARD inline bool operator==(const PtrIter<S *> &compare) const noexcept
            {
                return ptr_ == compare.ptr();
            }

            template <typename S>
            SEAL_NODISCARD inline bool operator!=(const PtrIter<S *> &compare) const noexcept
            {
                return !(*this == compare);
            }

            template <typename S>
            SEAL_NODISCARD inline bool operator<(const PtrIter<S *> &compare) const noexcept
            {
                return ptr_ < compare.ptr();
            }

            template <typename S>
            SEAL_NODISCARD inline bool operator>(const PtrIter<S *> &compare) const noexcept
            {
                return ptr_ > compare.ptr();
            }

            template <typename S>
            SEAL_NODISCARD inline bool operator<=(const PtrIter<S *> &compare) const noexcept
            {
                return !(ptr_ > compare.ptr());
            }

            template <typename S>
            SEAL_NODISCARD inline bool operator>=(const PtrIter<S *> &compare) const noexcept
            {
                return !(ptr_ < compare.ptr());
            }

            SEAL_NODISCARD explicit inline operator bool() const noexcept
            {
                return nullptr != ptr_;
            }

            SEAL_NODISCARD inline reference operator->() const noexcept
            {
                return **this;
            }

            SEAL_NODISCARD inline pointer ptr() const noexcept
            {
                return ptr_;
            }

            SEAL_NODISCARD inline operator pointer() const noexcept
            {
                return ptr_;
            }

        private:
            pointer ptr_ = nullptr;
        };

        template <typename T>
        class StrideIter<T *> : public SEALIterBase
        {
        public:
            using self_type = StrideIter;

            // Standard iterator typedefs
            using value_type = PtrIter<T *>;
            using pointer = T *;
            using reference = const value_type &;
            using iterator_category = std::random_access_iterator_tag;
            using difference_type = std::ptrdiff_t;

            StrideIter() = default;

            template <typename S>
            StrideIter(S *ptr, std::size_t stride) noexcept : ptr_it_(ptr), stride_(stride)
            {}

            template <typename S>
            StrideIter(StrideIter<S *> copy) noexcept : ptr_it_(copy.ptr()), stride_(copy.stride())
            {}

            template <typename S>
            StrideIter(std::vector<S> &arr, std::size_t stride) noexcept : StrideIter(arr.data(), stride)
            {}

            template <typename S>
            StrideIter(const std::vector<S> &arr, std::size_t stride) noexcept : StrideIter(arr.data(), stride)
            {}

            template <typename S>
            StrideIter(const Pointer<S> &arr, std::size_t stride) noexcept : StrideIter(arr.get(), stride)
            {}

            template <typename S>
            inline self_type &operator=(const StrideIter<S *> &assign) noexcept
            {
                ptr_it_ = assign.ptr();
                stride_ = assign.stride();
                return *this;
            }

            SEAL_NODISCARD inline reference operator*() const noexcept
            {
                return ptr_it_;
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
                ptr_it_ += static_cast<difference_type>(stride_);
                return *this;
            }

            inline self_type operator++(int) noexcept
            {
                self_type result(*this);
                ptr_it_ += static_cast<difference_type>(stride_);
                return result;
            }

            inline self_type &operator--() noexcept
            {
                ptr_it_ -= static_cast<difference_type>(stride_);
                return *this;
            }

            inline self_type operator--(int) noexcept
            {
                self_type result(*this);
                ptr_it_ -= static_cast<difference_type>(stride_);
                return result;
            }

            template <typename SizeT>
            inline self_type &operator+=(SizeT n) noexcept
            {
                ptr_it_ += static_cast<difference_type>(n) * static_cast<difference_type>(stride_);
                return *this;
            }

            template <typename SizeT>
            SEAL_NODISCARD inline self_type operator+(SizeT n) const noexcept
            {
                self_type result(*this);
                result.ptr_it_ += static_cast<difference_type>(n) * static_cast<difference_type>(stride_);
                return result;
            }

            template <typename SizeT>
            inline self_type &operator-=(SizeT n) noexcept
            {
                ptr_it_ -= static_cast<difference_type>(n) * static_cast<difference_type>(stride_);
                return *this;
            }

            template <typename SizeT>
            SEAL_NODISCARD inline self_type operator-(SizeT n) const noexcept
            {
                return *this + (-static_cast<difference_type>(n));
            }

            template <typename S>
            SEAL_NODISCARD inline difference_type operator-(const StrideIter<S *> &b) const
            {
#ifdef SEAL_DEBUG
                if (!stride_)
                {
                    throw std::logic_error("stride cannot be zero");
                }
                if (stride_ != b.stride())
                {
                    throw std::invalid_argument("incompatible iterators");
                }
#endif
                return (ptr_it_ - *b) / static_cast<difference_type>(stride_);
            }

            template <typename S>
            SEAL_NODISCARD inline bool operator==(const StrideIter<S *> &compare) const noexcept
            {
                return ptr_it_ == *compare;
            }

            template <typename S>
            SEAL_NODISCARD inline bool operator!=(const StrideIter<S *> &compare) const noexcept
            {
                return !(*this == compare);
            }

            template <typename S>
            SEAL_NODISCARD inline bool operator<(const StrideIter<S *> &compare) const noexcept
            {
                return ptr_it_ < *compare;
            }

            template <typename S>
            SEAL_NODISCARD inline bool operator>(const StrideIter<S *> &compare) const noexcept
            {
                return ptr_it_ > *compare;
            }

            template <typename S>
            SEAL_NODISCARD inline bool operator<=(const StrideIter<S *> &compare) const noexcept
            {
                return !(ptr_it_ > *compare);
            }

            template <typename S>
            SEAL_NODISCARD inline bool operator>=(const StrideIter<S *> &compare) const noexcept
            {
                return !(ptr_it_ < *compare);
            }

            SEAL_NODISCARD explicit inline operator bool() const noexcept
            {
                return static_cast<bool>(ptr_it_);
            }

            SEAL_NODISCARD inline reference operator->() const noexcept
            {
                return **this;
            }

            SEAL_NODISCARD inline std::size_t stride() const noexcept
            {
                return stride_;
            }

            SEAL_NODISCARD inline pointer ptr() const noexcept
            {
                return ptr_it_.ptr();
            }

            SEAL_NODISCARD inline operator pointer() const noexcept
            {
                return ptr_it_.operator pointer();
            }

        private:
            PtrIter<T *> ptr_it_ = {};

            std::size_t stride_ = 0;
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

            RNSIter() : ptr_it_(), step_size_(0)
            {}

            RNSIter(std::uint64_t *ptr, std::size_t poly_modulus_degree) : ptr_it_(ptr), step_size_(poly_modulus_degree)
            {}

            RNSIter(const self_type &copy) = default;

            self_type &operator=(const self_type &assign) = default;

            template <typename S>
            RNSIter(const StrideIter<S *> &stride_it) : RNSIter(stride_it.ptr(), stride_it.stride())
            {}

            template <typename S>
            inline self_type &operator=(const StrideIter<S *> &assign)
            {
                ptr_it_ = assign;
                step_size_ = assign.stride();
                return *this;
            }

            SEAL_NODISCARD inline reference operator*() const noexcept
            {
                return ptr_it_;
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
                ptr_it_ += static_cast<difference_type>(step_size_);
                return *this;
            }

            inline self_type operator++(int) noexcept
            {
                self_type result(*this);
                ptr_it_ += static_cast<difference_type>(step_size_);
                return result;
            }

            inline self_type &operator--() noexcept
            {
                ptr_it_ -= static_cast<difference_type>(step_size_);
                return *this;
            }

            inline self_type operator--(int) noexcept
            {
                self_type result(*this);
                ptr_it_ -= static_cast<difference_type>(step_size_);
                return result;
            }

            template <typename SizeT>
            inline self_type &operator+=(SizeT n) noexcept
            {
                ptr_it_ += static_cast<difference_type>(n) * static_cast<difference_type>(step_size_);
                return *this;
            }

            template <typename SizeT>
            SEAL_NODISCARD inline self_type operator+(SizeT n) const noexcept
            {
                self_type result(*this);
                result.ptr_it_ += static_cast<difference_type>(n) * static_cast<difference_type>(step_size_);
                return result;
            }

            template <typename SizeT>
            inline self_type &operator-=(SizeT n) noexcept
            {
                ptr_it_ -= static_cast<difference_type>(n) * static_cast<difference_type>(step_size_);
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
                return (ptr_it_ - b.ptr_it_) / static_cast<difference_type>(step_size_);
            }

            SEAL_NODISCARD inline bool operator==(const self_type &compare) const noexcept
            {
                return ptr_it_ == compare.ptr_it_;
            }

            SEAL_NODISCARD inline bool operator!=(const self_type &compare) const noexcept
            {
                return !(*this == compare);
            }

            SEAL_NODISCARD inline bool operator<(const self_type &compare) const noexcept
            {
                return ptr_it_ < compare.ptr_it_;
            }

            SEAL_NODISCARD inline bool operator>(const self_type &compare) const noexcept
            {
                return ptr_it_ > compare.ptr_it_;
            }

            SEAL_NODISCARD inline bool operator<=(const self_type &compare) const noexcept
            {
                return !(ptr_it_ > compare.ptr_it_);
            }

            SEAL_NODISCARD inline bool operator>=(const self_type &compare) const noexcept
            {
                return !(ptr_it_ < compare.ptr_it_);
            }

            SEAL_NODISCARD inline operator std::uint64_t *() const noexcept
            {
                return static_cast<std::uint64_t *>(ptr_it_);
            }

            SEAL_NODISCARD explicit inline operator bool() const noexcept
            {
                return static_cast<bool>(ptr_it_);
            }

            SEAL_NODISCARD inline reference operator->() const noexcept
            {
                return **this;
            }

            SEAL_NODISCARD inline std::size_t poly_modulus_degree() const noexcept
            {
                return step_size_;
            }

        private:
            CoeffIter ptr_it_ = {};

            std::size_t step_size_ = 0;
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

            ConstRNSIter() : ptr_it_(), step_size_(0)
            {}

            ConstRNSIter(const std::uint64_t *ptr, std::size_t poly_modulus_degree)
                : ptr_it_(ptr), step_size_(poly_modulus_degree)
            {}

            ConstRNSIter(const self_type &copy) = default;

            self_type &operator=(const self_type &assign) = default;

            ConstRNSIter(const RNSIter &copy)
                : ptr_it_(static_cast<const std::uint64_t *>(copy)), step_size_(copy.poly_modulus_degree())
            {}

            template <typename S>
            ConstRNSIter(const StrideIter<S *> &stride_it) : ConstRNSIter(stride_it.ptr(), stride_it.stride())
            {}

            template <typename S>
            inline self_type &operator=(const StrideIter<S *> &assign)
            {
                ptr_it_ = assign;
                step_size_ = assign.stride();
                return *this;
            }

            SEAL_NODISCARD inline reference operator*() const noexcept
            {
                return ptr_it_;
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
                ptr_it_ += static_cast<difference_type>(step_size_);
                return *this;
            }

            inline self_type operator++(int) noexcept
            {
                self_type result(*this);
                ptr_it_ += static_cast<difference_type>(step_size_);
                return result;
            }

            inline self_type &operator--() noexcept
            {
                ptr_it_ -= static_cast<difference_type>(step_size_);
                return *this;
            }

            inline self_type operator--(int) noexcept
            {
                self_type result(*this);
                ptr_it_ -= static_cast<difference_type>(step_size_);
                return result;
            }

            template <typename SizeT>
            inline self_type &operator+=(SizeT n) noexcept
            {
                ptr_it_ += static_cast<difference_type>(n) * static_cast<difference_type>(step_size_);
                return *this;
            }

            template <typename SizeT>
            SEAL_NODISCARD inline self_type operator+(SizeT n) const noexcept
            {
                self_type result(*this);
                result.ptr_it_ += static_cast<difference_type>(n) * static_cast<difference_type>(step_size_);
                return result;
            }

            template <typename SizeT>
            inline self_type &operator-=(SizeT n) noexcept
            {
                ptr_it_ -= static_cast<difference_type>(n) * static_cast<difference_type>(step_size_);
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
                return (ptr_it_ - b.ptr_it_) / static_cast<difference_type>(step_size_);
            }

            SEAL_NODISCARD inline bool operator==(const self_type &compare) const noexcept
            {
                return ptr_it_ == compare.ptr_it_;
            }

            SEAL_NODISCARD inline bool operator!=(const self_type &compare) const noexcept
            {
                return !(*this == compare);
            }

            SEAL_NODISCARD inline bool operator<(const self_type &compare) const noexcept
            {
                return ptr_it_ < compare.ptr_it_;
            }

            SEAL_NODISCARD inline bool operator>(const self_type &compare) const noexcept
            {
                return ptr_it_ > compare.ptr_it_;
            }

            SEAL_NODISCARD inline bool operator<=(const self_type &compare) const noexcept
            {
                return !(ptr_it_ > compare.ptr_it_);
            }

            SEAL_NODISCARD inline bool operator>=(const self_type &compare) const noexcept
            {
                return !(ptr_it_ < compare.ptr_it_);
            }

            SEAL_NODISCARD inline operator const std::uint64_t *() const noexcept
            {
                return static_cast<const std::uint64_t *>(ptr_it_);
            }

            SEAL_NODISCARD explicit inline operator bool() const noexcept
            {
                return static_cast<bool>(ptr_it_);
            }

            SEAL_NODISCARD inline reference operator->() const noexcept
            {
                return **this;
            }

            SEAL_NODISCARD inline std::size_t poly_modulus_degree() const noexcept
            {
                return step_size_;
            }

        private:
            ConstCoeffIter ptr_it_ = {};

            std::size_t step_size_ = 0;
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
                rns_it_.ptr_it_ += step_size_;
                return *this;
            }

            inline self_type operator++(int) noexcept
            {
                self_type result(*this);
                rns_it_.ptr_it_ += step_size_;
                return result;
            }

            inline self_type &operator--() noexcept
            {
                rns_it_.ptr_it_ -= step_size_;
                return *this;
            }

            inline self_type operator--(int) noexcept
            {
                self_type result(*this);
                rns_it_.ptr_it_ -= step_size_;
                return result;
            }

            template <typename SizeT>
            inline self_type &operator+=(SizeT n) noexcept
            {
                rns_it_.ptr_it_ += static_cast<difference_type>(n) * static_cast<difference_type>(step_size_);
                return *this;
            }

            template <typename SizeT>
            SEAL_NODISCARD inline self_type operator+(SizeT n) const noexcept
            {
                self_type result(*this);
                result.rns_it_.ptr_it_ += static_cast<difference_type>(n) * static_cast<difference_type>(step_size_);
                return result;
            }

            template <typename SizeT>
            inline self_type &operator-=(SizeT n) noexcept
            {
                rns_it_.ptr_it_ -= static_cast<difference_type>(n) * static_cast<difference_type>(step_size_);
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
                return (rns_it_.ptr_it_ - b.rns_it_.ptr_it_) / static_cast<difference_type>(step_size_);
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

            SEAL_NODISCARD inline reference operator->() const noexcept
            {
                return **this;
            }

            SEAL_NODISCARD inline std::size_t poly_modulus_degree() const noexcept
            {
                return rns_it_.poly_modulus_degree();
            }

            SEAL_NODISCARD inline std::size_t coeff_modulus_size() const noexcept
            {
                return coeff_modulus_size_;
            }

        private:
            RNSIter rns_it_ = {};

            std::size_t coeff_modulus_size_ = 0;

            std::size_t step_size_ = 0;
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

            ConstPolyIter(const PolyIter &copy)
                : rns_it_(static_cast<const std::uint64_t *>(copy), copy.poly_modulus_degree()),
                  coeff_modulus_size_(copy.coeff_modulus_size()),
                  step_size_(mul_safe(rns_it_.poly_modulus_degree(), coeff_modulus_size_))
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
                rns_it_.ptr_it_ += step_size_;
                return *this;
            }

            inline self_type operator++(int) noexcept
            {
                self_type result(*this);
                rns_it_.ptr_it_ += step_size_;
                return result;
            }

            inline self_type &operator--() noexcept
            {
                rns_it_.ptr_it_ -= step_size_;
                return *this;
            }

            inline self_type operator--(int) noexcept
            {
                self_type result(*this);
                rns_it_.ptr_it_ -= step_size_;
                return result;
            }

            template <typename SizeT>
            inline self_type &operator+=(SizeT n) noexcept
            {
                rns_it_.ptr_it_ += static_cast<difference_type>(n) * static_cast<difference_type>(step_size_);
                return *this;
            }

            template <typename SizeT>
            SEAL_NODISCARD inline self_type operator+(SizeT n) const noexcept
            {
                self_type result(*this);
                result.rns_it_.ptr_it_ += static_cast<difference_type>(n) * static_cast<difference_type>(step_size_);
                return result;
            }

            template <typename SizeT>
            inline self_type &operator-=(SizeT n) noexcept
            {
                rns_it_.ptr_it_ -= static_cast<difference_type>(n) * static_cast<difference_type>(step_size_);
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
                return (rns_it_.ptr_it_ - b.rns_it_.ptr_it_) / static_cast<difference_type>(step_size_);
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

            SEAL_NODISCARD inline reference operator->() const noexcept
            {
                return **this;
            }

            SEAL_NODISCARD inline std::size_t poly_modulus_degree() const noexcept
            {
                return rns_it_.poly_modulus_degree();
            }

            SEAL_NODISCARD inline std::size_t coeff_modulus_size() const noexcept
            {
                return coeff_modulus_size_;
            }

        private:
            ConstRNSIter rns_it_ = {};

            std::size_t coeff_modulus_size_ = 0;

            std::size_t step_size_ = 0;
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

            ReverseIter(const self_type &copy) = default;

            self_type &operator=(const self_type &assign) = default;

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

            SEAL_NODISCARD inline reference operator->() const noexcept
            {
                return **this;
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

            template <typename... Ts>
            struct extend_std_tuple;

            template <typename T, typename... Rest>
            struct extend_std_tuple<T, std::tuple<Rest...>>
            {
                using type = std::tuple<T, Rest...>;
            };

            template <typename T1, typename T2>
            struct extend_std_tuple<T1, T2>
            {
                using type = std::tuple<T1, T2>;
            };
        } // namespace iterator_internal

        template <typename SEALIter, typename... Rest>
        class IterTuple<SEALIter, Rest...> : public SEALIterBase
        {
        public:
            static_assert(
                std::is_base_of<SEALIterBase, SEALIter>::value,
                "Template parameter must derive from seal::util::SEALIterBase");

            using self_type = IterTuple<SEALIter, Rest...>;

            // Standard iterator typedefs
            using value_type = typename iterator_internal::extend_std_tuple<
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

            template <typename... Ts>
            IterTuple(const std::tuple<Ts...> &tp)
                : IterTuple(seal_apply(
                      [](auto &&... args) -> IterTuple { return { std::forward<decltype(args)>(args)... }; },
                      std::forward<decltype(tp)>(tp)))
            {
                static_assert(
                    sizeof...(Ts) == sizeof...(Rest) + 1, "std::tuple size does not match seal::util::IterTuple size");
            }

            template <typename... Ts>
            IterTuple(std::tuple<Ts...> &&tp)
                : IterTuple(seal_apply(
                      [](auto &&... args) -> IterTuple && { return { std::forward<decltype(args)>(args)... }; },
                      std::forward<decltype(tp)>(tp)))
            {
                static_assert(
                    sizeof...(Ts) == sizeof...(Rest) + 1, "std::tuple size does not match seal::util::IterTuple size");
            }

            IterTuple(const self_type &copy) = default;

            self_type &operator=(const self_type &assign) = default;

            SEAL_NODISCARD inline value_type operator*() const noexcept
            {
                return seal_apply(
                    [this](auto &&... args) -> value_type {
                        return { *first_, std::forward<decltype(args)>(args)... };
                    },
                    *rest_);
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
            SEALIter first_ = {};

            IterTuple<Rest...> rest_ = {};
        };

        template <typename SEALIter>
        class IterTuple<SEALIter> : public SEALIterBase
        {
        public:
            static_assert(
                std::is_base_of<SEALIterBase, SEALIter>::value,
                "Template parameter must derive from seal::util::SEALIterBase");

            using self_type = IterTuple<SEALIter>;

            // Standard iterator typedefs
            using value_type = std::tuple<typename std::iterator_traits<SEALIter>::value_type>;
            using pointer = void;
            using reference = const value_type &;
            using iterator_category = std::random_access_iterator_tag;
            using difference_type = std::ptrdiff_t;

            IterTuple(){};

            IterTuple(SEALIter first) : first_(first)
            {}

            template <typename T>
            IterTuple(const std::tuple<T> &tp) : IterTuple(std::get<0>(std::forward<decltype(tp)>(tp)))
            {}

            template <typename T>
            IterTuple(std::tuple<T> &&tp) : IterTuple(std::get<0>(std::forward<decltype(tp)>(tp)))
            {}

            IterTuple(const self_type &copy) = default;

            self_type &operator=(const self_type &assign) = default;

            SEAL_NODISCARD inline value_type operator*() const noexcept
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

            SEAL_NODISCARD inline reference operator->() const noexcept
            {
                return **this;
            }

            SEAL_NODISCARD inline const SEALIter &first() const noexcept
            {
                return first_;
            }

        private:
            SEALIter first_ = {};
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
                SEAL_NODISCARD static auto Apply(const IterTuple<SEALIter, Rest...> &it) noexcept
                {
                    return GetHelperStruct<N - 1>::Apply(it.rest());
                }
            };

            template <>
            struct GetHelperStruct<0>
            {
                template <typename SEALIter, typename... Rest>
                SEAL_NODISCARD static auto Apply(const IterTuple<SEALIter, Rest...> &it) noexcept
                {
                    return it.first();
                }
            };

            template <std::size_t N, typename... SEALIters>
            SEAL_NODISCARD inline auto get(const IterTuple<SEALIters...> &it) noexcept
            {
                static_assert(N < sizeof...(SEALIters), "seal::util::IterTuple index out of range");
                return iterator_internal::GetHelperStruct<N>::Apply(it);
            }

            template <typename T, typename... Rest>
            struct IterType<
                seal_void_t<
                    std::enable_if_t<(sizeof...(Rest) > 0)>, typename IterType<void, T>::type,
                    typename IterType<void, Rest...>::type>,
                T, Rest...>
            {
                using type = typename extend_iter_tuple<
                    typename IterType<void, T>::type, typename IterType<void, Rest...>::type>::type;
            };

            template <typename... Ts>
            struct IterType<void, const std::tuple<Ts...> &>
            {
                using type = typename IterType<void, Ts...>::type;
            };

            template <typename... Ts>
            struct IterType<void, std::tuple<Ts...> &>
            {
                using type = typename IterType<void, Ts...>::type;
            };
        } // namespace iterator_internal

        template <
            std::size_t N, std::size_t... Rest, typename... SEALIters, typename = std::enable_if_t<sizeof...(Rest)>>
        SEAL_NODISCARD inline auto get(const IterTuple<SEALIters...> &it) noexcept
        {
            return get<Rest...>(iterator_internal::get<N>(it));
        }

        template <std::size_t N, typename... SEALIters>
        SEAL_NODISCARD inline auto get(const IterTuple<SEALIters...> &it) noexcept
        {
            return iterator_internal::get<N>(it);
        }

        template <std::size_t N, std::size_t... Rest, typename... Ts, typename = std::enable_if_t<sizeof...(Rest)>>
        SEAL_NODISCARD inline auto get(const std::tuple<Ts...> &tp) noexcept
        {
            return get<Rest...>(std::get<N>(tp));
        }

        template <typename... Ts>
        SEAL_NODISCARD inline auto iter(Ts &&... ts) noexcept -> typename iterator_internal::IterType<void, Ts...>::type
        {
            return { std::forward<Ts>(ts)... };
        }

        template <typename... Ts>
        SEAL_NODISCARD inline auto reverse_iter(Ts &&... ts) noexcept
            -> ReverseIter<typename iterator_internal::IterType<void, Ts...>::type>
        {
            return typename iterator_internal::IterType<void, Ts...>::type(std::forward<Ts>(ts)...);
        }
    } // namespace util
} // namespace seal
