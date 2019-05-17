// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#pragma once

#include <cstdint>
#include <iostream>
#include <array>
#include "seal/util/uintcore.h"
#include "seal/memorymanager.h"

namespace seal
{
    /**
    Represent an integer modulus of up to 62 bits. An instance of the SmallModulus
    class represents a non-negative integer modulus up to 62 bits. In particular,
    the encryption parameter plain_modulus, and the primes in coeff_modulus, are
    represented by instances of SmallModulus. The purpose of this class is to
    perform and store the pre-computation required by Barrett reduction.

    @par Thread Safety
    In general, reading from SmallModulus is thread-safe as long as no other thread
    is concurrently mutating it.

    @see EncryptionParameters for a description of the encryption parameters.
    */
    class SmallModulus
    {
    public:
        /**
        Creates a SmallModulus instance. The value of the SmallModulus is set to
        the given value, or to zero by default.

        @param[in] value The integer modulus
        @throws std::invalid_argument if value is 1 or more than 62 bits
        */
        SmallModulus(std::uint64_t value = 0)
        {
            set_value(value);
        }

        /**
        Creates a new SmallModulus by copying a given one.

        @param[in] copy The SmallModulus to copy from
        */
        SmallModulus(const SmallModulus &copy) = default;

        /**
        Creates a new SmallModulus by copying a given one.

        @param[in] source The SmallModulus to move from
        */
        SmallModulus(SmallModulus &&source) = default;

        /**
        Copies a given SmallModulus to the current one.

        @param[in] assign The SmallModulus to copy from
        */
        SmallModulus &operator =(const SmallModulus &assign) = default;

        /**
        Moves a given SmallModulus to the current one.

        @param[in] assign The SmallModulus to move from
        */
        SmallModulus &operator =(SmallModulus &&assign) = default;

        /**
        Sets the value of the SmallModulus.

        @param[in] value The new integer modulus
        @throws std::invalid_argument if value is 1 or more than 62 bits
        */
        inline SmallModulus &operator =(std::uint64_t value)
        {
            set_value(value);
            return *this;
        }

        /**
        Returns the significant bit count of the value of the current SmallModulus.
        */
        inline int bit_count() const noexcept
        {
            return bit_count_;
        }

        /**
        Returns the size (in 64-bit words) of the value of the current SmallModulus.
        */
        inline std::size_t uint64_count() const noexcept
        {
            return uint64_count_;
        }

        /**
        Returns a const pointer to the value of the current SmallModulus.
        */
        inline const uint64_t *data() const noexcept
        {
            return &value_;
        }

        /**
        Returns the value of the current SmallModulus.
        */
        inline std::uint64_t value() const noexcept
        {
            return value_;
        }

        /**
        Returns the Barrett ratio computed for the value of the current SmallModulus.
        The first two components of the Barrett ratio are the floor of 2^128/value,
        and the third component is the remainder.
        */
        inline auto &const_ratio() const noexcept
        {
            return const_ratio_;
        }

        /**
        Returns whether the value of the current SmallModulus is zero.
        */
        inline bool is_zero() const noexcept
        {
            return value_ == 0;
        }

        /**
        Returns whether the value of the current SmallModulus is a prime number.
        */
        inline bool is_prime() const noexcept
        {
            return is_prime_;
        }

        /**
        Compares two SmallModulus instances.

        @param[in] compare The SmallModulus to compare against
        */
        inline bool operator ==(const SmallModulus &compare) const noexcept
        {
            return value_ == compare.value_;
        }

        /**
        Compares a SmallModulus value to an unsigned integer.

        @param[in] compare The unsigned integer to compare against
        */
        inline bool operator ==(std::uint64_t compare) const noexcept
        {
            return value_ == compare;
        }

        /**
        Compares two SmallModulus instances.

        @param[in] compare The SmallModulus to compare against
        */
        inline bool operator !=(const SmallModulus &compare) const noexcept
        {
            return !(value_ == compare.value_);
        }

        /**
        Compares a SmallModulus value to an unsigned integer.

        @param[in] compare The unsigned integer to compare against
        */
        inline bool operator !=(std::uint64_t compare) const noexcept
        {
            return value_ != compare;
        }

        /**
        Compares two SmallModulus instances.

        @param[in] compare The SmallModulus to compare against
        */
        inline bool operator <(const SmallModulus &compare) const noexcept
        {
            return value_ < compare.value_;
        }

        /**
        Compares a SmallModulus value to an unsigned integer.

        @param[in] compare The unsigned integer to compare against
        */
        inline bool operator <(std::uint64_t compare) const noexcept
        {
            return value_ < compare;
        }

        /**
        Compares two SmallModulus instances.

        @param[in] compare The SmallModulus to compare against
        */
        inline bool operator <=(const SmallModulus &compare) const noexcept
        {
            return value_ <= compare.value_;
        }

        /**
        Compares a SmallModulus value to an unsigned integer.

        @param[in] compare The unsigned integer to compare against
        */
        inline bool operator <=(std::uint64_t compare) const noexcept
        {
            return value_ <= compare;
        }

        /**
        Compares two SmallModulus instances.

        @param[in] compare The SmallModulus to compare against
        */
        inline bool operator >(const SmallModulus &compare) const noexcept
        {
            return value_ > compare.value_;
        }

        /**
        Compares a SmallModulus value to an unsigned integer.

        @param[in] compare The unsigned integer to compare against
        */
        inline bool operator >(std::uint64_t compare) const noexcept
        {
            return value_ > compare;
        }

        /**
        Compares two SmallModulus instances.

        @param[in] compare The SmallModulus to compare against
        */
        inline bool operator >=(const SmallModulus &compare) const noexcept
        {
            return value_ >= compare.value_;
        }

        /**
        Compares a SmallModulus value to an unsigned integer.

        @param[in] compare The unsigned integer to compare against
        */
        inline bool operator >=(std::uint64_t compare) const noexcept
        {
            return value_ >= compare;
        }

        /**
        Saves the SmallModulus to an output stream. The full state of the modulus is
        serialized. The output is in binary format and not human-readable. The output
        stream must have the "binary" flag set.

        @param[in] stream The stream to save the SmallModulus to
        @throws std::exception if the SmallModulus could not be written to stream
        */
        void save(std::ostream &stream) const;

        /**
        Loads a SmallModulus from an input stream overwriting the current SmallModulus.

        @param[in] stream The stream to load the SmallModulus from
        @throws std::exception if a valid SmallModulus could not be read from stream
        */
        void load(std::istream &stream);

        /**
        Returns in decreasing order a vector of the largest prime numbers of a given
        length that all support NTTs of a given size. More precisely, the generated
        primes are all congruent to 1 modulo 2 * ntt_size. Typically, the user might
        call this function by passing poly_modulus_degree as ntt_size if the primes
        are to be used as a coefficient modulus primes for encryption parameters.

        @param[in] bit_size the bit-size of primes to be generated, no less than 2 and
        no larger than 62
        @param[in] count The total number of primes to be generated
        @param[in] ntt_size The size of NTT that should be supported
        @throws std::invalid_argument if bit_size is less than 2
        @throws std::invalid_argument if count or ntt_size is zero
        @throws std::logic_error if enough qualifying primes cannot be found
        */
        //static std::vector<SmallModulus> GetPrimes(int bit_size, std::size_t count,
        //    std::size_t ntt_size);

        //static std::vector<SmallModulus> BuildCoeffModulus(
        //    std::size_t poly_modulus_degree, std::vector<int> bit_sizes);

    private:
        void set_value(std::uint64_t value);

        std::uint64_t value_ = 0;

        std::array<std::uint64_t, 3> const_ratio_{ { 0, 0, 0 } };

        std::size_t uint64_count_ = 0;

        int bit_count_ = 0;

        bool is_prime_ = false;
    };
}