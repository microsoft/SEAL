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
        inline int bit_count() const
        {
            return bit_count_;
        }

        /**
        Returns the size (in 64-bit words) of the value of the current SmallModulus.
        */
        inline std::size_t uint64_count() const
        {
            return uint64_count_;
        }

        /**
        Returns a const pointer to the value of the current SmallModulus.
        */
        inline const uint64_t *data() const
        {
            return &value_;
        }

        /**
        Returns the value of the current SmallModulus.
        */
        inline std::uint64_t value() const
        {
            return value_;
        }

        /**
        Returns the Barrett ratio computed for the value of the current SmallModulus.
        The first two components of the Barrett ratio are the floor of 2^128/value,
        and the third component is the remainder.
        */
        inline auto &const_ratio() const
        {
            return const_ratio_;
        }

        /**
        Returns whether the value of the current SmallModulus is zero.
        */
        inline bool is_zero() const
        {
            return value_ == 0;
        }

        /**
        Compares two SmallModulus instances.

        @param[in] compare The SmallModulus to compare against
        */
        inline bool operator ==(const SmallModulus &compare) const
        {
            return value_ == compare.value_;
        }

        /**
        Compares two SmallModulus instances.

        @param[in] compare The SmallModulus to compare against
        */
        inline bool operator !=(const SmallModulus &compare) const
        {
            return !(value_ == compare.value_);
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

    private:
        SmallModulus(std::uint64_t value,
            std::array<std::uint64_t, 3> const_ratio,
            int bit_count, std::size_t uint64_count) :
            value_(value), const_ratio_(const_ratio),
            bit_count_(bit_count), uint64_count_(uint64_count)
        {
        }

        void set_value(std::uint64_t value);

        std::uint64_t value_ = 0;

        std::array<std::uint64_t, 3> const_ratio_{ { 0, 0, 0 } };

        int bit_count_ = 0;

        std::size_t uint64_count_ = 0;
    };


    /**
    Returns true if value is a prime based on Miller-Rabin primality test.
    @par[in] in The SmallModulus to be tested.
    @par[in] num_rounds The number of rounds of testing to be performed.
    Note: Input uses SmallModulus for faster modular arithmetic required in
    Miller-Rabin test, in comparison to using std::uint64_t.
    */
    bool is_prime(const SmallModulus &input, std::size_t num_rounds = 40);

    /**
    Returns in decreasing order a vector of the largest prime numbers with a
    given bitsize that all support NTTs of a given size.
    @par[in] bit_size the bit_size of primes to be generated, no less than 2 and
    no larger than 62
    @par[in] count the total number of primes to be generated, larger than 0
    @par[in] ntt_size equals to poly_modulus_degree in EncryptionParms, so that
    all primes support NTT for a given parameter set
    @throws std::logic_error if cannot find enough qualifying primes
    */
    inline std::vector<SmallModulus> get_primes(std::size_t bit_size,
        std::size_t count, std::size_t ntt_size)
    {
        if (bit_size >= 63 || bit_size <= 1)
        {
            throw std::invalid_argument("A prime must have at least 2 bit and at most 62 bits.");
        }
        if (0 == count)
        {
            throw std::invalid_argument("The count of primes to be generated must be positive.");
        }
        std::vector<SmallModulus> destination(count);
        auto dest = destination.begin();
        std::uint64_t factor = 2 * static_cast<std::uint64_t>(ntt_size);
        // start with 2^bit_size - 2 * ntt_size + 1
        std::uint64_t value = (uint64_t(0x1) << bit_size) - factor + 1;
        while (count > 0 && value > (uint64_t(0x1) << (bit_size - 1)))
        {
            *dest = value;
            if (is_prime(*dest))
            {
                count--;
                dest++;
            }
            value -= factor;
        }

        if (count > 0)
        {
            throw std::logic_error("Cannot find enough qualifying primes");
        }
        return destination;
    }
}
