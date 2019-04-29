// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include "seal/smallmodulus.h"
#include "seal/util/uintarith.h"
#include "seal/util/uintarithsmallmod.h"
#include "seal/util/common.h"
#include <stdexcept>
#include <random>

using namespace seal::util;
using namespace std;

namespace seal
{
    void SmallModulus::save(ostream &stream) const
    {
        auto old_except_mask = stream.exceptions();
        try
        {
            // Throw exceptions on std::ios_base::badbit and std::ios_base::failbit
            stream.exceptions(ios_base::badbit | ios_base::failbit);

            stream.write(reinterpret_cast<const char*>(&value_), sizeof(uint64_t));
        }
        catch (const exception &)
        {
            stream.exceptions(old_except_mask);
            throw;
        }

        stream.exceptions(old_except_mask);
    }

    void SmallModulus::load(istream &stream)
    {
        auto old_except_mask = stream.exceptions();
        try
        {
            // Throw exceptions on std::ios_base::badbit and std::ios_base::failbit
            stream.exceptions(ios_base::badbit | ios_base::failbit);

            uint64_t value;
            stream.read(reinterpret_cast<char*>(&value), sizeof(uint64_t));
            set_value(value);
        }
        catch (const exception &)
        {
            stream.exceptions(old_except_mask);
            throw;
        }

        stream.exceptions(old_except_mask);
    }

    void SmallModulus::set_value(uint64_t value)
    {
        if (value == 0)
        {
            // Zero settings
            bit_count_ = 0;
            uint64_count_ = 1;
            value_ = 0;
            const_ratio_ = { { 0, 0, 0 } };
            is_prime_ = false;
        }
        else if ((value >> 62 != 0) || (value == uint64_t(0x4000000000000000)) ||
            (value == 1))
        {
            throw invalid_argument("value can be at most 62 bits and cannot be 1");
        }
        else
        {
            // All normal, compute const_ratio and set everything
            value_ = value;
            bit_count_ = get_significant_bit_count(value_);

            // Compute Barrett ratios for 64-bit words (barrett_reduce_128)
            uint64_t numerator[3]{ 0, 0, 1 };
            uint64_t quotient[3]{ 0, 0, 0 };

            // Use a special method to avoid using memory pool
            divide_uint192_uint64_inplace(numerator, value_, quotient);

            const_ratio_[0] = quotient[0];
            const_ratio_[1] = quotient[1];

            // We store also the remainder
            const_ratio_[2] = numerator[0];

            uint64_count_ = 1;

            // Set the primality flag
            is_prime_ = is_prime_internal();
        }
    }

    bool SmallModulus::is_prime_internal(size_t num_rounds) const
    {
        // First check the simplest cases.
        if (value_ < 2)
        {
            return false;
        }
        if (2 == value_)
        {
            return true;
        }
        if (0 == (value_ & 0x1))
        {
            return false;
        }
        if (3 == value_)
        {
            return true;
        }
        if (0 == (value_ % 3))
        {
            return false;
        }
        if (5 == value_)
        {
            return true;
        }
        if (0 == (value_ % 5))
        {
            return false;
        }
        if (7 == value_)
        {
            return true;
        }
        if (0 == (value_ % 7))
        {
            return false;
        }
        if (11 == value_)
        {
            return true;
        }
        if (0 == (value_ % 11))
        {
            return false;
        }
        if (13 == value_)
        {
            return true;
        }
        if (0 == (value_ % 13))
        {
            return false;
        }

        // Second, Miller-Rabin test.
        // Find r and odd d that satisfy value = 2^r * d + 1.
        uint64_t d = value_ - 1;
        uint64_t r = 0;
        while (0 == (d & 0x1))
        {
            d >>= 1;
            r++;
        }
        if (r == 0)
        {
            return false;
        }

        // 1) Pick a = 2, check a^(value_ - 1).
        // 2) Pick a randomly from [3, value - 1], check a^(value_ - 1).
        // 3) Repeat 2) for another num_rounds - 2 times.
        random_device rand;
        uniform_int_distribution<unsigned long long> dist(3, value_ - 1);
        for (size_t i = 0; i < num_rounds; i++)
        {
            uint64_t a = i ? dist(rand) : 2;
            uint64_t x = exponentiate_uint_mod(a, d, *this);
            if (x == 1 || x == value_ - 1)
            {
                continue;
            }
            uint64_t count = 0;
            do
            {
                x = multiply_uint_uint_mod(x, x, *this);
                count++;
            }
            while (x != value_ - 1 && count < r - 1);
            if (x != value_ - 1 && count == r - 1)
            {
                return false;
            }
        }
        return true;
    }

    vector<SmallModulus> SmallModulus::GetPrimes(int bit_size, size_t count, size_t ntt_size)
    {
        if (bit_size >= 63 || bit_size <= 1)
        {
            throw invalid_argument("bit_size must be at least 2 and at most 62");
        }
        if (!count)
        {
            throw invalid_argument("count must be positive");
        }
        if (!ntt_size)
        {
            throw invalid_argument("ntt_size must be positive");
        }

        vector<SmallModulus> destination;
        uint64_t factor = 2 * static_cast<uint64_t>(ntt_size);

        // Start with 2^bit_size - 2 * ntt_size + 1
        uint64_t value = (uint64_t(0x1) << bit_size) - factor + 1;

        uint64_t lower_bound = uint64_t(0x1) << (bit_size - 1);
        while (count > 0 && value > lower_bound)
        {
            SmallModulus new_mod(value);
            if (new_mod.is_prime())
            {
                destination.emplace_back(move(new_mod));
                count--;
            }
            value -= factor;
        }
        if (count > 0)
        {
            throw logic_error("failed to find enough qualifying primes");
        }
        return destination;
    }
}