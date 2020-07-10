// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include "seal/modulus.h"
#include "seal/util/common.h"
#include "seal/util/numth.h"
#include "seal/util/uintarith.h"
#include "seal/util/uintarithsmallmod.h"
#include <numeric>
#include <stdexcept>
#include <unordered_map>

using namespace std;
using namespace seal::util;

namespace seal
{
    void Modulus::save_members(ostream &stream) const
    {
        auto old_except_mask = stream.exceptions();
        try
        {
            // Throw exceptions on std::ios_base::badbit and std::ios_base::failbit
            stream.exceptions(ios_base::badbit | ios_base::failbit);

            stream.write(reinterpret_cast<const char *>(&value_), sizeof(uint64_t));
        }
        catch (const ios_base::failure &)
        {
            stream.exceptions(old_except_mask);
            throw runtime_error("I/O error");
        }
        catch (...)
        {
            stream.exceptions(old_except_mask);
            throw;
        }
        stream.exceptions(old_except_mask);
    }

    void Modulus::load_members(istream &stream)
    {
        auto old_except_mask = stream.exceptions();
        try
        {
            // Throw exceptions on std::ios_base::badbit and std::ios_base::failbit
            stream.exceptions(ios_base::badbit | ios_base::failbit);

            uint64_t value;
            stream.read(reinterpret_cast<char *>(&value), sizeof(uint64_t));
            set_value(value);
        }
        catch (const ios_base::failure &)
        {
            stream.exceptions(old_except_mask);
            throw runtime_error("I/O error");
        }
        catch (...)
        {
            stream.exceptions(old_except_mask);
            throw;
        }
        stream.exceptions(old_except_mask);
    }

    void Modulus::set_value(uint64_t value)
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
        else if ((value >> SEAL_MOD_BIT_COUNT_MAX != 0) || (value == 1))
        {
            throw invalid_argument("value can be at most 61-bit and cannot be 1");
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
            divide_uint192_inplace(numerator, value_, quotient);

            const_ratio_[0] = quotient[0];
            const_ratio_[1] = quotient[1];

            // We store also the remainder
            const_ratio_[2] = numerator[0];

            uint64_count_ = 1;

            // Set the primality flag
            is_prime_ = util::is_prime(*this);
        }
    }

    vector<Modulus> CoeffModulus::BFVDefault(size_t poly_modulus_degree, sec_level_type sec_level)
    {
        if (!MaxBitCount(poly_modulus_degree, sec_level))
        {
            throw invalid_argument("non-standard poly_modulus_degree");
        }
        if (sec_level == sec_level_type::none)
        {
            throw invalid_argument("invalid security level");
        }

        switch (sec_level)
        {
        case sec_level_type::tc128:
            return global_variables::GetDefaultCoeffModulus128().at(poly_modulus_degree);

        case sec_level_type::tc192:
            return global_variables::GetDefaultCoeffModulus192().at(poly_modulus_degree);

        case sec_level_type::tc256:
            return global_variables::GetDefaultCoeffModulus256().at(poly_modulus_degree);

        default:
            throw runtime_error("invalid security level");
        }
    }

    vector<Modulus> CoeffModulus::Create(size_t poly_modulus_degree, vector<int> bit_sizes)
    {
        if (poly_modulus_degree > SEAL_POLY_MOD_DEGREE_MAX || poly_modulus_degree < SEAL_POLY_MOD_DEGREE_MIN ||
            get_power_of_two(static_cast<uint64_t>(poly_modulus_degree)) < 0)
        {
            throw invalid_argument("poly_modulus_degree is invalid");
        }
        if (bit_sizes.size() > SEAL_COEFF_MOD_COUNT_MAX)
        {
            throw invalid_argument("bit_sizes is invalid");
        }
        if (accumulate(
                bit_sizes.cbegin(), bit_sizes.cend(), SEAL_USER_MOD_BIT_COUNT_MIN,
                [](int a, int b) { return max(a, b); }) > SEAL_USER_MOD_BIT_COUNT_MAX ||
            accumulate(bit_sizes.cbegin(), bit_sizes.cend(), SEAL_USER_MOD_BIT_COUNT_MAX, [](int a, int b) {
                return min(a, b);
            }) < SEAL_USER_MOD_BIT_COUNT_MIN)
        {
            throw invalid_argument("bit_sizes is invalid");
        }

        unordered_map<int, size_t> count_table;
        unordered_map<int, vector<Modulus>> prime_table;
        for (int size : bit_sizes)
        {
            ++count_table[size];
        }
        for (const auto &table_elt : count_table)
        {
            prime_table[table_elt.first] = get_primes(poly_modulus_degree, table_elt.first, table_elt.second);
        }

        vector<Modulus> result;
        for (int size : bit_sizes)
        {
            result.emplace_back(prime_table[size].back());
            prime_table[size].pop_back();
        }
        return result;
    }
} // namespace seal