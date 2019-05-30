// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stdexcept>
#include <unordered_map>
#include <numeric>
#include "seal/modulus.h"
#include "seal/util/numth.h"
#include "seal/util/common.h"

using namespace std;
using namespace seal::util;

namespace seal
{
    vector<SmallModulus> CoeffModulus::BFVDefault(
        size_t poly_modulus_degree, sec_level_type sec_level)
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
            return global_variables::default_coeff_modulus_128.
                at(poly_modulus_degree);

        case sec_level_type::tc192:
            return global_variables::default_coeff_modulus_192.
                at(poly_modulus_degree);

        case sec_level_type::tc256:
            return global_variables::default_coeff_modulus_256.
                at(poly_modulus_degree);

        default:
            throw runtime_error("invalid security level");
        }
    }

    vector<SmallModulus> CoeffModulus::Create(
        size_t poly_modulus_degree, vector<int> bit_sizes)
    {
        if (poly_modulus_degree > SEAL_POLY_MOD_DEGREE_MAX ||
            poly_modulus_degree < SEAL_POLY_MOD_DEGREE_MIN ||
            get_power_of_two(static_cast<uint64_t>(poly_modulus_degree)) < 0)
        {
            throw invalid_argument("poly_modulus_degree is invalid");
        }
        if (bit_sizes.size() > SEAL_COEFF_MOD_COUNT_MAX)
        {
            throw invalid_argument("bit_sizes is invalid");
        }
        if (accumulate(bit_sizes.cbegin(), bit_sizes.cend(),
                SEAL_USER_MOD_BIT_COUNT_MIN, [](int a, int b) {
                    return max(a, b); }) > SEAL_USER_MOD_BIT_COUNT_MAX ||
            accumulate(bit_sizes.cbegin(), bit_sizes.cend(),
                SEAL_USER_MOD_BIT_COUNT_MAX, [](int a, int b) {
                    return min(a, b); }) < SEAL_USER_MOD_BIT_COUNT_MIN)
        {
            throw invalid_argument("bit_sizes is invalid");
        }

        unordered_map<int, size_t> count_table;
        unordered_map<int, vector<SmallModulus>> prime_table;
        for (int size : bit_sizes)
        {
            ++count_table[size];
        }
        for (const auto &table_elt : count_table)
        {
            prime_table[table_elt.first] = get_primes(
                poly_modulus_degree, table_elt.first, table_elt.second);
        }

        vector<SmallModulus> result;
        for (int size : bit_sizes)
        {
            result.emplace_back(prime_table[size].back());
            prime_table[size].pop_back();
        }
        return result;
    }
}