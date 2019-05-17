// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <random>
#include "seal/util/numth.h"
#include "seal/util/uintcore.h"
#include "seal/util/uintarithsmallmod.h"

using namespace std;

namespace seal
{
    namespace util
    {
        vector<uint64_t> conjugate_classes(uint64_t modulus,
            uint64_t subgroup_generator)
        {
            if (!product_fits_in(modulus, subgroup_generator))
            {
                throw invalid_argument("inputs too large");
            }

            vector<uint64_t> classes{};
            for (uint64_t i = 0; i < modulus; i++)
            {
                if (gcd(i, modulus) > 1)
                {
                    classes.push_back(0);
                }
                else
                {
                    classes.push_back(i);
                }
            }
            for (uint64_t i = 0; i < modulus; i++)
            {
                if (classes[i] == 0)
                {
                    continue;
                }
                if (classes[i] < i)
                {
                    // i is not a pivot, updated its pivot
                    classes[i] = classes[classes[i]];
                    continue;
                }
                // If i is a pivot, update other pivots to point to it
                uint64_t j = (i * subgroup_generator) % modulus;
                while (classes[j] != i)
                {
                    // Merge the equivalence classes of j and i
                    // Note: if classes[j] != j then classes[j] will be updated later,
                    // when we get to i = j and use the code for "i not pivot".
                    classes[classes[j]] = i;
                    j = (j * subgroup_generator) % modulus;
                }
            }
            return classes;
        }

        vector<uint64_t> multiplicative_orders(
            vector<uint64_t> conjugate_classes, uint64_t modulus)
        {
            if (!product_fits_in(modulus, modulus))
            {
                throw invalid_argument("inputs too large");
            }

            vector<uint64_t> orders{};
            orders.push_back(0);
            orders.push_back(1);

            for (uint64_t i = 2; i < modulus; i++)
            {
                if (conjugate_classes[i] <= 1)
                {
                    orders.push_back(conjugate_classes[i]);
                    continue;
                }
                if (conjugate_classes[i] < i)
                {
                    orders.push_back(orders[conjugate_classes[i]]);
                    continue;
                }
                uint64_t j = (i * i) % modulus;
                uint64_t order = 2;
                while (conjugate_classes[j] != 1)
                {
                    j = (j * i) % modulus;
                    order++;
                }
                orders.push_back(order);
            }
            return orders;
        }

        void babystep_giantstep(uint64_t modulus,
            vector<uint64_t> &baby_steps, vector<uint64_t> &giant_steps)
        {
            int exponent = get_power_of_two(modulus);
            if (exponent < 0)
            {
                throw invalid_argument("modulus must be a power of 2");
            }

            // Compute square root of modulus (k stores the baby steps)
            uint64_t k = uint64_t(1) << (exponent / 2);
            uint64_t l = modulus / k;

            baby_steps.clear();
            giant_steps.clear();

            uint64_t m = mul_safe(modulus, uint64_t(2));
            uint64_t g = 3; // the generator
            uint64_t kprime = k >> 1;
            uint64_t value = 1;
            for (uint64_t i = 0; i < kprime; i++)
            {
                baby_steps.push_back(value);
                baby_steps.push_back(m - value);
                value = mul_safe(value, g) % m;
            }

            // now value should equal to g**kprime
            uint64_t value2 = value;
            for (uint64_t j = 0; j < l; j++)
            {
                giant_steps.push_back(value2);
                value2 = mul_safe(value2, value) % m;
            }
        }

        pair<size_t, size_t> decompose_babystep_giantstep(
            uint64_t modulus, uint64_t input,
            const vector<uint64_t> &baby_steps,
            const vector<uint64_t> &giant_steps)
        {
            for (size_t i = 0; i < giant_steps.size(); i++)
            {
                uint64_t gs = giant_steps[i];
                for (size_t j = 0; j < baby_steps.size(); j++)
                {
                    uint64_t bs = baby_steps[j];
                    if (mul_safe(gs, bs) % modulus == input)
                    {
                        return { i, j };
                    }
                }
            }
            throw logic_error("failed to decompose input");
        }

        bool is_prime(const SmallModulus &modulus, size_t num_rounds)
        {
            uint64_t value = modulus.value();
            // First check the simplest cases.
            if (value < 2)
            {
                return false;
            }
            if (2 == value)
            {
                return true;
            }
            if (0 == (value & 0x1))
            {
                return false;
            }
            if (3 == value)
            {
                return true;
            }
            if (0 == (value % 3))
            {
                return false;
            }
            if (5 == value)
            {
                return true;
            }
            if (0 == (value % 5))
            {
                return false;
            }
            if (7 == value)
            {
                return true;
            }
            if (0 == (value % 7))
            {
                return false;
            }
            if (11 == value)
            {
                return true;
            }
            if (0 == (value % 11))
            {
                return false;
            }
            if (13 == value)
            {
                return true;
            }
            if (0 == (value % 13))
            {
                return false;
            }

            // Second, Miller-Rabin test.
            // Find r and odd d that satisfy value = 2^r * d + 1.
            uint64_t d = value - 1;
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

            // 1) Pick a = 2, check a^(value - 1).
            // 2) Pick a randomly from [3, value - 1], check a^(value - 1).
            // 3) Repeat 2) for another num_rounds - 2 times.
            random_device rand;
            uniform_int_distribution<unsigned long long> dist(3, value - 1);
            for (size_t i = 0; i < num_rounds; i++)
            {
                uint64_t a = i ? dist(rand) : 2;
                uint64_t x = exponentiate_uint_mod(a, d, modulus);
                if (x == 1 || x == value - 1)
                {
                    continue;
                }
                uint64_t count = 0;
                do
                {
                    x = multiply_uint_uint_mod(x, x, modulus);
                    count++;
                } while (x != value - 1 && count < r - 1);
                if (x != value - 1)
                {
                    return false;
                }
            }
            return true;
        }

        vector<SmallModulus> get_primes(size_t ntt_size, int bit_size, size_t count)
        {
            if (!count)
            {
                throw invalid_argument("count must be positive");
            }
            if (!ntt_size)
            {
                throw invalid_argument("ntt_size must be positive");
            }
            if (bit_size >= 63 || bit_size <= 1)
            {
                throw invalid_argument("bit_size is invalid");
            }

            vector<SmallModulus> destination;
            uint64_t factor = mul_safe(uint64_t(2), safe_cast<uint64_t>(ntt_size));

            // Start with 2^bit_size - 2 * ntt_size + 1
            uint64_t value = uint64_t(0x1) << bit_size;
            try
            {
                value = sub_safe(value, factor) + 1;
            }
            catch (const out_of_range &)
            {
                throw logic_error("failed to find enough qualifying primes");
            }

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
}