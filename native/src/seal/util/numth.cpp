// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include "seal/util/numth.h"
#include "seal/util/uintarithsmallmod.h"
#include "seal/util/uintcore.h"
#include <random>

using namespace std;

namespace seal
{
    namespace util
    {
        vector<uint64_t> conjugate_classes(uint64_t modulus, uint64_t subgroup_generator)
        {
#ifdef SEAL_DEBUG
            if (!product_fits_in(modulus, subgroup_generator) || !fits_in<size_t>(modulus))
            {
                throw invalid_argument("inputs too large");
            }
#endif
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
                if (classes[static_cast<size_t>(i)] == 0)
                {
                    continue;
                }
                if (classes[static_cast<size_t>(i)] < i)
                {
                    // i is not a pivot, updated its pivot
                    classes[static_cast<size_t>(i)] = classes[static_cast<size_t>(classes[static_cast<size_t>(i)])];
                    continue;
                }
                // If i is a pivot, update other pivots to point to it
                uint64_t j = (i * subgroup_generator) % modulus;
                while (classes[static_cast<size_t>(j)] != i)
                {
                    // Merge the equivalence classes of j and i
                    // Note: if classes[j] != j then classes[j] will be updated later,
                    // when we get to i = j and use the code for "i not pivot".
                    classes[static_cast<size_t>(classes[static_cast<size_t>(j)])] = i;
                    j = (j * subgroup_generator) % modulus;
                }
            }
            return classes;
        }

        bool try_invert_uint_mod(uint64_t value, uint64_t modulus, uint64_t &result)
        {
#ifdef SEAL_DEBUG
            if (modulus <= 1)
            {
                throw invalid_argument("modulus must be at least 2");
            }
#endif
            if (value == 0)
            {
                return false;
            }
            auto gcd_tuple = xgcd(value, modulus);
            if (get<0>(gcd_tuple) != 1)
            {
                return false;
            }
            else if (get<1>(gcd_tuple) < 0)
            {
                result = static_cast<uint64_t>(get<1>(gcd_tuple)) + modulus;
                return true;
            }
            else
            {
                result = static_cast<uint64_t>(get<1>(gcd_tuple));
                return true;
            }
        }

        vector<uint64_t> multiplicative_orders(vector<uint64_t> conjugate_classes, uint64_t modulus)
        {
#ifdef SEAL_DEBUG
            if (!product_fits_in(modulus, modulus) || !fits_in<size_t>(modulus))
            {
                throw invalid_argument("inputs too large");
            }
#endif
            vector<uint64_t> orders{};
            orders.push_back(0);
            orders.push_back(1);

            for (uint64_t i = 2; i < modulus; i++)
            {
                if (conjugate_classes[static_cast<size_t>(i)] <= 1)
                {
                    orders.push_back(conjugate_classes[static_cast<size_t>(i)]);
                    continue;
                }
                if (conjugate_classes[static_cast<size_t>(i)] < i)
                {
                    orders.push_back(orders[static_cast<size_t>(conjugate_classes[static_cast<size_t>(i)])]);
                    continue;
                }
                uint64_t j = (i * i) % modulus;
                uint64_t order = 2;
                while (conjugate_classes[static_cast<size_t>(j)] != 1)
                {
                    j = (j * i) % modulus;
                    order++;
                }
                orders.push_back(order);
            }
            return orders;
        }

        void babystep_giantstep(uint64_t modulus, vector<uint64_t> &baby_steps, vector<uint64_t> &giant_steps)
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
            uint64_t modulus, uint64_t input, const vector<uint64_t> &baby_steps, const vector<uint64_t> &giant_steps)
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

        bool is_prime(const Modulus &modulus, size_t num_rounds)
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
                    x = multiply_uint_mod(x, x, modulus);
                    count++;
                } while (x != value - 1 && count < r - 1);
                if (x != value - 1)
                {
                    return false;
                }
            }
            return true;
        }

        vector<Modulus> get_primes(size_t ntt_size, int bit_size, size_t count)
        {
#ifdef SEAL_DEBUG
            if (!count)
            {
                throw invalid_argument("count must be positive");
            }
            if (get_power_of_two(ntt_size) < 0)
            {
                throw invalid_argument("ntt_size must be a power of two");
            }
            if (bit_size > SEAL_MOD_BIT_COUNT_MAX || bit_size < SEAL_MOD_BIT_COUNT_MIN)
            {
                throw invalid_argument("bit_size is invalid");
            }
#endif
            vector<Modulus> destination;
            uint64_t factor = mul_safe(uint64_t(2), safe_cast<uint64_t>(ntt_size));

            // Start with 2^bit_size - 2 * ntt_size + 1
            uint64_t value = uint64_t(0x1) << bit_size;
            try
            {
                value = sub_safe(value, factor) + 1;
            }
            catch (const logic_error &)
            {
                throw logic_error("failed to find enough qualifying primes");
            }

            uint64_t lower_bound = uint64_t(0x1) << (bit_size - 1);
            while (count > 0 && value > lower_bound)
            {
                Modulus new_mod(value);
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

        bool is_primitive_root(uint64_t root, uint64_t degree, const Modulus &modulus)
        {
#ifdef SEAL_DEBUG
            if (modulus.bit_count() < 2)
            {
                throw invalid_argument("modulus");
            }
            if (root >= modulus.value())
            {
                throw out_of_range("operand");
            }
            if (get_power_of_two(degree) < 1)
            {
                throw invalid_argument("degree must be a power of two and at least two");
            }
#endif
            if (root == 0)
            {
                return false;
            }

            // We check if root is a degree-th root of unity in integers modulo modulus,
            // where degree is a power of two. It suffices to check that root^(degree/2)
            // is -1 modulo modulus.
            return exponentiate_uint_mod(root, degree >> 1, modulus) == (modulus.value() - 1);
        }

        bool try_primitive_root(uint64_t degree, const Modulus &modulus, uint64_t &destination)
        {
#ifdef SEAL_DEBUG
            if (modulus.bit_count() < 2)
            {
                throw invalid_argument("modulus");
            }
            if (get_power_of_two(degree) < 1)
            {
                throw invalid_argument("degree must be a power of two and at least two");
            }
#endif
            // We need to divide modulus-1 by degree to get the size of the quotient group
            uint64_t size_entire_group = modulus.value() - 1;

            // Compute size of quotient group
            uint64_t size_quotient_group = size_entire_group / degree;

            // size_entire_group must be divisible by degree, or otherwise the primitive root does not
            // exist in integers modulo modulus
            if (size_entire_group - size_quotient_group * degree != 0)
            {
                return false;
            }

            // For randomness
            random_device rd;

            int attempt_counter = 0;
            int attempt_counter_max = 100;
            do
            {
                attempt_counter++;

                // Set destination to be a random number modulo modulus
                destination =
                    barrett_reduce_64((static_cast<uint64_t>(rd()) << 32) | static_cast<uint64_t>(rd()), modulus);

                // Raise the random number to power the size of the quotient
                // to get rid of irrelevant part
                destination = exponentiate_uint_mod(destination, size_quotient_group, modulus);
            } while (!is_primitive_root(destination, degree, modulus) && (attempt_counter < attempt_counter_max));

            return is_primitive_root(destination, degree, modulus);
        }

        bool try_minimal_primitive_root(uint64_t degree, const Modulus &modulus, uint64_t &destination)
        {
            uint64_t root;
            if (!try_primitive_root(degree, modulus, root))
            {
                return false;
            }
            uint64_t generator_sq = multiply_uint_mod(root, root, modulus);
            uint64_t current_generator = root;

            // destination is going to always contain the smallest generator found
            for (size_t i = 0; i < degree; i++)
            {
                // If our current generator is strictly smaller than destination,
                // update
                if (current_generator < root)
                {
                    root = current_generator;
                }

                // Then move on to the next generator
                current_generator = multiply_uint_mod(current_generator, generator_sq, modulus);
            }

            destination = root;
            return true;
        }
    } // namespace util
} // namespace seal