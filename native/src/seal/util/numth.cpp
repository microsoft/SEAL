// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include "seal/util/numth.h"
#include "seal/util/uintarithmod.h"
#include "seal/util/uintarithsmallmod.h"
#include "seal/util/uintcore.h"
#include <algorithm>
#include <random>

using namespace std;

namespace seal
{
    namespace util
    {
        bool CRTTool::initialize(const vector<SmallModulus> &prime_array)
        {
            prime_count_ = prime_array.size();

            // Verify that the prime array has at least two primes
            if (prime_count_ < 2)
            {
                reset();
                return is_initialized_;
            }

            // Verify that the size is not too large
            if (!product_fits_in(prime_count_, prime_count_))
            {
                reset();
                return is_initialized_;
            }

            // Verify that inputs are primes
            for (const auto &prime : prime_array)
            {
                if (!prime.is_prime())
                {
                    reset();
                    return is_initialized_;
                }
            }

            // Copy over the primes to local variables
            prime_array_ = allocate<SmallModulus>(prime_count_, pool_);
            copy(prime_array.cbegin(), prime_array.cend(), prime_array_.get());

            auto prime_array_values = allocate<uint64_t>(prime_count_, pool_);
            transform(prime_array.cbegin(), prime_array.cend(), prime_array_values.get(), [](const auto &prime) {
                return prime.value();
            });

            // Create punctured products
            punctured_product_array_ = allocate_zero_uint(prime_count_ * prime_count_, pool_);
            for (size_t i = 0; i < prime_count_; i++)
            {
                multiply_many_uint64_except(
                    prime_array_values.get(), prime_count_, i, punctured_product_array_.get() + (i * prime_count_),
                    pool_);
            }

            // Compute the full product
            auto temp_mpi(allocate_uint(prime_count_, pool_));
            prime_product_ = allocate_uint(prime_count_, pool_);
            multiply_uint_uint64(
                punctured_product_array_.get(), prime_count_, prime_array_[0].value(), prime_count_, temp_mpi.get());
            set_uint_uint(temp_mpi.get(), prime_count_, prime_product_.get());

            // Compute inverses of punctured products mod primes
            inv_punctured_product_mod_prime_array_ = allocate_uint(prime_count_, pool_);
            for (size_t i = 0; i < prime_count_; i++)
            {
                inv_punctured_product_mod_prime_array_[i] = modulo_uint(
                    punctured_product_array_.get() + (i * prime_count_), prime_count_, prime_array_[i], pool_);
                if (!try_invert_uint_mod(
                        inv_punctured_product_mod_prime_array_[i], prime_array_[i],
                        inv_punctured_product_mod_prime_array_[i]))
                {
                    reset();
                    return is_initialized_;
                }
            }

            // Everything went well
            is_initialized_ = true;
            return is_initialized_;
        }

        void CRTTool::decompose(uint64_t *value) const
        {
            if (!is_initialized_)
            {
                throw invalid_argument("CRTTool is uninitialized");
            }

            // Decompose a single multi-precision integer into CRT factors
            auto temp(allocate_uint(prime_count_, pool_));
            set_uint_uint(value, prime_count_, temp.get());
            for (size_t i = 0; i < prime_count_; i++)
            {
                value[i] = modulo_uint(temp.get(), prime_count_, prime_array_[i], pool_);
            }
        }

        void CRTTool::decompose_array(uint64_t *value, size_t count) const
        {
            if (!is_initialized_)
            {
                throw invalid_argument("CRTTool is uninitialized");
            }
            if (!product_fits_in(count, prime_count_))
            {
                throw invalid_argument("count is too large");
            }

            // Decompose an array of multi-precision integers into an array of arrays,
            // one per each CRT factor
            auto temp(allocate_uint(count * prime_count_, pool_));
            for (size_t i = 0; i < count; i++, value += prime_count_)
            {
                set_uint_uint(value, prime_count_, temp.get());
                for (size_t j = 0; j < prime_count_; j++)
                {
                    value[i * prime_count_ + j] = modulo_uint(temp.get(), prime_count_, prime_array_[j], pool_);
                }
            }
        }

        void CRTTool::compose(uint64_t *value) const
        {
            if (!is_initialized_)
            {
                throw invalid_argument("CRTTool is uninitialized");
            }

            // Copy the value
            auto temp_value(allocate_uint(prime_count_, pool_));
            copy_n(value, prime_count_, temp_value.get());

            // Clear the result
            set_zero_uint(prime_count_, value);

            // Compose an array of integers (one per CRT factor) into a single multi-precision integer
            auto temp_mpi(allocate_uint(prime_count_, pool_));
            for (size_t i = 0; i < prime_count_; i++)
            {
                uint64_t temp_prod =
                    multiply_uint_uint_mod(temp_value[i], inv_punctured_product_mod_prime_array_[i], prime_array_[i]);
                multiply_uint_uint64(
                    punctured_product_array_.get() + (i * prime_count_), prime_count_, temp_prod, prime_count_,
                    temp_mpi.get());
                add_uint_uint_mod(temp_mpi.get(), value, prime_product_.get(), prime_count_, value);
            }
        }

        void CRTTool::compose_array(uint64_t *value, size_t count) const
        {
            if (!is_initialized_)
            {
                throw invalid_argument("CRTTool is uninitialized");
            }
            if (!product_fits_in(count, prime_count_))
            {
                throw invalid_argument("count is too large");
            }

            // Compose an array of arrays of integers (one array per CRT factor) into
            // a single array of multi-precision integers
            auto temp_array(allocate_uint(count * prime_count_, pool_));

            // Merge the coefficients first
            for (size_t i = 0; i < count; i++)
            {
                for (size_t j = 0; j < prime_count_; j++)
                {
                    temp_array[j + (i * prime_count_)] = value[(j * count) + i];
                }
            }

            // Clear the result
            set_zero_uint(count * prime_count_, value);

            auto temp_mpi(allocate_uint(prime_count_, pool_));
            for (size_t i = 0; i < count; i++)
            {
                // Do CRT compose for each coefficient
                for (size_t j = 0; j < prime_count_; j++)
                {
                    uint64_t temp_prod = multiply_uint_uint_mod(
                        temp_array[(i * prime_count_) + j], inv_punctured_product_mod_prime_array_[j], prime_array_[j]);
                    multiply_uint_uint64(
                        punctured_product_array_.get() + (j * prime_count_), prime_count_, temp_prod, prime_count_,
                        temp_mpi.get());
                    add_uint_uint_mod(
                        temp_mpi.get(), value + (i * prime_count_), prime_product_.get(), prime_count_,
                        value + (i * prime_count_));
                }
            }
        }

        vector<uint64_t> conjugate_classes(uint64_t modulus, uint64_t subgroup_generator)
        {
            if (!product_fits_in(modulus, subgroup_generator) || !fits_in<size_t>(modulus))
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

        vector<uint64_t> multiplicative_orders(vector<uint64_t> conjugate_classes, uint64_t modulus)
        {
            if (!product_fits_in(modulus, modulus) || !fits_in<size_t>(modulus))
            {
                throw invalid_argument("inputs too large");
            }

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
    } // namespace util
} // namespace seal