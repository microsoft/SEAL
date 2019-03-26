// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include "seal/util/uintcore.h"
#include "seal/util/uintarith.h"
#include "seal/util/uintarithmod.h"
#include "seal/util/uintarithsmallmod.h"
#include <random>

using namespace std;

namespace seal
{
    namespace util
    {
        bool is_primitive_root(uint64_t root, uint64_t degree,
            const SmallModulus &modulus)
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

            // We check if root is a degree-th root of unity in integers modulo
            // modulus, where degree is a power of two.
            // It suffices to check that root^(degree/2) is -1 modulo modulus.
            return exponentiate_uint_mod(
                root, degree >> 1, modulus) == (modulus.value() - 1);
        }

        bool try_primitive_root(uint64_t degree, const SmallModulus &modulus,
            uint64_t &destination)
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
            // We need to divide modulus-1 by degree to get the size of the
            // quotient group
            uint64_t size_entire_group = modulus.value() - 1;

            // Compute size of quotient group
            uint64_t size_quotient_group = size_entire_group / degree;

            // size_entire_group must be divisible by degree, or otherwise the
            // primitive root does not exist in integers modulo modulus
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
                destination = (static_cast<uint64_t>(rd()) << 32) |
                    static_cast<uint64_t>(rd());
                destination %= modulus.value();

                // Raise the random number to power the size of the quotient
                // to get rid of irrelevant part
                destination = exponentiate_uint_mod(
                    destination, size_quotient_group, modulus);
            } while (!is_primitive_root(destination, degree, modulus) &&
                (attempt_counter < attempt_counter_max));

            return is_primitive_root(destination, degree, modulus);
        }

        bool try_minimal_primitive_root(uint64_t degree,
            const SmallModulus &modulus, uint64_t &destination)
        {
            uint64_t root;
            if (!try_primitive_root(degree, modulus, root))
            {
                return false;
            }
            uint64_t generator_sq = multiply_uint_uint_mod(root, root, modulus);
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
                current_generator = multiply_uint_uint_mod(
                    current_generator, generator_sq, modulus);
            }

            destination = root;
            return true;
        }

        uint64_t exponentiate_uint_mod(uint64_t operand, uint64_t exponent,
            const SmallModulus &modulus)
        {
#ifdef SEAL_DEBUG
            if (modulus.is_zero())
            {
                throw invalid_argument("modulus");
            }
            if (operand >= modulus.value())
            {
                throw invalid_argument("operand");
            }
#endif
            // Fast cases
            if (exponent == 0)
            {
                // Result is supposed to be only one digit
                return 1;
            }

            if (exponent == 1)
            {
                return operand;
            }

            // Perform binary exponentiation.
            uint64_t power = operand;
            uint64_t product = 0;
            uint64_t intermediate = 1;

            // Initially: power = operand and intermediate = 1, product is irrelevant.
            while (true)
            {
                if (exponent & 1)
                {
                    product = multiply_uint_uint_mod(power, intermediate, modulus);
                    swap(product, intermediate);
                }
                exponent >>= 1;
                if (exponent == 0)
                {
                    break;
                }
                product = multiply_uint_uint_mod(power, power, modulus);
                swap(product, power);
            }
            return intermediate;
        }

        void divide_uint_uint_mod_inplace(uint64_t *numerator,
            const SmallModulus &modulus, size_t uint64_count,
            uint64_t *quotient, MemoryPool &pool)
        {
            // Handle base cases
            if (uint64_count == 2)
            {
                divide_uint128_uint64_inplace(numerator, modulus.value(), quotient);
                return;
            }
            else if(uint64_count == 1)
            {
                *numerator = *numerator % modulus.value();
                *quotient = *numerator / modulus.value();
                return;
            }
            else
            {
                // If uint64_count > 2.
                // x = numerator = x1 * 2^128 + x2.
                // 2^128 = A*value + B.

                auto x1_alloc(allocate_uint(uint64_count - 2 , pool));
                uint64_t *x1 = x1_alloc.get();
                uint64_t x2[2];
                auto quot_alloc(allocate_uint(uint64_count, pool));
                uint64_t *quot = quot_alloc.get();
                auto rem_alloc(allocate_uint(uint64_count, pool));
                uint64_t *rem = rem_alloc.get();
                set_uint_uint(numerator + 2, uint64_count - 2, x1);
                set_uint_uint(numerator, 2, x2); // x2 = (num) % 2^128.

                multiply_uint_uint(x1, uint64_count - 2, &modulus.const_ratio()[0], 2,
                    uint64_count, quot); // x1*A.
                multiply_uint_uint64(x1, uint64_count - 2, modulus.const_ratio()[2],
                    uint64_count - 1, rem); // x1*B
                add_uint_uint(rem, uint64_count - 1, x2, 2, 0, uint64_count, rem); // x1*B + x2;

                size_t remainder_uint64_count = get_significant_uint64_count_uint(rem, uint64_count);
                divide_uint_uint_mod_inplace(rem, modulus, remainder_uint64_count, quotient, pool);
                add_uint_uint(quotient, quot, uint64_count, quotient);
                *numerator = rem[0];

                return;
            }
        }

        uint64_t steps_to_galois_elt(int steps, size_t coeff_count)
        {
            uint32_t n = safe_cast<uint32_t>(coeff_count);
            uint32_t m32 = mul_safe(n, uint32_t(2));
            uint64_t m = static_cast<uint64_t>(m32);

            if (steps == 0)
            {
                return m - 1;
            }
            else
            {
                // Extract sign of steps. When steps is positive, the rotation
                // is to the left; when steps is negative, it is to the right.
                bool sign = steps < 0;
                uint32_t pos_steps = safe_cast<uint32_t>(abs(steps));

                if (pos_steps >= (n >> 1))
                {
                    throw invalid_argument("step count too large");
                }

                pos_steps &= m32 - 1;
                if (sign)
                {
                    steps = safe_cast<int>(n >> 1) - safe_cast<int>(pos_steps);
                }
                else
                {
                    steps = safe_cast<int>(pos_steps);
                }

                // Construct Galois element for row rotation
                uint64_t gen = 3;
                uint64_t galois_elt = 1;
                while(steps--)
                {
                    galois_elt *= gen;
                    galois_elt &= m - 1;
                }
                return galois_elt;
            }
        }
    }
}
