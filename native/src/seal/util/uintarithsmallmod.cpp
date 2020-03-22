// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include "seal/util/uintarith.h"
#include "seal/util/uintarithmod.h"
#include "seal/util/uintarithsmallmod.h"
#include "seal/util/uintcore.h"
#include <random>
#include <tuple>
#include <numeric>

using namespace std;

namespace seal
{
    namespace util
    {
        uint64_t exponentiate_uint_mod(uint64_t operand, uint64_t exponent, const SmallModulus &modulus)
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

        void divide_uint_uint_mod_inplace(
            uint64_t *numerator, const SmallModulus &modulus, size_t uint64_count, uint64_t *quotient, MemoryPool &pool)
        {
            // Handle base cases
            if (uint64_count == 2)
            {
                divide_uint128_uint64_inplace(numerator, modulus.value(), quotient);
                return;
            }
            else if (uint64_count == 1)
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

                auto x1_alloc(allocate_uint(uint64_count - 2, pool));
                uint64_t *x1 = x1_alloc.get();
                uint64_t x2[2];
                auto quot_alloc(allocate_uint(uint64_count, pool));
                uint64_t *quot = quot_alloc.get();
                auto rem_alloc(allocate_uint(uint64_count, pool));
                uint64_t *rem = rem_alloc.get();
                set_uint_uint(numerator + 2, uint64_count - 2, x1);
                set_uint_uint(numerator, 2, x2); // x2 = (num) % 2^128.

                multiply_uint_uint(x1, uint64_count - 2, &modulus.const_ratio()[0], 2, uint64_count, quot);  // x1*A.
                multiply_uint_uint64(x1, uint64_count - 2, modulus.const_ratio()[2], uint64_count - 1, rem); // x1*B
                add_uint_uint(rem, uint64_count - 1, x2, 2, 0, uint64_count, rem); // x1*B + x2;

                size_t remainder_uint64_count = get_significant_uint64_count_uint(rem, uint64_count);
                divide_uint_uint_mod_inplace(rem, modulus, remainder_uint64_count, quotient, pool);
                add_uint_uint(quotient, quot, uint64_count, quotient);
                *numerator = rem[0];

                return;
            }
        }

        uint64_t galois_elt_from_step(int step, size_t coeff_count)
        {
            uint32_t n = safe_cast<uint32_t>(coeff_count);
            uint32_t m32 = mul_safe(n, uint32_t(2));
            uint64_t m = static_cast<uint64_t>(m32);

            if (step == 0)
            {
                return m - 1;
            }
            else
            {
                // Extract sign of steps. When steps is positive, the rotation
                // is to the left; when steps is negative, it is to the right.
                bool sign = step < 0;
                uint32_t pos_step = safe_cast<uint32_t>(abs(step));

                if (pos_step >= (n >> 1))
                {
                    throw invalid_argument("step count too large");
                }

                pos_step &= m32 - 1;
                if (sign)
                {
                    step = safe_cast<int>(n >> 1) - safe_cast<int>(pos_step);
                }
                else
                {
                    step = safe_cast<int>(pos_step);
                }

                // Construct Galois element for row rotation
                uint64_t gen = 3;
                uint64_t galois_elt = 1;
                while (step--)
                {
                    galois_elt *= gen;
                    galois_elt &= m - 1;
                }
                return galois_elt;
            }
        }

        uint64_t dot_product_mod(
            const uint64_t *operand1, size_t count, const uint64_t *operand2, const SmallModulus &modulus)
        {
#ifdef SEAL_DEBUG
            if (!operand1 && count)
            {
                throw invalid_argument("operand1");
            }
            if (!operand2 && count)
            {
                throw invalid_argument("operand2");
            }
            if (modulus.is_zero())
            {
                throw invalid_argument("modulus");
            }
#endif
            // Product of two numbers is up to 61 bit + 61 bit = 122 bit. We can sum up to 64 of them with no reduction.
            size_t lazy_reduction_summand_bound;
#if SEAL_MOD_BIT_COUNT_MAX > 32
            lazy_reduction_summand_bound = safe_cast<size_t>(1 << (128 - (SEAL_MOD_BIT_COUNT_MAX << 1)));
#else
            lazy_reduction_summand_bound = numeric_limits<size_t>::max();
#endif
            // We may have to perform multiple lazy reductions depending on count
            size_t r = lazy_reduction_summand_bound;
            unsigned long long accumulator[2]{ 0, 0 };
            for (size_t i = 0; i < count; i++, operand1++, operand2++)
            {
                // Compute current product
                unsigned long long qword[2];
                multiply_uint64(*operand1, *operand2, qword);

                // 128-bit addition to accumulator; ignore carry bit since it can never be set
                add_uint128(qword, accumulator, accumulator);

                // Lazy reduction
                if (!--r)
                {
                    r = lazy_reduction_summand_bound;
                    accumulator[0] = barrett_reduce_128(accumulator, modulus);
                    accumulator[1] = 0;
                }
            }
            return barrett_reduce_128(accumulator, modulus);
        }
    } // namespace util
} // namespace seal
