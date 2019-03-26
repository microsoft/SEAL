// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include "seal/util/common.h"
#include "seal/util/uintcore.h"
#include "seal/util/uintarith.h"
#include "seal/util/uintarithmod.h"
#include "seal/util/polycore.h"
#include "seal/util/polyarith.h"

using namespace std;

namespace seal
{
    namespace util
    {
        void multiply_poly_poly(const uint64_t *operand1,
            size_t operand1_coeff_count, size_t operand1_coeff_uint64_count,
            const uint64_t *operand2, size_t operand2_coeff_count,
            size_t operand2_coeff_uint64_count, size_t result_coeff_count,
            size_t result_coeff_uint64_count, uint64_t *result, MemoryPool &pool)
        {
#ifdef SEAL_DEBUG
            if (operand1 == nullptr && operand1_coeff_count > 0 &&
                operand1_coeff_uint64_count > 0)
            {
                throw invalid_argument("operand1");
            }
            if (operand2 == nullptr && operand2_coeff_count > 0 &&
                operand2_coeff_uint64_count > 0)
            {
                throw invalid_argument("operand2");
            }
            if (result == nullptr && result_coeff_count > 0 &&
                result_coeff_uint64_count > 0)
            {
                throw invalid_argument("result");
            }
            if (result != nullptr &&
                (operand1 == result || operand2 == result))
            {
                throw invalid_argument("result cannot point to the same value as operand1 or operand2");
            }
            if (!sum_fits_in(operand1_coeff_count, operand2_coeff_count))
            {
                throw invalid_argument("operand1 and operand2 too large");
            }
#endif
            auto intermediate(allocate_uint(result_coeff_uint64_count, pool));

            // Clear product.
            set_zero_poly(result_coeff_count, result_coeff_uint64_count, result);

            operand1_coeff_count = get_significant_coeff_count_poly(
                operand1, operand1_coeff_count, operand1_coeff_uint64_count);
            operand2_coeff_count = get_significant_coeff_count_poly(
                operand2, operand2_coeff_count, operand2_coeff_uint64_count);
            for (size_t operand1_index = 0;
                operand1_index < operand1_coeff_count; operand1_index++)
            {
                const uint64_t *operand1_coeff = get_poly_coeff(
                    operand1, operand1_index, operand1_coeff_uint64_count);
                for (size_t operand2_index = 0;
                    operand2_index < operand2_coeff_count; operand2_index++)
                {
                    size_t product_coeff_index = operand1_index + operand2_index;
                    if (product_coeff_index >= result_coeff_count)
                    {
                        break;
                    }

                    const uint64_t *operand2_coeff = get_poly_coeff(
                        operand2, operand2_index, operand2_coeff_uint64_count);
                    multiply_uint_uint(operand1_coeff, operand1_coeff_uint64_count,
                        operand2_coeff, operand2_coeff_uint64_count,
                        result_coeff_uint64_count, intermediate.get());
                    uint64_t *result_coeff = get_poly_coeff(
                        result, product_coeff_index, result_coeff_uint64_count);
                    add_uint_uint(result_coeff, intermediate.get(),
                        result_coeff_uint64_count, result_coeff);
                }
            }
        }

        void poly_eval_poly(const uint64_t *poly_to_eval,
            size_t poly_to_eval_coeff_count,
            size_t poly_to_eval_coeff_uint64_count,
            const uint64_t *value, size_t value_coeff_count,
            size_t value_coeff_uint64_count, size_t result_coeff_count,
            size_t result_coeff_uint64_count, uint64_t *result, MemoryPool &pool)
        {
#ifdef SEAL_DEBUG
            if (poly_to_eval == nullptr)
            {
                throw invalid_argument("poly_to_eval");
            }
            if (value == nullptr)
            {
                throw invalid_argument("value");
            }
            if (result == nullptr)
            {
                throw invalid_argument("result");
            }
            if (poly_to_eval_coeff_count == 0)
            {
                throw invalid_argument("poly_to_eval_coeff_count");
            }
            if (poly_to_eval_coeff_uint64_count == 0)
            {
                throw invalid_argument("poly_to_eval_coeff_uint64_count");
            }
            if (value_coeff_count == 0)
            {
                throw invalid_argument("value_coeff_count");
            }
            if (value_coeff_uint64_count == 0)
            {
                throw invalid_argument("value_coeff_uint64_count");
            }
            if (result_coeff_count == 0)
            {
                throw invalid_argument("result_coeff_count");
            }
            if (result_coeff_uint64_count == 0)
            {
                throw invalid_argument("result_coeff_uint64_count");
            }
#endif
            // Evaluate poly at value using Horner's method
            auto temp1(allocate_poly(result_coeff_count, result_coeff_uint64_count, pool));
            auto temp2(allocate_zero_poly(result_coeff_count, result_coeff_uint64_count, pool));
            uint64_t *productptr = temp1.get();
            uint64_t *intermediateptr = temp2.get();

            while (poly_to_eval_coeff_count--)
            {
                multiply_poly_poly(intermediateptr, result_coeff_count,
                    result_coeff_uint64_count, value, value_coeff_count,
                    value_coeff_uint64_count, result_coeff_count,
                    result_coeff_uint64_count, productptr, pool);
                const uint64_t *curr_coeff = get_poly_coeff(
                    poly_to_eval, poly_to_eval_coeff_count,
                    poly_to_eval_coeff_uint64_count);
                add_uint_uint(productptr, result_coeff_uint64_count, curr_coeff,
                    poly_to_eval_coeff_uint64_count, false,
                    result_coeff_uint64_count, productptr);
                swap(productptr, intermediateptr);
            }
            set_poly_poly(intermediateptr, result_coeff_count,
                result_coeff_uint64_count, result);
        }

        void exponentiate_poly(const std::uint64_t *poly, size_t poly_coeff_count,
            size_t poly_coeff_uint64_count, const uint64_t *exponent,
            size_t exponent_uint64_count, size_t result_coeff_count,
            size_t result_coeff_uint64_count, std::uint64_t *result, MemoryPool &pool)
        {
#ifdef SEAL_DEBUG
            if (poly == nullptr)
            {
                throw invalid_argument("poly");
            }
            if (poly_coeff_count == 0)
            {
                throw invalid_argument("poly_coeff_count");
            }
            if (poly_coeff_uint64_count == 0)
            {
                throw invalid_argument("poly_coeff_uint64_count");
            }
            if (exponent == nullptr)
            {
                throw invalid_argument("exponent");
            }
            if (exponent_uint64_count == 0)
            {
                throw invalid_argument("exponent_uint64_count");
            }
            if (result == nullptr)
            {
                throw invalid_argument("result");
            }
            if (result_coeff_count == 0)
            {
                throw invalid_argument("result_coeff_count");
            }
            if (result_coeff_uint64_count == 0)
            {
                throw invalid_argument("result_coeff_uint64_count");
            }
#endif
            // Fast cases
            if (is_zero_uint(exponent, exponent_uint64_count))
            {
                set_zero_poly(result_coeff_count, result_coeff_uint64_count, result);
                *result = 1;
                return;
            }
            if (is_equal_uint(exponent, exponent_uint64_count, 1))
            {
                set_poly_poly(poly, poly_coeff_count, poly_coeff_uint64_count,
                    result_coeff_count, result_coeff_uint64_count, result);
                return;
            }

            // Need to make a copy of exponent
            auto exponent_copy(allocate_uint(exponent_uint64_count, pool));
            set_uint_uint(exponent, exponent_uint64_count, exponent_copy.get());

            // Perform binary exponentiation.
            auto big_alloc(allocate_uint(mul_safe(
                add_safe(result_coeff_count, result_coeff_count, result_coeff_count),
                result_coeff_uint64_count), pool));

            uint64_t *powerptr = big_alloc.get();
            uint64_t *productptr = get_poly_coeff(
                powerptr, result_coeff_count, result_coeff_uint64_count);
            uint64_t *intermediateptr = get_poly_coeff(
                productptr, result_coeff_count, result_coeff_uint64_count);

            set_poly_poly(poly, poly_coeff_count, poly_coeff_uint64_count, result_coeff_count,
                result_coeff_uint64_count, powerptr);
            set_zero_poly(result_coeff_count, result_coeff_uint64_count, intermediateptr);
            *intermediateptr = 1;

            // Initially: power = operand and intermediate = 1, product is not initialized.
            while (true)
            {
                if ((*exponent_copy.get() % 2) == 1)
                {
                    multiply_poly_poly(powerptr, result_coeff_count, result_coeff_uint64_count,
                        intermediateptr, result_coeff_count, result_coeff_uint64_count,
                        result_coeff_count, result_coeff_uint64_count, productptr, pool);
                    swap(productptr, intermediateptr);
                }
                right_shift_uint(exponent_copy.get(), 1, exponent_uint64_count, exponent_copy.get());
                if (is_zero_uint(exponent_copy.get(), exponent_uint64_count))
                {
                    break;
                }
                multiply_poly_poly(powerptr, result_coeff_count, result_coeff_uint64_count,
                    powerptr, result_coeff_count, result_coeff_uint64_count,
                    result_coeff_count, result_coeff_uint64_count, productptr, pool);
                swap(productptr, powerptr);
            }
            set_poly_poly(intermediateptr, result_coeff_count, result_coeff_uint64_count, result);
        }
    }
}
