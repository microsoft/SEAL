// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include "seal/util/common.h"
#include "seal/util/uintcore.h"
#include "seal/util/uintarithsmallmod.h"
#include "seal/util/uintarith.h"
#include "seal/util/polycore.h"
#include "seal/util/polyarith.h"
#include "seal/util/polyarithsmallmod.h"
#include "seal/util/defines.h"

using namespace std;

namespace seal
{
    namespace util
    {
        void multiply_poly_scalar_coeffmod(const uint64_t *poly,
            size_t coeff_count, uint64_t scalar, const SmallModulus &modulus,
            uint64_t *result)
        {
#ifdef SEAL_DEBUG
            if (poly == nullptr && coeff_count > 0)
            {
                throw invalid_argument("poly");
            }
            if (result == nullptr && coeff_count > 0)
            {
                throw invalid_argument("result");
            }
            if (modulus.is_zero())
            {
                throw invalid_argument("modulus");
            }
#endif
            // Explicit inline
            //for (int i = 0; i < coeff_count; i++)
            //{
            //    *result++ = multiply_uint_uint_mod(*poly++, scalar, modulus);
            //}
            const uint64_t modulus_value = modulus.value();
            const uint64_t const_ratio_0 = modulus.const_ratio()[0];
            const uint64_t const_ratio_1 = modulus.const_ratio()[1];
            for (; coeff_count--; poly++, result++)
            {
                unsigned long long z[2], tmp1, tmp2[2], tmp3, carry;
                multiply_uint64(*poly, scalar, z);

                // Reduces z using base 2^64 Barrett reduction

                // Multiply input and const_ratio
                // Round 1
                multiply_uint64_hw64(z[0], const_ratio_0, &carry);
                multiply_uint64(z[0], const_ratio_1, tmp2);
                tmp3 = tmp2[1] + add_uint64(tmp2[0], carry, &tmp1);

                // Round 2
                multiply_uint64(z[1], const_ratio_0, tmp2);
                carry = tmp2[1] + add_uint64(tmp1, tmp2[0], &tmp1);

                // This is all we care about
                tmp1 = z[1] * const_ratio_1 + tmp3 + carry;

                // Barrett subtraction
                tmp3 = z[0] - tmp1 * modulus_value;

                // Claim: One more subtraction is enough
                *result = tmp3 - (modulus_value & static_cast<uint64_t>(
                    -static_cast<int64_t>(tmp3 >= modulus_value)));
            }
        }

        void multiply_poly_poly_coeffmod(const uint64_t *operand1,
            size_t operand1_coeff_count, const uint64_t *operand2,
            size_t operand2_coeff_count, const SmallModulus &modulus,
            size_t result_coeff_count, uint64_t *result)
        {
#ifdef SEAL_DEBUG
            if (operand1 == nullptr && operand1_coeff_count > 0)
            {
                throw invalid_argument("operand1");
            }
            if (operand2 == nullptr && operand2_coeff_count > 0)
            {
                throw invalid_argument("operand2");
            }
            if (result == nullptr && result_coeff_count > 0)
            {
                throw invalid_argument("result");
            }
            if (result != nullptr && (operand1 == result || operand2 == result))
            {
                throw invalid_argument("result cannot point to the same value as operand1, operand2, or modulus");
            }
            if (modulus.is_zero())
            {
                throw invalid_argument("modulus");
            }
            if (!sum_fits_in(operand1_coeff_count, operand2_coeff_count))
            {
                throw invalid_argument("operand1 and operand2 too large");
            }
#endif
            // Clear product.
            set_zero_uint(result_coeff_count, result);

            operand1_coeff_count = get_significant_coeff_count_poly(
                operand1, operand1_coeff_count, 1);
            operand2_coeff_count = get_significant_coeff_count_poly(
                operand2, operand2_coeff_count, 1);
            for (size_t operand1_index = 0;
                operand1_index < operand1_coeff_count; operand1_index++)
            {
                if (operand1[operand1_index] == 0)
                {
                    // If coefficient is 0, then move on to next coefficient.
                    continue;
                }
                // Do expensive add
                for (size_t operand2_index = 0;
                    operand2_index < operand2_coeff_count; operand2_index++)
                {
                    size_t product_coeff_index = operand1_index + operand2_index;
                    if (product_coeff_index >= result_coeff_count)
                    {
                        break;
                    }

                    if (operand2[operand2_index] == 0)
                    {
                        // If coefficient is 0, then move on to next coefficient.
                        continue;
                    }

                    // Lazy reduction
                    unsigned long long temp[2];
                    multiply_uint64(operand1[operand1_index], operand2[operand2_index], temp);
                    temp[1] += add_uint64(temp[0], result[product_coeff_index], 0, temp);
                    result[product_coeff_index] = barrett_reduce_128(temp, modulus);
                }
            }
        }

        void multiply_poly_poly_coeffmod(const uint64_t *operand1,
            const uint64_t *operand2, size_t coeff_count,
            const SmallModulus &modulus, uint64_t *result)
        {
#ifdef SEAL_DEBUG
            if (operand1 == nullptr && coeff_count > 0)
            {
                throw invalid_argument("operand1");
            }
            if (operand2 == nullptr && coeff_count > 0)
            {
                throw invalid_argument("operand2");
            }
            if (result == nullptr && coeff_count > 0)
            {
                throw invalid_argument("result");
            }
            if (result != nullptr && (operand1 == result || operand2 == result))
            {
                throw invalid_argument("result cannot point to the same value as operand1, operand2, or modulus");
            }
            if (modulus.is_zero())
            {
                throw invalid_argument("modulus");
            }
#endif
            size_t result_coeff_count = coeff_count + coeff_count - 1;

            // Clear product.
            set_zero_uint(result_coeff_count, result);

            for (size_t operand1_index = 0; operand1_index < coeff_count; operand1_index++)
            {
                if (operand1[operand1_index] == 0)
                {
                    // If coefficient is 0, then move on to next coefficient.
                    continue;
                }
                // Lastly, do more expensive add if other cases don't handle it.
                for (size_t operand2_index = 0; operand2_index < coeff_count; operand2_index++)
                {
                    uint64_t operand2_coeff = operand2[operand2_index];
                    if (operand2_coeff == 0)
                    {
                        // If coefficient is 0, then move on to next coefficient.
                        continue;
                    }

                    // Lazy reduction
                    unsigned long long temp[2];
                    multiply_uint64(operand1[operand1_index], operand2_coeff, temp);
                    temp[1] += add_uint64(temp[0], result[operand1_index + operand2_index], 0, temp);

                    result[operand1_index + operand2_index] = barrett_reduce_128(temp, modulus);
                }
            }
        }

        void divide_poly_poly_coeffmod_inplace(uint64_t *numerator,
            const uint64_t *denominator, size_t coeff_count,
            const SmallModulus &modulus, uint64_t *quotient)
        {
#ifdef SEAL_DEBUG
            if (numerator == nullptr)
            {
                throw invalid_argument("numerator");
            }
            if (denominator == nullptr)
            {
                throw invalid_argument("denominator");
            }
            if (is_zero_poly(denominator, coeff_count, modulus.uint64_count()))
            {
                throw invalid_argument("denominator");
            }
            if (quotient == nullptr)
            {
                throw invalid_argument("quotient");
            }
            if (numerator == quotient || denominator == quotient)
            {
                throw invalid_argument("quotient cannot point to same value as numerator or denominator");
            }
            if (numerator == denominator)
            {
                throw invalid_argument("numerator cannot point to same value as denominator");
            }
            if (modulus.is_zero())
            {
                throw invalid_argument("modulus");
            }
#endif
            // Clear quotient.
            set_zero_uint(coeff_count, quotient);

            // Determine most significant coefficients of numerator and denominator.
            size_t numerator_coeffs = get_significant_uint64_count_uint(
                numerator, coeff_count);
            size_t denominator_coeffs = get_significant_uint64_count_uint(
                denominator, coeff_count);

            // If numerator has lesser degree than denominator, then done.
            if (numerator_coeffs < denominator_coeffs)
            {
                return;
            }

            // Create scalar to store value that makes denominator monic.
            uint64_t monic_denominator_scalar;

            // Create temporary scalars used during calculation of quotient.
            // Both are purposely twice as wide to store intermediate product prior to modulo operation.
            uint64_t temp_quotient;
            uint64_t subtrahend;

            // Determine scalar necessary to make denominator monic.
            uint64_t leading_denominator_coeff = denominator[denominator_coeffs - 1];
            if (!try_invert_uint_mod(leading_denominator_coeff, modulus, monic_denominator_scalar))
            {
                throw invalid_argument("modulus is not coprime with leading denominator coefficient");
            }

            // Perform coefficient-wise division algorithm.
            while (numerator_coeffs >= denominator_coeffs)
            {
                // Determine leading numerator coefficient.
                uint64_t leading_numerator_coeff = numerator[numerator_coeffs - 1];

                // If leading numerator coefficient is not zero, then need to make zero by subtraction.
                if (leading_numerator_coeff)
                {
                    // Determine shift necesarry to bring significant coefficients in alignment.
                    size_t denominator_shift = numerator_coeffs - denominator_coeffs;

                    // Determine quotient's coefficient, which is scalar that makes
                    // denominator's leading coefficient one multiplied by leading
                    // coefficient of denominator (which when subtracted will zero
                    // out the topmost denominator coefficient).
                    uint64_t &quotient_coeff = quotient[denominator_shift];
                    temp_quotient = multiply_uint_uint_mod(
                        monic_denominator_scalar, leading_numerator_coeff, modulus);
                    quotient_coeff = temp_quotient;

                    // Subtract numerator and quotient*denominator (shifted by denominator_shift).
                    for (size_t denominator_coeff_index = 0;
                        denominator_coeff_index < denominator_coeffs; denominator_coeff_index++)
                    {
                        // Multiply denominator's coefficient by quotient.
                        uint64_t denominator_coeff = denominator[denominator_coeff_index];
                        subtrahend = multiply_uint_uint_mod(temp_quotient, denominator_coeff, modulus);

                        // Subtract numerator with resulting product, appropriately shifted by denominator shift.
                        uint64_t &numerator_coeff = numerator[denominator_coeff_index + denominator_shift];
                        numerator_coeff = sub_uint_uint_mod(numerator_coeff, subtrahend, modulus);
                    }
                }

                // Top numerator coefficient must now be zero, so adjust coefficient count.
                numerator_coeffs--;
            }
        }

        void apply_galois(const uint64_t *input, int coeff_count_power,
            uint64_t galois_elt, const SmallModulus &modulus, uint64_t *result)
        {
#ifdef SEAL_DEBUG
            if (input == nullptr)
            {
                throw invalid_argument("input");
            }
            if (result == nullptr)
            {
                throw invalid_argument("result");
            }
            if (input == result)
            {
                throw invalid_argument("result cannot point to the same value as input");
            }
            if (coeff_count_power < get_power_of_two(SEAL_POLY_MOD_DEGREE_MIN) ||
                coeff_count_power > get_power_of_two(SEAL_POLY_MOD_DEGREE_MAX))
            {
                throw invalid_argument("coeff_count_power");
            }
            // Verify coprime conditions.
            if (!(galois_elt & 1) ||
                (galois_elt >= 2 * (uint64_t(1) << coeff_count_power)))
            {
                throw invalid_argument("Galois element is not valid");
            }
            if (modulus.is_zero())
            {
                throw invalid_argument("modulus");
            }
#endif
            const uint64_t modulus_value = modulus.value();
            uint64_t coeff_count_minus_one = (uint64_t(1) << coeff_count_power) - 1;
            for (uint64_t i = 0; i <= coeff_count_minus_one; i++)
            {
                uint64_t index_raw = i * galois_elt;
                uint64_t index = index_raw & coeff_count_minus_one;
                uint64_t result_value = *input++;
                if ((index_raw >> coeff_count_power) & 1)
                {
                    // Explicit inline
                    //result[index] = negate_uint_mod(result[index], modulus);
                    int64_t non_zero = (result_value != 0);
                    result_value = (modulus_value - result_value) &
                        static_cast<uint64_t>(-non_zero);
                }
                result[index] = result_value;
            }
        }

        void apply_galois_ntt(const uint64_t *input, int coeff_count_power,
            uint64_t galois_elt, uint64_t *result)
        {
#ifdef SEAL_DEBUG
            if (input == nullptr)
            {
                throw invalid_argument("input");
            }
            if (result == nullptr)
            {
                throw invalid_argument("result");
            }
            if (input == result)
            {
                throw invalid_argument("result cannot point to the same value as input");
            }
            if (coeff_count_power <= 0)
            {
                throw invalid_argument("coeff_count_power");
            }
            // Verify coprime conditions.
            if (!(galois_elt & 1) ||
                (galois_elt >= 2 * (uint64_t(1) << coeff_count_power)))
            {
                throw invalid_argument("Galois element is not valid");
            }
#endif
            size_t coeff_count = size_t(1) << coeff_count_power;
            uint64_t m_minus_one = 2 * coeff_count - 1;
            for (size_t i = 0; i < coeff_count; i++)
            {
                uint64_t reversed = reverse_bits(i, coeff_count_power);
                uint64_t index_raw = galois_elt * (2 * reversed + 1);
                index_raw &= m_minus_one;
                uint64_t index = reverse_bits((index_raw - 1) >> 1, coeff_count_power);
                result[i] = input[index];
            }
        }

        void dyadic_product_coeffmod(const uint64_t *operand1,
            const uint64_t *operand2, size_t coeff_count,
            const SmallModulus &modulus, uint64_t *result)
        {
#ifdef SEAL_DEBUG
            if (operand1 == nullptr)
            {
                throw invalid_argument("operand1");
            }
            if (operand2 == nullptr)
            {
                throw invalid_argument("operand2");
            }
            if (result == nullptr)
            {
                throw invalid_argument("result");
            }
            if (coeff_count == 0)
            {
                throw invalid_argument("coeff_count");
            }
            if (modulus.is_zero())
            {
                throw invalid_argument("modulus");
            }
#endif
            // Explicit inline
            //for (int i = 0; i < coeff_count; i++)
            //{
            //    *result++ = multiply_uint_uint_mod(*operand1++, *operand2++, modulus);
            //}
            const uint64_t modulus_value = modulus.value();
            const uint64_t const_ratio_0 = modulus.const_ratio()[0];
            const uint64_t const_ratio_1 = modulus.const_ratio()[1];
            for (; coeff_count--; operand1++, operand2++, result++)
            {
                // Reduces z using base 2^64 Barrett reduction
                unsigned long long z[2], tmp1, tmp2[2], tmp3, carry;
                multiply_uint64(*operand1, *operand2, z);

                // Multiply input and const_ratio
                // Round 1
                multiply_uint64_hw64(z[0], const_ratio_0, &carry);
                multiply_uint64(z[0], const_ratio_1, tmp2);
                tmp3 = tmp2[1] + add_uint64(tmp2[0], carry, &tmp1);

                // Round 2
                multiply_uint64(z[1], const_ratio_0, tmp2);
                carry = tmp2[1] + add_uint64(tmp1, tmp2[0], &tmp1);

                // This is all we care about
                tmp1 = z[1] * const_ratio_1 + tmp3 + carry;

                // Barrett subtraction
                tmp3 = z[0] - tmp1 * modulus_value;

                // Claim: One more subtraction is enough
                *result = tmp3 - (modulus_value & static_cast<uint64_t>(
                    -static_cast<int64_t>(tmp3 >= modulus_value)));
            }
        }

        uint64_t poly_infty_norm_coeffmod(const uint64_t *operand,
            size_t coeff_count, const SmallModulus &modulus)
        {
#ifdef SEAL_DEBUG
            if (operand == nullptr && coeff_count > 0)
            {
                throw invalid_argument("operand");
            }
            if (modulus.is_zero())
            {
                throw invalid_argument("modulus");
            }
#endif
            // Construct negative threshold (first negative modulus value) to compute absolute values of coeffs.
            uint64_t modulus_neg_threshold = (modulus.value() + 1) >> 1;

            // Mod out the poly coefficients and choose a symmetric representative from
            // [-modulus,modulus). Keep track of the max.
            uint64_t result = 0;
            for (size_t coeff_index = 0; coeff_index < coeff_count; coeff_index++)
            {
                uint64_t poly_coeff = operand[coeff_index] % modulus.value();
                if (poly_coeff >= modulus_neg_threshold)
                {
                    poly_coeff = modulus.value() - poly_coeff;
                }
                if (poly_coeff > result)
                {
                    result = poly_coeff;
                }
            }
            return result;
        }

        bool try_invert_poly_coeffmod(const uint64_t *operand, const uint64_t *poly_modulus,
            size_t coeff_count, const SmallModulus &modulus, uint64_t *result, MemoryPool &pool)
        {
#ifdef SEAL_DEBUG
            if (operand == nullptr)
            {
                throw invalid_argument("operand");
            }
            if (poly_modulus == nullptr)
            {
                throw invalid_argument("poly_modulus");
            }
            if (coeff_count == 0)
            {
                throw invalid_argument("coeff_count");
            }
            if (result == nullptr)
            {
                throw invalid_argument("result");
            }
            if (get_significant_uint64_count_uint(operand, coeff_count) >=
                get_significant_uint64_count_uint(poly_modulus, coeff_count))
            {
                throw out_of_range("operand");
            }
            if (modulus.is_zero())
            {
                throw invalid_argument("modulus");
            }
#endif
            // Cannot invert 0 poly.
            if (is_zero_poly(operand, coeff_count, size_t(1)))
            {
                return false;
            }

            // Construct a mutable copy of operand and modulus, with numerator being modulus
            // and operand being denominator. Notice that degree(numerator) >= degree(denominator).
            auto numerator_anchor(allocate_uint(coeff_count, pool));
            uint64_t *numerator = numerator_anchor.get();
            set_uint_uint(poly_modulus, coeff_count, numerator);
            auto denominator_anchor(allocate_uint(coeff_count, pool));
            uint64_t *denominator = denominator_anchor.get();
            set_uint_uint(operand, coeff_count, denominator);

            // Determine most significant coefficients of each.
            size_t numerator_coeffs = get_significant_coeff_count_poly(
                numerator, coeff_count, size_t(1));
            size_t denominator_coeffs = get_significant_coeff_count_poly(
                denominator, coeff_count, size_t(1));

            // Create poly to store quotient.
            auto quotient(allocate_uint(coeff_count, pool));

            // Create scalar to store value that makes denominator monic.
            uint64_t monic_denominator_scalar;

            // Create temporary scalars used during calculation of quotient.
            // Both are purposely twice as wide to store intermediate product prior to modulo operation.
            uint64_t temp_quotient;
            uint64_t subtrahend;

            // Create three polynomials to store inverse.
            // Initialize invert_prior to 0 and invert_curr to 1.
            auto invert_prior_anchor(allocate_uint(coeff_count, pool));
            uint64_t *invert_prior = invert_prior_anchor.get();
            set_zero_uint(coeff_count, invert_prior);
            auto invert_curr_anchor(allocate_uint(coeff_count, pool));
            uint64_t *invert_curr = invert_curr_anchor.get();
            set_zero_uint(coeff_count, invert_curr);
            invert_curr[0] = 1;
            auto invert_next_anchor(allocate_uint(coeff_count, pool));
            uint64_t *invert_next = invert_next_anchor.get();

            // Perform extended Euclidean algorithm.
            while (true)
            {
                // NOTE: degree(numerator) >= degree(denominator).

                // Determine scalar necessary to make denominator monic.
                uint64_t leading_denominator_coeff =
                    denominator[denominator_coeffs - 1];
                if (!try_invert_uint_mod(leading_denominator_coeff, modulus,
                    monic_denominator_scalar))
                {
                    throw invalid_argument("modulus is not coprime with leading denominator coefficient");
                }

                // Clear quotient.
                set_zero_uint(coeff_count, quotient.get());

                // Perform coefficient-wise division algorithm.
                while (numerator_coeffs >= denominator_coeffs)
                {
                    // Determine leading numerator coefficient.
                    uint64_t leading_numerator_coeff = numerator[numerator_coeffs - 1];

                    // If leading numerator coefficient is not zero, then need to make zero by subtraction.
                    if (leading_numerator_coeff)
                    {
                        // Determine shift necessary to bring significant coefficients in alignment.
                        size_t denominator_shift = numerator_coeffs - denominator_coeffs;

                        // Determine quotient's coefficient, which is scalar that makes
                        // denominator's leading coefficient one multiplied by leading
                        // coefficient of denominator (which when subtracted will zero
                        // out the topmost denominator coefficient).
                        uint64_t &quotient_coeff = quotient[denominator_shift];
                        temp_quotient = multiply_uint_uint_mod(
                            monic_denominator_scalar, leading_numerator_coeff, modulus);
                        quotient_coeff  = temp_quotient;

                        // Subtract numerator and quotient*denominator (shifted by denominator_shift).
                        for (size_t denominator_coeff_index = 0;
                            denominator_coeff_index < denominator_coeffs;
                            denominator_coeff_index++)
                        {
                            // Multiply denominator's coefficient by quotient.
                            uint64_t denominator_coeff = denominator[denominator_coeff_index];
                            subtrahend = multiply_uint_uint_mod(temp_quotient, denominator_coeff, modulus);

                            // Subtract numerator with resulting product, appropriately shifted by
                            // denominator shift.
                            uint64_t &numerator_coeff = numerator[denominator_coeff_index + denominator_shift];
                            numerator_coeff = sub_uint_uint_mod(numerator_coeff, subtrahend, modulus);
                        }
                    }

                    // Top numerator coefficient must now be zero, so adjust coefficient count.
                    numerator_coeffs--;
                }

                // Double check that numerator coefficients is correct because possible
                // other coefficients are zero.
                numerator_coeffs = get_significant_coeff_count_poly(
                    numerator, coeff_count, size_t(1));

                // We are done if numerator is zero.
                if (numerator_coeffs == 0)
                {
                    break;
                }

                // Integrate quotient with invert coefficients.
                // Calculate: invert_next = invert_prior + -quotient * invert_curr
                multiply_truncate_poly_poly_coeffmod(quotient.get(), invert_curr,
                    coeff_count, modulus, invert_next);
                sub_poly_poly_coeffmod(invert_prior, invert_next, coeff_count,
                    modulus, invert_next);

                // Swap prior and curr, and then curr and next.
                swap(invert_prior, invert_curr);
                swap(invert_curr, invert_next);

                // Swap numerator and denominator.
                swap(numerator, denominator);
                swap(numerator_coeffs, denominator_coeffs);
            }

            // Polynomial is invertible only if denominator is just a scalar.
            if (denominator_coeffs != 1)
            {
                return false;
            }

            // Determine scalar necessary to make denominator monic.
            uint64_t leading_denominator_coeff = denominator[0];
            if (!try_invert_uint_mod(leading_denominator_coeff, modulus,
                monic_denominator_scalar))
            {
                throw invalid_argument("modulus is not coprime with leading denominator coefficient");
            }

            // Multiply inverse by scalar and done.
            multiply_poly_scalar_coeffmod(invert_curr, coeff_count,
                monic_denominator_scalar, modulus, result);
            return true;
        }

        void negacyclic_shift_poly_coeffmod(const uint64_t *operand,
            size_t coeff_count, size_t shift, const SmallModulus &modulus,
            uint64_t *result)
        {
#ifdef SEAL_DEBUG
            if (operand == nullptr)
            {
                throw invalid_argument("operand");
            }
            if (result == nullptr)
            {
                throw invalid_argument("result");
            }
            if (operand == result)
            {
                throw invalid_argument("result cannot point to the same value as operand");
            }
            if (modulus.is_zero())
            {
                throw invalid_argument("modulus");
            }
            if (util::get_power_of_two(static_cast<uint64_t>(coeff_count)) < 0)
            {
                throw invalid_argument("coeff_count");
            }
            if (shift >= coeff_count)
            {
                throw invalid_argument("shift");
            }
#endif
            // Nothing to do
            if (shift == 0)
            {
                set_uint_uint(operand, coeff_count, result);
                return;
            }

            uint64_t index_raw = shift;
            uint64_t coeff_count_mod_mask = static_cast<uint64_t>(coeff_count) - 1;
            for (size_t i = 0; i < coeff_count; i++, operand++, index_raw++)
            {
                uint64_t index = index_raw & coeff_count_mod_mask;
                if (!(index_raw & static_cast<uint64_t>(coeff_count)) || !*operand)
                {
                    result[index] = *operand;
                }
                else
                {
                    result[index] = modulus.value() - *operand;
                }
            }
        }
    }
}
