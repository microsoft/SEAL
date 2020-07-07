// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include "seal/util/polyarithsmallmod.h"
#include "seal/util/uintarith.h"
#include "seal/util/uintcore.h"

using namespace std;

namespace seal
{
    namespace util
    {
        void add_poly_scalar_coeffmod(
            ConstCoeffIter poly, size_t coeff_count, uint64_t scalar, const Modulus &modulus, CoeffIter result)
        {
#ifdef SEAL_DEBUG
            if (!poly && coeff_count > 0)
            {
                throw invalid_argument("poly");
            }
            if (!result && coeff_count > 0)
            {
                throw invalid_argument("result");
            }
            if (modulus.is_zero())
            {
                throw invalid_argument("modulus");
            }
            if (scalar >= modulus.value())
            {
                throw invalid_argument("scalar");
            }
#endif

            SEAL_ITERATE(iter(poly, result), coeff_count, [&](auto I) {
                const uint64_t x = get<0>(I);
                get<1>(I) = add_uint_mod(x, scalar, modulus);
            });
        }

        void sub_poly_scalar_coeffmod(
            ConstCoeffIter poly, size_t coeff_count, uint64_t scalar, const Modulus &modulus, CoeffIter result)
        {
#ifdef SEAL_DEBUG
            if (!poly && coeff_count > 0)
            {
                throw invalid_argument("poly");
            }
            if (!result && coeff_count > 0)
            {
                throw invalid_argument("result");
            }
            if (modulus.is_zero())
            {
                throw invalid_argument("modulus");
            }
            if (scalar >= modulus.value())
            {
                throw invalid_argument("scalar");
            }
#endif

            SEAL_ITERATE(iter(poly, result), coeff_count, [&](auto I) {
                const uint64_t x = get<0>(I);
                get<1>(I) = sub_uint_mod(x, scalar, modulus);
            });
        }

        void multiply_poly_scalar_coeffmod(
            ConstCoeffIter poly, size_t coeff_count, MultiplyUIntModOperand scalar, const Modulus &modulus,
            CoeffIter result)
        {
#ifdef SEAL_DEBUG
            if (!poly && coeff_count > 0)
            {
                throw invalid_argument("poly");
            }
            if (!result && coeff_count > 0)
            {
                throw invalid_argument("result");
            }
            if (modulus.is_zero())
            {
                throw invalid_argument("modulus");
            }
#endif
            SEAL_ITERATE(iter(poly, result), coeff_count, [&](auto I) {
                const uint64_t x = get<0>(I);
                get<1>(I) = multiply_uint_mod(x, scalar, modulus);
            });
        }

        void dyadic_product_coeffmod(
            ConstCoeffIter operand1, ConstCoeffIter operand2, size_t coeff_count, const Modulus &modulus,
            CoeffIter result)
        {
#ifdef SEAL_DEBUG
            if (!operand1)
            {
                throw invalid_argument("operand1");
            }
            if (!operand2)
            {
                throw invalid_argument("operand2");
            }
            if (!result)
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
            const uint64_t modulus_value = modulus.value();
            const uint64_t const_ratio_0 = modulus.const_ratio()[0];
            const uint64_t const_ratio_1 = modulus.const_ratio()[1];

            SEAL_ITERATE(iter(operand1, operand2, result), coeff_count, [&](auto I) {
                // Reduces z using base 2^64 Barrett reduction
                unsigned long long z[2], tmp1, tmp2[2], tmp3, carry;
                multiply_uint64(get<0>(I), get<1>(I), z);

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
                get<2>(I) =
                    tmp3 - (modulus_value & static_cast<uint64_t>(-static_cast<int64_t>(tmp3 >= modulus_value)));
            });
        }

        uint64_t poly_infty_norm_coeffmod(ConstCoeffIter operand, size_t coeff_count, const Modulus &modulus)
        {
#ifdef SEAL_DEBUG
            if (!operand && coeff_count > 0)
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
            SEAL_ITERATE(operand, coeff_count, [&](auto I) {
                uint64_t poly_coeff = barrett_reduce_64(I, modulus);
                if (poly_coeff >= modulus_neg_threshold)
                {
                    poly_coeff = modulus.value() - poly_coeff;
                }
                if (poly_coeff > result)
                {
                    result = poly_coeff;
                }
            });

            return result;
        }

        void negacyclic_shift_poly_coeffmod(
            ConstCoeffIter poly, size_t coeff_count, size_t shift, const Modulus &modulus, CoeffIter result)
        {
#ifdef SEAL_DEBUG
            if (!poly)
            {
                throw invalid_argument("poly");
            }
            if (!result)
            {
                throw invalid_argument("result");
            }
            if (poly == result)
            {
                throw invalid_argument("result cannot point to the same value as poly");
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
                set_uint(poly, coeff_count, result);
                return;
            }

            uint64_t index_raw = shift;
            uint64_t coeff_count_mod_mask = static_cast<uint64_t>(coeff_count) - 1;
            for (size_t i = 0; i < coeff_count; i++, poly++, index_raw++)
            {
                uint64_t index = index_raw & coeff_count_mod_mask;
                if (!(index_raw & static_cast<uint64_t>(coeff_count)) || !*poly)
                {
                    result[index] = *poly;
                }
                else
                {
                    result[index] = modulus.value() - *poly;
                }
            }
        }
    } // namespace util
} // namespace seal
