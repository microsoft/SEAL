// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include "seal/util/polyarithsmallmod.h"
#include "seal/util/uintarith.h"
#include "seal/util/uintcore.h"

#ifdef SEAL_USE_INTEL_HEXL
#include "hexl/hexl.hpp"
#endif

using namespace std;

namespace seal
{
    namespace util
    {
        void modulo_poly_coeffs(ConstCoeffIter poly, std::size_t coeff_count, const Modulus &modulus, CoeffIter result)
        {
#ifdef SEAL_DEBUG
            if (!poly && coeff_count > 0)
            {
                throw std::invalid_argument("poly");
            }
            if (!result && coeff_count > 0)
            {
                throw std::invalid_argument("result");
            }
            if (modulus.is_zero())
            {
                throw std::invalid_argument("modulus");
            }
#endif

#ifdef SEAL_USE_INTEL_HEXL
            // Intel HEXL reduces arbitrary 64-bit input correctly only modulo moduli of at least 14 bits
            if (modulus.bit_count() >= 14)
            {
                intel::hexl::EltwiseReduceMod(result, poly, coeff_count, modulus.value(), modulus.value(), 1);
                return;
            }
#endif
            // Local copies, since result may alias modulus
            const uint64_t modulus_value = modulus.value();
            const uint64_t const_ratio_1 = modulus.const_ratio()[1];
            const uint64_t *in = poly.ptr();
            uint64_t *out = result.ptr();
            for (size_t i = 0; i < coeff_count; i++)
            {
                unsigned long long q;
                multiply_uint64_hw64(in[i], const_ratio_1, &q);
                out[i] = sub_if_ge_uint64(in[i] - q * modulus_value, modulus_value);
            }
        }

        void add_poly_coeffmod(
            ConstCoeffIter operand1, ConstCoeffIter operand2, std::size_t coeff_count, const Modulus &modulus,
            CoeffIter result)
        {
#ifdef SEAL_DEBUG
            if (!operand1 && coeff_count > 0)
            {
                throw std::invalid_argument("operand1");
            }
            if (!operand2 && coeff_count > 0)
            {
                throw std::invalid_argument("operand2");
            }
            if (modulus.is_zero())
            {
                throw std::invalid_argument("modulus");
            }
            if (!result && coeff_count > 0)
            {
                throw std::invalid_argument("result");
            }
#endif
            const uint64_t modulus_value = modulus.value();

#ifdef SEAL_USE_INTEL_HEXL
            intel::hexl::EltwiseAddMod(&result[0], &operand1[0], &operand2[0], coeff_count, modulus_value);
#else

            SEAL_ITERATE(iter(operand1, operand2, result), coeff_count, [&](auto I) {
#ifdef SEAL_DEBUG
                if (get<0>(I) >= modulus_value)
                {
                    throw std::invalid_argument("operand1");
                }
                if (get<1>(I) >= modulus_value)
                {
                    throw std::invalid_argument("operand2");
                }
#endif
                std::uint64_t sum = get<0>(I) + get<1>(I);
                get<2>(I) = SEAL_COND_SELECT(sum >= modulus_value, sum - modulus_value, sum);
            });
#endif
        }

        void sub_poly_coeffmod(
            ConstCoeffIter operand1, ConstCoeffIter operand2, std::size_t coeff_count, const Modulus &modulus,
            CoeffIter result)
        {
#ifdef SEAL_DEBUG
            if (!operand1 && coeff_count > 0)
            {
                throw std::invalid_argument("operand1");
            }
            if (!operand2 && coeff_count > 0)
            {
                throw std::invalid_argument("operand2");
            }
            if (modulus.is_zero())
            {
                throw std::invalid_argument("modulus");
            }
            if (!result && coeff_count > 0)
            {
                throw std::invalid_argument("result");
            }
#endif

            const uint64_t modulus_value = modulus.value();
#ifdef SEAL_USE_INTEL_HEXL
            intel::hexl::EltwiseSubMod(result, operand1, operand2, coeff_count, modulus_value);
#else
            SEAL_ITERATE(iter(operand1, operand2, result), coeff_count, [&](auto I) {
#ifdef SEAL_DEBUG
                if (get<0>(I) >= modulus_value)
                {
                    throw std::invalid_argument("operand1");
                }
                if (get<1>(I) >= modulus_value)
                {
                    throw std::invalid_argument("operand2");
                }
#endif
                unsigned long long temp_result;
                std::int64_t borrow = sub_uint64(get<0>(I), get<1>(I), &temp_result);
                get<2>(I) = temp_result + (modulus_value & static_cast<std::uint64_t>(-borrow));
            });
#endif
        }

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

#ifdef SEAL_USE_INTEL_HEXL
            intel::hexl::EltwiseAddMod(result, poly, scalar, coeff_count, modulus.value());
#else
            SEAL_ITERATE(iter(poly, result), coeff_count, [&](auto I) {
                const uint64_t x = get<0>(I);
                get<1>(I) = add_uint_mod(x, scalar, modulus);
            });
#endif
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

#ifdef SEAL_USE_INTEL_HEXL
            intel::hexl::EltwiseSubMod(result, poly, scalar, coeff_count, modulus.value());
#else
            SEAL_ITERATE(iter(poly, result), coeff_count, [&](auto I) {
                const uint64_t x = get<0>(I);
                get<1>(I) = sub_uint_mod(x, scalar, modulus);
            });
#endif
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

#ifdef SEAL_USE_INTEL_HEXL
            intel::hexl::EltwiseFMAMod(&result[0], &poly[0], scalar.operand, nullptr, coeff_count, modulus.value(), 8);
#else
            // Local copies, since result may alias modulus
            const uint64_t modulus_value = modulus.value();
            const uint64_t *in = poly.ptr();
            uint64_t *out = result.ptr();
            for (size_t i = 0; i < coeff_count; i++)
            {
                unsigned long long q;
                multiply_uint64_hw64(in[i], scalar.quotient, &q);
                out[i] = sub_if_ge_uint64(scalar.operand * in[i] - q * modulus_value, modulus_value);
            }
#endif
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
#ifdef SEAL_USE_INTEL_HEXL
            intel::hexl::EltwiseMultMod(&result[0], &operand1[0], &operand2[0], coeff_count, modulus.value(), 4);
#else
            // Local copies, since result may alias modulus
            const uint64_t modulus_value = modulus.value();
            const uint64_t const_ratio_0 = modulus.const_ratio()[0];
            const uint64_t const_ratio_1 = modulus.const_ratio()[1];
            const uint64_t r64 = two_pow_64_mod(modulus);

            const uint64_t *op1 = operand1.ptr();
            const uint64_t *op2 = operand2.ptr();
            uint64_t *res = result.ptr();
            for (size_t i = 0; i < coeff_count; i++)
            {
                unsigned long long z[2];
                multiply_uint64(op1[i], op2[i], z);
                res[i] = barrett_reduce_128_precomputed(z[0], z[1], modulus_value, r64, const_ratio_0, const_ratio_1);
            }
#endif
        }

#ifndef SEAL_USE_INTEL_HEXL
        namespace
        {
            // Returns floor(b * 2^64 / p) or one less, for b < p, given floor(2^128 / p) = ratio_hi * 2^64 + ratio_lo.
            // A Shoup multiplication by b with this quotient gives a result in [0, 3p).
            SEAL_NODISCARD SEAL_FORCE_INLINE uint64_t
            shoup_quotient_from_ratio(uint64_t b, uint64_t ratio_lo, uint64_t ratio_hi) noexcept
            {
                unsigned long long t;
                multiply_uint64_hw64(b, ratio_lo, &t);
                return b * ratio_hi + static_cast<uint64_t>(t);
            }
        } // namespace
#endif

        void dyadic_product_add_coeffmod(
            ConstCoeffIter operand1, ConstCoeffIter operand2, ConstCoeffIter addend, size_t coeff_count,
            const Modulus &modulus, CoeffIter result)
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
            if (!addend)
            {
                throw invalid_argument("addend");
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
            for (size_t i = 0; i < coeff_count; i++)
            {
                if (operand2[i] >= modulus.value())
                {
                    throw invalid_argument("operand2");
                }
                if (addend[i] >= modulus.value())
                {
                    throw invalid_argument("addend");
                }
            }
#endif
#ifdef SEAL_USE_INTEL_HEXL
            intel::hexl::EltwiseMultMod(&result[0], &operand1[0], &operand2[0], coeff_count, modulus.value(), 4);
            intel::hexl::EltwiseAddMod(&result[0], &result[0], &addend[0], coeff_count, modulus.value());
#else
            // Local copies, since result may alias modulus
            const uint64_t modulus_value = modulus.value();
            const uint64_t two_modulus_value = modulus_value << 1;
            const uint64_t const_ratio_0 = modulus.const_ratio()[0];
            const uint64_t const_ratio_1 = modulus.const_ratio()[1];

            const uint64_t *a = operand1.ptr();
            const uint64_t *b = operand2.ptr();
            const uint64_t *c = addend.ptr();
            uint64_t *r = result.ptr();
            for (size_t i = 0; i < coeff_count; i++)
            {
                const uint64_t bi = b[i];
                const uint64_t w = shoup_quotient_from_ratio(bi, const_ratio_0, const_ratio_1);

                // The Shoup product is in [0, 3p), so the sum is in [0, 4p)
                const uint64_t x = a[i];
                unsigned long long q;
                multiply_uint64_hw64(x, w, &q);
                const uint64_t sum = (x * bi - static_cast<uint64_t>(q) * modulus_value) + c[i];
                r[i] = sub_if_ge_uint64(sub_if_ge_uint64(sum, two_modulus_value), modulus_value);
            }
#endif
        }

        void dyadic_product_shared_coeffmod(
            ConstCoeffIter operand1, ConstCoeffIter operand2, ConstCoeffIter shared, size_t coeff_count,
            const Modulus &modulus, CoeffIter result1, CoeffIter result2)
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
            if (!shared)
            {
                throw invalid_argument("shared");
            }
            if (!result1)
            {
                throw invalid_argument("result1");
            }
            if (!result2)
            {
                throw invalid_argument("result2");
            }
            if (coeff_count == 0)
            {
                throw invalid_argument("coeff_count");
            }
            if (modulus.is_zero())
            {
                throw invalid_argument("modulus");
            }
            for (size_t i = 0; i < coeff_count; i++)
            {
                if (shared[i] >= modulus.value())
                {
                    throw invalid_argument("shared");
                }
            }
#endif
#ifdef SEAL_USE_INTEL_HEXL
            intel::hexl::EltwiseMultMod(&result1[0], &operand1[0], &shared[0], coeff_count, modulus.value(), 4);
            intel::hexl::EltwiseMultMod(&result2[0], &operand2[0], &shared[0], coeff_count, modulus.value(), 4);
#else
            // Local copies, since result1 and result2 may alias modulus
            const uint64_t modulus_value = modulus.value();
            const uint64_t two_modulus_value = modulus_value << 1;
            const uint64_t const_ratio_0 = modulus.const_ratio()[0];
            const uint64_t const_ratio_1 = modulus.const_ratio()[1];

            const uint64_t *a1 = operand1.ptr();
            const uint64_t *a2 = operand2.ptr();
            const uint64_t *b = shared.ptr();
            uint64_t *r1 = result1.ptr();
            uint64_t *r2 = result2.ptr();
            for (size_t i = 0; i < coeff_count; i++)
            {
                // One Shoup quotient for both products
                const uint64_t bi = b[i];
                const uint64_t w = shoup_quotient_from_ratio(bi, const_ratio_0, const_ratio_1);

                // Shoup products in [0, 3p)
                const uint64_t x1 = a1[i];
                const uint64_t x2 = a2[i];
                unsigned long long q1, q2;
                multiply_uint64_hw64(x1, w, &q1);
                multiply_uint64_hw64(x2, w, &q2);
                const uint64_t s1 = x1 * bi - static_cast<uint64_t>(q1) * modulus_value;
                const uint64_t s2 = x2 * bi - static_cast<uint64_t>(q2) * modulus_value;

                r1[i] = sub_if_ge_uint64(sub_if_ge_uint64(s1, two_modulus_value), modulus_value);
                r2[i] = sub_if_ge_uint64(sub_if_ge_uint64(s2, two_modulus_value), modulus_value);
            }
#endif
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
