// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#pragma once

#include <cstdint>
#include <stdexcept>
#include <algorithm>
#include "seal/smallmodulus.h"
#include "seal/util/common.h"
#include "seal/util/polycore.h"
#include "seal/util/uintarithsmallmod.h"
#include "seal/util/pointer.h"

namespace seal
{
    namespace util
    {
        inline void modulo_poly_coeffs(const std::uint64_t *poly,
            std::size_t coeff_count, const SmallModulus &modulus,
            std::uint64_t *result)
        {
#ifdef SEAL_DEBUG
            if (poly == nullptr && coeff_count > 0)
            {
                throw std::invalid_argument("poly");
            }
            if (result == nullptr && coeff_count > 0)
            {
                throw std::invalid_argument("result");
            }
            if (modulus.is_zero())
            {
                throw std::invalid_argument("modulus");
            }
#endif
            std::transform(poly, poly + coeff_count, result,
                [&](auto coeff) {
                    uint64_t temp[2]{ coeff, 0 };
                    return barrett_reduce_128(temp, modulus); });
        }

        inline void modulo_poly_coeffs_63(const std::uint64_t *poly,
            std::size_t coeff_count, const SmallModulus &modulus,
            std::uint64_t *result)
        {
#ifdef SEAL_DEBUG
            if (poly == nullptr && coeff_count > 0)
            {
                throw std::invalid_argument("poly");
            }
            if (result == nullptr && coeff_count > 0)
            {
                throw std::invalid_argument("result");
            }
            if (modulus.is_zero())
            {
                throw std::invalid_argument("modulus");
            }
#endif
            // This function is the fastest for reducing polynomial coefficients,
            // but requires that the input coefficients are at most 63 bits, unlike
            // modulo_poly_coeffs that allows also 64-bit coefficients.
            std::transform(poly, poly + coeff_count, result,
                [&](auto coeff) {
                    return barrett_reduce_63(coeff, modulus); });
        }

        inline void negate_poly_coeffmod(const std::uint64_t *poly,
            std::size_t coeff_count, const SmallModulus &modulus,
            std::uint64_t *result)
        {
#ifdef SEAL_DEBUG
            if (poly == nullptr && coeff_count > 0)
            {
                throw std::invalid_argument("poly");
            }
            if (modulus.is_zero())
            {
                throw std::invalid_argument("modulus");
            }
            if (result == nullptr && coeff_count > 0)
            {
                throw std::invalid_argument("result");
            }
#endif
            const uint64_t modulus_value = modulus.value();
            for (; coeff_count--; poly++, result++)
            {
                // Explicit inline
                //*result = negate_uint_mod(*poly, modulus);
#ifdef SEAL_DEBUG
                if (*poly >= modulus_value)
                {
                    throw std::out_of_range("poly");
                }
#endif
                std::int64_t non_zero = (*poly != 0);
                *result = (modulus_value - *poly) &
                    static_cast<std::uint64_t>(-non_zero);
            }
        }

        inline void add_poly_poly_coeffmod(const std::uint64_t *operand1,
            const std::uint64_t *operand2, std::size_t coeff_count,
            const SmallModulus &modulus, std::uint64_t *result)
        {
#ifdef SEAL_DEBUG
            if (operand1 == nullptr && coeff_count > 0)
            {
                throw std::invalid_argument("operand1");
            }
            if (operand2 == nullptr && coeff_count > 0)
            {
                throw std::invalid_argument("operand2");
            }
            if (modulus.is_zero())
            {
                throw std::invalid_argument("modulus");
            }
            if (result == nullptr && coeff_count > 0)
            {
                throw std::invalid_argument("result");
            }
#endif
            const uint64_t modulus_value = modulus.value();
            for (; coeff_count--; result++, operand1++, operand2++)
            {
                // Explicit inline
                //result[i] = add_uint_uint_mod(operand1[i], operand2[i], modulus);
#ifdef SEAL_DEBUG
                if (*operand1 >= modulus_value)
                {
                    throw std::invalid_argument("operand1");
                }
                if (*operand2 >= modulus_value)
                {
                    throw std::invalid_argument("operand2");
                }
#endif
                std::uint64_t sum = *operand1 + *operand2;
                *result = sum - (modulus_value & static_cast<std::uint64_t>(
                    -static_cast<std::int64_t>(sum >= modulus_value)));
            }
        }

        inline void sub_poly_poly_coeffmod(const std::uint64_t *operand1,
            const std::uint64_t *operand2, std::size_t coeff_count,
            const SmallModulus &modulus, std::uint64_t *result)
        {
#ifdef SEAL_DEBUG
            if (operand1 == nullptr && coeff_count > 0)
            {
                throw std::invalid_argument("operand1");
            }
            if (operand2 == nullptr && coeff_count > 0)
            {
                throw std::invalid_argument("operand2");
            }
            if (modulus.is_zero())
            {
                throw std::invalid_argument("modulus");
            }
            if (result == nullptr && coeff_count > 0)
            {
                throw std::invalid_argument("result");
            }
#endif
            const uint64_t modulus_value = modulus.value();
            for (; coeff_count--; result++, operand1++, operand2++)
            {
#ifdef SEAL_DEBUG
                if (*operand1 >= modulus_value)
                {
                    throw std::out_of_range("operand1");
                }
                if (*operand2 >= modulus_value)
                {
                    throw std::out_of_range("operand2");
                }
#endif
                unsigned long long temp_result;
                std::int64_t borrow = sub_uint64(*operand1, *operand2, &temp_result);
                *result = temp_result + (modulus_value & static_cast<std::uint64_t>(-borrow));
            }
        }

        void multiply_poly_scalar_coeffmod(const std::uint64_t *poly,
            std::size_t coeff_count, std::uint64_t scalar, const SmallModulus &modulus,
            std::uint64_t *result);

        void multiply_poly_poly_coeffmod(const std::uint64_t *operand1,
            std::size_t operand1_coeff_count, const std::uint64_t *operand2,
            std::size_t operand2_coeff_count, const SmallModulus &modulus,
            std::size_t result_coeff_count, std::uint64_t *result);

        void multiply_poly_poly_coeffmod(const std::uint64_t *operand1,
            const std::uint64_t *operand2, std::size_t coeff_count,
            const SmallModulus &modulus, std::uint64_t *result);

        inline void multiply_truncate_poly_poly_coeffmod(
            const std::uint64_t *operand1, const std::uint64_t *operand2,
            std::size_t coeff_count, const SmallModulus &modulus, std::uint64_t *result)
        {
            multiply_poly_poly_coeffmod(operand1, coeff_count, operand2, coeff_count,
                modulus, coeff_count, result);
        }

        void divide_poly_poly_coeffmod_inplace(std::uint64_t *numerator,
            const std::uint64_t *denominator, std::size_t coeff_count,
            const SmallModulus &modulus, std::uint64_t *quotient);

        inline void divide_poly_poly_coeffmod(const std::uint64_t *numerator,
            const std::uint64_t *denominator, std::size_t coeff_count,
            const SmallModulus &modulus, std::uint64_t *quotient,
            std::uint64_t *remainder)
        {
            set_uint_uint(numerator, coeff_count, remainder);
            divide_poly_poly_coeffmod_inplace(remainder, denominator, coeff_count,
                modulus, quotient);
        }

        void apply_galois(const std::uint64_t *input, int coeff_count_power,
            std::uint64_t galois_elt, const SmallModulus &modulus, std::uint64_t *result);

        void apply_galois_ntt(const std::uint64_t *input, int coeff_count_power,
            std::uint64_t galois_elt, std::uint64_t *result);

        void dyadic_product_coeffmod(const std::uint64_t *operand1,
            const std::uint64_t *operand2, std::size_t coeff_count,
            const SmallModulus &modulus, std::uint64_t *result);

        std::uint64_t poly_infty_norm_coeffmod(const std::uint64_t *operand,
            std::size_t coeff_count, const SmallModulus &modulus);

        bool try_invert_poly_coeffmod(const std::uint64_t *operand,
            const std::uint64_t *poly_modulus, std::size_t coeff_count,
            const SmallModulus &modulus, std::uint64_t *result, MemoryPool &pool);

        void negacyclic_shift_poly_coeffmod(const std::uint64_t *operand,
            std::size_t coeff_count, std::size_t shift, const SmallModulus &modulus,
            std::uint64_t *result);

        inline void negacyclic_multiply_poly_mono_coeffmod(
            const std::uint64_t *operand, std::size_t coeff_count,
            std::uint64_t mono_coeff, std::size_t mono_exponent,
            const SmallModulus &modulus, std::uint64_t *result, MemoryPool &pool)
        {
            auto temp(util::allocate_uint(coeff_count, pool));
            multiply_poly_scalar_coeffmod(
                operand, coeff_count, mono_coeff, modulus, temp.get());
            negacyclic_shift_poly_coeffmod(temp.get(), coeff_count, mono_exponent,
                modulus, result);
        }
    }
}
