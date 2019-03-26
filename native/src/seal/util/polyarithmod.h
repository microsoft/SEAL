// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#pragma once

#include <cstdint>
#include "seal/util/pointer.h"
#include "seal/util/polycore.h"
#include "seal/util/uintarithmod.h"

namespace seal
{
    namespace util
    {
        inline void negate_poly_coeffmod(const std::uint64_t *poly,
            std::size_t coeff_count, const std::uint64_t *coeff_modulus,
            std::size_t coeff_uint64_count, std::uint64_t *result)
        {
#ifdef SEAL_DEBUG
            if (poly == nullptr && coeff_count > 0)
            {
                throw std::invalid_argument("poly");
            }
            if (coeff_modulus == nullptr)
            {
                throw std::invalid_argument("coeff_modulus");
            }
            if (coeff_uint64_count == 0)
            {
                throw std::invalid_argument("coeff_uint64_count");
            }
            if (result == nullptr && coeff_count > 0)
            {
                throw std::invalid_argument("result");
            }
#endif
            for (std::size_t i = 0; i < coeff_count; i++)
            {
                negate_uint_mod(poly, coeff_modulus, coeff_uint64_count, result);
                poly += coeff_uint64_count;
                result += coeff_uint64_count;
            }
        }

        inline void add_poly_poly_coeffmod(const std::uint64_t *operand1,
            const std::uint64_t *operand2, std::size_t coeff_count,
            const std::uint64_t *coeff_modulus, std::size_t coeff_uint64_count,
            std::uint64_t *result)
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
            if (coeff_modulus == nullptr)
            {
                throw std::invalid_argument("coeff_modulus");
            }
            if (coeff_uint64_count == 0)
            {
                throw std::invalid_argument("coeff_uint64_count");
            }
            if (result == nullptr && coeff_count > 0)
            {
                throw std::invalid_argument("result");
            }
#endif
            for (std::size_t i = 0; i < coeff_count; i++)
            {
                add_uint_uint_mod(operand1, operand2, coeff_modulus,
                    coeff_uint64_count, result);
                operand1 += coeff_uint64_count;
                operand2 += coeff_uint64_count;
                result += coeff_uint64_count;
            }
        }

        inline void sub_poly_poly_coeffmod(const std::uint64_t *operand1,
            const std::uint64_t *operand2, std::size_t coeff_count,
            const std::uint64_t *coeff_modulus, std::size_t coeff_uint64_count,
            std::uint64_t *result)
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
            if (coeff_modulus == nullptr)
            {
                throw std::invalid_argument("coeff_modulus");
            }
            if (coeff_uint64_count == 0)
            {
                throw std::invalid_argument("coeff_uint64_count");
            }
            if (result == nullptr && coeff_count > 0)
            {
                throw std::invalid_argument("result");
            }
#endif
            for (std::size_t i = 0; i < coeff_count; i++)
            {
                sub_uint_uint_mod(operand1, operand2, coeff_modulus,
                    coeff_uint64_count, result);
                operand1 += coeff_uint64_count;
                operand2 += coeff_uint64_count;
                result += coeff_uint64_count;
            }
        }

        void poly_infty_norm_coeffmod(const std::uint64_t *poly,
            std::size_t coeff_count, std::size_t coeff_uint64_count,
            const std::uint64_t *modulus, std::uint64_t *result, MemoryPool &pool);
    }
}
