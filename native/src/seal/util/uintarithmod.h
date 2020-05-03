// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#pragma once

#include "seal/util/pointer.h"
#include "seal/util/uintarith.h"
#include "seal/util/uintcore.h"
#include <cstdint>

namespace seal
{
    namespace util
    {
        inline void increment_uint_mod(
            const std::uint64_t *operand, const std::uint64_t *modulus, std::size_t uint64_count, std::uint64_t *result)
        {
#ifdef SEAL_DEBUG
            if (!operand)
            {
                throw std::invalid_argument("operand");
            }
            if (!modulus)
            {
                throw std::invalid_argument("modulus");
            }
            if (!uint64_count)
            {
                throw std::invalid_argument("uint64_count");
            }
            if (!result)
            {
                throw std::invalid_argument("result");
            }
            if (is_greater_than_or_equal_uint(operand, modulus, uint64_count))
            {
                throw std::invalid_argument("operand");
            }
            if (modulus == result)
            {
                throw std::invalid_argument("result cannot point to the same value as modulus");
            }
#endif
            unsigned char carry = increment_uint(operand, uint64_count, result);
            if (carry || is_greater_than_or_equal_uint(result, modulus, uint64_count))
            {
                sub_uint(result, modulus, uint64_count, result);
            }
        }

        inline void decrement_uint_mod(
            const std::uint64_t *operand, const std::uint64_t *modulus, std::size_t uint64_count, std::uint64_t *result)
        {
#ifdef SEAL_DEBUG
            if (!operand)
            {
                throw std::invalid_argument("operand");
            }
            if (!modulus)
            {
                throw std::invalid_argument("modulus");
            }
            if (!uint64_count)
            {
                throw std::invalid_argument("uint64_count");
            }
            if (!result)
            {
                throw std::invalid_argument("result");
            }
            if (is_greater_than_or_equal_uint(operand, modulus, uint64_count))
            {
                throw std::invalid_argument("operand");
            }
            if (modulus == result)
            {
                throw std::invalid_argument("result cannot point to the same value as modulus");
            }
#endif
            if (decrement_uint(operand, uint64_count, result))
            {
                add_uint(result, modulus, uint64_count, result);
            }
        }

        inline void negate_uint_mod(
            const std::uint64_t *operand, const std::uint64_t *modulus, std::size_t uint64_count, std::uint64_t *result)
        {
#ifdef SEAL_DEBUG
            if (!operand)
            {
                throw std::invalid_argument("operand");
            }
            if (!modulus)
            {
                throw std::invalid_argument("modulus");
            }
            if (!uint64_count)
            {
                throw std::invalid_argument("uint64_count");
            }
            if (!result)
            {
                throw std::invalid_argument("result");
            }
            if (is_greater_than_or_equal_uint(operand, modulus, uint64_count))
            {
                throw std::invalid_argument("operand");
            }
#endif
            if (is_zero_uint(operand, uint64_count))
            {
                // Negation of zero is zero.
                set_zero_uint(uint64_count, result);
            }
            else
            {
                // Otherwise, we know operand > 0 and < modulus so subtract modulus - operand.
                sub_uint(modulus, operand, uint64_count, result);
            }
        }

        inline void div2_uint_mod(
            const std::uint64_t *operand, const std::uint64_t *modulus, std::size_t uint64_count, std::uint64_t *result)
        {
#ifdef SEAL_DEBUG
            if (!operand)
            {
                throw std::invalid_argument("operand");
            }
            if (!modulus)
            {
                throw std::invalid_argument("modulus");
            }
            if (!uint64_count)
            {
                throw std::invalid_argument("uint64_count");
            }
            if (!result)
            {
                throw std::invalid_argument("result");
            }
            if (!is_bit_set_uint(modulus, uint64_count, 0))
            {
                throw std::invalid_argument("modulus");
            }
            if (is_greater_than_or_equal_uint(operand, modulus, uint64_count))
            {
                throw std::invalid_argument("operand");
            }
#endif
            if (*operand & 1)
            {
                unsigned char carry = add_uint(operand, modulus, uint64_count, result);
                right_shift_uint(result, 1, uint64_count, result);
                if (carry)
                {
                    set_bit_uint(result, uint64_count, static_cast<int>(uint64_count) * bits_per_uint64 - 1);
                }
            }
            else
            {
                right_shift_uint(operand, 1, uint64_count, result);
            }
        }

        inline void add_uint_uint_mod(
            const std::uint64_t *operand1, const std::uint64_t *operand2, const std::uint64_t *modulus,
            std::size_t uint64_count, std::uint64_t *result)
        {
#ifdef SEAL_DEBUG
            if (!operand1)
            {
                throw std::invalid_argument("operand1");
            }
            if (!operand2)
            {
                throw std::invalid_argument("operand2");
            }
            if (!modulus)
            {
                throw std::invalid_argument("modulus");
            }
            if (!uint64_count)
            {
                throw std::invalid_argument("uint64_count");
            }
            if (!result)
            {
                throw std::invalid_argument("result");
            }
            if (is_greater_than_or_equal_uint(operand1, modulus, uint64_count))
            {
                throw std::invalid_argument("operand1");
            }
            if (is_greater_than_or_equal_uint(operand2, modulus, uint64_count))
            {
                throw std::invalid_argument("operand2");
            }
            if (modulus == result)
            {
                throw std::invalid_argument("result cannot point to the same value as modulus");
            }
#endif
            unsigned char carry = add_uint(operand1, operand2, uint64_count, result);
            if (carry || is_greater_than_or_equal_uint(result, modulus, uint64_count))
            {
                sub_uint(result, modulus, uint64_count, result);
            }
        }

        inline void sub_uint_uint_mod(
            const std::uint64_t *operand1, const std::uint64_t *operand2, const std::uint64_t *modulus,
            std::size_t uint64_count, std::uint64_t *result)
        {
#ifdef SEAL_DEBUG
            if (!operand1)
            {
                throw std::invalid_argument("operand1");
            }
            if (!operand2)
            {
                throw std::invalid_argument("operand2");
            }
            if (!modulus)
            {
                throw std::invalid_argument("modulus");
            }
            if (!uint64_count)
            {
                throw std::invalid_argument("uint64_count");
            }
            if (!result)
            {
                throw std::invalid_argument("result");
            }
            if (is_greater_than_or_equal_uint(operand1, modulus, uint64_count))
            {
                throw std::invalid_argument("operand1");
            }
            if (is_greater_than_or_equal_uint(operand2, modulus, uint64_count))
            {
                throw std::invalid_argument("operand2");
            }
            if (modulus == result)
            {
                throw std::invalid_argument("result cannot point to the same value as modulus");
            }
#endif
            if (sub_uint(operand1, operand2, uint64_count, result))
            {
                add_uint(result, modulus, uint64_count, result);
            }
        }

        bool try_invert_uint_mod(
            const std::uint64_t *operand, const std::uint64_t *modulus, std::size_t uint64_count, std::uint64_t *result,
            MemoryPool &pool);
    } // namespace util
} // namespace seal
