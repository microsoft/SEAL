// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#pragma once

#include <cstdint>
#include <type_traits>
#include "seal/smallmodulus.h"
#include "seal/util/defines.h"
#include "seal/util/pointer.h"
#include "seal/util/numth.h"
#include "seal/util/uintarith.h"

namespace seal
{
    namespace util
    {
        inline std::uint64_t increment_uint_mod(std::uint64_t operand,
            const SmallModulus &modulus)
        {
#ifdef SEAL_DEBUG
            if (modulus.is_zero())
            {
                throw std::invalid_argument("modulus");
            }
            if (operand >= modulus.value())
            {
                throw std::out_of_range("operand");
            }
#endif
            operand++;
            return operand - (modulus.value() & static_cast<std::uint64_t>(
                -static_cast<std::int64_t>(operand >= modulus.value())));
        }

        inline std::uint64_t decrement_uint_mod(std::uint64_t operand,
            const SmallModulus &modulus)
        {
#ifdef SEAL_DEBUG
            if (modulus.is_zero())
            {
                throw std::invalid_argument("modulus");
            }
            if (operand >= modulus.value())
            {
                throw std::out_of_range("operand");
            }
#endif
            std::int64_t carry = (operand == 0);
            return operand - 1 + (modulus.value() &
                static_cast<std::uint64_t>(-carry));
        }

        inline std::uint64_t negate_uint_mod(std::uint64_t operand,
            const SmallModulus &modulus)
        {
#ifdef SEAL_DEBUG
            if (modulus.is_zero())
            {
                throw std::invalid_argument("modulus");
            }
            if (operand >= modulus.value())
            {
                throw std::out_of_range("operand");
            }
#endif
            std::int64_t non_zero = (operand != 0);
            return (modulus.value() - operand)
                & static_cast<std::uint64_t>(-non_zero);
        }

        inline std::uint64_t div2_uint_mod(std::uint64_t operand,
            const SmallModulus &modulus)
        {
#ifdef SEAL_DEBUG
            if (modulus.is_zero())
            {
                throw std::invalid_argument("modulus");
            }
            if (operand >= modulus.value())
            {
                throw std::out_of_range("operand");
            }
#endif
            if (operand & 1)
            {
                unsigned long long temp;
                int64_t carry = add_uint64(operand, modulus.value(), 0, &temp);
                operand = temp >> 1;
                if (carry)
                {
                    return operand | (std::uint64_t(1) << (bits_per_uint64 - 1));
                }
                return operand;
            }
            return operand >> 1;
        }

        inline std::uint64_t add_uint_uint_mod(std::uint64_t operand1,
            std::uint64_t operand2, const SmallModulus &modulus)
        {
#ifdef SEAL_DEBUG
            if (modulus.is_zero())
            {
                throw std::invalid_argument("modulus");
            }
            if (operand1 >= modulus.value())
            {
                throw std::out_of_range("operand1");
            }
            if (operand2 >= modulus.value())
            {
                throw std::out_of_range("operand2");
            }
#endif
            // Sum of operands modulo SmallModulus can never wrap around 2^64
            operand1 += operand2;
            return operand1 - (modulus.value() & static_cast<std::uint64_t>(
                -static_cast<std::int64_t>(operand1 >= modulus.value())));
        }

        inline std::uint64_t sub_uint_uint_mod(std::uint64_t operand1,
            std::uint64_t operand2, const SmallModulus &modulus)
        {
#ifdef SEAL_DEBUG
            if (modulus.is_zero())
            {
                throw std::invalid_argument("modulus");
            }

            if (operand1 >= modulus.value())
            {
                throw std::out_of_range("operand1");
            }
            if (operand2 >= modulus.value())
            {
                throw std::out_of_range("operand2");
            }
#endif
            unsigned long long temp;
            std::int64_t borrow = SEAL_SUB_BORROW_UINT64(operand1, operand2, 0, &temp);
            return static_cast<std::uint64_t>(temp) +
                (modulus.value() & static_cast<std::uint64_t>(-borrow));
        }

        template<typename T, typename = std::enable_if<is_uint64_v<T>>>
        inline std::uint64_t barrett_reduce_128(const T *input,
            const SmallModulus &modulus)
        {
#ifdef SEAL_DEBUG
            if (!input)
            {
                throw std::invalid_argument("input");
            }
            if (modulus.is_zero())
            {
                throw std::invalid_argument("modulus");
            }
#endif
            // Reduces input using base 2^64 Barrett reduction
            // input allocation size must be 128 bits

            unsigned long long tmp1, tmp2[2], tmp3, carry;
            const std::uint64_t *const_ratio = modulus.const_ratio().data();

            // Multiply input and const_ratio
            // Round 1
            multiply_uint64_hw64(input[0], const_ratio[0], &carry);

            multiply_uint64(input[0], const_ratio[1], tmp2);
            tmp3 = tmp2[1] + add_uint64(tmp2[0], carry, 0, &tmp1);

            // Round 2
            multiply_uint64(input[1], const_ratio[0], tmp2);
            carry = tmp2[1] + add_uint64(tmp1, tmp2[0], 0, &tmp1);

            // This is all we care about
            tmp1 = input[1] * const_ratio[1] + tmp3 + carry;

            // Barrett subtraction
            tmp3 = input[0] - tmp1 * modulus.value();

            // One more subtraction is enough
            return static_cast<std::uint64_t>(tmp3) -
                (modulus.value() & static_cast<std::uint64_t>(
                    -static_cast<std::int64_t>(tmp3 >= modulus.value())));
        }

        template<typename T, typename = std::enable_if<is_uint64_v<T>>>
        inline std::uint64_t barrett_reduce_63(T input,
            const SmallModulus &modulus)
        {
#ifdef SEAL_DEBUG
            if (modulus.is_zero())
            {
                throw std::invalid_argument("modulus");
            }
            if (input >> 63)
            {
                throw std::invalid_argument("input");
            }
#endif
            // Reduces input using base 2^64 Barrett reduction
            // input must be at most 63 bits

            unsigned long long tmp[2];
            const std::uint64_t *const_ratio = modulus.const_ratio().data();
            multiply_uint64(input, const_ratio[1], tmp);

            // Barrett subtraction
            tmp[0] = input - tmp[1] * modulus.value();

            // One more subtraction is enough
            return static_cast<std::uint64_t>(tmp[0]) -
                (modulus.value() & static_cast<std::uint64_t>(
                    -static_cast<std::int64_t>(tmp[0] >= modulus.value())));
        }

        inline std::uint64_t multiply_uint_uint_mod(std::uint64_t operand1,
            std::uint64_t operand2, const SmallModulus &modulus)
        {
#ifdef SEAL_DEBUG
            if (modulus.is_zero())
            {
                throw std::invalid_argument("modulus");
            }
#endif
            unsigned long long z[2];
            multiply_uint64(operand1, operand2, z);
            return barrett_reduce_128(z, modulus);
        }

        inline void modulo_uint_inplace(std::uint64_t *value,
            std::size_t value_uint64_count, const SmallModulus &modulus)
        {
#ifdef SEAL_DEBUG
            if (!value && value_uint64_count > 0)
            {
                throw std::invalid_argument("value");
            }
#endif
            if (value_uint64_count == 1)
            {
                value[0] %= modulus.value();
                return;
            }

            // Starting from the top, reduce always 128-bit blocks
            for (std::size_t i = value_uint64_count - 1; i--; )
            {
                value[i] = barrett_reduce_128(value + i, modulus);
                value[i + 1] = 0;
            }
        }

        inline std::uint64_t modulo_uint(const std::uint64_t *value,
            std::size_t value_uint64_count, const SmallModulus &modulus,
            MemoryPool &pool)
        {
#ifdef SEAL_DEBUG
            if (!value && value_uint64_count)
            {
                throw std::invalid_argument("value");
            }
            if (!value_uint64_count)
            {
                throw std::invalid_argument("value_uint64_count");
            }
#endif
            if (value_uint64_count == 1)
            {
                // If value < modulus no operation is needed
                return *value % modulus.value();
            }

            auto value_copy(allocate_uint(value_uint64_count, pool));
            set_uint_uint(value, value_uint64_count, value_copy.get());

            // Starting from the top, reduce always 128-bit blocks
            for (std::size_t i = value_uint64_count - 1; i--; )
            {
                value_copy[i] = barrett_reduce_128(value_copy.get() + i, modulus);
            }

            return value_copy[0];
        }

        inline bool try_invert_uint_mod(uint64_t operand,
            const SmallModulus &modulus, std::uint64_t &result)
        {
            return try_mod_inverse(operand, modulus.value(), result);
        }

        bool is_primitive_root(std::uint64_t root, std::uint64_t degree,
            const SmallModulus &prime_modulus);

        // Try to find a primitive degree-th root of unity modulo small prime
        // modulus, where degree must be a power of two.
        bool try_primitive_root(std::uint64_t degree,
            const SmallModulus &prime_modulus, std::uint64_t &destination);

        // Try to find the smallest (as integer) primitive degree-th root of
        // unity modulo small prime modulus, where degree must be a power of two.
        bool try_minimal_primitive_root(std::uint64_t degree,
            const SmallModulus &prime_modulus, std::uint64_t &destination);

        std::uint64_t exponentiate_uint_mod(std::uint64_t operand,
            std::uint64_t exponent, const SmallModulus &modulus);

        void divide_uint_uint_mod_inplace(uint64_t *numerator,
            const SmallModulus &modulus, std::size_t uint64_count,
            uint64_t *quotient, MemoryPool &pool);

        std::uint64_t steps_to_galois_elt(int steps, std::size_t coeff_count);
    }
}
