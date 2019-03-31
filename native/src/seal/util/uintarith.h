// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#pragma once

#include <stdexcept>
#include <cstdint>
#include <functional>
#include <type_traits>
#include "seal/util/common.h"
#include "seal/util/uintcore.h"
#include "seal/util/pointer.h"
#include "seal/util/defines.h"

namespace seal
{
    namespace util
    {
        template<typename T, typename S, typename = std::enable_if<is_uint64_v<T, S>>>
        inline unsigned char add_uint64_generic(T operand1, S operand2,
            unsigned char carry, unsigned long long *result)
        {
#ifdef SEAL_DEBUG
            if (!result)
            {
                throw std::invalid_argument("result cannot be null");
            }
#endif
            operand1 += operand2;
            *result = operand1 + carry;
            return (operand1 < operand2) || (~operand1 < carry);
        }

        template<typename T, typename S, typename = std::enable_if<is_uint64_v<T, S>>>
        inline unsigned char add_uint64(T operand1, S operand2,
            unsigned char carry, unsigned long long *result)
        {
            return SEAL_ADD_CARRY_UINT64(operand1, operand2, carry, result);
        }

        template<typename T, typename S, typename R,
            typename = std::enable_if<is_uint64_v<T, S, R>>>
        inline unsigned char add_uint64(T operand1, S operand2, R *result)
        {
            *result = operand1 + operand2;
            return static_cast<unsigned char>(*result < operand1);
        }

        inline unsigned char add_uint_uint(const std::uint64_t *operand1,
            std::size_t operand1_uint64_count, const std::uint64_t *operand2,
            std::size_t operand2_uint64_count, unsigned char carry,
            std::size_t result_uint64_count, std::uint64_t *result)
        {
#ifdef SEAL_DEBUG
            if (!operand1_uint64_count)
            {
                throw std::invalid_argument("operand1_uint64_count");
            }
            if (!operand2_uint64_count)
            {
                throw std::invalid_argument("operand2_uint64_count");
            }
            if (!result_uint64_count)
            {
                throw std::invalid_argument("result_uint64_count");
            }
            if (!operand1)
            {
                throw std::invalid_argument("operand1");
            }
            if (!operand2)
            {
                throw std::invalid_argument("operand2");
            }
            if (!result)
            {
                throw std::invalid_argument("result");
            }
#endif
            for (std::size_t i = 0; i < result_uint64_count; i++)
            {
                unsigned long long temp_result;
                carry = add_uint64(
                    (i < operand1_uint64_count) ? *operand1++ : 0,
                    (i < operand2_uint64_count) ? *operand2++ : 0,
                    carry, &temp_result);
                *result++ = temp_result;
            }
            return carry;
        }

        inline unsigned char add_uint_uint(const std::uint64_t *operand1,
            const std::uint64_t *operand2, std::size_t uint64_count,
            std::uint64_t *result)
        {
#ifdef SEAL_DEBUG
            if (!uint64_count)
            {
                throw std::invalid_argument("uint64_count");
            }
            if (!operand1)
            {
                throw std::invalid_argument("operand1");
            }
            if (!operand2)
            {
                throw std::invalid_argument("operand2");
            }
            if (!result)
            {
                throw std::invalid_argument("result");
            }
#endif
            // Unroll first iteration of loop. We assume uint64_count > 0.
            unsigned char carry = add_uint64(*operand1++, *operand2++, result++);

            // Do the rest
            for(; --uint64_count; operand1++, operand2++, result++)
            {
                unsigned long long temp_result;
                carry = add_uint64(*operand1, *operand2, carry, &temp_result);
                *result = temp_result;
            }
            return carry;
        }

        inline unsigned char add_uint_uint64(const std::uint64_t *operand1,
            std::uint64_t operand2, std::size_t uint64_count, std::uint64_t *result)
        {
#ifdef SEAL_DEBUG
            if (!uint64_count)
            {
                throw std::invalid_argument("uint64_count");
            }
            if (!operand1)
            {
                throw std::invalid_argument("operand1");
            }
            if (!result)
            {
                throw std::invalid_argument("result");
            }
#endif
            // Unroll first iteration of loop. We assume uint64_count > 0.
            unsigned char carry = add_uint64(*operand1++, operand2, result++);

            // Do the rest
            for(; --uint64_count; operand1++, result++)
            {
                unsigned long long temp_result;
                carry = add_uint64(*operand1, std::uint64_t(0), carry, &temp_result);
                *result = temp_result;
            }
            return carry;
        }

        template<typename T, typename S, typename = std::enable_if<is_uint64_v<T, S>>>
        inline unsigned char sub_uint64_generic(T operand1, S operand2,
            unsigned char borrow, unsigned long long *result)
        {
#ifdef SEAL_DEBUG
            if (!result)
            {
                throw std::invalid_argument("result cannot be null");
            }
#endif
            auto diff = operand1 - operand2;
            *result = diff - (borrow != 0);
            return (diff > operand1) || (diff < borrow);
        }

        template<typename T, typename S, typename = std::enable_if<is_uint64_v<T, S>>>
        inline unsigned char sub_uint64(T operand1, S operand2,
            unsigned char borrow, unsigned long long *result)
        {
            return SEAL_SUB_BORROW_UINT64(operand1, operand2, borrow, result);
        }

        template<typename T, typename S, typename R,
            typename = std::enable_if<is_uint64_v<T, S, R>>>
        inline unsigned char sub_uint64(T operand1, S operand2, R *result)
        {
            *result = operand1 - operand2;
            return static_cast<unsigned char>(operand2 > operand1);
        }

        inline unsigned char sub_uint_uint(const std::uint64_t *operand1,
            std::size_t operand1_uint64_count, const std::uint64_t *operand2,
            std::size_t operand2_uint64_count, unsigned char borrow,
            std::size_t result_uint64_count, std::uint64_t *result)
        {
#ifdef SEAL_DEBUG
            if (!result_uint64_count)
            {
                throw std::invalid_argument("result_uint64_count");
            }
            if (!result)
            {
                throw std::invalid_argument("result");
            }
#endif
            for (std::size_t i = 0; i < result_uint64_count;
                i++, operand1++, operand2++, result++)
            {
                unsigned long long temp_result;
                borrow = sub_uint64((i < operand1_uint64_count) ? *operand1 : 0,
                    (i < operand2_uint64_count) ? *operand2 : 0, borrow, &temp_result);
                *result = temp_result;
            }
            return borrow;
        }

        inline unsigned char sub_uint_uint(const std::uint64_t *operand1,
            const std::uint64_t *operand2, std::size_t uint64_count, std::uint64_t *result)
        {
#ifdef SEAL_DEBUG
            if (!uint64_count)
            {
                throw std::invalid_argument("uint64_count");
            }
            if (!operand1)
            {
                throw std::invalid_argument("operand1");
            }
            if (!operand2)
            {
                throw std::invalid_argument("operand2");
            }
            if (!result)
            {
                throw std::invalid_argument("result");
            }
#endif
            // Unroll first iteration of loop. We assume uint64_count > 0.
            unsigned char borrow = sub_uint64(*operand1++, *operand2++, result++);

            // Do the rest
            for(; --uint64_count; operand1++, operand2++, result++)
            {
                unsigned long long temp_result;
                borrow = sub_uint64(*operand1, *operand2, borrow, &temp_result);
                *result = temp_result;
            }
            return borrow;
        }

        inline unsigned char sub_uint_uint64(const std::uint64_t *operand1,
            std::uint64_t operand2, std::size_t uint64_count, std::uint64_t *result)
        {
#ifdef SEAL_DEBUG
            if (!uint64_count)
            {
                throw std::invalid_argument("uint64_count");
            }
            if (!operand1)
            {
                throw std::invalid_argument("operand1");
            }
            if (!result)
            {
                throw std::invalid_argument("result");
            }
#endif
            // Unroll first iteration of loop. We assume uint64_count > 0.
            unsigned char borrow = sub_uint64(*operand1++, operand2, result++);

            // Do the rest
            for(; --uint64_count; operand1++, operand2++, result++)
            {
                unsigned long long temp_result;
                borrow = sub_uint64(*operand1, std::uint64_t(0), borrow, &temp_result);
                *result = temp_result;
            }
            return borrow;
        }

        inline unsigned char increment_uint(const std::uint64_t *operand,
            std::size_t uint64_count, std::uint64_t *result)
        {
#ifdef SEAL_DEBUG
            if (!operand)
            {
                throw std::invalid_argument("operand");
            }
            if (!uint64_count)
            {
                throw std::invalid_argument("uint64_count");
            }
            if (!result)
            {
                throw std::invalid_argument("result");
            }
#endif
            return add_uint_uint64(operand, 1, uint64_count, result);
        }

        inline unsigned char decrement_uint(const std::uint64_t *operand,
            std::size_t uint64_count, std::uint64_t *result)
        {
#ifdef SEAL_DEBUG
            if (!operand && uint64_count > 0)
            {
                throw std::invalid_argument("operand");
            }
            if (!result && uint64_count > 0)
            {
                throw std::invalid_argument("result");
            }
#endif
            return sub_uint_uint64(operand, 1, uint64_count, result);
        }

        inline void negate_uint(const std::uint64_t *operand, std::size_t uint64_count,
            std::uint64_t *result)
        {
#ifdef SEAL_DEBUG
            if (!operand)
            {
                throw std::invalid_argument("operand");
            }
            if (!uint64_count)
            {
                throw std::invalid_argument("uint64_count");
            }
            if (!result)
            {
                throw std::invalid_argument("result");
            }
#endif
            // Negation is equivalent to inverting bits and adding 1.
            unsigned char carry = add_uint64(~*operand++, std::uint64_t(1), result++);
            for(; --uint64_count; operand++, result++)
            {
                unsigned long long temp_result;
                carry = add_uint64(
                    ~*operand, std::uint64_t(0), carry, &temp_result);
                *result = temp_result;
            }
        }

        inline void left_shift_uint(const std::uint64_t *operand,
            int shift_amount, std::size_t uint64_count, std::uint64_t *result)
        {
            const std::size_t bits_per_uint64_sz =
                static_cast<std::size_t>(bits_per_uint64);
#ifdef SEAL_DEBUG
            if (!operand)
            {
                throw std::invalid_argument("operand");
            }
            if (shift_amount < 0 ||
                unsigned_geq(shift_amount,
                    mul_safe(uint64_count, bits_per_uint64_sz)))
            {
                throw std::invalid_argument("shift_amount");
            }
            if (!uint64_count)
            {
                throw std::invalid_argument("uint64_count");
            }
            if (!result)
            {
                throw std::invalid_argument("result");
            }
#endif
            // How many words to shift
            std::size_t uint64_shift_amount =
                static_cast<std::size_t>(shift_amount) / bits_per_uint64_sz;

            // Shift words
            for (std::size_t i = 0; i < uint64_count - uint64_shift_amount; i++)
            {
                result[uint64_count - i - 1] = operand[uint64_count - i - 1 - uint64_shift_amount];
            }
            for (std::size_t i = uint64_count - uint64_shift_amount; i < uint64_count; i++)
            {
                result[uint64_count - i - 1] = 0;
            }

            // How many bits to shift in addition
            std::size_t bit_shift_amount = static_cast<std::size_t>(shift_amount)
                - (uint64_shift_amount * bits_per_uint64_sz);

            if (bit_shift_amount)
            {
                std::size_t neg_bit_shift_amount = bits_per_uint64_sz - bit_shift_amount;

                for (std::size_t i = uint64_count - 1; i > 0; i--)
                {
                    result[i] = (result[i] << bit_shift_amount) |
                        (result[i - 1] >> neg_bit_shift_amount);
                }
                result[0] = result[0] << bit_shift_amount;
            }
        }

        inline void right_shift_uint(const std::uint64_t *operand,
            int shift_amount, std::size_t uint64_count, std::uint64_t *result)
        {
            const std::size_t bits_per_uint64_sz =
                static_cast<std::size_t>(bits_per_uint64);
#ifdef SEAL_DEBUG
            if (!operand)
            {
                throw std::invalid_argument("operand");
            }
            if (shift_amount < 0 ||
                unsigned_geq(shift_amount,
                    mul_safe(uint64_count, bits_per_uint64_sz)))
            {
                throw std::invalid_argument("shift_amount");
            }
            if (!uint64_count)
            {
                throw std::invalid_argument("uint64_count");
            }
            if (!result)
            {
                throw std::invalid_argument("result");
            }
#endif
            // How many words to shift
            std::size_t uint64_shift_amount =
                static_cast<std::size_t>(shift_amount) / bits_per_uint64_sz;

            // Shift words
            for (std::size_t i = 0; i < uint64_count - uint64_shift_amount; i++)
            {
                result[i] = operand[i + uint64_shift_amount];
            }
            for (std::size_t i = uint64_count - uint64_shift_amount; i < uint64_count; i++)
            {
                result[i] = 0;
            }

            // How many bits to shift in addition
            std::size_t bit_shift_amount = static_cast<std::size_t>(shift_amount)
                - (uint64_shift_amount * bits_per_uint64_sz);

            if (bit_shift_amount)
            {
                std::size_t neg_bit_shift_amount = bits_per_uint64_sz - bit_shift_amount;

                for (std::size_t i = 0; i < uint64_count - 1; i++)
                {
                    result[i] = (result[i] >> bit_shift_amount) |
                        (result[i + 1] << neg_bit_shift_amount);
                }
                result[uint64_count - 1] = result[uint64_count - 1] >> bit_shift_amount;
            }
        }

        inline void left_shift_uint128(
            const std::uint64_t *operand, int shift_amount, std::uint64_t *result)
        {
            const std::size_t bits_per_uint64_sz =
                static_cast<std::size_t>(bits_per_uint64);
#ifdef SEAL_DEBUG
            if (!operand)
            {
                throw std::invalid_argument("operand");
            }
            if (shift_amount < 0 ||
                unsigned_geq(shift_amount, 2 * bits_per_uint64_sz))
            {
                throw std::invalid_argument("shift_amount");
            }
            if (!result)
            {
                throw std::invalid_argument("result");
            }
#endif
            const std::size_t shift_amount_sz =
                static_cast<std::size_t>(shift_amount);

            // Early return
            if (shift_amount_sz & bits_per_uint64_sz)
            {
                result[1] = operand[0];
                result[0] = 0;
            }
            else
            {
                result[1] = operand[1];
                result[0] = operand[0];
            }

            // How many bits to shift in addition to word shift
            std::size_t bit_shift_amount = shift_amount_sz & (bits_per_uint64_sz - 1);

            // Do we have a word shift
            if (bit_shift_amount)
            {
                std::size_t neg_bit_shift_amount = bits_per_uint64_sz - bit_shift_amount;

                // Warning: if bit_shift_amount == 0 this is incorrect
                result[1] = (result[1] << bit_shift_amount) |
                    (result[0] >> neg_bit_shift_amount);
                result[0] = result[0] << bit_shift_amount;
            }
        }

        inline void right_shift_uint128(
            const std::uint64_t *operand, int shift_amount, std::uint64_t *result)
        {
            const std::size_t bits_per_uint64_sz =
                static_cast<std::size_t>(bits_per_uint64);
#ifdef SEAL_DEBUG
            if (!operand)
            {
                throw std::invalid_argument("operand");
            }
            if (shift_amount < 0 ||
                unsigned_geq(shift_amount, 2 * bits_per_uint64_sz))
            {
                throw std::invalid_argument("shift_amount");
            }
            if (!result)
            {
                throw std::invalid_argument("result");
            }
#endif
            const std::size_t shift_amount_sz =
                static_cast<std::size_t>(shift_amount);

            if (shift_amount_sz & bits_per_uint64_sz)
            {
                result[0] = operand[1];
                result[1] = 0;
            }
            else
            {
                result[1] = operand[1];
                result[0] = operand[0];
            }

            // How many bits to shift in addition to word shift
            std::size_t bit_shift_amount = shift_amount_sz & (bits_per_uint64_sz - 1);

            if (bit_shift_amount)
            {
                std::size_t neg_bit_shift_amount = bits_per_uint64_sz - bit_shift_amount;

                // Warning: if bit_shift_amount == 0 this is incorrect
                result[0] = (result[0] >> bit_shift_amount) |
                    (result[1] << neg_bit_shift_amount);
                result[1] = result[1] >> bit_shift_amount;
            }
        }

        inline void left_shift_uint192(
            const std::uint64_t *operand, int shift_amount, std::uint64_t *result)
        {
            const std::size_t bits_per_uint64_sz =
                static_cast<std::size_t>(bits_per_uint64);
#ifdef SEAL_DEBUG
            if (!operand)
            {
                throw std::invalid_argument("operand");
            }
            if (shift_amount < 0 ||
                unsigned_geq(shift_amount, 3 * bits_per_uint64_sz))
            {
                throw std::invalid_argument("shift_amount");
            }
            if (!result)
            {
                throw std::invalid_argument("result");
            }
#endif
            const std::size_t shift_amount_sz =
                static_cast<std::size_t>(shift_amount);

            if (shift_amount_sz & (bits_per_uint64_sz << 1))
            {
                result[2] = operand[0];
                result[1] = 0;
                result[0] = 0;
            }
            else if (shift_amount_sz & bits_per_uint64_sz)
            {
                result[2] = operand[1];
                result[1] = operand[0];
                result[0] = 0;
            }
            else
            {
                result[2] = operand[2];
                result[1] = operand[1];
                result[0] = operand[0];
            }

            // How many bits to shift in addition to word shift
            std::size_t bit_shift_amount = shift_amount_sz & (bits_per_uint64_sz - 1);

            if (bit_shift_amount)
            {
                std::size_t neg_bit_shift_amount = bits_per_uint64_sz - bit_shift_amount;

                // Warning: if bit_shift_amount == 0 this is incorrect
                result[2] = (result[2] << bit_shift_amount) |
                    (result[1] >> neg_bit_shift_amount);
                result[1] = (result[1] << bit_shift_amount) |
                    (result[0] >> neg_bit_shift_amount);
                result[0] = result[0] << bit_shift_amount;
            }
        }

        inline void right_shift_uint192(
            const std::uint64_t *operand, int shift_amount, std::uint64_t *result)
        {
            const std::size_t bits_per_uint64_sz =
                static_cast<std::size_t>(bits_per_uint64);
#ifdef SEAL_DEBUG
            if (!operand)
            {
                throw std::invalid_argument("operand");
            }
            if (shift_amount < 0 ||
                unsigned_geq(shift_amount, 3 * bits_per_uint64_sz))
            {
                throw std::invalid_argument("shift_amount");
            }
            if (!result)
            {
                throw std::invalid_argument("result");
            }
#endif
            const std::size_t shift_amount_sz =
                static_cast<std::size_t>(shift_amount);

            if (shift_amount_sz & (bits_per_uint64_sz << 1))
            {
                result[0] = operand[2];
                result[1] = 0;
                result[2] = 0;
            }
            else if (shift_amount_sz & bits_per_uint64_sz)
            {
                result[0] = operand[1];
                result[1] = operand[2];
                result[2] = 0;
            }
            else
            {
                result[2] = operand[2];
                result[1] = operand[1];
                result[0] = operand[0];
            }

            // How many bits to shift in addition to word shift
            std::size_t bit_shift_amount = shift_amount_sz & (bits_per_uint64_sz - 1);

            if (bit_shift_amount)
            {
                std::size_t neg_bit_shift_amount = bits_per_uint64_sz - bit_shift_amount;

                // Warning: if bit_shift_amount == 0 this is incorrect
                result[0] = (result[0] >> bit_shift_amount) |
                    (result[1] << neg_bit_shift_amount);
                result[1] = (result[1] >> bit_shift_amount) |
                    (result[2] << neg_bit_shift_amount);
                result[2] = result[2] >> bit_shift_amount;
            }
        }

        inline void half_round_up_uint(const std::uint64_t *operand,
            std::size_t uint64_count, std::uint64_t *result)
        {
#ifdef SEAL_DEBUG
            if (!operand && uint64_count > 0)
            {
                throw std::invalid_argument("operand");
            }
            if (!result && uint64_count > 0)
            {
                throw std::invalid_argument("result");
            }
#endif
            if (!uint64_count)
            {
                return;
            }
            // Set result to (operand + 1) / 2. To prevent overflowing operand, right shift
            // and then increment result if low-bit of operand was set.
            bool low_bit_set = operand[0] & 1;

            for (std::size_t i = 0; i < uint64_count - 1; i++)
            {
                result[i] = (operand[i] >> 1) | (operand[i + 1] << (bits_per_uint64 - 1));
            }
            result[uint64_count - 1] = operand[uint64_count - 1] >> 1;

            if (low_bit_set)
            {
                increment_uint(result, uint64_count, result);
            }
        }

        inline void not_uint(const std::uint64_t *operand, std::size_t uint64_count,
            std::uint64_t *result)
        {
#ifdef SEAL_DEBUG
            if (!operand && uint64_count > 0)
            {
                throw std::invalid_argument("operand");
            }
            if (!result && uint64_count > 0)
            {
                throw std::invalid_argument("result");
            }
#endif
            for (; uint64_count--; result++, operand++)
            {
                *result = ~*operand;
            }
        }

        inline void and_uint_uint(const std::uint64_t *operand1,
            const std::uint64_t *operand2, std::size_t uint64_count, std::uint64_t *result)
        {
#ifdef SEAL_DEBUG
            if (!operand1 && uint64_count > 0)
            {
                throw std::invalid_argument("operand1");
            }
            if (!operand2 && uint64_count > 0)
            {
                throw std::invalid_argument("operand2");
            }
            if (!result && uint64_count > 0)
            {
                throw std::invalid_argument("result");
            }
#endif
            for (; uint64_count--; result++, operand1++, operand2++)
            {
                *result = *operand1 & *operand2;
            }
        }

        inline void or_uint_uint(const std::uint64_t *operand1,
            const std::uint64_t *operand2, std::size_t uint64_count, std::uint64_t *result)
        {
#ifdef SEAL_DEBUG
            if (!operand1 && uint64_count > 0)
            {
                throw std::invalid_argument("operand1");
            }
            if (!operand2 && uint64_count > 0)
            {
                throw std::invalid_argument("operand2");
            }
            if (!result && uint64_count > 0)
            {
                throw std::invalid_argument("result");
            }
#endif
            for (; uint64_count--; result++, operand1++, operand2++)
            {
                *result = *operand1 | *operand2;
            }
        }

        inline void xor_uint_uint(const std::uint64_t *operand1,
            const std::uint64_t *operand2, std::size_t uint64_count, std::uint64_t *result)
        {
#ifdef SEAL_DEBUG
            if (!operand1 && uint64_count > 0)
            {
                throw std::invalid_argument("operand1");
            }
            if (!operand2 && uint64_count > 0)
            {
                throw std::invalid_argument("operand2");
            }
            if (!result && uint64_count > 0)
            {
                throw std::invalid_argument("result");
            }
#endif
            for (; uint64_count--; result++, operand1++, operand2++)
            {
                *result = *operand1 ^ *operand2;
            }
        }

        template<typename T, typename S, typename = std::enable_if<is_uint64_v<T, S>>>
        inline void multiply_uint64_generic(T operand1, S operand2,
            unsigned long long *result128)
        {
#ifdef SEAL_DEBUG
            if (!result128)
            {
                throw std::invalid_argument("result128 cannot be null");
            }
#endif
            auto operand1_coeff_right = operand1 & 0x00000000FFFFFFFF;
            auto operand2_coeff_right = operand2 & 0x00000000FFFFFFFF;
            operand1 >>= 32;
            operand2 >>= 32;

            auto middle1 = operand1 * operand2_coeff_right;
            T middle;
            auto left = operand1 * operand2 + (static_cast<T>(add_uint64(
                middle1, operand2 * operand1_coeff_right, &middle)) << 32);
            auto right = operand1_coeff_right * operand2_coeff_right;
            auto temp_sum = (right >> 32) + (middle & 0x00000000FFFFFFFF);

            result128[1] = static_cast<unsigned long long>(
                left + (middle >> 32) + (temp_sum >> 32));
            result128[0] = static_cast<unsigned long long>(
                (temp_sum << 32) | (right & 0x00000000FFFFFFFF));
        }

        template<typename T, typename S, typename = std::enable_if<is_uint64_v<T, S>>>
        inline void multiply_uint64(T operand1, S operand2,
            unsigned long long *result128)
        {
            SEAL_MULTIPLY_UINT64(operand1, operand2, result128);
        }

        template<typename T, typename S, typename = std::enable_if<is_uint64_v<T, S>>>
        inline void multiply_uint64_hw64_generic(T operand1, S operand2,
            unsigned long long *hw64)
        {
#ifdef SEAL_DEBUG
            if (!hw64)
            {
                throw std::invalid_argument("hw64 cannot be null");
            }
#endif
            auto operand1_coeff_right = operand1 & 0x00000000FFFFFFFF;
            auto operand2_coeff_right = operand2 & 0x00000000FFFFFFFF;
            operand1 >>= 32;
            operand2 >>= 32;

            auto middle1 = operand1 * operand2_coeff_right;
            T middle;
            auto left = operand1 * operand2 + (static_cast<T>(add_uint64(
                middle1, operand2 * operand1_coeff_right, &middle)) << 32);
            auto right = operand1_coeff_right * operand2_coeff_right;
            auto temp_sum = (right >> 32) + (middle & 0x00000000FFFFFFFF);

            *hw64 = static_cast<unsigned long long>(
                left + (middle >> 32) + (temp_sum >> 32));
        }

        template<typename T, typename S, typename = std::enable_if<is_uint64_v<T, S>>>
        inline void multiply_uint64_hw64(T operand1, S operand2,
            unsigned long long *hw64)
        {
            SEAL_MULTIPLY_UINT64_HW64(operand1, operand2, hw64);
        }

        void multiply_uint_uint(const std::uint64_t *operand1,
            std::size_t operand1_uint64_count, const std::uint64_t *operand2,
            std::size_t operand2_uint64_count, std::size_t result_uint64_count,
            std::uint64_t *result);

        inline void multiply_uint_uint(const std::uint64_t *operand1,
            const std::uint64_t *operand2, std::size_t uint64_count, std::uint64_t *result)
        {
            multiply_uint_uint(operand1, uint64_count, operand2, uint64_count,
                uint64_count * 2, result);
        }

        void multiply_uint_uint64(const std::uint64_t *operand1,
            std::size_t operand1_uint64_count, std::uint64_t operand2,
            std::size_t result_uint64_count, std::uint64_t *result);

        inline void multiply_truncate_uint_uint(const std::uint64_t *operand1,
            const std::uint64_t *operand2, std::size_t uint64_count, std::uint64_t *result)
        {
            multiply_uint_uint(operand1, uint64_count, operand2, uint64_count,
                uint64_count, result);
        }

        void divide_uint_uint_inplace(std::uint64_t *numerator,
            const std::uint64_t *denominator, std::size_t uint64_count,
            std::uint64_t *quotient, MemoryPool &pool);

        inline void divide_uint_uint(const std::uint64_t *numerator,
            const std::uint64_t *denominator, std::size_t uint64_count,
            std::uint64_t *quotient, std::uint64_t *remainder, MemoryPool &pool)
        {
            set_uint_uint(numerator, uint64_count, remainder);
            divide_uint_uint_inplace(remainder, denominator, uint64_count, quotient, pool);
        }

        void divide_uint128_uint64_inplace_generic(std::uint64_t *numerator,
            std::uint64_t denominator, std::uint64_t *quotient);

        inline void divide_uint128_uint64_inplace(std::uint64_t *numerator,
            std::uint64_t denominator, std::uint64_t *quotient)
        {
#ifdef SEAL_DEBUG
            if (!numerator)
            {
                throw std::invalid_argument("numerator");
            }
            if (denominator == 0)
            {
                throw std::invalid_argument("denominator");
            }
            if (!quotient)
            {
                throw std::invalid_argument("quotient");
            }
            if (numerator == quotient)
            {
                throw std::invalid_argument("quotient cannot point to same value as numerator");
            }
#endif
            SEAL_DIVIDE_UINT128_UINT64(numerator, denominator, quotient);
        }

        void divide_uint128_uint64_inplace(std::uint64_t *numerator,
            std::uint64_t denominator, std::uint64_t *quotient);

        void divide_uint192_uint64_inplace(std::uint64_t *numerator,
            std::uint64_t denominator, std::uint64_t *quotient);

        void exponentiate_uint(const std::uint64_t *operand,
            std::size_t operand_uint64_count, const std::uint64_t *exponent,
            std::size_t exponent_uint64_count, std::size_t result_uint64_count,
            std::uint64_t *result, MemoryPool &pool);

        std::uint64_t exponentiate_uint64_safe(std::uint64_t operand,
            std::uint64_t exponent);

        std::uint64_t exponentiate_uint64(std::uint64_t operand,
            std::uint64_t exponent);
    }
}
