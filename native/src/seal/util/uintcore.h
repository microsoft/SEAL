// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#pragma once

#include <limits>
#include <cstdint>
#include <stdexcept>
#include <algorithm>
#include <cstring>
#include "seal/util/common.h"
#include "seal/util/pointer.h"
#include "seal/util/defines.h"

namespace seal
{
    namespace util
    {
        std::string uint_to_hex_string(const std::uint64_t *value,
            std::size_t uint64_count);

        std::string uint_to_dec_string(const std::uint64_t *value,
            std::size_t uint64_count, MemoryPool &pool);

        inline void hex_string_to_uint(const char *hex_string,
            int char_count, std::size_t uint64_count, std::uint64_t *result)
        {
#ifdef SEAL_DEBUG
            if (!hex_string && char_count > 0)
            {
                throw std::invalid_argument("hex_string");
            }
            if (uint64_count && !result)
            {
                throw std::invalid_argument("result");
            }
            if (unsigned_gt(get_hex_string_bit_count(hex_string, char_count),
                mul_safe(uint64_count, static_cast<size_t>(bits_per_uint64))))
            {
                throw std::invalid_argument("hex_string");
            }
#endif
            const char *hex_string_ptr = hex_string + char_count;
            for (std::size_t uint64_index = 0;
                uint64_index < uint64_count; uint64_index++)
            {
                std::uint64_t value = 0;
                for (int bit_index = 0; bit_index < bits_per_uint64;
                    bit_index += bits_per_nibble)
                {
                    if (hex_string_ptr == hex_string)
                    {
                        break;
                    }
                    char hex = *--hex_string_ptr;
                    int nibble = hex_to_nibble(hex);
                    if (nibble == -1)
                    {
                        throw std::invalid_argument("hex_value");
                    }
                    value |= static_cast<std::uint64_t>(nibble) << bit_index;
                }
                result[uint64_index] = value;
            }
        }

        inline auto allocate_uint(std::size_t uint64_count, MemoryPool &pool)
        {
            return allocate<std::uint64_t>(uint64_count, pool);
        }

        inline void set_zero_uint(std::size_t uint64_count, std::uint64_t *result)
        {
#ifdef SEAL_DEBUG
            if (!result && uint64_count)
            {
                throw std::invalid_argument("result");
            }
#endif
            std::fill_n(result, uint64_count, std::uint64_t(0));
        }

        inline auto allocate_zero_uint(std::size_t uint64_count, MemoryPool &pool)
        {
            auto result(allocate_uint(uint64_count, pool));
            set_zero_uint(uint64_count, result.get());
            return result;

            // The following looks better but seems to yield worse results.
            // return allocate<std::uint64_t>(uint64_count, pool, std::uint64_t(0));
        }

        inline void set_uint(std::uint64_t value, std::size_t uint64_count,
            std::uint64_t *result)
        {
#ifdef SEAL_DEBUG
            if (!uint64_count)
            {
                throw std::invalid_argument("uint64_count");
            }
            if (!result)
            {
                throw std::invalid_argument("result");
            }
#endif
            *result++ = value;
            for (; --uint64_count; result++)
            {
                *result = 0;
            }
        }

        inline void set_uint_uint(const std::uint64_t *value,
            std::size_t uint64_count, std::uint64_t *result)
        {
#ifdef SEAL_DEBUG
            if (!value && uint64_count)
            {
                throw std::invalid_argument("value");
            }
            if (!result && uint64_count)
            {
                throw std::invalid_argument("result");
            }
#endif
            if ((value == result) || !uint64_count)
            {
                return;
            }
            std::copy_n(value, uint64_count, result);
        }

        inline bool is_zero_uint(const std::uint64_t *value,
            std::size_t uint64_count)
        {
#ifdef SEAL_DEBUG
            if (!value && uint64_count)
            {
                throw std::invalid_argument("value");
            }
#endif
            return std::all_of(value, value + uint64_count,
                [](auto coeff) -> bool { return !coeff; });
        }

        inline bool is_equal_uint(const std::uint64_t *value,
            std::size_t uint64_count, std::uint64_t scalar)
        {
#ifdef SEAL_DEBUG
            if (!value)
            {
                throw std::invalid_argument("value");
            }
            if (!uint64_count)
            {
                throw std::invalid_argument("uint64_count");
            }
#endif
            if (*value++ != scalar)
            {
                return false;
            }
            return std::all_of(value, value + uint64_count - 1,
                [](auto coeff) -> bool { return !coeff; });
        }

        inline bool is_high_bit_set_uint(const std::uint64_t *value,
            std::size_t uint64_count)
        {
#ifdef SEAL_DEBUG
            if (!value)
            {
                throw std::invalid_argument("value");
            }
            if (!uint64_count)
            {
                throw std::invalid_argument("uint64_count");
            }
#endif
            return (value[uint64_count - 1] >> (bits_per_uint64 - 1)) != 0;
        }
#ifndef SEAL_USE_MAYBE_UNUSED
#if (SEAL_COMPILER == SEAL_COMPILER_GCC)
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-parameter"
#elif (SEAL_COMPILER == SEAL_COMPILER_CLANG)
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wunused-parameter"
#endif
#endif
        inline bool is_bit_set_uint(const std::uint64_t *value,
            std::size_t uint64_count SEAL_MAYBE_UNUSED, int bit_index)
        {
#ifdef SEAL_DEBUG
            if (!value)
            {
                throw std::invalid_argument("value");
            }
            if (!uint64_count)
            {
                throw std::invalid_argument("uint64_count");
            }
            if (bit_index < 0 ||
                static_cast<std::int64_t>(bit_index) >=
                static_cast<std::int64_t>(uint64_count) * bits_per_uint64)
            {
                throw std::invalid_argument("bit_index");
            }
#endif
            int uint64_index = bit_index / bits_per_uint64;
            int sub_bit_index = bit_index - uint64_index * bits_per_uint64;
            return ((value[static_cast<std::size_t>(uint64_index)]
                >> sub_bit_index) & 1) != 0;
        }

        inline void set_bit_uint(std::uint64_t *value,
            std::size_t uint64_count SEAL_MAYBE_UNUSED, int bit_index)
        {
#ifdef SEAL_DEBUG
            if (!value)
            {
                throw std::invalid_argument("value");
            }
            if (!uint64_count)
            {
                throw std::invalid_argument("uint64_count");
            }
            if (bit_index < 0 ||
                static_cast<std::int64_t>(bit_index) >=
                static_cast<std::int64_t>(uint64_count) * bits_per_uint64)
            {
                throw std::invalid_argument("bit_index");
            }
#endif
            int uint64_index = bit_index / bits_per_uint64;
            int sub_bit_index = bit_index % bits_per_uint64;
            value[static_cast<std::size_t>(uint64_index)] |=
                std::uint64_t(1) << sub_bit_index;
        }
#ifndef SEAL_USE_MAYBE_UNUSED
#if (SEAL_COMPILER == SEAL_COMPILER_GCC)
#pragma GCC diagnostic pop
#elif (SEAL_COMPILER == SEAL_COMPILER_CLANG)
#pragma clang diagnostic pop
#endif
#endif
        inline int get_significant_bit_count_uint(
            const std::uint64_t *value, std::size_t uint64_count)
        {
#ifdef SEAL_DEBUG
            if (!value && uint64_count)
            {
                throw std::invalid_argument("value");
            }
            if (!uint64_count)
            {
                throw std::invalid_argument("uint64_count");
            }
#endif
            if (!uint64_count)
            {
                return 0;
            }

            value += uint64_count - 1;
            for (; *value == 0 && uint64_count > 1; uint64_count--)
            {
                value--;
            }

            return static_cast<int>(uint64_count - 1) * bits_per_uint64 +
                get_significant_bit_count(*value);
        }

        inline std::size_t get_significant_uint64_count_uint(
            const std::uint64_t *value, std::size_t uint64_count)
        {
#ifdef SEAL_DEBUG
            if (!value && uint64_count)
            {
                throw std::invalid_argument("value");
            }
            if (!uint64_count)
            {
                throw std::invalid_argument("uint64_count");
            }
#endif
            value += uint64_count - 1;
            for (; uint64_count && !*value; uint64_count--)
            {
                value--;
            }

            return uint64_count;
        }

        inline std::size_t get_nonzero_uint64_count_uint(
            const std::uint64_t *value, std::size_t uint64_count)
        {
#ifdef SEAL_DEBUG
            if (!value && uint64_count)
            {
                throw std::invalid_argument("value");
            }
            if (!uint64_count)
            {
                throw std::invalid_argument("uint64_count");
            }
#endif
            std::size_t nonzero_count = uint64_count;

            value += uint64_count - 1;
            for (; uint64_count; uint64_count--)
            {
                if (*value-- == 0)
                {
                    nonzero_count--;
                }
            }

            return nonzero_count;
        }

        inline void set_uint_uint(const std::uint64_t *value,
            std::size_t value_uint64_count,
            std::size_t result_uint64_count, std::uint64_t *result)
        {
#ifdef SEAL_DEBUG
            if (!value && value_uint64_count)
            {
                throw std::invalid_argument("value");
            }
            if (!result && result_uint64_count)
            {
                throw std::invalid_argument("result");
            }
#endif
            if (value == result || !value_uint64_count)
            {
                // Fast path to handle self assignment.
                std::fill(result + value_uint64_count,
                    result + result_uint64_count, std::uint64_t(0));
            }
            else
            {
                std::size_t min_uint64_count =
                    std::min(value_uint64_count, result_uint64_count);
                std::copy_n(value, min_uint64_count, result);
                std::fill(result + min_uint64_count,
                    result + result_uint64_count, std::uint64_t(0));
            }
        }

        inline int get_power_of_two(std::uint64_t value)
        {
            if (value == 0 || (value & (value - 1)) != 0)
            {
                return -1;
            }

            unsigned long result = 0;
            SEAL_MSB_INDEX_UINT64(&result, value);
            return static_cast<int>(result);
        }

        inline int get_power_of_two_minus_one(std::uint64_t value)
        {
            if (value == 0xFFFFFFFFFFFFFFFF)
            {
                return bits_per_uint64;
            }
            return get_power_of_two(value + 1);
        }

        inline int get_power_of_two_uint(const std::uint64_t *operand,
            std::size_t uint64_count)
        {
#ifdef SEAL_DEBUG
            if (!operand && uint64_count)
            {
                throw std::invalid_argument("operand");
            }
#endif
            operand += uint64_count;
            int long_index = safe_cast<int>(uint64_count), local_result = -1;
            for (; (long_index >= 1) && (local_result == -1); long_index--)
            {
                operand--;
                local_result = get_power_of_two(*operand);
            }

            // If local_result != -1, we've found a power-of-two highest order block,
            // in which case need to check that rest are zero.
            // If local_result == -1, operand is not power of two.
            if (local_result == -1)
            {
                return -1;
            }

            int zeros = 1;
            for (int j = long_index; j >= 1; j--)
            {
                zeros &= (*--operand == 0);
            }

            return add_safe(mul_safe(zeros,
                add_safe(local_result,
                    mul_safe(long_index, bits_per_uint64))), zeros, -1);
        }

        inline int get_power_of_two_minus_one_uint(
            const std::uint64_t *operand, std::size_t uint64_count)
        {
#ifdef SEAL_DEBUG
            if (!operand && uint64_count)
            {
                throw std::invalid_argument("operand");
            }
            if (unsigned_geq(uint64_count, std::numeric_limits<int>::max()))
            {
                throw std::invalid_argument("uint64_count");
            }
#endif
            operand += uint64_count;
            int long_index = safe_cast<int>(uint64_count), local_result = 0;
            for (; (long_index >= 1) && (local_result == 0); long_index--)
            {
                operand--;
                local_result = get_power_of_two_minus_one(*operand);
            }

            // If local_result != -1, we've found a power-of-two-minus-one highest
            // order block, in which case need to check that rest are ~0.
            // If local_result == -1, operand is not power of two minus one.
            if (local_result == -1)
            {
                return -1;
            }

            int ones = 1;
            for (int j = long_index; j >= 1; j--)
            {
                ones &= (~*--operand == 0);
            }

            return add_safe(mul_safe(ones,
                add_safe(local_result,
                    mul_safe(long_index, bits_per_uint64))), ones, -1);
        }

        inline void filter_highbits_uint(std::uint64_t *operand,
            std::size_t uint64_count, int bit_count)
        {
            std::size_t bits_per_uint64_sz = static_cast<std::size_t>(bits_per_uint64);
#ifdef SEAL_DEBUG
            if (!operand && uint64_count)
            {
                throw std::invalid_argument("operand");
            }
            if (bit_count < 0 || unsigned_gt(bit_count,
                mul_safe(uint64_count, bits_per_uint64_sz)))
            {
                throw std::invalid_argument("bit_count");
            }
#endif
            if (unsigned_eq(bit_count, mul_safe(uint64_count, bits_per_uint64_sz)))
            {
                return;
            }
            int uint64_index = bit_count / bits_per_uint64;
            int subbit_index = bit_count - uint64_index * bits_per_uint64;
            operand += uint64_index;
            *operand++ &= (std::uint64_t(1) << subbit_index) - 1;
            for (int long_index = uint64_index + 1;
                unsigned_lt(long_index, uint64_count); long_index++)
            {
                *operand++ = 0;
            }
        }

        inline auto duplicate_uint_if_needed(const std::uint64_t *input,
            std::size_t uint64_count, std::size_t new_uint64_count,
            bool force, MemoryPool &pool)
        {
#ifdef SEAL_DEBUG
            if (!input && uint64_count)
            {
                throw std::invalid_argument("uint");
            }
#endif
            if (!force && uint64_count >= new_uint64_count)
            {
                return ConstPointer<std::uint64_t>::Aliasing(input);
            }

            auto allocation(allocate<std::uint64_t>(new_uint64_count, pool));
            set_uint_uint(input, uint64_count, new_uint64_count, allocation.get());
            return ConstPointer<std::uint64_t>(std::move(allocation));
        }

        inline int compare_uint_uint(const std::uint64_t *operand1,
            const std::uint64_t *operand2, std::size_t uint64_count)
        {
#ifdef SEAL_DEBUG
            if (!operand1 && uint64_count)
            {
                throw std::invalid_argument("operand1");
            }
            if (!operand2 && uint64_count)
            {
                throw std::invalid_argument("operand2");
            }
#endif
            int result = 0;
            operand1 += uint64_count - 1;
            operand2 += uint64_count - 1;

            for (; (result == 0) && uint64_count--; operand1--, operand2--)
            {
                result = (*operand1 > *operand2) - (*operand1 < *operand2);
            }
            return result;
        }

        inline int compare_uint_uint(const std::uint64_t *operand1,
            std::size_t operand1_uint64_count, const std::uint64_t *operand2,
            std::size_t operand2_uint64_count)
        {
#ifdef SEAL_DEBUG
            if (!operand1 && operand1_uint64_count)
            {
                throw std::invalid_argument("operand1");
            }
            if (!operand2 && operand2_uint64_count)
            {
                throw std::invalid_argument("operand2");
            }
#endif
            int result = 0;
            operand1 += operand1_uint64_count - 1;
            operand2 += operand2_uint64_count - 1;

            std::size_t min_uint64_count =
                std::min(operand1_uint64_count, operand2_uint64_count);

            operand1_uint64_count -= min_uint64_count;
            for (; (result == 0) && operand1_uint64_count--; operand1--)
            {
                result = (*operand1 > 0);
            }

            operand2_uint64_count -= min_uint64_count;
            for (; (result == 0) && operand2_uint64_count--; operand2--)
            {
                result = -(*operand2 > 0);
            }

            for (; (result == 0) && min_uint64_count--; operand1--, operand2--)
            {
                result = (*operand1 > *operand2) - (*operand1 < *operand2);
            }
            return result;
        }

        inline bool is_greater_than_uint_uint(const std::uint64_t *operand1,
            const std::uint64_t *operand2, std::size_t uint64_count)
        {
            return compare_uint_uint(operand1, operand2, uint64_count) > 0;
        }

        inline bool is_greater_than_or_equal_uint_uint(const std::uint64_t *operand1,
            const std::uint64_t *operand2, std::size_t uint64_count)
        {
            return compare_uint_uint(operand1, operand2, uint64_count) >= 0;
        }

        inline bool is_less_than_uint_uint(const std::uint64_t *operand1,
            const std::uint64_t *operand2, std::size_t uint64_count)
        {
            return compare_uint_uint(operand1, operand2, uint64_count) < 0;
        }

        inline bool is_less_than_or_equal_uint_uint(const std::uint64_t *operand1,
            const std::uint64_t *operand2, std::size_t uint64_count)
        {
            return compare_uint_uint(operand1, operand2, uint64_count) <= 0;
        }

        inline bool is_equal_uint_uint(const std::uint64_t *operand1,
            const std::uint64_t *operand2, std::size_t uint64_count)
        {
            return compare_uint_uint(operand1, operand2, uint64_count) == 0;
        }

        inline bool is_not_equal_uint_uint(const std::uint64_t *operand1,
            const std::uint64_t *operand2, std::size_t uint64_count)
        {
            return compare_uint_uint(operand1, operand2, uint64_count) != 0;
        }

        inline bool is_greater_than_uint_uint(const std::uint64_t *operand1,
            std::size_t operand1_uint64_count, const std::uint64_t *operand2,
            std::size_t operand2_uint64_count)
        {
            return compare_uint_uint(operand1, operand1_uint64_count, operand2,
                operand2_uint64_count) > 0;
        }

        inline bool is_greater_than_or_equal_uint_uint(
            const std::uint64_t *operand1, std::size_t operand1_uint64_count,
            const std::uint64_t *operand2, std::size_t operand2_uint64_count)
        {
            return compare_uint_uint(operand1, operand1_uint64_count, operand2,
                operand2_uint64_count) >= 0;
        }

        inline bool is_less_than_uint_uint(const std::uint64_t *operand1,
            std::size_t operand1_uint64_count, const std::uint64_t *operand2,
            std::size_t operand2_uint64_count)
        {
            return compare_uint_uint(operand1, operand1_uint64_count, operand2,
                operand2_uint64_count) < 0;
        }

        inline bool is_less_than_or_equal_uint_uint(const std::uint64_t *operand1,
            std::size_t operand1_uint64_count, const std::uint64_t *operand2,
            std::size_t operand2_uint64_count)
        {
            return compare_uint_uint(operand1, operand1_uint64_count, operand2,
                operand2_uint64_count) <= 0;
        }

        inline bool is_equal_uint_uint(const std::uint64_t *operand1,
            std::size_t operand1_uint64_count, const std::uint64_t *operand2,
            std::size_t operand2_uint64_count)
        {
            return compare_uint_uint(operand1, operand1_uint64_count, operand2,
                operand2_uint64_count) == 0;
        }

        inline bool is_not_equal_uint_uint(const std::uint64_t *operand1,
            std::size_t operand1_uint64_count, const std::uint64_t *operand2,
            std::size_t operand2_uint64_count)
        {
            return compare_uint_uint(operand1, operand1_uint64_count, operand2,
                operand2_uint64_count) != 0;
        }

        inline std::uint64_t hamming_weight(std::uint64_t value)
        {
            std::uint64_t res = 0;
            while (value)
            {
                res++;
                value &= value - 1;
            }
            return res;
        }

        inline std::uint64_t hamming_weight_split(std::uint64_t value)
        {
            std::uint64_t hwx = hamming_weight(value);
            std::uint64_t target = (hwx + 1) >> 1;
            std::uint64_t now = 0;
            std::uint64_t result = 0;

            for (int i = 0; i < bits_per_uint64; i++)
            {
                std::uint64_t xbit = value & 1;
                value = value >> 1;
                now += xbit;
                result += (xbit << i);

                if (now >= target)
                {
                    break;
                }
            }
            return result;
        }
    }
}
