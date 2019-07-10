// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#pragma once

#include <cstdint>
#include <cmath>
#include <stdexcept>
#include <vector>
#include <type_traits>
#include <limits>
#include <algorithm>
#include "seal/util/defines.h"

namespace seal
{
    namespace util
    {
        template<typename T, typename...>
        struct is_uint64 : std::conditional<
            std::is_integral<T>::value &&
            std::is_unsigned<T>::value &&
            (sizeof(T) == sizeof(std::uint64_t)),
            std::true_type, std::false_type>::type
        {
        };

        template<typename T, typename U, typename... Rest>
        struct is_uint64<T, U, Rest...> : std::conditional<
            is_uint64<T>::value &&
            is_uint64<U, Rest...>::value,
            std::true_type, std::false_type>::type
        {
        };

        template<typename T, typename... Rest>
        constexpr bool is_uint64_v = is_uint64<T, Rest...>::value;

        template<typename T, typename...>
        struct is_uint32 : std::conditional<
            std::is_integral<T>::value &&
            std::is_unsigned<T>::value &&
            (sizeof(T) == sizeof(std::uint32_t)),
            std::true_type, std::false_type>::type
        {
        };

        template<typename T, typename U, typename... Rest>
        struct is_uint32<T, U, Rest...> : std::conditional<
            is_uint32<T>::value &&
            is_uint32<U, Rest...>::value,
            std::true_type, std::false_type>::type
        {
        };

        template<typename T, typename... Rest>
        constexpr bool is_uint32_v = is_uint32<T, Rest...>::value;

        template<typename T, typename S,
            typename = std::enable_if_t<std::is_integral<T>::value>,
            typename = std::enable_if_t<std::is_integral<S>::value>>
        inline constexpr bool unsigned_lt(T in1, S in2) noexcept
        {
            return static_cast<std::uint64_t>(in1) < static_cast<std::uint64_t>(in2);
        }

        template<typename T, typename S,
            typename = std::enable_if_t<std::is_integral<T>::value>,
            typename = std::enable_if_t<std::is_integral<S>::value>>
        inline constexpr bool unsigned_leq(T in1, S in2) noexcept
        {
            return static_cast<std::uint64_t>(in1) <= static_cast<std::uint64_t>(in2);
        }

        template<typename T, typename S,
            typename = std::enable_if_t<std::is_integral<T>::value>,
            typename = std::enable_if_t<std::is_integral<S>::value>>
        inline constexpr bool unsigned_gt(T in1, S in2) noexcept
        {
            return static_cast<std::uint64_t>(in1) > static_cast<std::uint64_t>(in2);
        }

        template<typename T, typename S,
            typename = std::enable_if_t<std::is_integral<T>::value>,
            typename = std::enable_if_t<std::is_integral<S>::value>>
        inline constexpr bool unsigned_geq(T in1, S in2) noexcept
        {
            return static_cast<std::uint64_t>(in1) >= static_cast<std::uint64_t>(in2);
        }

        template<typename T, typename S,
            typename = std::enable_if_t<std::is_integral<T>::value>,
            typename = std::enable_if_t<std::is_integral<S>::value>>
        inline constexpr bool unsigned_eq(T in1, S in2) noexcept
        {
            return static_cast<std::uint64_t>(in1) == static_cast<std::uint64_t>(in2);
        }

        template<typename T, typename S,
            typename = std::enable_if_t<std::is_integral<T>::value>,
            typename = std::enable_if_t<std::is_integral<S>::value>>
        inline constexpr bool unsigned_neq(T in1, S in2) noexcept
        {
            return static_cast<std::uint64_t>(in1) != static_cast<std::uint64_t>(in2);
        }

        template<typename T,
            typename = std::enable_if_t<std::is_integral<T>::value>>
        inline constexpr T mul_safe(T in1) noexcept
        {
            return in1;
        }

        template<typename T,
            typename = std::enable_if_t<std::is_integral<T>::value>>
        inline constexpr T mul_safe(T in1, T in2)
        {
            SEAL_IF_CONSTEXPR (std::is_unsigned<T>::value)
            {
                if (in1 && (in2 > std::numeric_limits<T>::max() / in1))
                {
                    throw std::out_of_range("unsigned overflow");
                }
            }
            else
            {
                // Positive inputs
                if ((in1 > 0) && (in2 > 0) &&
                    (in2 > std::numeric_limits<T>::max() / in1))
                {
                    throw std::out_of_range("signed overflow");
                }
#if (SEAL_COMPILER == SEAL_COMPILER_MSVC) && !defined(SEAL_USE_IF_CONSTEXPR)
#pragma warning(push)
#pragma warning(disable: 4146)
#endif
                // Negative inputs
                else if ((in1 < 0) && (in2 < 0) &&
                    ((-in2) > std::numeric_limits<T>::max() / (-in1)))
                {
                    throw std::out_of_range("signed overflow");
                }
                // Negative in1; positive in2
                else if ((in1 < 0) && (in2 > 0) &&
                    (in2 > std::numeric_limits<T>::max() / (-in1)))
                {
                    throw std::out_of_range("signed underflow");
                }
#if (SEAL_COMPILER == SEAL_COMPILER_MSVC) && !defined(SEAL_USE_IF_CONSTEXPR)
#pragma warning(pop)
#endif
                // Positive in1; negative in2
                else if ((in1 > 0) && (in2 < 0) &&
                    (in2 < std::numeric_limits<T>::min() / in1))
                {
                    throw std::out_of_range("signed underflow");
                }
            }
            return in1 * in2;
        }

        template<typename T, typename... Args,
            typename = std::enable_if_t<std::is_integral<T>::value>>
        inline constexpr T mul_safe(T in1, T in2, Args &&...args)
        {
            return mul_safe(mul_safe(in1, in2), mul_safe(std::forward<Args>(args)...));
        }

        template<typename T,
            typename = std::enable_if_t<std::is_arithmetic<T>::value>>
        inline constexpr T add_safe(T in1) noexcept
        {
            return in1;
        }

        template<typename T,
            typename = std::enable_if_t<std::is_arithmetic<T>::value>>
        inline constexpr T add_safe(T in1, T in2)
        {
            SEAL_IF_CONSTEXPR (std::is_unsigned<T>::value)
            {
                T result = in1 + in2;
                if (result < in1)
                {
                    throw std::out_of_range("unsigned overflow");
                }
                return result;
            }
            else
            {
                if (in1 > 0 && (in2 > std::numeric_limits<T>::max() - in1))
                {
                    throw std::out_of_range("signed overflow");
                }
                else if (in1 < 0 &&
                    (in2 < std::numeric_limits<T>::min() - in1))
                {
                    throw std::out_of_range("signed underflow");
                }
                return in1 + in2;
            }
        }

        template<typename T, typename... Args,
            typename = std::enable_if_t<std::is_arithmetic<T>::value>>
        inline constexpr T add_safe(T in1, T in2, Args &&...args)
        {
            return add_safe(add_safe(in1, in2), add_safe(std::forward<Args>(args)...));
        }

        template<typename T,
            typename = std::enable_if_t<std::is_arithmetic<T>::value>>
        inline T sub_safe(T in1, T in2)
        {
            SEAL_IF_CONSTEXPR (std::is_unsigned<T>::value)
            {
                T result = in1 - in2;
                if (result > in1)
                {
                    throw std::out_of_range("unsigned underflow");
                }
                return result;
            }
            else
            {
                if (in1 < 0 && (in2 > std::numeric_limits<T>::max() + in1))
                {
                    throw std::out_of_range("signed underflow");
                }
                else if (in1 > 0 &&
                    (in2 < std::numeric_limits<T>::min() + in1))
                {
                    throw std::out_of_range("signed overflow");
                }
                return in1 - in2;
            }
        }

        template<typename T, typename S,
            typename = std::enable_if_t<std::is_arithmetic<T>::value>,
            typename = std::enable_if_t<std::is_arithmetic<S>::value>>
        inline constexpr bool fits_in(S value SEAL_MAYBE_UNUSED) noexcept
        {
            SEAL_IF_CONSTEXPR (std::is_same<T, S>::value)
            {
                // Same type
                return true;
            }

            SEAL_IF_CONSTEXPR (sizeof(S) <= sizeof(T))
            {
                // Converting to bigger type
                SEAL_IF_CONSTEXPR (std::is_integral<T>::value && std::is_integral<S>::value)
                {
                    // Converting to at least equally big integer type
                    SEAL_IF_CONSTEXPR ((std::is_unsigned<T>::value && std::is_unsigned<S>::value)
                        || (!std::is_unsigned<T>::value && !std::is_unsigned<S>::value))
                    {
                        // Both either signed or unsigned
                        return true;
                    }
                    else SEAL_IF_CONSTEXPR (std::is_unsigned<T>::value
                        && std::is_signed<S>::value)
                    {
                        // Converting from signed to at least equally big unsigned type
                        return value >= 0;
                    }
                }
                else SEAL_IF_CONSTEXPR (std::is_floating_point<T>::value
                    && std::is_floating_point<S>::value)
                {
                    // Both floating-point
                    return true;
                }

                // Still need to consider integer-float conversions and all
                // unsigned to signed conversions
            }

            SEAL_IF_CONSTEXPR (std::is_integral<T>::value && std::is_integral<S>::value)
            {
                // Both integer types
                if (value >= 0)
                {
                    // Non-negative number; compare as std::uint64_t
                    // Cannot use unsigned_leq with C++14 for lack of `if constexpr'
                    return static_cast<std::uint64_t>(value) <=
                        static_cast<std::uint64_t>(std::numeric_limits<T>::max());
                }
                else
                {
                    // Negative number; compare as std::int64_t
                    return (static_cast<std::int64_t>(value) >=
                        static_cast<std::int64_t>(std::numeric_limits<T>::min()));
                }
            }
            else SEAL_IF_CONSTEXPR (std::is_floating_point<T>::value)
            {
                // Converting to floating-point
                return (static_cast<double>(value) <=
                    static_cast<double>(std::numeric_limits<T>::max())) &&
                    (static_cast<double>(value) >=
                        -static_cast<double>(std::numeric_limits<T>::max()));
            }
            else
            {
                // Converting from floating-point
                return (static_cast<double>(value) <=
                    static_cast<double>(std::numeric_limits<T>::max())) &&
                    (static_cast<double>(value) >=
                        static_cast<double>(std::numeric_limits<T>::min()));
            }
        }

        template<typename T, typename... Args,
            typename = std::enable_if_t<std::is_arithmetic<T>::value>>
        inline constexpr bool sum_fits_in(Args &&...args)
        {
            return fits_in<T>(add_safe(std::forward<Args>(args)...));
        }

        template<typename T, typename... Args,
            typename = std::enable_if_t<std::is_arithmetic<T>::value>>
        inline constexpr bool sum_fits_in(T in1, Args &&...args)
        {
            return fits_in<T>(add_safe(in1, std::forward<Args>(args)...));
        }

        template<typename T, typename... Args,
            typename = std::enable_if_t<std::is_arithmetic<T>::value>>
        inline constexpr bool product_fits_in(Args &&...args)
        {
            return fits_in<T>(mul_safe(std::forward<Args>(args)...));
        }

        template<typename T, typename... Args,
            typename = std::enable_if_t<std::is_arithmetic<T>::value>>
        inline constexpr bool product_fits_in(T in1, Args &&...args)
        {
            return fits_in<T>(mul_safe(in1, std::forward<Args>(args)...));
        }

        template<typename T, typename S,
            typename = std::enable_if_t<std::is_arithmetic<T>::value>,
            typename = std::enable_if_t<std::is_arithmetic<S>::value>>
        inline T safe_cast(S value)
        {
            SEAL_IF_CONSTEXPR (!std::is_same<T, S>::value)
            {
                if(!fits_in<T>(value))
                {
                    throw std::out_of_range("cast failed");
                }
            }
            return static_cast<T>(value);
        }

        constexpr int bytes_per_uint64 = sizeof(std::uint64_t);

        constexpr int bytes_per_uint32 = sizeof(std::uint32_t);

        constexpr int uint32_per_uint64 = 2;

        constexpr int bits_per_nibble = 4;

        constexpr int bits_per_byte = 8;

        constexpr int bits_per_uint64 = bytes_per_uint64 * bits_per_byte;

        constexpr int bits_per_uint32 = bytes_per_uint32 * bits_per_byte;

        constexpr int nibbles_per_byte = 2;

        constexpr int nibbles_per_uint64 = bytes_per_uint64 * nibbles_per_byte;

        constexpr std::uint64_t uint64_high_bit = std::uint64_t(1) << (bits_per_uint64 - 1);

        template<typename T, typename = std::enable_if_t<is_uint32_v<T> || is_uint64_v<T>>>
        inline constexpr T reverse_bits(T operand) noexcept
        {
            SEAL_IF_CONSTEXPR (is_uint32_v<T>)
            {
                operand = (((operand & T(0xaaaaaaaa)) >> 1) | ((operand & T(0x55555555)) << 1));
                operand = (((operand & T(0xcccccccc)) >> 2) | ((operand & T(0x33333333)) << 2));
                operand = (((operand & T(0xf0f0f0f0)) >> 4) | ((operand & T(0x0f0f0f0f)) << 4));
                operand = (((operand & T(0xff00ff00)) >> 8) | ((operand & T(0x00ff00ff)) << 8));
                return static_cast<T>(operand >> 16) | static_cast<T>(operand << 16);
            }
            else SEAL_IF_CONSTEXPR (is_uint64_v<T>)
            {
// Temporarily disable UB warnings when `if constexpr` is not available.
#ifndef SEAL_USE_IF_CONSTEXPR
#if (SEAL_COMPILER == SEAL_COMPILER_MSVC)
#pragma warning(push)
#pragma warning(disable: 4293)
#elif (SEAL_COMPILER == SEAL_COMPILER_GCC)
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wshift-count-overflow"
#elif (SEAL_COMPILER == SEAL_COMPILER_CLANG)
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wshift-count-overflow"
#endif
#endif
                return static_cast<T>(reverse_bits(static_cast<std::uint32_t>(operand >> 32))) |
                    (static_cast<T>(reverse_bits(static_cast<std::uint32_t>(operand & T(0xFFFFFFFF)))) << 32);
#ifndef SEAL_USE_IF_CONSTEXPR
#if (SEAL_COMPILER == SEAL_COMPILER_MSVC)
#pragma warning(pop)
#elif (SEAL_COMPILER == SEAL_COMPILER_GCC)
#pragma GCC diagnostic pop
#elif (SEAL_COMPILER == SEAL_COMPILER_CLANG)
#pragma clang diagnostic pop
#endif
#endif
            }
        }

        template<typename T, typename = std::enable_if_t<is_uint32_v<T> || is_uint64_v<T>>>
        inline T reverse_bits(T operand, int bit_count)
        {
#ifdef SEAL_DEBUG
            if (bit_count < 0 ||
                static_cast<std::size_t>(bit_count) >
                    mul_safe(sizeof(T), static_cast<std::size_t>(bits_per_byte)))
            {
                throw std::invalid_argument("bit_count");
            }
#endif
            // Just return zero if bit_count is zero
            return (bit_count == 0) ? T(0) : reverse_bits(operand) >> (
                sizeof(T) * static_cast<std::size_t>(bits_per_byte)
                    - static_cast<std::size_t>(bit_count));
        }

        inline void get_msb_index_generic(unsigned long *result, std::uint64_t value)
        {
#ifdef SEAL_DEBUG
            if (result == nullptr)
            {
                throw std::invalid_argument("result");
            }
#endif
            static const unsigned long deBruijnTable64[64] = {
                63,  0, 58,  1, 59, 47, 53,  2,
                60, 39, 48, 27, 54, 33, 42,  3,
                61, 51, 37, 40, 49, 18, 28, 20,
                55, 30, 34, 11, 43, 14, 22,  4,
                62, 57, 46, 52, 38, 26, 32, 41,
                50, 36, 17, 19, 29, 10, 13, 21,
                56, 45, 25, 31, 35, 16,  9, 12,
                44, 24, 15,  8, 23,  7,  6,  5
            };

            value |= value >> 1;
            value |= value >> 2;
            value |= value >> 4;
            value |= value >> 8;
            value |= value >> 16;
            value |= value >> 32;

            *result = deBruijnTable64[((value - (value >> 1)) * std::uint64_t(0x07EDD5E59A4E28C2)) >> 58];
        }

        inline int get_significant_bit_count(std::uint64_t value)
        {
            if (value == 0)
            {
                return 0;
            }

            unsigned long result;
            SEAL_MSB_INDEX_UINT64(&result, value);
            return static_cast<int>(result + 1);
        }

        inline bool is_hex_char(char hex)
        {
            if (hex >= '0' && hex <= '9')
            {
                return true;
            }
            if (hex >= 'A' && hex <= 'F')
            {
                return true;
            }
            if (hex >= 'a' && hex <= 'f')
            {
                return true;
            }
            return false;
        }

        inline char nibble_to_upper_hex(int nibble)
        {
#ifdef SEAL_DEBUG
            if (nibble < 0 || nibble > 15)
            {
                throw std::invalid_argument("nibble");
            }
#endif
            if (nibble < 10)
            {
                return static_cast<char>(nibble + static_cast<int>('0'));
            }
            return static_cast<char>(nibble + static_cast<int>('A') - 10);
        }

        inline int hex_to_nibble(char hex)
        {
            if (hex >= '0' && hex <= '9')
            {
                return static_cast<int>(hex) - static_cast<int>('0');
            }
            if (hex >= 'A' && hex <= 'F')
            {
                return static_cast<int>(hex) - static_cast<int>('A') + 10;
            }
            if (hex >= 'a' && hex <= 'f')
            {
                return static_cast<int>(hex) - static_cast<int>('a') + 10;
            }
#ifdef SEAL_DEBUG
            throw std::invalid_argument("hex");
#endif
            return -1;
        }

        inline SEAL_BYTE *get_uint64_byte(std::uint64_t *value, std::size_t byte_index)
        {
#ifdef SEAL_DEBUG
            if (value == nullptr)
            {
                throw std::invalid_argument("value");
            }
#endif
            return reinterpret_cast<SEAL_BYTE*>(value) + byte_index;
        }

        inline const SEAL_BYTE *get_uint64_byte(const std::uint64_t *value, std::size_t byte_index)
        {
#ifdef SEAL_DEBUG
            if (value == nullptr)
            {
                throw std::invalid_argument("value");
            }
#endif
            return reinterpret_cast<const SEAL_BYTE*>(value) + byte_index;
        }

        inline int get_hex_string_bit_count(const char *hex_string, int char_count)
        {
#ifdef SEAL_DEBUG
            if (hex_string == nullptr && char_count > 0)
            {
                throw std::invalid_argument("hex_string");
            }
            if (char_count < 0)
            {
                throw std::invalid_argument("char_count");
            }
#endif
            for (int i = 0; i < char_count; i++)
            {
                char hex = *hex_string++;
                int nibble = hex_to_nibble(hex);
                if (nibble != 0)
                {
                    int nibble_bits = get_significant_bit_count(static_cast<std::uint64_t>(nibble));
                    int remaining_nibbles = (char_count - i - 1) * bits_per_nibble;
                    return nibble_bits + remaining_nibbles;
                }
            }
            return 0;
        }

        template<typename T, typename = std::enable_if<std::is_integral<T>::value>>
        inline T divide_round_up(T value, T divisor)
        {
#ifdef SEAL_DEBUG
            if (value < 0)
            {
                throw std::invalid_argument("value");
            }
            if (divisor <= 0)
            {
                throw std::invalid_argument("divisor");
            }
#endif
            return (add_safe(value, divisor - 1)) / divisor;
        }

        template<typename T>
        constexpr double epsilon = std::numeric_limits<T>::epsilon();

        template<typename T,
            typename = std::enable_if_t<std::is_floating_point<T>::value>>
        inline bool are_close(T value1, T value2) noexcept
        {
            double scale_factor = std::max<T>(
                { std::fabs(value1), std::fabs(value2), T{ 1.0 } });
            return std::fabs(value1 - value2) < epsilon<T> * scale_factor;
        }

        template<typename T,
            typename = std::enable_if_t<std::is_integral<T>::value>>
        inline constexpr bool is_zero(T value) noexcept
        {
            return value == T{ 0 };
        }
    }
}
