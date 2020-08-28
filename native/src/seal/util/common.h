// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#pragma once

#include "seal/util/defines.h"
#include <algorithm>
#include <cmath>
#include <cstdint>
#include <limits>
#include <stdexcept>
#include <tuple>
#include <type_traits>
#include <utility>
#include <vector>

namespace seal
{
    namespace util
    {
        template <typename... Ts>
        struct VoidType
        {
            using type = void;
        };

        template <typename... Ts>
        using seal_void_t = typename VoidType<Ts...>::type;

        template <typename ForwardIt, typename Size, typename Func>
        inline ForwardIt seal_for_each_n(ForwardIt first, Size size, Func &&func)
        {
            for (; size--; (void)++first)
            {
                func(*first);
            }
            return first;
        }

        template <typename Func, typename Tuple, std::size_t... Is>
        inline decltype(auto) seal_apply_impl(Func &&func, Tuple &&tp, std::index_sequence<Is...>)
        {
            return func(std::get<Is>(std::forward<Tuple>(tp))...);
        }

        template <typename Func, typename Tuple, std::size_t... Is>
        inline decltype(auto) seal_apply(Func &&func, Tuple &&tp)
        {
            using iseq_t = std::make_index_sequence<std::tuple_size<std::decay_t<Tuple>>::value>;
            return seal_apply_impl(std::forward<Func>(func), std::forward<Tuple>(tp), iseq_t{});
        }

        template <typename T, typename...>
        struct IsUInt64
            : std::conditional<
                  std::is_integral<T>::value && std::is_unsigned<T>::value && (sizeof(T) == sizeof(std::uint64_t)),
                  std::true_type, std::false_type>::type
        {};

        template <typename T, typename U, typename... Rest>
        struct IsUInt64<T, U, Rest...>
            : std::conditional<IsUInt64<T>::value && IsUInt64<U, Rest...>::value, std::true_type, std::false_type>::type
        {};

        template <typename T, typename... Rest>
        constexpr bool is_uint64_v = IsUInt64<T, Rest...>::value;

        template <typename T, typename...>
        struct IsUInt32
            : std::conditional<
                  std::is_integral<T>::value && std::is_unsigned<T>::value && (sizeof(T) == sizeof(std::uint32_t)),
                  std::true_type, std::false_type>::type
        {};

        template <typename T, typename U, typename... Rest>
        struct IsUInt32<T, U, Rest...>
            : std::conditional<IsUInt32<T>::value && IsUInt32<U, Rest...>::value, std::true_type, std::false_type>::type
        {};

        template <typename T, typename... Rest>
        constexpr bool is_uint32_v = IsUInt32<T, Rest...>::value;

        template <
            typename T, typename S, typename = std::enable_if_t<std::is_integral<T>::value>,
            typename = std::enable_if_t<std::is_integral<S>::value>>
        SEAL_NODISCARD inline constexpr bool unsigned_lt(T in1, S in2) noexcept
        {
            return static_cast<std::uint64_t>(in1) < static_cast<std::uint64_t>(in2);
        }

        template <
            typename T, typename S, typename = std::enable_if_t<std::is_integral<T>::value>,
            typename = std::enable_if_t<std::is_integral<S>::value>>
        SEAL_NODISCARD inline constexpr bool unsigned_leq(T in1, S in2) noexcept
        {
            return static_cast<std::uint64_t>(in1) <= static_cast<std::uint64_t>(in2);
        }

        template <
            typename T, typename S, typename = std::enable_if_t<std::is_integral<T>::value>,
            typename = std::enable_if_t<std::is_integral<S>::value>>
        SEAL_NODISCARD inline constexpr bool unsigned_gt(T in1, S in2) noexcept
        {
            return static_cast<std::uint64_t>(in1) > static_cast<std::uint64_t>(in2);
        }

        template <
            typename T, typename S, typename = std::enable_if_t<std::is_integral<T>::value>,
            typename = std::enable_if_t<std::is_integral<S>::value>>
        SEAL_NODISCARD inline constexpr bool unsigned_geq(T in1, S in2) noexcept
        {
            return static_cast<std::uint64_t>(in1) >= static_cast<std::uint64_t>(in2);
        }

        template <
            typename T, typename S, typename = std::enable_if_t<std::is_integral<T>::value>,
            typename = std::enable_if_t<std::is_integral<S>::value>>
        SEAL_NODISCARD inline constexpr bool unsigned_eq(T in1, S in2) noexcept
        {
            return static_cast<std::uint64_t>(in1) == static_cast<std::uint64_t>(in2);
        }

        template <
            typename T, typename S, typename = std::enable_if_t<std::is_integral<T>::value>,
            typename = std::enable_if_t<std::is_integral<S>::value>>
        SEAL_NODISCARD inline constexpr bool unsigned_neq(T in1, S in2) noexcept
        {
            return static_cast<std::uint64_t>(in1) != static_cast<std::uint64_t>(in2);
        }

        template <typename T, typename = std::enable_if_t<std::is_integral<T>::value>>
        SEAL_NODISCARD inline constexpr T mul_safe(T in1) noexcept
        {
            return in1;
        }

        template <typename T, typename = std::enable_if_t<std::is_integral<T>::value>>
        SEAL_NODISCARD inline constexpr T mul_safe(T in1, T in2)
        {
            SEAL_IF_CONSTEXPR(std::is_unsigned<T>::value)
            {
                if (in1 && (in2 > std::numeric_limits<T>::max() / in1))
                {
                    throw std::logic_error("unsigned overflow");
                }
            }
            else
            {
                // Positive inputs
                if ((in1 > 0) && (in2 > 0) && (in2 > std::numeric_limits<T>::max() / in1))
                {
                    throw std::logic_error("signed overflow");
                }
#if (SEAL_COMPILER == SEAL_COMPILER_MSVC) && !defined(SEAL_USE_IF_CONSTEXPR)
#pragma warning(push)
#pragma warning(disable : 4146)
#endif
                // Negative inputs
                else if ((in1 < 0) && (in2 < 0) && ((-in2) > std::numeric_limits<T>::max() / (-in1)))
                {
                    throw std::logic_error("signed overflow");
                }
                // Negative in1; positive in2
                else if ((in1 < 0) && (in2 > 0) && (in2 > std::numeric_limits<T>::max() / (-in1)))
                {
                    throw std::logic_error("signed underflow");
                }
#if (SEAL_COMPILER == SEAL_COMPILER_MSVC) && !defined(SEAL_USE_IF_CONSTEXPR)
#pragma warning(pop)
#endif
                // Positive in1; negative in2
                else if ((in1 > 0) && (in2 < 0) && (in2 < std::numeric_limits<T>::min() / in1))
                {
                    throw std::logic_error("signed underflow");
                }
            }
            return static_cast<T>(in1 * in2);
        }

        template <typename T, typename... Args, typename = std::enable_if_t<std::is_integral<T>::value>>
        SEAL_NODISCARD inline constexpr T mul_safe(T in1, T in2, Args &&... args)
        {
            return mul_safe(mul_safe(in1, in2), mul_safe(std::forward<Args>(args)...));
        }

        template <typename T, typename = std::enable_if_t<std::is_arithmetic<T>::value>>
        SEAL_NODISCARD inline constexpr T add_safe(T in1) noexcept
        {
            return in1;
        }

        template <typename T, typename = std::enable_if_t<std::is_arithmetic<T>::value>>
        SEAL_NODISCARD inline constexpr T add_safe(T in1, T in2)
        {
            SEAL_IF_CONSTEXPR(std::is_unsigned<T>::value)
            {
                if (in2 > std::numeric_limits<T>::max() - in1)
                {
                    throw std::logic_error("unsigned overflow");
                }
            }
            else
            {
                if (in1 > 0 && (in2 > std::numeric_limits<T>::max() - in1))
                {
                    throw std::logic_error("signed overflow");
                }
                else if (in1 < 0 && (in2 < std::numeric_limits<T>::min() - in1))
                {
                    throw std::logic_error("signed underflow");
                }
            }
            return static_cast<T>(in1 + in2);
        }

        template <typename T, typename... Args, typename = std::enable_if_t<std::is_arithmetic<T>::value>>
        SEAL_NODISCARD inline constexpr T add_safe(T in1, T in2, Args &&... args)
        {
            return add_safe(add_safe(in1, in2), add_safe(std::forward<Args>(args)...));
        }

        template <typename T, typename = std::enable_if_t<std::is_arithmetic<T>::value>>
        SEAL_NODISCARD inline T sub_safe(T in1, T in2)
        {
            SEAL_IF_CONSTEXPR(std::is_unsigned<T>::value)
            {
                if (in1 < in2)
                {
                    throw std::logic_error("unsigned underflow");
                }
            }
            else
            {
                if (in1 < 0 && (in2 > std::numeric_limits<T>::max() + in1))
                {
                    throw std::logic_error("signed underflow");
                }
                else if (in1 > 0 && (in2 < std::numeric_limits<T>::min() + in1))
                {
                    throw std::logic_error("signed overflow");
                }
            }
            return static_cast<T>(in1 - in2);
        }

        template <
            typename T, typename S, typename = std::enable_if_t<std::is_arithmetic<T>::value>,
            typename = std::enable_if_t<std::is_arithmetic<S>::value>>
        SEAL_NODISCARD inline constexpr bool fits_in(S value SEAL_MAYBE_UNUSED) noexcept
        {
            SEAL_IF_CONSTEXPR(std::is_same<T, S>::value)
            {
                // Same type
                return true;
            }

            SEAL_IF_CONSTEXPR(sizeof(S) <= sizeof(T))
            {
                // Converting to bigger type
                SEAL_IF_CONSTEXPR(std::is_integral<T>::value && std::is_integral<S>::value)
                {
                    // Converting to at least equally big integer type
                    SEAL_IF_CONSTEXPR(
                        (std::is_unsigned<T>::value && std::is_unsigned<S>::value) ||
                        (!std::is_unsigned<T>::value && !std::is_unsigned<S>::value))
                    {
                        // Both either signed or unsigned
                        return true;
                    }
                    else SEAL_IF_CONSTEXPR(std::is_unsigned<T>::value && std::is_signed<S>::value)
                    {
                        // Converting from signed to at least equally big unsigned type
                        return value >= 0;
                    }
                }
                else SEAL_IF_CONSTEXPR(std::is_floating_point<T>::value && std::is_floating_point<S>::value)
                {
                    // Both floating-point
                    return true;
                }

                // Still need to consider integer-float conversions and all
                // unsigned to signed conversions
            }

            SEAL_IF_CONSTEXPR(std::is_integral<T>::value && std::is_integral<S>::value)
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
                    return (
                        static_cast<std::int64_t>(value) >= static_cast<std::int64_t>(std::numeric_limits<T>::min()));
                }
            }
            else SEAL_IF_CONSTEXPR(std::is_floating_point<T>::value)
            {
                // Converting to floating-point
                return (static_cast<double>(value) <= static_cast<double>(std::numeric_limits<T>::max())) &&
                       (static_cast<double>(value) >= -static_cast<double>(std::numeric_limits<T>::max()));
            }
            else
            {
                // Converting from floating-point
                return (static_cast<double>(value) <= static_cast<double>(std::numeric_limits<T>::max())) &&
                       (static_cast<double>(value) >= static_cast<double>(std::numeric_limits<T>::min()));
            }
        }

        template <typename T, typename... Args, typename = std::enable_if_t<std::is_arithmetic<T>::value>>
        SEAL_NODISCARD inline constexpr bool sum_fits_in(Args &&... args)
        {
            return fits_in<T>(add_safe(std::forward<Args>(args)...));
        }

        template <typename T, typename... Args, typename = std::enable_if_t<std::is_arithmetic<T>::value>>
        SEAL_NODISCARD inline constexpr bool sum_fits_in(T in1, Args &&... args)
        {
            return fits_in<T>(add_safe(in1, std::forward<Args>(args)...));
        }

        template <typename T, typename... Args, typename = std::enable_if_t<std::is_arithmetic<T>::value>>
        SEAL_NODISCARD inline constexpr bool product_fits_in(Args &&... args)
        {
            return fits_in<T>(mul_safe(std::forward<Args>(args)...));
        }

        template <typename T, typename... Args, typename = std::enable_if_t<std::is_arithmetic<T>::value>>
        SEAL_NODISCARD inline constexpr bool product_fits_in(T in1, Args &&... args)
        {
            return fits_in<T>(mul_safe(in1, std::forward<Args>(args)...));
        }

        template <
            typename T, typename S, typename = std::enable_if_t<std::is_arithmetic<T>::value>,
            typename = std::enable_if_t<std::is_arithmetic<S>::value>>
        SEAL_NODISCARD inline T safe_cast(S value)
        {
            SEAL_IF_CONSTEXPR(!std::is_same<T, S>::value)
            {
                if (!fits_in<T>(value))
                {
                    throw std::logic_error("cast failed");
                }
            }
            return static_cast<T>(value);
        }

        constexpr int bytes_per_uint64 = sizeof(std::uint64_t);

        constexpr int bits_per_nibble = 4;

        constexpr int bits_per_byte = 8;

        constexpr int bits_per_uint64 = bytes_per_uint64 * bits_per_byte;

        constexpr int nibbles_per_byte = 2;

        constexpr int nibbles_per_uint64 = bytes_per_uint64 * nibbles_per_byte;

        template <typename T, typename = std::enable_if_t<is_uint32_v<T> || is_uint64_v<T>>>
        SEAL_NODISCARD inline constexpr T reverse_bits(T operand) noexcept
        {
            SEAL_IF_CONSTEXPR(is_uint32_v<T>)
            {
                operand = (((operand & T(0xaaaaaaaa)) >> 1) | ((operand & T(0x55555555)) << 1));
                operand = (((operand & T(0xcccccccc)) >> 2) | ((operand & T(0x33333333)) << 2));
                operand = (((operand & T(0xf0f0f0f0)) >> 4) | ((operand & T(0x0f0f0f0f)) << 4));
                operand = (((operand & T(0xff00ff00)) >> 8) | ((operand & T(0x00ff00ff)) << 8));
                return static_cast<T>(operand >> 16) | static_cast<T>(operand << 16);
            }
            else SEAL_IF_CONSTEXPR(is_uint64_v<T>)
            {
// Temporarily disable UB warnings when `if constexpr` is not available.
#ifndef SEAL_USE_IF_CONSTEXPR
#if (SEAL_COMPILER == SEAL_COMPILER_MSVC)
#pragma warning(push)
#pragma warning(disable : 4293)
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

        template <typename T, typename = std::enable_if_t<is_uint32_v<T> || is_uint64_v<T>>>
        SEAL_NODISCARD inline T reverse_bits(T operand, int bit_count)
        {
#ifdef SEAL_DEBUG
            if (bit_count < 0 ||
                static_cast<std::size_t>(bit_count) > mul_safe(sizeof(T), static_cast<std::size_t>(bits_per_byte)))
            {
                throw std::invalid_argument("bit_count");
            }
#endif
            // Just return zero if bit_count is zero
            return (bit_count == 0) ? T(0)
                                    : reverse_bits(operand) >> (sizeof(T) * static_cast<std::size_t>(bits_per_byte) -
                                                                static_cast<std::size_t>(bit_count));
        }

        inline void get_msb_index_generic(unsigned long *result, std::uint64_t value)
        {
#ifdef SEAL_DEBUG
            if (result == nullptr)
            {
                throw std::invalid_argument("result");
            }
#endif
            static const unsigned long deBruijnTable64[64] = { 63, 0,  58, 1,  59, 47, 53, 2,  60, 39, 48, 27, 54,
                                                               33, 42, 3,  61, 51, 37, 40, 49, 18, 28, 20, 55, 30,
                                                               34, 11, 43, 14, 22, 4,  62, 57, 46, 52, 38, 26, 32,
                                                               41, 50, 36, 17, 19, 29, 10, 13, 21, 56, 45, 25, 31,
                                                               35, 16, 9,  12, 44, 24, 15, 8,  23, 7,  6,  5 };

            value |= value >> 1;
            value |= value >> 2;
            value |= value >> 4;
            value |= value >> 8;
            value |= value >> 16;
            value |= value >> 32;

            *result = deBruijnTable64[((value - (value >> 1)) * std::uint64_t(0x07EDD5E59A4E28C2)) >> 58];
        }

        SEAL_NODISCARD inline int get_significant_bit_count(std::uint64_t value)
        {
            if (value == 0)
            {
                return 0;
            }

            unsigned long result;
            SEAL_MSB_INDEX_UINT64(&result, value);
            return static_cast<int>(result + 1);
        }

        SEAL_NODISCARD inline bool is_hex_char(char hex)
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

        SEAL_NODISCARD inline char nibble_to_upper_hex(int nibble)
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

        SEAL_NODISCARD inline int hex_to_nibble(char hex)
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

        SEAL_NODISCARD inline int get_hex_string_bit_count(const char *hex_string, int char_count)
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

        template <typename T, typename = std::enable_if_t<std::is_integral<T>::value>>
        SEAL_NODISCARD inline T divide_round_up(T value, T divisor)
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

        template <typename T>
        constexpr double epsilon = std::numeric_limits<T>::epsilon();

        template <typename T, typename = std::enable_if_t<std::is_floating_point<T>::value>>
        SEAL_NODISCARD inline bool are_close(T value1, T value2) noexcept
        {
            double scale_factor = std::max<T>({ std::fabs(value1), std::fabs(value2), T{ 1.0 } });
            return std::fabs(value1 - value2) < epsilon<T> * scale_factor;
        }

        template <typename T, typename = std::enable_if_t<std::is_integral<T>::value>>
        SEAL_NODISCARD inline constexpr bool is_zero(T value) noexcept
        {
            return value == T{ 0 };
        }

        void seal_memzero(void *const data, std::size_t size);
    } // namespace util
} // namespace seal
