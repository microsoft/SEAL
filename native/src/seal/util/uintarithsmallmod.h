// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#pragma once

#include "seal/modulus.h"
#include "seal/util/defines.h"
#include "seal/util/numth.h"
#include "seal/util/pointer.h"
#include "seal/util/uintarith.h"
#include <cstdint>
#include <type_traits>

namespace seal
{
    namespace util
    {
        // Lazy reductions in this file, and in the NTT and RNS kernels built on it, keep values in [0, 4 * modulus),
        // which fits in 64 bits only for moduli less than 2^62
        static_assert(SEAL_MOD_BIT_COUNT_MAX <= 61, "lazy reductions require moduli of at most 61 bits");

        /**
        Returns x - m if x >= m, and x otherwise. In the lazy reductions that use this function, x >= m about half of
        the time in no predictable pattern, so a branch would be mispredicted often. With GCC and Clang on x86-64 and
        AArch64, the subtraction and the conditional move are therefore written in assembly: compilers, notably GCC,
        otherwise sometimes emit a branch.
        */
        SEAL_NODISCARD SEAL_FORCE_INLINE std::uint64_t sub_if_ge_uint64(std::uint64_t x, std::uint64_t m) noexcept
        {
#if (defined(__GNUC__) || defined(__clang__)) && !defined(SEAL_AVOID_BRANCHING) && defined(__x86_64__)
            std::uint64_t t = x;
            __asm__("subq %[m], %[t]\n\tcmovbq %[x], %[t]" : [t] "+&r"(t) : [m] "r"(m), [x] "r"(x) : "cc");
            return t;
#elif (defined(__GNUC__) || defined(__clang__)) && !defined(SEAL_AVOID_BRANCHING) && defined(__aarch64__)
            std::uint64_t t;
            __asm__("subs %[t], %[x], %[m]\n\tcsel %[t], %[x], %[t], lo"
                    : [t] "=&r"(t)
                    : [x] "r"(x), [m] "r"(m)
                    : "cc");
            return t;
#else
            return SEAL_COND_SELECT(x >= m, x - m, x);
#endif
        }

        /**
        Returns 2^64 - 1 if x < y, and 0 otherwise. Like sub_if_ge_uint64, this is written in assembly with GCC and
        Clang on x86-64 and AArch64, so that selections made with the mask, such as (a & mask) | (b & ~mask), have no
        branch.
        */
        SEAL_NODISCARD SEAL_FORCE_INLINE std::uint64_t less_than_mask_uint64(std::uint64_t x, std::uint64_t y) noexcept
        {
#if (defined(__GNUC__) || defined(__clang__)) && !defined(SEAL_AVOID_BRANCHING) && defined(__x86_64__)
            std::uint64_t mask;
            __asm__("cmpq %[y], %[x]\n\tsbbq %[r], %[r]" : [r] "=r"(mask) : [x] "r"(x), [y] "r"(y) : "cc");
            return mask;
#elif (defined(__GNUC__) || defined(__clang__)) && !defined(SEAL_AVOID_BRANCHING) && defined(__aarch64__)
            std::uint64_t mask;
            __asm__("cmp %[x], %[y]\n\tcsetm %[r], lo" : [r] "=r"(mask) : [x] "r"(x), [y] "r"(y) : "cc");
            return mask;
#else
            return std::uint64_t(0) - static_cast<std::uint64_t>(x < y);
#endif
        }

        /**
        Returns (operand++) mod modulus.
        Correctness: operand must be at most (2 * modulus -2) for correctness.
        */
        SEAL_NODISCARD inline std::uint64_t increment_uint_mod(std::uint64_t operand, const Modulus &modulus)
        {
#ifdef SEAL_DEBUG
            if (modulus.is_zero())
            {
                throw std::invalid_argument("modulus");
            }
            if (operand > (modulus.value() - 1) << 1)
            {
                throw std::out_of_range("operand");
            }
#endif
            operand++;
            return operand - (modulus.value() &
                              static_cast<std::uint64_t>(-static_cast<std::int64_t>(operand >= modulus.value())));
        }

        /**
        Returns (operand--) mod modulus.
        @param[in] operand Must be at most (modulus - 1).
        */
        SEAL_NODISCARD inline std::uint64_t decrement_uint_mod(std::uint64_t operand, const Modulus &modulus)
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
            std::int64_t carry = static_cast<std::int64_t>(operand == 0);
            return operand - 1 + (modulus.value() & static_cast<std::uint64_t>(-carry));
        }

        /**
        Returns (-operand) mod modulus.
        Correctness: operand must be at most modulus for correctness.
        */
        SEAL_NODISCARD inline std::uint64_t negate_uint_mod(std::uint64_t operand, const Modulus &modulus)
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
            std::int64_t non_zero = static_cast<std::int64_t>(operand != 0);
            return (modulus.value() - operand) & static_cast<std::uint64_t>(-non_zero);
        }

        /**
        Returns (operand * inv(2)) mod modulus.
        Correctness: operand must be even and at most (2 * modulus - 2) or odd and at most (modulus - 2).
        @param[in] operand Should be at most (modulus - 1).
        */
        SEAL_NODISCARD inline std::uint64_t div2_uint_mod(std::uint64_t operand, const Modulus &modulus)
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
                unsigned char carry = add_uint64(operand, modulus.value(), 0, &temp);
                operand = temp >> 1;
                if (carry)
                {
                    return operand | (std::uint64_t(1) << (bits_per_uint64 - 1));
                }
                return operand;
            }
            return operand >> 1;
        }

        /**
        Returns (operand1 + operand2) mod modulus.
        Correctness: (operand1 + operand2) must be at most (2 * modulus - 1).
        */
        SEAL_NODISCARD inline std::uint64_t add_uint_mod(
            std::uint64_t operand1, std::uint64_t operand2, const Modulus &modulus)
        {
#ifdef SEAL_DEBUG
            if (modulus.is_zero())
            {
                throw std::invalid_argument("modulus");
            }
            if (operand1 + operand2 >= modulus.value() << 1)
            {
                throw std::out_of_range("operands");
            }
#endif
            // Sum of operands modulo Modulus can never wrap around 2^64
            operand1 += operand2;
            return SEAL_COND_SELECT(operand1 >= modulus.value(), operand1 - modulus.value(), operand1);
        }

        /**
        Returns (operand1 - operand2) mod modulus.
        Correctness: (operand1 - operand2) must be at most (modulus - 1) and at least (-modulus).
        @param[in] operand1 Should be at most (modulus - 1).
        @param[in] operand2 Should be at most (modulus - 1).
        */
        SEAL_NODISCARD inline std::uint64_t sub_uint_mod(
            std::uint64_t operand1, std::uint64_t operand2, const Modulus &modulus)
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
            std::int64_t borrow = static_cast<std::int64_t>(SEAL_SUB_BORROW_UINT64(operand1, operand2, 0, &temp));
            return static_cast<std::uint64_t>(temp) + (modulus.value() & static_cast<std::uint64_t>(-borrow));
        }

        /**
        Returns (hi * 2^64 + lo) mod p. With 2^64 = ratio_hi * p + r64 the input is congruent to hi * r64 + lo; the
        first term is reduced to [0, 2p) with a Shoup multiplication whose quotient is ratio_lo = floor(r64 * 2^64 / p),
        the second with a 64-bit Barrett reduction, and the sum is fully reduced with two conditional subtractions.
        Correctness: p must be less than 2^62.

        @param[in] r64 2^64 mod p (see two_pow_64_mod)
        @param[in] ratio_lo The low word of floor(2^128 / p), i.e., modulus.const_ratio()[0]
        @param[in] ratio_hi The high word of floor(2^128 / p), i.e., modulus.const_ratio()[1]
        */
        SEAL_NODISCARD SEAL_FORCE_INLINE std::uint64_t barrett_reduce_128_precomputed(
            std::uint64_t lo, std::uint64_t hi, std::uint64_t p, std::uint64_t r64, std::uint64_t ratio_lo,
            std::uint64_t ratio_hi)
        {
            unsigned long long q_hi, q_lo;
            multiply_uint64_hw64(hi, ratio_lo, &q_hi);
            multiply_uint64_hw64(lo, ratio_hi, &q_lo);
            // hi * r64 mod p in [0, 2p) plus lo mod p in [0, 2p)
            std::uint64_t r = (hi * r64 - q_hi * p) + (lo - q_lo * p);
            const std::uint64_t two_p = p << 1;
            return sub_if_ge_uint64(sub_if_ge_uint64(r, two_p), p);
        }

        /**
        Returns 2^64 mod modulus.
        */
        SEAL_NODISCARD inline std::uint64_t two_pow_64_mod(const Modulus &modulus)
        {
            // floor(2^128 / p) has high word floor(2^64 / p), so 2^64 mod p = 2^64 - floor(2^64 / p) * p
            return static_cast<std::uint64_t>(0) - modulus.const_ratio()[1] * modulus.value();
        }

        /**
        Returns -p^(-1) mod 2^64 for odd p.
        */
        SEAL_NODISCARD inline std::uint64_t neg_inv_mod_2_64(std::uint64_t p) noexcept
        {
            // Newton iteration: p * p = 1 mod 8, so p is the inverse to 3 bits, and each step doubles the number of
            // correct bits
            std::uint64_t inv = p;
            for (int i = 0; i < 5; i++)
            {
                inv *= std::uint64_t(2) - p * inv;
            }
            return std::uint64_t(0) - inv;
        }

        /**
        Returns (hi * 2^64 + lo) * 2^(-64) mod p, fully reduced (Montgomery reduction).
        Correctness: p must be odd and less than 2^63, neg_inv_p must be -p^(-1) mod 2^64 (see neg_inv_mod_2_64), and
        hi * 2^64 + lo must be less than p * 2^64.
        */
        SEAL_NODISCARD SEAL_FORCE_INLINE std::uint64_t montgomery_reduce_128(
            std::uint64_t lo, std::uint64_t hi, std::uint64_t p, std::uint64_t neg_inv_p) noexcept
        {
            // With m = lo * (-p^(-1)) mod 2^64, the input plus m * p is divisible by 2^64: the low words add to zero
            // modulo 2^64, with a carry exactly when lo != 0. The quotient is less than 2p.
            std::uint64_t m = lo * neg_inv_p;
            unsigned long long u;
            multiply_uint64_hw64(m, p, &u);
            std::uint64_t r = hi + static_cast<std::uint64_t>(u) + static_cast<std::uint64_t>(lo != 0);
            return sub_if_ge_uint64(r, p);
        }

        /**
        Montgomery reduction modulo an odd p of at most 61 bits for dyadic products of NTT-form polynomials:
        reduce(lo, hi) returns (hi * 2^64 + lo) * 2^(-64) mod p, fully reduced, for hi * 2^64 + lo < p * 2^64. Inputs
        from ntt_negacyclic_harvey_lazy (in [0, 4p)) are first reduced to [0, 2p) with reduce_input; then every product,
        and every sum of two products, is below 8p^2 < p * 2^64. Callers fold the factor 2^64 into a later constant
        multiplication, such as the scalar of an inverse NTT.
        */
        class DyadicMontgomeryReducer
        {
        public:
            explicit DyadicMontgomeryReducer(const Modulus &modulus)
                : p_(modulus.value()), two_p_(modulus.value() << 1), neg_inv_p_(neg_inv_mod_2_64(modulus.value()))
            {}

            // Reduces x in [0, 4p) to [0, 2p)
            SEAL_NODISCARD SEAL_FORCE_INLINE std::uint64_t reduce_input(std::uint64_t x) const noexcept
            {
                return sub_if_ge_uint64(x, two_p_);
            }

            // Returns (hi * 2^64 + lo) * 2^(-64) mod p (see montgomery_reduce_128)
            SEAL_NODISCARD SEAL_FORCE_INLINE std::uint64_t reduce(std::uint64_t lo, std::uint64_t hi) const noexcept
            {
                return montgomery_reduce_128(lo, hi, p_, neg_inv_p_);
            }

        private:
            std::uint64_t p_;

            std::uint64_t two_p_;

            std::uint64_t neg_inv_p_;
        };

        /**
        Returns input mod modulus. This is not standard Barrett reduction.
        Correctness: modulus must be less than 2^62.
        @param[in] input Should be at most 128-bit.
        */
        template <typename T, typename = std::enable_if_t<is_uint64_v<T>>>
        SEAL_NODISCARD inline std::uint64_t barrett_reduce_128(const T *input, const Modulus &modulus)
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
            // See barrett_reduce_128_precomputed
            return barrett_reduce_128_precomputed(
                static_cast<std::uint64_t>(input[0]), static_cast<std::uint64_t>(input[1]), modulus.value(),
                two_pow_64_mod(modulus), modulus.const_ratio()[0], modulus.const_ratio()[1]);
        }

        /**
        Returns input mod modulus. This is not standard Barrett reduction.
        Correctness: modulus must be at most 63-bit.
        */
        template <typename T, typename = std::enable_if_t<is_uint64_v<T>>>
        SEAL_NODISCARD inline std::uint64_t barrett_reduce_64(T input, const Modulus &modulus)
        {
#ifdef SEAL_DEBUG
            if (modulus.is_zero())
            {
                throw std::invalid_argument("modulus");
            }
#endif
            // Reduces input using base 2^64 Barrett reduction
            // floor(2^64 / mod) == floor( floor(2^128 / mod) )
            unsigned long long tmp[2];
            const std::uint64_t *const_ratio = modulus.const_ratio().data();
            multiply_uint64_hw64(input, const_ratio[1], tmp + 1);

            // Barrett subtraction
            tmp[0] = input - tmp[1] * modulus.value();

            // One more subtraction is enough
            return sub_if_ge_uint64(tmp[0], modulus.value());
        }

        /**
        Returns (operand1 * operand2) mod modulus.
        Correctness: Follows the condition of barrett_reduce_128.
        */
        SEAL_NODISCARD inline std::uint64_t multiply_uint_mod(
            std::uint64_t operand1, std::uint64_t operand2, const Modulus &modulus)
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

        /**
        This struct contains a operand and a precomputed quotient: (operand << 64) / modulus, for a specific modulus.
        When passed to multiply_uint_mod, a faster variant of Barrett reduction will be performed.
        Operand must be less than modulus.
        */
        struct MultiplyUIntModOperand
        {
            std::uint64_t operand;
            std::uint64_t quotient;

            void set_quotient(const Modulus &modulus)
            {
#ifdef SEAL_DEBUG
                if (operand >= modulus.value())
                {
                    throw std::invalid_argument("input must be less than modulus");
                }
#endif
                std::uint64_t wide_quotient[2]{ 0, 0 };
                std::uint64_t wide_coeff[2]{ 0, operand };
                divide_uint128_inplace(wide_coeff, modulus.value(), wide_quotient);
                quotient = wide_quotient[0];
            }

            void set(std::uint64_t new_operand, const Modulus &modulus)
            {
#ifdef SEAL_DEBUG
                if (new_operand >= modulus.value())
                {
                    throw std::invalid_argument("input must be less than modulus");
                }
#endif
                operand = new_operand;
                set_quotient(modulus);
            }
        };

        /**
        Returns x * y mod modulus.
        This is a highly-optimized variant of Barrett reduction.
        Correctness: modulus should be at most 63-bit, and y must be less than modulus.
        */
        SEAL_NODISCARD inline std::uint64_t multiply_uint_mod(
            std::uint64_t x, MultiplyUIntModOperand y, const Modulus &modulus)
        {
#ifdef SEAL_DEBUG
            if (y.operand >= modulus.value())
            {
                throw std::invalid_argument("operand y must be less than modulus");
            }
#endif
            unsigned long long tmp1, tmp2;
            const std::uint64_t p = modulus.value();
            multiply_uint64_hw64(x, y.quotient, &tmp1);
            tmp2 = y.operand * x - tmp1 * p;
            return sub_if_ge_uint64(tmp2, p);
        }

        /**
        Returns x * y mod modulus or x * y mod modulus + modulus.
        This is a highly-optimized variant of Barrett reduction and reduce to [0, 2 * modulus - 1].
        Correctness: modulus should be at most 63-bit, and y must be less than modulus.
        */
        SEAL_NODISCARD inline std::uint64_t multiply_uint_mod_lazy(
            std::uint64_t x, MultiplyUIntModOperand y, const Modulus &modulus)
        {
#ifdef SEAL_DEBUG
            if (y.operand >= modulus.value())
            {
                throw std::invalid_argument("operand y must be less than modulus");
            }
#endif
            unsigned long long tmp1;
            const std::uint64_t p = modulus.value();
            multiply_uint64_hw64(x, y.quotient, &tmp1);
            return y.operand * x - tmp1 * p;
        }

        /**
        Returns value[0] = value mod modulus.
        Correctness: Follows the condition of barrett_reduce_128.
        */
        inline void modulo_uint_inplace(std::uint64_t *value, std::size_t value_uint64_count, const Modulus &modulus)
        {
#ifdef SEAL_DEBUG
            if (!value)
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
                if (*value < modulus.value())
                {
                    return;
                }
                else
                {
                    *value = barrett_reduce_64(*value, modulus);
                }
            }

            // Starting from the top, reduce always 128-bit blocks
            for (std::size_t i = value_uint64_count - 1; i--;)
            {
                value[i] = barrett_reduce_128(value + i, modulus);
                value[i + 1] = 0;
            }
        }

        /**
        Returns value mod modulus.
        Correctness: Follows the condition of barrett_reduce_128.
        */
        SEAL_NODISCARD inline std::uint64_t modulo_uint(
            const std::uint64_t *value, std::size_t value_uint64_count, const Modulus &modulus)
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
                if (*value < modulus.value())
                    return *value;
                else
                    return barrett_reduce_64(*value, modulus);
            }

            // Temporary space for 128-bit reductions
            uint64_t temp[2]{ 0, value[value_uint64_count - 1] };
            for (size_t k = value_uint64_count - 1; k--;)
            {
                temp[0] = value[k];
                temp[1] = barrett_reduce_128(temp, modulus);
            }

            // Save the result modulo i-th prime
            return temp[1];
        }

        /**
        Returns (operand1 * operand2) + operand3 mod modulus.
        Correctness: Follows the condition of barrett_reduce_128.
        */
        inline std::uint64_t multiply_add_uint_mod(
            std::uint64_t operand1, std::uint64_t operand2, std::uint64_t operand3, const Modulus &modulus)
        {
            // Lazy reduction
            unsigned long long temp[2];
            multiply_uint64(operand1, operand2, temp);
            temp[1] += add_uint64(temp[0], operand3, temp);
            return barrett_reduce_128(temp, modulus);
        }

        /**
        Returns (operand1 * operand2) + operand3 mod modulus.
        Correctness: Follows the condition of multiply_uint_mod.
        */
        inline std::uint64_t multiply_add_uint_mod(
            std::uint64_t operand1, MultiplyUIntModOperand operand2, std::uint64_t operand3, const Modulus &modulus)
        {
            return add_uint_mod(
                multiply_uint_mod(operand1, operand2, modulus), barrett_reduce_64(operand3, modulus), modulus);
        }

        inline bool try_invert_uint_mod(std::uint64_t operand, const Modulus &modulus, std::uint64_t &result)
        {
            return try_invert_uint_mod(operand, modulus.value(), result);
        }

        /**
        Returns operand^exponent mod modulus.
        Correctness: Follows the condition of barrett_reduce_128.
        */
        SEAL_NODISCARD std::uint64_t exponentiate_uint_mod(
            std::uint64_t operand, std::uint64_t exponent, const Modulus &modulus);

        /**
        Computes numerator = numerator mod modulus, quotient = numerator / modulus.
        Correctness: Follows the condition of barrett_reduce_128.
        */
        void divide_uint_mod_inplace(
            std::uint64_t *numerator, const Modulus &modulus, std::size_t uint64_count, std::uint64_t *quotient,
            MemoryPool &pool);

        /**
        Computes <operand1, operand2> mod modulus.
        Correctness: Follows the condition of barrett_reduce_128.
        */
        SEAL_NODISCARD std::uint64_t dot_product_mod(
            const std::uint64_t *operand1, const std::uint64_t *operand2, std::size_t count, const Modulus &modulus);
    } // namespace util
} // namespace seal
