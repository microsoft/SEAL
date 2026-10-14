// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include "seal/memorymanager.h"
#include "seal/modulus.h"
#include "seal/util/uintarithsmallmod.h"
#include "seal/util/uintcore.h"
#include <random>
#include <utility>
#include <vector>
#include "gtest/gtest.h"

using namespace seal::util;
using namespace seal;
using namespace std;

namespace sealtest
{
    namespace util
    {
        TEST(UIntArithSmallMod, IncrementUIntMod)
        {
            Modulus mod(2);
            ASSERT_EQ(1ULL, increment_uint_mod(0, mod));
            ASSERT_EQ(0ULL, increment_uint_mod(1ULL, mod));

            mod = 0x10000;
            ASSERT_EQ(1ULL, increment_uint_mod(0, mod));
            ASSERT_EQ(2ULL, increment_uint_mod(1ULL, mod));
            ASSERT_EQ(0ULL, increment_uint_mod(0xFFFFULL, mod));

            mod = 2305843009211596801ULL;
            ASSERT_EQ(1ULL, increment_uint_mod(0, mod));
            ASSERT_EQ(0ULL, increment_uint_mod(2305843009211596800ULL, mod));
            ASSERT_EQ(1ULL, increment_uint_mod(0, mod));
        }

        TEST(UIntArithSmallMod, DecrementUIntMod)
        {
            Modulus mod(2);
            ASSERT_EQ(0ULL, decrement_uint_mod(1, mod));
            ASSERT_EQ(1ULL, decrement_uint_mod(0ULL, mod));

            mod = 0x10000;
            ASSERT_EQ(0ULL, decrement_uint_mod(1, mod));
            ASSERT_EQ(1ULL, decrement_uint_mod(2ULL, mod));
            ASSERT_EQ(0xFFFFULL, decrement_uint_mod(0ULL, mod));

            mod = 2305843009211596801ULL;
            ASSERT_EQ(0ULL, decrement_uint_mod(1, mod));
            ASSERT_EQ(2305843009211596800ULL, decrement_uint_mod(0ULL, mod));
            ASSERT_EQ(0ULL, decrement_uint_mod(1, mod));
        }

        TEST(UIntArithSmallMod, NegateUIntMod)
        {
            Modulus mod(2);
            ASSERT_EQ(0ULL, negate_uint_mod(0, mod));
            ASSERT_EQ(1ULL, negate_uint_mod(1, mod));

            mod = 0xFFFFULL;
            ASSERT_EQ(0ULL, negate_uint_mod(0, mod));
            ASSERT_EQ(0xFFFEULL, negate_uint_mod(1, mod));
            ASSERT_EQ(0x1ULL, negate_uint_mod(0xFFFEULL, mod));

            mod = 0x10000ULL;
            ASSERT_EQ(0ULL, negate_uint_mod(0, mod));
            ASSERT_EQ(0xFFFFULL, negate_uint_mod(1, mod));
            ASSERT_EQ(0x1ULL, negate_uint_mod(0xFFFFULL, mod));

            mod = 2305843009211596801ULL;
            ASSERT_EQ(0ULL, negate_uint_mod(0, mod));
            ASSERT_EQ(2305843009211596800ULL, negate_uint_mod(1, mod));
        }

        TEST(UIntArithSmallMod, Div2UIntMod)
        {
            Modulus mod(3);
            ASSERT_EQ(0ULL, div2_uint_mod(0ULL, mod));
            ASSERT_EQ(2ULL, div2_uint_mod(1ULL, mod));

            mod = 17;
            ASSERT_EQ(11ULL, div2_uint_mod(5ULL, mod));
            ASSERT_EQ(4ULL, div2_uint_mod(8ULL, mod));

            mod = 0xFFFFFFFFFFFFFFFULL;
            ASSERT_EQ(0x800000000000000ULL, div2_uint_mod(1ULL, mod));
            ASSERT_EQ(0x800000000000001ULL, div2_uint_mod(3ULL, mod));
        }

        TEST(UIntArithSmallMod, AddUIntMod)
        {
            Modulus mod(2);
            ASSERT_EQ(0ULL, add_uint_mod(0, 0, mod));
            ASSERT_EQ(1ULL, add_uint_mod(0, 1, mod));
            ASSERT_EQ(1ULL, add_uint_mod(1, 0, mod));
            ASSERT_EQ(0ULL, add_uint_mod(1, 1, mod));

            mod = 10;
            ASSERT_EQ(0ULL, add_uint_mod(0, 0, mod));
            ASSERT_EQ(1ULL, add_uint_mod(0, 1, mod));
            ASSERT_EQ(1ULL, add_uint_mod(1, 0, mod));
            ASSERT_EQ(2ULL, add_uint_mod(1, 1, mod));
            ASSERT_EQ(4ULL, add_uint_mod(7, 7, mod));
            ASSERT_EQ(3ULL, add_uint_mod(6, 7, mod));

            mod = 2305843009211596801ULL;
            ASSERT_EQ(0ULL, add_uint_mod(0, 0, mod));
            ASSERT_EQ(1ULL, add_uint_mod(0, 1, mod));
            ASSERT_EQ(1ULL, add_uint_mod(1, 0, mod));
            ASSERT_EQ(2ULL, add_uint_mod(1, 1, mod));
            ASSERT_EQ(0ULL, add_uint_mod(1152921504605798400ULL, 1152921504605798401ULL, mod));
            ASSERT_EQ(1ULL, add_uint_mod(1152921504605798401ULL, 1152921504605798401ULL, mod));
            ASSERT_EQ(2305843009211596799ULL, add_uint_mod(2305843009211596800ULL, 2305843009211596800ULL, mod));
        }

        TEST(UIntArithSmallMod, SubUIntMod)
        {
            Modulus mod(2);
            ASSERT_EQ(0ULL, sub_uint_mod(0, 0, mod));
            ASSERT_EQ(1ULL, sub_uint_mod(0, 1, mod));
            ASSERT_EQ(1ULL, sub_uint_mod(1, 0, mod));
            ASSERT_EQ(0ULL, sub_uint_mod(1, 1, mod));

            mod = 10;
            ASSERT_EQ(0ULL, sub_uint_mod(0, 0, mod));
            ASSERT_EQ(9ULL, sub_uint_mod(0, 1, mod));
            ASSERT_EQ(1ULL, sub_uint_mod(1, 0, mod));
            ASSERT_EQ(0ULL, sub_uint_mod(1, 1, mod));
            ASSERT_EQ(0ULL, sub_uint_mod(7, 7, mod));
            ASSERT_EQ(9ULL, sub_uint_mod(6, 7, mod));
            ASSERT_EQ(1ULL, sub_uint_mod(7, 6, mod));

            mod = 2305843009211596801ULL;
            ASSERT_EQ(0ULL, sub_uint_mod(0, 0, mod));
            ASSERT_EQ(2305843009211596800ULL, sub_uint_mod(0, 1, mod));
            ASSERT_EQ(1ULL, sub_uint_mod(1, 0, mod));
            ASSERT_EQ(0ULL, sub_uint_mod(1, 1, mod));
            ASSERT_EQ(2305843009211596800ULL, sub_uint_mod(1152921504605798400ULL, 1152921504605798401ULL, mod));
            ASSERT_EQ(1ULL, sub_uint_mod(1152921504605798401ULL, 1152921504605798400ULL, mod));
            ASSERT_EQ(0ULL, sub_uint_mod(1152921504605798401ULL, 1152921504605798401ULL, mod));
            ASSERT_EQ(0ULL, sub_uint_mod(2305843009211596800ULL, 2305843009211596800ULL, mod));
        }

        TEST(UIntArithSmallMod, BarrettReduce128)
        {
            uint64_t input[2];

            Modulus mod(2);
            input[0] = 0;
            input[1] = 0;
            ASSERT_EQ(0ULL, barrett_reduce_128(input, mod));
            input[0] = 1;
            input[1] = 0;
            ASSERT_EQ(1ULL, barrett_reduce_128(input, mod));
            input[0] = 0xFFFFFFFFFFFFFFFFULL;
            input[1] = 0xFFFFFFFFFFFFFFFFULL;
            ASSERT_EQ(1ULL, barrett_reduce_128(input, mod));

            mod = 3;
            input[0] = 0;
            input[1] = 0;
            ASSERT_EQ(0ULL, barrett_reduce_128(input, mod));
            input[0] = 1;
            input[1] = 0;
            ASSERT_EQ(1ULL, barrett_reduce_128(input, mod));
            input[0] = 123;
            input[1] = 456;
            ASSERT_EQ(0ULL, barrett_reduce_128(input, mod));
            input[0] = 0xFFFFFFFFFFFFFFFFULL;
            input[1] = 0xFFFFFFFFFFFFFFFFULL;
            ASSERT_EQ(0ULL, barrett_reduce_128(input, mod));

            mod = 13131313131313ULL;
            input[0] = 0;
            input[1] = 0;
            ASSERT_EQ(0ULL, barrett_reduce_128(input, mod));
            input[0] = 1;
            input[1] = 0;
            ASSERT_EQ(1ULL, barrett_reduce_128(input, mod));
            input[0] = 123;
            input[1] = 456;
            ASSERT_EQ(8722750765283ULL, barrett_reduce_128(input, mod));
            input[0] = 24242424242424;
            input[1] = 79797979797979;
            ASSERT_EQ(1010101010101ULL, barrett_reduce_128(input, mod));
        }

        namespace
        {
            // (hi * 2^64 + lo) mod p by bit-by-bit long division
            uint64_t reference_mod_128(uint64_t lo, uint64_t hi, uint64_t p)
            {
                uint64_t r = 0;
                for (int bit = 127; bit >= 0; bit--)
                {
                    uint64_t b = bit >= 64 ? (hi >> (bit - 64)) & 1 : (lo >> bit) & 1;
                    r = (r << 1) | b;
                    if (r >= p)
                    {
                        r -= p;
                    }
                }
                return r;
            }

            // Odd, even, power-of-two, tiny, and maximal (61-bit) moduli
            vector<uint64_t> test_moduli(mt19937_64 &rng)
            {
                vector<uint64_t> moduli{ 2, 3, 5, 17, 65537 };
                moduli.push_back((uint64_t(1) << 61) - 1);
                moduli.push_back((uint64_t(1) << 60) + 1);
                moduli.push_back(0x1fffffffffe00001ULL);
                moduli.push_back(0xffffffffffc0001ULL);
                for (int k = 2; k <= 61; k++)
                {
                    moduli.push_back(uint64_t(1) << (k - 1));
                    moduli.push_back((uint64_t(1) << k) - 1);
                    moduli.push_back((rng() >> (64 - k)) | (uint64_t(1) << (k - 1)) | 1);
                }
                return moduli;
            }
        } // namespace

        TEST(UIntArithSmallMod, BarrettReduce128Random)
        {
            mt19937_64 rng(777);
            for (uint64_t p : test_moduli(rng))
            {
                Modulus mod(p);
                vector<pair<uint64_t, uint64_t>> inputs{ { 0, 0 },
                                                         { 1, 0 },
                                                         { p - 1, 0 },
                                                         { p, 0 },
                                                         { ~uint64_t(0), 0 },
                                                         { 0, ~uint64_t(0) },
                                                         { ~uint64_t(0), ~uint64_t(0) },
                                                         { 0, p - 1 },
                                                         { ~uint64_t(0), p - 1 },
                                                         { 0, p } };

                // Squares of the largest values in [0, p), [0, 2p), and [0, 4p)
                for (uint64_t a : { p - 1, 2 * p - 1, 4 * p - 1 })
                {
                    unsigned long long z[2];
                    multiply_uint64(a, a, z);
                    inputs.emplace_back(z[0], z[1]);
                }

                for (int i = 0; i < 300; i++)
                {
                    inputs.emplace_back(rng(), rng());
                    inputs.emplace_back(rng(), rng() % p);
                }

                for (auto &in : inputs)
                {
                    uint64_t input[2]{ in.first, in.second };
                    ASSERT_EQ(reference_mod_128(in.first, in.second, p), barrett_reduce_128(input, mod))
                        << "p = " << p << ", input = " << in.second << " * 2^64 + " << in.first;
                }
            }
        }

        TEST(UIntArithSmallMod, TwoPow64Mod)
        {
            mt19937_64 rng(778);
            for (uint64_t p : test_moduli(rng))
            {
                ASSERT_EQ(reference_mod_128(0, 1, p), two_pow_64_mod(Modulus(p))) << "p = " << p;
            }
        }

        TEST(UIntArithSmallMod, SubIfGeUInt64)
        {
            const uint64_t max = ~uint64_t(0);
            ASSERT_EQ(0ULL, sub_if_ge_uint64(0, 0));
            ASSERT_EQ(0ULL, sub_if_ge_uint64(0, 1));
            ASSERT_EQ(0ULL, sub_if_ge_uint64(1, 1));
            ASSERT_EQ(1ULL, sub_if_ge_uint64(1, 2));
            ASSERT_EQ(1ULL, sub_if_ge_uint64(3, 2));
            ASSERT_EQ(0ULL, sub_if_ge_uint64(max, max));
            ASSERT_EQ(max - 1, sub_if_ge_uint64(max - 1, max));
            ASSERT_EQ(max, sub_if_ge_uint64(max, 0));
            ASSERT_EQ(uint64_t(1) << 63, sub_if_ge_uint64(max, (uint64_t(1) << 63) - 1));
            ASSERT_EQ((uint64_t(1) << 63) - 1, sub_if_ge_uint64((uint64_t(1) << 63) - 1, uint64_t(1) << 63));
        }

        TEST(UIntArithSmallMod, LessThanMaskUInt64)
        {
            const uint64_t max = ~uint64_t(0);
            ASSERT_EQ(0ULL, less_than_mask_uint64(0, 0));
            ASSERT_EQ(max, less_than_mask_uint64(0, 1));
            ASSERT_EQ(0ULL, less_than_mask_uint64(1, 0));
            ASSERT_EQ(0ULL, less_than_mask_uint64(max, max));
            ASSERT_EQ(max, less_than_mask_uint64(max - 1, max));
            ASSERT_EQ(0ULL, less_than_mask_uint64(max, max - 1));
            ASSERT_EQ(max, less_than_mask_uint64((uint64_t(1) << 63) - 1, uint64_t(1) << 63));
        }

        TEST(UIntArithSmallMod, SelectUInt64)
        {
            const uint64_t max = ~uint64_t(0);
            ASSERT_EQ(1ULL, select_uint64(true, 1, 2));
            ASSERT_EQ(2ULL, select_uint64(false, 1, 2));
            ASSERT_EQ(max, select_uint64(true, max, 0));
            ASSERT_EQ(0ULL, select_uint64(false, max, 0));
            ASSERT_EQ(0ULL, select_uint64(true, 0, max));
            ASSERT_EQ(max, select_uint64(false, 0, max));
        }

        TEST(UIntArithSmallMod, BranchFreeHelpersRandom)
        {
            // Compare with plain C++ on random values and on values close to each other
            mt19937_64 rng(5);
            for (int i = 0; i < 100000; i++)
            {
                uint64_t x = rng();
                uint64_t y = (i & 1) ? rng() : x + (rng() % 5) - 2;
                bool c = (rng() & 1) != 0;

                ASSERT_EQ(x >= y ? x - y : x, sub_if_ge_uint64(x, y));
                ASSERT_EQ(x < y ? ~uint64_t(0) : uint64_t(0), less_than_mask_uint64(x, y));
                ASSERT_EQ(c ? x : y, select_uint64(c, x, y));

                uint64_t m = rng();
                ASSERT_EQ(x < y ? x - y + m : x - y, sub_add_if_lt_uint64(x, y, m));

                // The same variable as two arguments checks the register constraints of the inline assembly
                ASSERT_EQ(0ULL, sub_add_if_lt_uint64(x, x, m));
                ASSERT_EQ(x < y ? x - y + x : x - y, sub_add_if_lt_uint64(x, y, x));
                ASSERT_EQ(x < y ? x : x - y, sub_add_if_lt_uint64(x, y, y));
                ASSERT_EQ(0ULL, sub_if_ge_uint64(x, x));
                ASSERT_EQ(0ULL, less_than_mask_uint64(x, x));
                ASSERT_EQ(x, select_uint64(c, x, x));
            }
        }

        TEST(UIntArithSmallMod, AddIfGeUInt)
        {
            const uint64_t max = ~uint64_t(0);

            // Compare with add_uint on random values and on values close to the threshold. Words equal to max make
            // carries run through several words.
            mt19937_64 rng(13);
            for (size_t count = 1; count <= 5; count++)
            {
                for (int i = 0; i < 20000; i++)
                {
                    uint64_t x = (i % 3) ? rng() : max - (rng() % 3);
                    uint64_t threshold = (i & 1) ? rng() : x + (rng() % 5) - 2;
                    vector<uint64_t> y(count);
                    for (auto &word : y)
                    {
                        word = (rng() % 4) ? rng() : max;
                    }

                    vector<uint64_t> expected(count, 0);
                    if (x >= threshold)
                    {
                        add_uint(y.data(), count, x, expected.data());
                    }
                    else
                    {
                        expected[0] = x;
                    }

                    // Every word of the result is written
                    vector<uint64_t> result(count, 0xA5A5A5A5A5A5A5A5ULL);
                    add_if_ge_uint(x, threshold, y.data(), count, result.data());
                    ASSERT_EQ(expected, result) << "x = " << x << ", threshold = " << threshold;
                }
            }

            uint64_t y[3]{ max, max, max };
            uint64_t result[3]{ 1, 1, 1 };
            add_if_ge_uint(1, 1, y, 3, result);
            ASSERT_EQ(vector<uint64_t>({ 0, 0, 0 }), vector<uint64_t>(result, result + 3));
            add_if_ge_uint(5, 6, y, 3, result);
            ASSERT_EQ(vector<uint64_t>({ 5, 0, 0 }), vector<uint64_t>(result, result + 3));
            add_if_ge_uint(max, max, y, 3, result);
            ASSERT_EQ(vector<uint64_t>({ max - 1, 0, 0 }), vector<uint64_t>(result, result + 3));

            uint64_t one[2]{ 1, 0 };
            add_if_ge_uint(max, 0, one, 2, result);
            ASSERT_EQ(vector<uint64_t>({ 0, 1 }), vector<uint64_t>(result, result + 2));
        }

        TEST(UIntArithSmallMod, MontgomeryReduce128)
        {
            mt19937_64 rng(779);

            // Odd moduli of up to 63 bits
            vector<uint64_t> moduli{ 3,
                                     5,
                                     65537,
                                     (uint64_t(1) << 61) - 1,
                                     0x1fffffffffe00001ULL,
                                     (uint64_t(1) << 62) + 1,
                                     (uint64_t(1) << 63) - 25 };
            for (int k = 2; k <= 63; k++)
            {
                moduli.push_back((rng() >> (64 - k)) | (uint64_t(1) << (k - 1)) | 1);
            }

            for (uint64_t p : moduli)
            {
                const uint64_t neg_inv_p = neg_inv_mod_2_64(p);
                ASSERT_EQ(~uint64_t(0), neg_inv_p * p) << "p = " << p;

                // The result r satisfies r * 2^64 = hi * 2^64 + lo (mod p) for inputs less than p * 2^64
                vector<pair<uint64_t, uint64_t>> inputs{ { 0, 0 }, { 1, 0 },     { ~uint64_t(0), 0 },
                                                         { 0, 1 }, { 0, p - 1 }, { ~uint64_t(0), p - 1 } };
                for (int i = 0; i < 300; i++)
                {
                    inputs.emplace_back(rng(), rng() % p);
                }

                for (auto &in : inputs)
                {
                    uint64_t r = montgomery_reduce_128(in.first, in.second, p, neg_inv_p);
                    ASSERT_LT(r, p);
                    ASSERT_EQ(reference_mod_128(in.first, in.second, p), reference_mod_128(0, r, p))
                        << "p = " << p << ", input = " << in.second << " * 2^64 + " << in.first;
                }
            }
        }

#ifdef SEAL_DEBUG
        TEST(UIntArithSmallMod, MontgomeryRequiresOddModulus)
        {
            ASSERT_THROW(static_cast<void>(neg_inv_mod_2_64(4)), invalid_argument);
            ASSERT_THROW(DyadicMontgomeryReducer{ Modulus(4) }, invalid_argument);
            ASSERT_NO_THROW(DyadicMontgomeryReducer{ Modulus((uint64_t(1) << 61) - 1) });
        }
#endif

        TEST(UIntArithSmallMod, MultiplyUIntMod)
        {
            Modulus mod(2);
            ASSERT_EQ(0ULL, multiply_uint_mod(0, 0, mod));
            ASSERT_EQ(0ULL, multiply_uint_mod(0, 1, mod));
            ASSERT_EQ(0ULL, multiply_uint_mod(1, 0, mod));
            ASSERT_EQ(1ULL, multiply_uint_mod(1, 1, mod));

            mod = 10;
            ASSERT_EQ(0ULL, multiply_uint_mod(0, 0, mod));
            ASSERT_EQ(0ULL, multiply_uint_mod(0, 1, mod));
            ASSERT_EQ(0ULL, multiply_uint_mod(1, 0, mod));
            ASSERT_EQ(1ULL, multiply_uint_mod(1, 1, mod));
            ASSERT_EQ(9ULL, multiply_uint_mod(7, 7, mod));
            ASSERT_EQ(2ULL, multiply_uint_mod(6, 7, mod));
            ASSERT_EQ(2ULL, multiply_uint_mod(7, 6, mod));

            mod = 2305843009211596801ULL;
            ASSERT_EQ(0ULL, multiply_uint_mod(0, 0, mod));
            ASSERT_EQ(0ULL, multiply_uint_mod(0, 1, mod));
            ASSERT_EQ(0ULL, multiply_uint_mod(1, 0, mod));
            ASSERT_EQ(1ULL, multiply_uint_mod(1, 1, mod));
            ASSERT_EQ(576460752302899200ULL, multiply_uint_mod(1152921504605798400ULL, 1152921504605798401ULL, mod));
            ASSERT_EQ(576460752302899200ULL, multiply_uint_mod(1152921504605798401ULL, 1152921504605798400ULL, mod));
            ASSERT_EQ(1729382256908697601ULL, multiply_uint_mod(1152921504605798401ULL, 1152921504605798401ULL, mod));
            ASSERT_EQ(1ULL, multiply_uint_mod(2305843009211596800ULL, 2305843009211596800ULL, mod));
        }

        TEST(UIntArithSmallMod, MultiplyAddMod)
        {
            Modulus mod(7);
            ASSERT_EQ(0ULL, multiply_add_uint_mod(0, 0, 0, mod));
            ASSERT_EQ(0ULL, multiply_add_uint_mod(1, 0, 0, mod));
            ASSERT_EQ(0ULL, multiply_add_uint_mod(0, 1, 0, mod));
            ASSERT_EQ(1ULL, multiply_add_uint_mod(0, 0, 1, mod));
            ASSERT_EQ(3ULL, multiply_add_uint_mod(3, 4, 5, mod));

            mod = 0x1FFFFFFFFFFFFFFFULL;
            ASSERT_EQ(0ULL, multiply_add_uint_mod(0, 0, 0, mod));
            ASSERT_EQ(0ULL, multiply_add_uint_mod(1, 0, 0, mod));
            ASSERT_EQ(0ULL, multiply_add_uint_mod(0, 1, 0, mod));
            ASSERT_EQ(1ULL, multiply_add_uint_mod(0, 0, 1, mod));
            ASSERT_EQ(0ULL, multiply_add_uint_mod(mod.value() - 1, mod.value() - 1, mod.value() - 1, mod));
        }

        TEST(UIntArithSmallMod, ModuloUIntMod)
        {
            MemoryPool &pool = *global_variables::global_memory_pool;
            auto value(allocate_uint(4, pool));

            Modulus mod(2);
            value[0] = 0;
            value[1] = 0;
            value[2] = 0;
            modulo_uint_inplace(value.get(), 3, mod);
            ASSERT_EQ(0ULL, value[0]);
            ASSERT_EQ(0ULL, value[1]);
            ASSERT_EQ(0ULL, value[2]);

            value[0] = 1;
            value[1] = 0;
            value[2] = 0;
            modulo_uint_inplace(value.get(), 3, mod);
            ASSERT_EQ(1ULL, value[0]);
            ASSERT_EQ(0ULL, value[1]);
            ASSERT_EQ(0ULL, value[2]);

            value[0] = 2;
            value[1] = 0;
            value[2] = 0;
            modulo_uint_inplace(value.get(), 3, mod);
            ASSERT_EQ(0ULL, value[0]);
            ASSERT_EQ(0ULL, value[1]);
            ASSERT_EQ(0ULL, value[2]);

            value[0] = 3;
            value[1] = 0;
            value[2] = 0;
            modulo_uint_inplace(value.get(), 3, mod);
            ASSERT_EQ(1ULL, value[0]);
            ASSERT_EQ(0ULL, value[1]);
            ASSERT_EQ(0ULL, value[2]);

            mod = 0xFFFF;
            value[0] = 9585656442714717620ul;
            value[1] = 1817697005049051848;
            value[2] = 0;
            modulo_uint_inplace(value.get(), 3, mod);
            ASSERT_EQ(65143ULL, value[0]);
            ASSERT_EQ(0ULL, value[1]);
            ASSERT_EQ(0ULL, value[2]);

            mod = 0x1000;
            value[0] = 9585656442714717620ul;
            value[1] = 1817697005049051848;
            value[2] = 0;
            modulo_uint_inplace(value.get(), 3, mod);
            ASSERT_EQ(0xDB4ULL, value[0]);
            ASSERT_EQ(0ULL, value[1]);
            ASSERT_EQ(0ULL, value[2]);

            mod = 0xFFFFFFFFC001ULL;
            value[0] = 9585656442714717620ul;
            value[1] = 1817697005049051848;
            value[2] = 14447416709120365380ul;
            value[3] = 67450014862939159;
            modulo_uint_inplace(value.get(), 4, mod);
            ASSERT_EQ(124510066632001ULL, value[0]);
            ASSERT_EQ(0ULL, value[1]);
            ASSERT_EQ(0ULL, value[2]);
            ASSERT_EQ(0ULL, value[3]);
        }

        TEST(UIntArithSmallMod, TryInvertUIntMod)
        {
            uint64_t result;
            Modulus mod(5);
            ASSERT_FALSE(try_invert_uint_mod(0, mod, result));
            ASSERT_TRUE(try_invert_uint_mod(1, mod, result));
            ASSERT_EQ(1ULL, result);
            ASSERT_TRUE(try_invert_uint_mod(2, mod, result));
            ASSERT_EQ(3ULL, result);
            ASSERT_TRUE(try_invert_uint_mod(3, mod, result));
            ASSERT_EQ(2ULL, result);
            ASSERT_TRUE(try_invert_uint_mod(4, mod, result));
            ASSERT_EQ(4ULL, result);

            mod = 6;
            ASSERT_FALSE(try_invert_uint_mod(2, mod, result));
            ASSERT_FALSE(try_invert_uint_mod(3, mod, result));
            ASSERT_TRUE(try_invert_uint_mod(5, mod, result));
            ASSERT_EQ(5ULL, result);

            mod = 1351315121;
            ASSERT_TRUE(try_invert_uint_mod(331975426, mod, result));
            ASSERT_EQ(1052541512ULL, result);
        }

        TEST(UIntArithSmallMod, ExponentiateUIntMod)
        {
            Modulus mod(5);
            ASSERT_EQ(1ULL, exponentiate_uint_mod(1, 0, mod));
            ASSERT_EQ(1ULL, exponentiate_uint_mod(1, 0xFFFFFFFFFFFFFFFFULL, mod));
            ASSERT_EQ(3ULL, exponentiate_uint_mod(2, 0xFFFFFFFFFFFFFFFFULL, mod));

            mod = 0x1000000000000000ULL;
            ASSERT_EQ(0ULL, exponentiate_uint_mod(2, 60, mod));
            ASSERT_EQ(0x800000000000000ULL, exponentiate_uint_mod(2, 59, mod));

            mod = 131313131313;
            ASSERT_EQ(39418477653ULL, exponentiate_uint_mod(2424242424, 16, mod));
        }

        TEST(UIntArithSmallMod, DotProductMod)
        {
            Modulus mod(5);
            uint64_t arr1[64], arr2[64];
            for (size_t i = 0; i < 64; i++)
            {
                arr1[i] = 2;
                arr2[i] = 3;
            }

            ASSERT_EQ(0, dot_product_mod(arr1, arr2, 0, mod));
            ASSERT_EQ(1, dot_product_mod(arr1, arr2, 1, mod));
            ASSERT_EQ(2, dot_product_mod(arr1, arr2, 2, mod));
            ASSERT_EQ(15 % mod.value(), dot_product_mod(arr1, arr2, 15, mod));
            ASSERT_EQ(16 % mod.value(), dot_product_mod(arr1, arr2, 16, mod));
            ASSERT_EQ(17 % mod.value(), dot_product_mod(arr1, arr2, 17, mod));
            ASSERT_EQ(32 % mod.value(), dot_product_mod(arr1, arr2, 32, mod));
            ASSERT_EQ(64 % mod.value(), dot_product_mod(arr1, arr2, 64, mod));

            mod = get_prime(1024 * 2, SEAL_MOD_BIT_COUNT_MAX);
            for (size_t i = 0; i < 64; i++)
            {
                arr1[i] = mod.value() - 1;
                arr2[i] = mod.value() - 1;
            }

            ASSERT_EQ(0, dot_product_mod(arr1, arr2, 0, mod));
            ASSERT_EQ(1, dot_product_mod(arr1, arr2, 1, mod));
            ASSERT_EQ(2, dot_product_mod(arr1, arr2, 2, mod));
            ASSERT_EQ(15, dot_product_mod(arr1, arr2, 15, mod));
            ASSERT_EQ(16, dot_product_mod(arr1, arr2, 16, mod));
            ASSERT_EQ(17, dot_product_mod(arr1, arr2, 17, mod));
            ASSERT_EQ(32, dot_product_mod(arr1, arr2, 32, mod));
            ASSERT_EQ(64, dot_product_mod(arr1, arr2, 64, mod));
        }

        TEST(UIntArithSmallMod, MultiplyUIntModOperand)
        {
            Modulus mod(3);
            MultiplyUIntModOperand y;
            y.set(1, mod);
            ASSERT_EQ(1ULL, y.operand);
            ASSERT_EQ(6148914691236517205ULL, y.quotient);
            y.set(2, mod);
            y.set_quotient(mod);
            ASSERT_EQ(2ULL, y.operand);
            ASSERT_EQ(12297829382473034410ULL, y.quotient);

            mod = 2147483647ULL;
            y.set(1, mod);
            ASSERT_EQ(1ULL, y.operand);
            ASSERT_EQ(8589934596ULL, y.quotient);
            y.set(2147483646ULL, mod);
            y.set_quotient(mod);
            ASSERT_EQ(2147483646ULL, y.operand);
            ASSERT_EQ(18446744065119617019ULL, y.quotient);

            mod = 2305843009211596801ULL;
            y.set(1, mod);
            ASSERT_EQ(1ULL, y.operand);
            ASSERT_EQ(8ULL, y.quotient);
            y.set(2305843009211596800ULL, mod);
            y.set_quotient(mod);
            ASSERT_EQ(2305843009211596800ULL, y.operand);
            ASSERT_EQ(18446744073709551607ULL, y.quotient);
        }

        TEST(UIntArithSmallMod, MultiplyUIntMod2)
        {
            Modulus mod(2);
            MultiplyUIntModOperand y;
            y.set(0, mod);
            ASSERT_EQ(0ULL, multiply_uint_mod(0, y, mod));
            ASSERT_EQ(0ULL, multiply_uint_mod(1, y, mod));
            y.set(1, mod);
            ASSERT_EQ(0ULL, multiply_uint_mod(0, y, mod));
            ASSERT_EQ(1ULL, multiply_uint_mod(1, y, mod));

            mod = 10;
            y.set(0, mod);
            ASSERT_EQ(0ULL, multiply_uint_mod(0, y, mod));
            ASSERT_EQ(0ULL, multiply_uint_mod(1, y, mod));
            y.set(1, mod);
            ASSERT_EQ(0ULL, multiply_uint_mod(0, y, mod));
            ASSERT_EQ(1ULL, multiply_uint_mod(1, y, mod));
            y.set(6, mod);
            ASSERT_EQ(2ULL, multiply_uint_mod(7, y, mod));
            y.set(7, mod);
            ASSERT_EQ(9ULL, multiply_uint_mod(7, y, mod));
            ASSERT_EQ(2ULL, multiply_uint_mod(6, y, mod));

            mod = 2305843009211596801ULL;
            y.set(0, mod);
            ASSERT_EQ(0ULL, multiply_uint_mod(0, y, mod));
            ASSERT_EQ(0ULL, multiply_uint_mod(1, y, mod));
            y.set(1, mod);
            ASSERT_EQ(0ULL, multiply_uint_mod(0, y, mod));
            ASSERT_EQ(1ULL, multiply_uint_mod(1, y, mod));
            y.set(1152921504605798400ULL, mod);
            ASSERT_EQ(576460752302899200ULL, multiply_uint_mod(1152921504605798401ULL, y, mod));
            y.set(1152921504605798401ULL, mod);
            ASSERT_EQ(576460752302899200ULL, multiply_uint_mod(1152921504605798400ULL, y, mod));
            ASSERT_EQ(1729382256908697601ULL, multiply_uint_mod(1152921504605798401ULL, y, mod));
            y.set(2305843009211596800ULL, mod);
            ASSERT_EQ(1ULL, multiply_uint_mod(2305843009211596800ULL, y, mod));
        }

        TEST(UIntArithSmallMod, MultiplyUIntModLazy)
        {
            Modulus mod(2);
            MultiplyUIntModOperand y;
            y.set(0, mod);
            ASSERT_EQ(0ULL, multiply_uint_mod_lazy(0, y, mod));
            ASSERT_EQ(0ULL, multiply_uint_mod_lazy(1, y, mod));
            y.set(1, mod);
            ASSERT_EQ(0ULL, multiply_uint_mod_lazy(0, y, mod));
            ASSERT_EQ(1ULL, multiply_uint_mod_lazy(1, y, mod));

            mod = 10;
            y.set(0, mod);
            ASSERT_EQ(0ULL, multiply_uint_mod_lazy(0, y, mod));
            ASSERT_EQ(0ULL, multiply_uint_mod_lazy(1, y, mod));
            y.set(1, mod);
            ASSERT_EQ(0ULL, multiply_uint_mod_lazy(0, y, mod));
            ASSERT_EQ(1ULL, multiply_uint_mod_lazy(1, y, mod));
            y.set(6, mod);
            ASSERT_EQ(2ULL, multiply_uint_mod_lazy(7, y, mod));
            y.set(7, mod);
            ASSERT_EQ(9ULL, multiply_uint_mod_lazy(7, y, mod));
            ASSERT_EQ(2ULL, multiply_uint_mod_lazy(6, y, mod));

            mod = 2305843009211596801ULL;
            y.set(0, mod);
            ASSERT_EQ(0ULL, multiply_uint_mod_lazy(0, y, mod));
            ASSERT_EQ(0ULL, multiply_uint_mod_lazy(1, y, mod));
            y.set(1, mod);
            ASSERT_EQ(0ULL, multiply_uint_mod_lazy(0, y, mod));
            ASSERT_EQ(1ULL, multiply_uint_mod_lazy(1, y, mod));
            y.set(1152921504605798400ULL, mod);
            ASSERT_EQ(576460752302899200ULL, multiply_uint_mod_lazy(1152921504605798401ULL, y, mod));
            y.set(1152921504605798401ULL, mod);
            ASSERT_EQ(576460752302899200ULL, multiply_uint_mod_lazy(1152921504605798400ULL, y, mod));
            ASSERT_EQ(1729382256908697601ULL, multiply_uint_mod_lazy(1152921504605798401ULL, y, mod));
            y.set(2305843009211596800ULL, mod);
            ASSERT_EQ(2305843009211596802ULL, multiply_uint_mod_lazy(2305843009211596800ULL, y, mod));
        }

        TEST(UIntArithSmallMod, MultiplyAddMod2)
        {
            Modulus mod(7);
            MultiplyUIntModOperand y;
            y.set(0, mod);
            ASSERT_EQ(0ULL, multiply_add_uint_mod(0, y, 0, mod));
            ASSERT_EQ(0ULL, multiply_add_uint_mod(1, y, 0, mod));
            ASSERT_EQ(1ULL, multiply_add_uint_mod(0, 0, 1, mod));
            y.set(1, mod);
            ASSERT_EQ(0ULL, multiply_add_uint_mod(0, y, 0, mod));
            y.set(4, mod);
            ASSERT_EQ(3ULL, multiply_add_uint_mod(3, y, 5, mod));

            mod = 0x1FFFFFFFFFFFFFFFULL;
            y.set(0, mod);
            ASSERT_EQ(0ULL, multiply_add_uint_mod(0, y, 0, mod));
            ASSERT_EQ(0ULL, multiply_add_uint_mod(1, y, 0, mod));
            ASSERT_EQ(1ULL, multiply_add_uint_mod(0, y, 1, mod));
            y.set(1, mod);
            ASSERT_EQ(0ULL, multiply_add_uint_mod(0, y, 0, mod));
            y.set(mod.value() - 1, mod);
            ASSERT_EQ(0ULL, multiply_add_uint_mod(mod.value() - 1, y, mod.value() - 1, mod));
        }
    } // namespace util
} // namespace sealtest
