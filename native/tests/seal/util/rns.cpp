// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include "seal/memorymanager.h"
#include "seal/modulus.h"
#include "seal/util/ntt.h"
#include "seal/util/numth.h"
#include "seal/util/polyarithsmallmod.h"
#include "seal/util/rns.h"
#include "seal/util/uintarith.h"
#include "seal/util/uintarithmod.h"
#include "seal/util/uintarithsmallmod.h"
#include "seal/util/uintcore.h"
#include <algorithm>
#include <random>
#include <stdexcept>
#include <vector>
#include "gtest/gtest.h"

using namespace seal;
using namespace seal::util;
using namespace std;

namespace sealtest
{
    namespace util
    {
        TEST(RNSBaseTest, Create)
        {
            auto pool = MemoryManager::GetPool();
            ASSERT_THROW(RNSBase base({ 0 }, pool), invalid_argument);
            ASSERT_THROW(RNSBase base({ 0, 3 }, pool), invalid_argument);
            ASSERT_THROW(RNSBase base({ 2, 2 }, pool), invalid_argument);
            ASSERT_THROW(RNSBase base({ 2, 3, 4 }, pool), invalid_argument);
            ASSERT_THROW(RNSBase base({ 3, 4, 5, 6 }, pool), invalid_argument);
            ASSERT_NO_THROW(RNSBase base({ 3, 4, 5, 7 }, pool));
            ASSERT_NO_THROW(RNSBase base({ 2 }, pool));
            ASSERT_NO_THROW(RNSBase base({ 3 }, pool));
            ASSERT_NO_THROW(RNSBase base({ 4 }, pool));
        }

        TEST(RNSBaseTest, ArrayAccess)
        {
            auto pool = MemoryManager::GetPool();
            {
                RNSBase base({ 2 }, pool);
                ASSERT_EQ(size_t(1), base.size());
                ASSERT_EQ(Modulus(2), base[0]);
                ASSERT_THROW(
                    [&]() {
                        return base[1].value();
                    }(),
                    out_of_range);
            }
            {
                RNSBase base({ 2, 3, 5 }, pool);
                ASSERT_EQ(size_t(3), base.size());
                ASSERT_EQ(Modulus(2), base[0]);
                ASSERT_EQ(Modulus(3), base[1]);
                ASSERT_EQ(Modulus(5), base[2]);
                ASSERT_THROW(
                    [&]() {
                        return base[3].value();
                    }(),
                    out_of_range);
            }
        }

        TEST(RNSBaseTest, Copy)
        {
            auto pool = MemoryManager::GetPool(mm_prof_opt::mm_force_new);
            RNSBase base({ 3, 4 }, pool);
            ASSERT_EQ(2l, pool.use_count());
            {
                RNSBase base2(base);
                ASSERT_EQ(3l, pool.use_count());
                ASSERT_EQ(base.size(), base2.size());
                ASSERT_EQ(base[0], base2[0]);
                ASSERT_EQ(base[1], base2[1]);
            }

            ASSERT_EQ(2l, pool.use_count());
            {
                RNSBase base2(base, MemoryManager::GetPool());
                ASSERT_EQ(2l, pool.use_count());
                ASSERT_EQ(base.size(), base2.size());
                ASSERT_EQ(base[0], base2[0]);
                ASSERT_EQ(base[1], base2[1]);
            }
        }

        TEST(RNSBaseTest, Contains)
        {
            RNSBase base({ 2, 3, 5, 13 }, MemoryManager::GetPool());
            ASSERT_TRUE(base.contains(2));
            ASSERT_TRUE(base.contains(3));
            ASSERT_TRUE(base.contains(5));
            ASSERT_TRUE(base.contains(13));
            ASSERT_FALSE(base.contains(7));
            ASSERT_FALSE(base.contains(4));
            ASSERT_FALSE(base.contains(0));
        }

        TEST(RNSBaseTest, IsSubbaseOf)
        {
            {
                RNSBase base({ 2 }, MemoryManager::GetPool());
                RNSBase base2({ 2 }, MemoryManager::GetPool());
                ASSERT_TRUE(base.is_subbase_of(base2));
                ASSERT_TRUE(base2.is_subbase_of(base));
                ASSERT_TRUE(base.is_superbase_of(base2));
                ASSERT_TRUE(base2.is_superbase_of(base));
            }
            {
                RNSBase base({ 2 }, MemoryManager::GetPool());
                RNSBase base2({ 2, 3 }, MemoryManager::GetPool());
                ASSERT_TRUE(base.is_subbase_of(base2));
                ASSERT_FALSE(base2.is_subbase_of(base));
                ASSERT_FALSE(base.is_superbase_of(base2));
                ASSERT_TRUE(base2.is_superbase_of(base));
            }
            {
                // Order does not matter for subbase/superbase
                RNSBase base({ 3, 13, 7 }, MemoryManager::GetPool());
                RNSBase base2({ 2, 3, 5, 7, 13, 19 }, MemoryManager::GetPool());
                ASSERT_TRUE(base.is_subbase_of(base2));
                ASSERT_FALSE(base2.is_subbase_of(base));
                ASSERT_FALSE(base.is_superbase_of(base2));
                ASSERT_TRUE(base2.is_superbase_of(base));
            }
            {
                RNSBase base({ 3, 13, 7, 23 }, MemoryManager::GetPool());
                RNSBase base2({ 2, 3, 5, 7, 13, 19 }, MemoryManager::GetPool());
                ASSERT_FALSE(base.is_subbase_of(base2));
                ASSERT_FALSE(base2.is_subbase_of(base));
                ASSERT_FALSE(base.is_superbase_of(base2));
                ASSERT_FALSE(base2.is_superbase_of(base));
            }
        }

        TEST(RNSBaseTest, Extend)
        {
            auto pool = MemoryManager::GetPool(mm_prof_opt::mm_force_new);
            RNSBase base({ 3 }, pool);
            ASSERT_EQ(2l, pool.use_count());

            RNSBase base2 = base.extend(5);
            ASSERT_EQ(3l, pool.use_count());
            ASSERT_EQ(size_t(2), base2.size());
            ASSERT_EQ(base[0], base2[0]);
            ASSERT_EQ(Modulus(5), base2[1]);

            RNSBase base3 = base2.extend(7);
            ASSERT_EQ(4l, pool.use_count());
            ASSERT_EQ(size_t(3), base3.size());
            ASSERT_EQ(base2[0], base3[0]);
            ASSERT_EQ(base2[1], base3[1]);
            ASSERT_EQ(Modulus(7), base3[2]);

            ASSERT_THROW(auto base4 = base3.extend(0), invalid_argument);
            ASSERT_THROW(auto base4 = base3.extend(14), logic_error);

            RNSBase base4({ 3, 4, 5 }, pool);
            RNSBase base5({ 7, 11, 13, 17 }, pool);
            RNSBase base6 = base4.extend(base5);
            ASSERT_EQ(size_t(7), base6.size());
            ASSERT_EQ(Modulus(3), base6[0]);
            ASSERT_EQ(Modulus(4), base6[1]);
            ASSERT_EQ(Modulus(5), base6[2]);
            ASSERT_EQ(Modulus(7), base6[3]);
            ASSERT_EQ(Modulus(11), base6[4]);
            ASSERT_EQ(Modulus(13), base6[5]);
            ASSERT_EQ(Modulus(17), base6[6]);

            ASSERT_THROW(auto base7 = base4.extend(RNSBase({ 7, 10, 11 }, pool)), invalid_argument);
        }

        TEST(RNSBaseTest, Drop)
        {
            auto pool = MemoryManager::GetPool(mm_prof_opt::mm_force_new);
            RNSBase base({ 3, 5, 7, 11 }, pool);
            ASSERT_EQ(2l, pool.use_count());

            RNSBase base2 = base.drop();
            ASSERT_EQ(3l, pool.use_count());
            ASSERT_EQ(size_t(3), base2.size());
            ASSERT_EQ(base[0], base2[0]);
            ASSERT_EQ(base[1], base2[1]);
            ASSERT_EQ(base[2], base2[2]);

            RNSBase base3 = base2.drop().drop();
            ASSERT_EQ(size_t(1), base3.size());
            ASSERT_EQ(base[0], base3[0]);

            ASSERT_THROW(auto b = base3.drop(), logic_error);
            ASSERT_THROW(auto b = base3.drop(3), logic_error);
            ASSERT_THROW(auto b = base3.drop(5), logic_error);

            RNSBase base4 = base.drop(5);
            ASSERT_EQ(size_t(3), base4.size());
            ASSERT_EQ(base[0], base4[0]);
            ASSERT_EQ(base[2], base4[1]);
            ASSERT_EQ(base[3], base4[2]);

            ASSERT_THROW(auto b = base4.drop(13), logic_error);
            ASSERT_THROW(auto b = base4.drop(0), logic_error);
            ASSERT_NO_THROW(auto b = base4.drop(7).drop(11));
            ASSERT_THROW(auto b = base4.drop(7).drop(11).drop(3), logic_error);
        }

        TEST(RNSBaseTest, ComposeDecompose)
        {
            MemoryPoolHandle pool = MemoryManager::GetPool();

            auto rns_test = [&pool](const RNSBase &base, vector<uint64_t> in, vector<uint64_t> out) {
                auto in_copy = in;
                base.decompose(in_copy.data(), pool);
                ASSERT_TRUE(in_copy == out);
                base.compose(in_copy.data(), pool);
                ASSERT_TRUE(in_copy == in);
            };

            {
                RNSBase base({ 2 }, pool);
                rns_test(base, { 0 }, { 0 });
                rns_test(base, { 1 }, { 1 });
            }
            {
                RNSBase base({ 5 }, pool);
                rns_test(base, { 0 }, { 0 });
                rns_test(base, { 1 }, { 1 });
                rns_test(base, { 2 }, { 2 });
                rns_test(base, { 3 }, { 3 });
                rns_test(base, { 4 }, { 4 });
            }
            {
                RNSBase base({ 3, 5 }, pool);
                rns_test(base, { 0, 0 }, { 0, 0 });
                rns_test(base, { 1, 0 }, { 1, 1 });
                rns_test(base, { 2, 0 }, { 2, 2 });
                rns_test(base, { 3, 0 }, { 0, 3 });
                rns_test(base, { 4, 0 }, { 1, 4 });
                rns_test(base, { 5, 0 }, { 2, 0 });
                rns_test(base, { 8, 0 }, { 2, 3 });
                rns_test(base, { 12, 0 }, { 0, 2 });
                rns_test(base, { 14, 0 }, { 2, 4 });
            }
            {
                RNSBase base({ 2, 3, 5 }, pool);
                rns_test(base, { 0, 0, 0 }, { 0, 0, 0 });
                rns_test(base, { 1, 0, 0 }, { 1, 1, 1 });
                rns_test(base, { 2, 0, 0 }, { 0, 2, 2 });
                rns_test(base, { 3, 0, 0 }, { 1, 0, 3 });
                rns_test(base, { 4, 0, 0 }, { 0, 1, 4 });
                rns_test(base, { 5, 0, 0 }, { 1, 2, 0 });
                rns_test(base, { 10, 0, 0 }, { 0, 1, 0 });
                rns_test(base, { 11, 0, 0 }, { 1, 2, 1 });
                rns_test(base, { 16, 0, 0 }, { 0, 1, 1 });
                rns_test(base, { 27, 0, 0 }, { 1, 0, 2 });
                rns_test(base, { 29, 0, 0 }, { 1, 2, 4 });
            }
            {
                RNSBase base({ 13, 37, 53, 97 }, pool);
                rns_test(base, { 0, 0, 0, 0 }, { 0, 0, 0, 0 });
                rns_test(base, { 1, 0, 0, 0 }, { 1, 1, 1, 1 });
                rns_test(base, { 2, 0, 0, 0 }, { 2, 2, 2, 2 });
                rns_test(base, { 12, 0, 0, 0 }, { 12, 12, 12, 12 });
                rns_test(base, { 321, 0, 0, 0 }, { 9, 25, 3, 30 });
            }
            {
                // Large example
                auto primes = get_primes(1024 * 2, 60, 4);
                vector<uint64_t> in_values{ 0xAAAAAAAAAAA, 0xBBBBBBBBBB, 0xCCCCCCCCCC, 0xDDDDDDDDDD };
                RNSBase base(primes, pool);
                rns_test(
                    base, in_values,
                    { modulo_uint(in_values.data(), in_values.size(), primes[0]),
                      modulo_uint(in_values.data(), in_values.size(), primes[1]),
                      modulo_uint(in_values.data(), in_values.size(), primes[2]),
                      modulo_uint(in_values.data(), in_values.size(), primes[3]) });
            }
        }

        TEST(RNSBaseTest, ComposeDecomposeArray)
        {
            MemoryPoolHandle pool = MemoryManager::GetPool();

            auto rns_test = [&pool](const RNSBase &base, size_t count, vector<uint64_t> in, vector<uint64_t> out) {
                auto in_copy = in;
                base.decompose_array(in_copy.data(), count, pool);
                ASSERT_TRUE(in_copy == out);
                base.compose_array(in_copy.data(), count, pool);
                ASSERT_TRUE(in_copy == in);
            };

            {
                RNSBase base({ 2 }, pool);
                rns_test(base, 1, { 0 }, { 0 });
                rns_test(base, 1, { 1 }, { 1 });
            }
            {
                RNSBase base({ 5 }, pool);
                rns_test(base, 3, { 0, 1, 2 }, { 0, 1, 2 });
            }
            {
                RNSBase base({ 3, 5 }, pool);
                rns_test(base, 1, { 0, 0 }, { 0, 0 });
                rns_test(base, 1, { 2, 0 }, { 2, 2 });
                rns_test(base, 1, { 7, 0 }, { 1, 2 });
                rns_test(base, 2, { 0, 0, 0, 0 }, { 0, 0, 0, 0 });
                rns_test(base, 2, { 1, 0, 2, 0 }, { 1, 2, 1, 2 });
                rns_test(base, 2, { 7, 0, 8, 0 }, { 1, 2, 2, 3 });
            }
            {
                RNSBase base({ 3, 5, 7 }, pool);
                rns_test(base, 1, { 0, 0, 0 }, { 0, 0, 0 });
                rns_test(base, 1, { 2, 0, 0 }, { 2, 2, 2 });
                rns_test(base, 1, { 7, 0, 0 }, { 1, 2, 0 });
                rns_test(base, 2, { 0, 0, 0, 0, 0, 0 }, { 0, 0, 0, 0, 0, 0 });
                rns_test(base, 2, { 1, 0, 0, 2, 0, 0 }, { 1, 2, 1, 2, 1, 2 });
                rns_test(base, 2, { 7, 0, 0, 8, 0, 0 }, { 1, 2, 2, 3, 0, 1 });
                rns_test(base, 3, { 7, 0, 0, 8, 0, 0, 9, 0, 0 }, { 1, 2, 0, 2, 3, 4, 0, 1, 2 });
            }
            {
                // Large example
                auto primes = get_primes(1024 * 2, 60, 2);
                vector<uint64_t> in_values{ 0xAAAAAAAAAAA, 0xBBBBBBBBBB, 0xCCCCCCCCCC,
                                            0xDDDDDDDDDD,  0xEEEEEEEEEE, 0xFFFFFFFFFF };
                RNSBase base(primes, pool);
                rns_test(
                    base, 3, in_values,
                    { modulo_uint(in_values.data(), primes.size(), primes[0]),
                      modulo_uint(in_values.data() + 2, primes.size(), primes[0]),
                      modulo_uint(in_values.data() + 4, primes.size(), primes[0]),
                      modulo_uint(in_values.data(), primes.size(), primes[1]),
                      modulo_uint(in_values.data() + 2, primes.size(), primes[1]),
                      modulo_uint(in_values.data() + 4, primes.size(), primes[1]) });
            }
        }

        TEST(BaseConverterTest, Initialize)
        {
            auto pool = MemoryManager::GetPool();

            // Good cases
            ASSERT_NO_THROW(BaseConverter bct(RNSBase({ 2 }, pool), RNSBase({ 2 }, pool), pool));
            ASSERT_NO_THROW(BaseConverter bct(RNSBase({ 2 }, pool), RNSBase({ 3 }, pool), pool));
            ASSERT_NO_THROW(BaseConverter bct(RNSBase({ 2, 3, 5 }, pool), RNSBase({ 2 }, pool), pool));
            ASSERT_NO_THROW(BaseConverter bct(RNSBase({ 2, 3, 5 }, pool), RNSBase({ 3, 5 }, pool), pool));
            ASSERT_NO_THROW(BaseConverter bct(RNSBase({ 2, 3, 5 }, pool), RNSBase({ 2, 3, 5, 7, 11 }, pool), pool));
            ASSERT_NO_THROW(BaseConverter bct(RNSBase({ 2, 3, 5 }, pool), RNSBase({ 7, 11 }, pool), pool));
        }

        TEST(BaseConverterTest, Convert)
        {
            auto pool = MemoryManager::GetPool();

            auto bct_test = [&](const BaseConverter &bct, const vector<uint64_t> &in, const vector<uint64_t> &out) {
                uint64_t in_array[3], out_array[3];
                copy(in.cbegin(), in.cend(), in_array);
                bct.fast_convert(in.data(), out_array, pool);
                for (size_t i = 0; i < out.size(); i++)
                {
                    ASSERT_EQ(out[i], out_array[i]);
                }
            };

            {
                BaseConverter bct(RNSBase({ 2 }, pool), RNSBase({ 2 }, pool), pool);
                bct_test(bct, { 0 }, { 0 });
                bct_test(bct, { 1 }, { 1 });
            }
            {
                BaseConverter bct(RNSBase({ 2 }, pool), RNSBase({ 3 }, pool), pool);
                bct_test(bct, { 0 }, { 0 });
                bct_test(bct, { 1 }, { 1 });
            }
            {
                BaseConverter bct(RNSBase({ 3 }, pool), RNSBase({ 2 }, pool), pool);
                bct_test(bct, { 0 }, { 0 });
                bct_test(bct, { 1 }, { 1 });
                bct_test(bct, { 2 }, { 0 });
            }
            {
                BaseConverter bct(RNSBase({ 2, 3 }, pool), RNSBase({ 2 }, pool), pool);
                bct_test(bct, { 0, 0 }, { 0 });
                bct_test(bct, { 1, 1 }, { 1 });
                bct_test(bct, { 0, 2 }, { 0 });
                bct_test(bct, { 1, 0 }, { 1 });
            }
            {
                BaseConverter bct(RNSBase({ 2, 3 }, pool), RNSBase({ 2, 3 }, pool), pool);
                bct_test(bct, { 0, 0 }, { 0, 0 });
                bct_test(bct, { 1, 1 }, { 1, 1 });
                bct_test(bct, { 1, 2 }, { 1, 2 });
                bct_test(bct, { 0, 2 }, { 0, 2 });
            }
            {
                BaseConverter bct(RNSBase({ 2, 3 }, pool), RNSBase({ 3, 4, 5 }, pool), pool);
                bct_test(bct, { 0, 0 }, { 0, 0, 0 });
                bct_test(bct, { 1, 1 }, { 1, 3, 2 });
                bct_test(bct, { 1, 2 }, { 2, 1, 0 });
            }
            {
                BaseConverter bct(RNSBase({ 3, 4, 5 }, pool), RNSBase({ 2, 3 }, pool), pool);
                bct_test(bct, { 0, 0, 0 }, { 0, 0 });
                bct_test(bct, { 1, 1, 1 }, { 1, 1 });
            }
        }

        TEST(BaseConverterTest, ConvertArray)
        {
            auto pool = MemoryManager::GetPool();

            auto bct_test = [&](const BaseConverter &bct, const vector<uint64_t> &in, const vector<uint64_t> &out) {
                uint64_t in_array[3 * 3], out_array[3 * 3];
                copy(in.cbegin(), in.cend(), in_array);
                bct.fast_convert_array(ConstRNSIter(in.data(), 3), RNSIter(out_array, 3), pool);
                for (size_t i = 0; i < out.size(); i++)
                {
                    ASSERT_EQ(out[i], out_array[i]);
                }
            };

            // In this test the input is an array of values in the first base and output
            // an array of values in the secnod base. Both input and output are stored in
            // array-major order, NOT modulus-major order.

            {
                BaseConverter bct(RNSBase({ 3 }, pool), RNSBase({ 2 }, pool), pool);
                bct_test(bct, { 0, 1, 2 }, { 0, 1, 0 });
            }
            {
                BaseConverter bct(RNSBase({ 2, 3 }, pool), RNSBase({ 2 }, pool), pool);
                bct_test(bct, { 0, 1, 0, 0, 1, 2 }, { 0, 1, 0 });
            }
            {
                BaseConverter bct(RNSBase({ 2, 3 }, pool), RNSBase({ 2, 3 }, pool), pool);
                bct_test(bct, { 1, 1, 0, 1, 2, 2 }, { 1, 1, 0, 1, 2, 2 });
            }
            {
                BaseConverter bct(RNSBase({ 2, 3 }, pool), RNSBase({ 3, 4, 5 }, pool), pool);
                bct_test(bct, { 0, 1, 1, 0, 1, 2 }, { 0, 1, 2, 0, 3, 1, 0, 2, 0 });
            }
        }

        namespace
        {
            // The integer in [0, prod(base)) with residues poly[i * n + c] for the elements of base, as size()
            // words
            vector<uint64_t> compose_coeff(const RNSBase &base, const uint64_t *poly, size_t n, size_t c)
            {
                vector<uint64_t> value(base.size());
                for (size_t i = 0; i < base.size(); i++)
                {
                    value[i] = poly[i * n + c];
                }
                base.compose(value.data(), MemoryManager::GetPool());
                return value;
            }

            // Residues modulo the elements of base of the signed multi-precision integer (-1)^negative * magnitude
            vector<uint64_t> decompose_signed(const RNSBase &base, const vector<uint64_t> &magnitude, bool negative)
            {
                vector<uint64_t> residues(base.size());
                for (size_t i = 0; i < base.size(); i++)
                {
                    uint64_t r = modulo_uint(magnitude.data(), magnitude.size(), base[i]);
                    residues[i] = negative ? negate_uint_mod(r, base[i]) : r;
                }
                return residues;
            }

            // Random values below q_i in component i, with 0 and q_i - 1 at the first two coefficients
            vector<uint64_t> random_rns_poly(const RNSBase &base, size_t n, mt19937_64 &rng)
            {
                vector<uint64_t> poly(base.size() * n);
                for (size_t i = 0; i < base.size(); i++)
                {
                    for (size_t c = 0; c < n; c++)
                    {
                        uint64_t q = base[i].value();
                        poly[i * n + c] = c == 0 ? 0 : (c == 1 ? q - 1 : rng() % q);
                    }
                }
                return poly;
            }
        } // namespace

        TEST(BaseConverterTest, ConvertArrayScaled)
        {
            // A scaled converter must give the same output as the unscaled converter applied to the input multiplied
            // by the input scaling factors, followed by multiplication by the output scaling factors.
            auto pool = MemoryManager::GetPool();
            mt19937_64 rng(4241);
            size_t count = 16;
            RNSBase ibase(CoeffModulus::Create(64, { 30, 40, 50, 60 }), pool);
            RNSBase obase(CoeffModulus::Create(64, { 31, 41, 51, 60, 59 }), pool);
            vector<uint64_t> ibase_scale{ 1, 12345, uint64_t(1) << 32, ibase[3].value() - 1 };
            vector<uint64_t> obase_scale{ 3, 1, uint64_t(1) << 40, obase[3].value() - 2, 1 };
            BaseConverter bct(ibase, obase, pool);
            BaseConverter bct_scaled(ibase, obase, ibase_scale, obase_scale, pool);

            vector<uint64_t> in(count * ibase.size()), in_scaled(count * ibase.size());
            vector<uint64_t> out(count * obase.size()), out_scaled(count * obase.size());
            for (size_t i = 0; i < ibase.size(); i++)
            {
                for (size_t k = 0; k < count; k++)
                {
                    // The scaled converter accepts any 64-bit input
                    uint64_t value = k == 0 ? ~uint64_t(0) : (k == 1 ? ibase[i].value() - 1 : rng());
                    in[i * count + k] = value;
                    in_scaled[i * count + k] = multiply_uint_mod(
                        barrett_reduce_64(value, ibase[i]), barrett_reduce_64(ibase_scale[i], ibase[i]), ibase[i]);
                }
            }
            bct.fast_convert_array(ConstRNSIter(in_scaled.data(), count), RNSIter(out.data(), count), pool);
            bct_scaled.fast_convert_array(ConstRNSIter(in.data(), count), RNSIter(out_scaled.data(), count), pool);
            for (size_t j = 0; j < obase.size(); j++)
            {
                for (size_t k = 0; k < count; k++)
                {
                    ASSERT_EQ(
                        multiply_uint_mod(out[j * count + k], barrett_reduce_64(obase_scale[j], obase[j]), obase[j]),
                        out_scaled[j * count + k]);
                }
            }

            // Scaling is not supported by exact conversion
            BaseConverter bct_exact(ibase, RNSBase({ obase[0] }, pool), ibase_scale, { 1 }, pool);
            vector<uint64_t> exact_out(count);
            ASSERT_THROW(
                bct_exact.exact_convert_array(ConstRNSIter(in.data(), count), CoeffIter(exact_out.data()), pool),
                logic_error);
            ASSERT_THROW(BaseConverter(ibase, obase, { 1 }, obase_scale, pool), invalid_argument);
        }

        // Compares fast_convert_array (blocked, Montgomery-reduced) with a straightforward reference implementation
        // (per-coefficient dot_product_mod) on random and edge-case inputs, for odd and even output moduli, small and
        // large bases (the latter forcing the input base to be split into several chunks), and coefficient counts
        // that are not multiples of the internal unrolling factors or block size. Also checks the allowed aliasing
        // of input and output.
        TEST(BaseConverterTest, ConvertArrayMatchesReference)
        {
            auto pool = MemoryManager::GetPool();
            mt19937_64 rng(4242);

            auto reference = [&](const RNSBase &ibase, const RNSBase &obase, const vector<uint64_t> &in, size_t count,
                                 const vector<uint64_t> &ibase_scale, const vector<uint64_t> &obase_scale) {
                size_t ibase_size = ibase.size();
                size_t obase_size = obase.size();
                vector<vector<uint64_t>> rows(obase_size, vector<uint64_t>(ibase_size));
                for (size_t j = 0; j < obase_size; j++)
                {
                    for (size_t i = 0; i < ibase_size; i++)
                    {
                        rows[j][i] = modulo_uint(ibase.punctured_prod_array() + i * ibase_size, ibase_size, obase[j]);
                    }
                }
                vector<uint64_t> out(obase_size * count);
                vector<uint64_t> temp(ibase_size);
                for (size_t c = 0; c < count; c++)
                {
                    for (size_t i = 0; i < ibase_size; i++)
                    {
                        MultiplyUIntModOperand ipp = ibase.inv_punctured_prod_mod_base_array()[i];
                        uint64_t x = in[i * count + c];
                        if (!ibase_scale.empty())
                        {
                            // [x * a_i]_{q_i}, then the usual first step
                            x = multiply_uint_mod(x, barrett_reduce_64(ibase_scale[i], ibase[i]), ibase[i]);
                        }
                        temp[i] =
                            (ipp.operand == 1) ? barrett_reduce_64(x, ibase[i]) : multiply_uint_mod(x, ipp, ibase[i]);
                    }
                    for (size_t j = 0; j < obase_size; j++)
                    {
                        out[j * count + c] = dot_product_mod(temp.data(), rows[j].data(), ibase_size, obase[j]);
                        if (!obase_scale.empty())
                        {
                            out[j * count + c] = multiply_uint_mod(
                                out[j * count + c], barrett_reduce_64(obase_scale[j], obase[j]), obase[j]);
                        }
                    }
                }
                return out;
            };

            auto run = [&](const vector<Modulus> &ibase_mods, const vector<Modulus> &obase_mods, bool scaled) {
                RNSBase ibase(ibase_mods, pool);
                RNSBase obase(obase_mods, pool);
                vector<uint64_t> ibase_scale, obase_scale;
                if (scaled)
                {
                    // Arbitrary 64-bit factors (including 0 and 1), reduced by the converter
                    for (size_t i = 0; i < ibase.size(); i++)
                    {
                        ibase_scale.push_back(i == 0 ? 1 : (i == 1 ? 0 : rng()));
                    }
                    for (size_t j = 0; j < obase.size(); j++)
                    {
                        obase_scale.push_back(j == 0 ? uint64_t(1) << 32 : rng());
                    }
                }
                Pointer<BaseConverter> bct_ptr =
                    scaled ? allocate<BaseConverter>(pool, ibase, obase, ibase_scale, obase_scale, pool)
                           : allocate<BaseConverter>(pool, ibase, obase, pool);
                const BaseConverter &bct = *bct_ptr;
                const vector<size_t> counts{ 1, 2, 3, 4, 5, 7, 8, 9, 15, 16, 17, 255, 256, 257, 511, 512, 513, 1027 };
                for (size_t count : counts)
                {
                    for (int pattern = 0; pattern < 5; pattern++)
                    {
                        vector<uint64_t> in(ibase.size() * count);
                        for (size_t i = 0; i < ibase.size(); i++)
                        {
                            uint64_t q = ibase[i].value();
                            for (size_t c = 0; c < count; c++)
                            {
                                uint64_t &x = in[i * count + c];
                                switch (pattern)
                                {
                                case 0:
                                    x = 0;
                                    break;
                                case 1:
                                    x = q - 1;
                                    break;
                                case 2:
                                    x = (c & 1) ? q - 1 : 0;
                                    break;
                                case 3:
                                    // Unreduced input; fast_convert_array reduces any 64-bit input
                                    x = rng();
                                    break;
                                default:
                                    x = rng() % q;
                                    break;
                                }
                            }
                        }
                        vector<uint64_t> ref = reference(ibase, obase, in, count, ibase_scale, obase_scale);
                        vector<uint64_t> out(obase.size() * count, 0xDEADBEEF);
                        bct.fast_convert_array(ConstRNSIter(in.data(), count), RNSIter(out.data(), count), pool);
                        ASSERT_EQ(ref, out) << "ibase size " << ibase.size() << ", obase size " << obase.size()
                                            << ", count " << count << ", pattern " << pattern << ", scaled " << scaled;

                        // in and out may overlap at equal coefficient indices: identical, or shifted by one component
                        size_t size = max(ibase.size(), obase.size()) + 1;
                        for (size_t shift : { size_t(0), size_t(1) })
                        {
                            vector<uint64_t> buffer(size * count);
                            copy(in.begin(), in.end(), buffer.data() + shift * count);
                            bct.fast_convert_array(
                                ConstRNSIter(buffer.data() + shift * count, count), RNSIter(buffer.data(), count),
                                pool);
                            ASSERT_TRUE(equal(ref.begin(), ref.end(), buffer.begin())) << "shift " << shift;
                        }
                    }
                }
            };

            // Typical BFV shapes: q of 36..60-bit primes to Bsk of 61-bit primes and back, plus even m_tilde
            auto q = get_primes(uint64_t(1) << 15, 50, 5);
            auto q60 = get_primes(uint64_t(1) << 15, 60, 3);
            q.insert(q.end(), q60.begin(), q60.end());
            auto bsk = get_primes(uint64_t(1) << 15, 61, 9);
            run(q, bsk, false);
            run(q, bsk, true);
            run(bsk, q, false);
            run(bsk, q, true);
            run(q, { Modulus(uint64_t(1) << 32) }, false);
            run(q, { Modulus(uint64_t(1) << 32) }, true);
            run(q, { Modulus(65537), Modulus(uint64_t(1) << 20), Modulus(3), bsk[0] }, false);
            run(q, { Modulus(65537), Modulus(uint64_t(1) << 20), Modulus(3), bsk[0] }, true);

            // Many 61-bit input primes: the sum of the input moduli exceeds 2^64, so the input base is split
            auto big = get_primes(uint64_t(1) << 15, 61, 20);
            run(big, { bsk[0], q[0], Modulus(uint64_t(1) << 32), Modulus(17) }, false);
            run(big, { bsk[0], q[0], Modulus(uint64_t(1) << 32), Modulus(17) }, true);

            // Single input modulus (inv_punctured_prod == 1) and tiny moduli
            run({ bsk[1] }, { bsk[0], q[0] }, false);
            run({ bsk[1] }, { bsk[0], q[0] }, true);
            run({ Modulus(2), Modulus(3), Modulus(5) }, { Modulus(7), Modulus(8), Modulus(11) }, false);
            run({ Modulus(2), Modulus(3), Modulus(5) }, { Modulus(7), Modulus(8), Modulus(11) }, true);
        }

        // exact_convert_array computes the centered representative of the input modulo prod(ibase), reduced modulo
        // the output modulus
        TEST(BaseConverterTest, ExactConvertArray)
        {
            auto pool = MemoryManager::GetPool();
            mt19937_64 rng(4243);
            auto q = get_primes(uint64_t(1) << 15, 50, 5);
            auto big = get_primes(uint64_t(1) << 15, 61, 20);
            for (auto ibase_mods : { vector<Modulus>{ q[0] }, q, big })
            {
                RNSBase ibase(ibase_mods, pool);
                for (const Modulus &p : { Modulus(65537), Modulus(uint64_t(1) << 20), Modulus(2), big[0] })
                {
                    BaseConverter bct(ibase, RNSBase({ p }, pool), pool);
                    uint64_t q_mod_p = modulo_uint(ibase.base_prod(), ibase.size(), p);
                    for (size_t count : { size_t(1), size_t(2), size_t(511), size_t(512), size_t(513), size_t(1027) })
                    {
                        vector<uint64_t> in = random_rns_poly(ibase, count, rng), out(count);
                        bct.exact_convert_array(ConstRNSIter(in.data(), count), CoeffIter(out.data()), pool);
                        for (size_t c = 0; c < count; c++)
                        {
                            vector<uint64_t> x = compose_coeff(ibase, in.data(), count, c);
                            uint64_t expected = modulo_uint(x.data(), x.size(), p);

                            // x - q if x > q / 2
                            vector<uint64_t> twice_x(x.size() + 1), q_wide(x.size() + 1);
                            left_shift_uint(x.data(), 1, x.size(), twice_x.data());
                            twice_x.back() = x.back() >> 63;
                            copy_n(ibase.base_prod(), ibase.size(), q_wide.begin());
                            if (is_greater_than_uint(twice_x.data(), q_wide.data(), twice_x.size()))
                            {
                                expected = sub_uint_mod(expected, q_mod_p, p);
                            }
                            ASSERT_EQ(expected, out[c]) << "count " << count << ", c " << c;
                        }
                    }
                }
            }
        }

        TEST(RNSToolTest, Initialize)
        {
            auto pool = MemoryManager::GetPool();

            size_t poly_modulus_degree = 32;
            size_t coeff_base_count = 4;
            int prime_bit_count = 20;

            Modulus plain_t = 65537;
            RNSBase coeff_base(get_primes(poly_modulus_degree * 2, prime_bit_count, coeff_base_count), pool);

            ASSERT_NO_THROW(RNSTool rns_tool(poly_modulus_degree, coeff_base, plain_t, pool));

            // Succeeds with 0 plain_modulus (case of CKKS)
            ASSERT_NO_THROW(RNSTool rns_tool(poly_modulus_degree, coeff_base, 0, pool));

            // Fails when poly_modulus_degree is too small
            ASSERT_THROW(RNSTool rns_tool(1, coeff_base, plain_t, pool), invalid_argument);
        }

        TEST(RNSToolTest, FastBConvMTilde)
        {
            // This function multiplies an input array with m_tilde (modulo q-base) and subsequently
            // performs base conversion to Bsk U {m_tilde}.

            Modulus plain_t = 0;
            auto pool = MemoryManager::GetPool();
            Pointer<RNSTool> rns_tool;
            {
                size_t poly_modulus_degree = 2;
                ASSERT_NO_THROW(
                    rns_tool = allocate<RNSTool>(pool, poly_modulus_degree, RNSBase({ 3 }, pool), plain_t, pool));

                vector<uint64_t> in(poly_modulus_degree * rns_tool->base_q()->size());
                vector<uint64_t> out(poly_modulus_degree * rns_tool->base_Bsk_m_tilde()->size());
                set_zero_uint(in.size(), in.data());
                ConstRNSIter in_iter(in.data(), poly_modulus_degree);
                RNSIter out_iter(out.data(), poly_modulus_degree);
                rns_tool->fastbconv_m_tilde(in_iter, out_iter, pool);
                for (auto val : out)
                {
                    ASSERT_EQ(0, val);
                }

                in[0] = 1;
                in[1] = 2;
                rns_tool->fastbconv_m_tilde(in_iter, out_iter, pool);

                // These are results for fase base conversion for a length-2 array ((m_tilde), (2*m_tilde))
                // before reduction to target base.
                uint64_t temp = rns_tool->m_tilde().value() % 3;
                uint64_t temp2 = (2 * rns_tool->m_tilde().value()) % 3;

                ASSERT_EQ(temp % (*rns_tool->base_Bsk_m_tilde())[0].value(), out[0]);
                ASSERT_EQ(temp2 % (*rns_tool->base_Bsk_m_tilde())[0].value(), out[1]);
                ASSERT_EQ(temp % (*rns_tool->base_Bsk_m_tilde())[1].value(), out[2]);
                ASSERT_EQ(temp2 % (*rns_tool->base_Bsk_m_tilde())[1].value(), out[3]);
                ASSERT_EQ(temp % (*rns_tool->base_Bsk_m_tilde())[2].value(), out[4]);
                ASSERT_EQ(temp2 % (*rns_tool->base_Bsk_m_tilde())[2].value(), out[5]);
            }
            {
                size_t poly_modulus_degree = 2;
                size_t coeff_modulus_size = 2;
                ASSERT_NO_THROW(
                    rns_tool = allocate<RNSTool>(pool, poly_modulus_degree, RNSBase({ 3, 5 }, pool), plain_t, pool));

                vector<uint64_t> in(poly_modulus_degree * coeff_modulus_size);
                vector<uint64_t> out(poly_modulus_degree * rns_tool->base_Bsk_m_tilde()->size());
                set_zero_uint(in.size(), in.data());
                ConstRNSIter in_iter(in.data(), poly_modulus_degree);
                RNSIter out_iter(out.data(), poly_modulus_degree);
                rns_tool->fastbconv_m_tilde(in_iter, out_iter, pool);
                for (auto val : out)
                {
                    ASSERT_EQ(0, val);
                }

                in[0] = 1;
                in[1] = 1;
                in[2] = 2;
                in[3] = 2;
                rns_tool->fastbconv_m_tilde(in_iter, out_iter, pool);
                uint64_t m_tilde = rns_tool->m_tilde().value();

                // This is the result of fast base conversion for a length-2 array
                // ((m_tilde, 2*m_tilde), (m_tilde, 2*m_tilde)) before reduction to target base.
                uint64_t temp = ((2 * m_tilde) % 3) * 5 + ((4 * m_tilde) % 5) * 3;

                for (size_t j = 0; j < rns_tool->base_Bsk_m_tilde()->size(); j++)
                {
                    ASSERT_EQ(temp % (*rns_tool->base_Bsk_m_tilde())[j].value(), out[2 * j]);
                    ASSERT_EQ(temp % (*rns_tool->base_Bsk_m_tilde())[j].value(), out[2 * j + 1]);
                }
            }
        }

        TEST(RNSToolTest, MontgomeryReduction)
        {
            // This function assumes the input is in base Bsk U {m_tilde}. If the input is
            // |[c*m_tilde]_q + qu|_m for m in Bsk U {m_tilde}, then the output is c' in Bsk
            // such that c' = c mod q. In other words, this function cancels the extra multiples
            // of q in the Bsk U {m_tilde} representation. The functions works correctly for
            // sufficiently small values of u.

            Modulus plain_t = 0;
            auto pool = MemoryManager::GetPool();
            Pointer<RNSTool> rns_tool;
            {
                size_t poly_modulus_degree = 2;
                ASSERT_NO_THROW(
                    rns_tool = allocate<RNSTool>(pool, poly_modulus_degree, RNSBase({ 3 }, pool), plain_t, pool));

                vector<uint64_t> in(poly_modulus_degree * rns_tool->base_Bsk_m_tilde()->size());
                vector<uint64_t> out(poly_modulus_degree * rns_tool->base_Bsk()->size());
                set_zero_uint(in.size(), in.data());
                ConstRNSIter in_iter(in.data(), poly_modulus_degree);
                RNSIter out_iter(out.data(), poly_modulus_degree);
                rns_tool->sm_mrq(in_iter, out_iter, pool);
                for (auto val : out)
                {
                    ASSERT_EQ(0, val);
                }

                // Input base is Bsk U {m_tilde}, in this case consisting of 3 primes.
                // m_tilde is always smaller than the primes in Bsk (SEAL_INTERNAL_MOD_BIT_COUNT (61) bits).
                // Set the length-2 array to have values 1*m_tilde and 2*m_tilde.
                in[0] = rns_tool->m_tilde().value();
                in[1] = 2 * rns_tool->m_tilde().value();
                in[2] = rns_tool->m_tilde().value();
                in[3] = 2 * rns_tool->m_tilde().value();

                // Modulo m_tilde
                in[4] = 0;
                in[5] = 0;

                // This should simply get rid of the m_tilde factor
                rns_tool->sm_mrq(in_iter, out_iter, pool);

                ASSERT_EQ(1, out[0]);
                ASSERT_EQ(2, out[1]);
                ASSERT_EQ(1, out[2]);
                ASSERT_EQ(2, out[3]);

                // Next add a multiple of q to the input and see if it is reduced properly
                in[0] = (*rns_tool->base_q())[0].value();
                in[1] = (*rns_tool->base_q())[0].value();
                in[2] = (*rns_tool->base_q())[0].value();
                in[3] = (*rns_tool->base_q())[0].value();
                in[4] = (*rns_tool->base_q())[0].value();
                in[5] = (*rns_tool->base_q())[0].value();

                rns_tool->sm_mrq(in_iter, out_iter, pool);
                for (auto val : out)
                {
                    ASSERT_EQ(0, val);
                }
            }
            {
                size_t poly_modulus_degree = 2;
                ASSERT_NO_THROW(
                    rns_tool = allocate<RNSTool>(pool, poly_modulus_degree, RNSBase({ 3, 5 }, pool), plain_t, pool));

                vector<uint64_t> in(poly_modulus_degree * rns_tool->base_Bsk_m_tilde()->size());
                vector<uint64_t> out(poly_modulus_degree * rns_tool->base_Bsk()->size());
                set_zero_uint(in.size(), in.data());
                ConstRNSIter in_iter(in.data(), poly_modulus_degree);
                RNSIter out_iter(out.data(), poly_modulus_degree);
                rns_tool->sm_mrq(in_iter, out_iter, pool);
                for (auto val : out)
                {
                    ASSERT_EQ(0, val);
                }

                // Input base is Bsk U {m_tilde}, with m_tilde as the last element.
                // m_tilde is always smaller than the primes in Bsk (SEAL_INTERNAL_MOD_BIT_COUNT (61) bits).
                // Set the length-2 array to have values 1*m_tilde and 2*m_tilde.
                size_t base_Bsk_size = rns_tool->base_Bsk()->size();
                for (size_t j = 0; j < base_Bsk_size; j++)
                {
                    in[2 * j] = rns_tool->m_tilde().value();
                    in[2 * j + 1] = 2 * rns_tool->m_tilde().value();
                }

                // Modulo m_tilde
                in[2 * base_Bsk_size] = 0;
                in[2 * base_Bsk_size + 1] = 0;

                // This should simply get rid of the m_tilde factor
                rns_tool->sm_mrq(in_iter, out_iter, pool);

                for (size_t j = 0; j < base_Bsk_size; j++)
                {
                    ASSERT_EQ(1, out[2 * j]);
                    ASSERT_EQ(2, out[2 * j + 1]);
                }

                // Next add a multiple of q to the input and see if it is reduced properly
                for (size_t j = 0; j <= base_Bsk_size; j++)
                {
                    in[2 * j] = 15;
                    in[2 * j + 1] = 30;
                }

                rns_tool->sm_mrq(in_iter, out_iter, pool);
                for (auto val : out)
                {
                    ASSERT_EQ(0, val);
                }

                // Now with a multiple of m_tilde + multiple of q
                for (size_t j = 0; j <= base_Bsk_size; j++)
                {
                    in[2 * j] = 2 * rns_tool->m_tilde().value() + 15;
                    in[2 * j + 1] = 2 * rns_tool->m_tilde().value() + 30;
                }

                rns_tool->sm_mrq(in_iter, out_iter, pool);
                for (auto val : out)
                {
                    ASSERT_EQ(2, val);
                }
            }
        }

        TEST(RNSToolTest, FastFloor)
        {
            // This function assumes the input is in base q U Bsk. It outputs an approximation of
            // the value divided by q floored in base Bsk. The approximation has absolute value up
            // to k-1, where k is the number of primes in the base q.

            Modulus plain_t = 0;
            auto pool = MemoryManager::GetPool();
            Pointer<RNSTool> rns_tool;
            {
                size_t poly_modulus_degree = 2;
                ASSERT_NO_THROW(
                    rns_tool = allocate<RNSTool>(pool, poly_modulus_degree, RNSBase({ 3 }, pool), plain_t, pool));

                vector<uint64_t> in(poly_modulus_degree * (rns_tool->base_Bsk()->size() + rns_tool->base_q()->size()));
                vector<uint64_t> out(poly_modulus_degree * rns_tool->base_Bsk()->size());
                set_zero_uint(in.size(), in.data());
                ConstRNSIter in_iter(in.data(), poly_modulus_degree);
                RNSIter out_iter(out.data(), poly_modulus_degree);
                rns_tool->fast_floor(in_iter, out_iter, pool);
                for (auto val : out)
                {
                    ASSERT_EQ(0, val);
                }

                // The size of q U Bsk is 3. We set the input to have values 15 and 5, and divide by 3 (i.e., q).
                in[0] = 15;
                in[1] = 3;
                in[2] = 15;
                in[3] = 3;
                in[4] = 15;
                in[5] = 3;

                // We get an exact result in this case since input base only has size 1
                rns_tool->fast_floor(in_iter, out_iter, pool);
                ASSERT_EQ(5ULL, out[0]);
                ASSERT_EQ(1ULL, out[1]);
                ASSERT_EQ(5ULL, out[2]);
                ASSERT_EQ(1ULL, out[3]);

                // Now a case where the floor really shows up
                in[0] = 17;
                in[1] = 4;
                in[2] = 17;
                in[3] = 4;
                in[4] = 17;
                in[5] = 4;

                // We get an exact result in this case since input base only has size 1
                rns_tool->fast_floor(in_iter, out_iter, pool);
                ASSERT_EQ(5ULL, out[0]);
                ASSERT_EQ(1ULL, out[1]);
                ASSERT_EQ(5ULL, out[2]);
                ASSERT_EQ(1ULL, out[3]);
            }
            {
                size_t poly_modulus_degree = 2;
                ASSERT_NO_THROW(
                    rns_tool = allocate<RNSTool>(pool, poly_modulus_degree, RNSBase({ 3, 5 }, pool), plain_t, pool));

                vector<uint64_t> in(poly_modulus_degree * (rns_tool->base_Bsk()->size() + rns_tool->base_q()->size()));
                vector<uint64_t> out(poly_modulus_degree * rns_tool->base_Bsk()->size());
                set_zero_uint(in.size(), in.data());
                ConstRNSIter in_iter(in.data(), poly_modulus_degree);
                RNSIter out_iter(out.data(), poly_modulus_degree);
                rns_tool->fast_floor(in_iter, out_iter, pool);
                for (auto val : out)
                {
                    ASSERT_EQ(0, val);
                }

                // The input base is q U Bsk. We set the input to multiples of 15 an divide by 15 (i.e., q).
                size_t in_base_size = rns_tool->base_q()->size() + rns_tool->base_Bsk()->size();
                for (size_t j = 0; j < in_base_size; j++)
                {
                    in[2 * j] = 15;
                    in[2 * j + 1] = 30;
                }

                // We get an exact result in this case
                rns_tool->fast_floor(in_iter, out_iter, pool);
                for (size_t j = 0; j < rns_tool->base_Bsk()->size(); j++)
                {
                    ASSERT_EQ(1ULL, out[2 * j]);
                    ASSERT_EQ(2ULL, out[2 * j + 1]);
                }

                // Now a case where the floor really shows up
                for (size_t j = 0; j < in_base_size; j++)
                {
                    in[2 * j] = 21;
                    in[2 * j + 1] = 32;
                }

                // The result is not exact but differs at most by 1
                rns_tool->fast_floor(in_iter, out_iter, pool);
                for (size_t j = 0; j < rns_tool->base_Bsk()->size(); j++)
                {
                    ASSERT_TRUE(fabs(1ULL - out[2 * j]) <= 1);
                    ASSERT_TRUE(fabs(2ULL - out[2 * j + 1]) <= 1);
                }
            }
        }

        TEST(RNSToolTest, FastBConvSK)
        {
            // This function assumes the input is in base Bsk and outputs a fast base conversion
            // with Shenoy-Kumaresan correction to base q. The conversion is exact.

            Modulus plain_t = 0;
            auto pool = MemoryManager::GetPool();
            Pointer<RNSTool> rns_tool;
            {
                size_t poly_modulus_degree = 2;
                ASSERT_NO_THROW(
                    rns_tool = allocate<RNSTool>(pool, poly_modulus_degree, RNSBase({ 3 }, pool), plain_t, pool));

                vector<uint64_t> in(poly_modulus_degree * rns_tool->base_Bsk()->size());
                vector<uint64_t> out(poly_modulus_degree * rns_tool->base_q()->size());
                set_zero_uint(in.size(), in.data());
                ConstRNSIter in_iter(in.data(), poly_modulus_degree);
                RNSIter out_iter(out.data(), poly_modulus_degree);
                rns_tool->fastbconv_sk(in_iter, out_iter, pool);
                for (auto val : out)
                {
                    ASSERT_EQ(0, val);
                }

                // The size of Bsk is 2
                in[0] = 1;
                in[1] = 2;
                in[2] = 1;
                in[3] = 2;

                rns_tool->fastbconv_sk(in_iter, out_iter, pool);
                ASSERT_EQ(1ULL, out[0]);
                ASSERT_EQ(2ULL, out[1]);
            }
            {
                size_t poly_modulus_degree = 2;
                ASSERT_NO_THROW(
                    rns_tool = allocate<RNSTool>(pool, poly_modulus_degree, RNSBase({ 3, 5 }, pool), plain_t, pool));

                vector<uint64_t> in(poly_modulus_degree * rns_tool->base_Bsk()->size());
                vector<uint64_t> out(poly_modulus_degree * rns_tool->base_q()->size());
                set_zero_uint(in.size(), in.data());
                ConstRNSIter in_iter(in.data(), poly_modulus_degree);
                RNSIter out_iter(out.data(), poly_modulus_degree);
                rns_tool->fastbconv_sk(in_iter, out_iter, pool);
                for (auto val : out)
                {
                    ASSERT_EQ(0, val);
                }

                for (size_t j = 0; j < rns_tool->base_Bsk()->size(); j++)
                {
                    in[2 * j] = 1;
                    in[2 * j + 1] = 2;
                }

                rns_tool->fastbconv_sk(in_iter, out_iter, pool);
                ASSERT_EQ(1ULL, out[0]);
                ASSERT_EQ(2ULL, out[1]);
                ASSERT_EQ(1ULL, out[2]);
                ASSERT_EQ(2ULL, out[3]);
            }
        }

        // The fused functions used by BFV multiplication must give the same results as the steps they replace, for
        // any input: fastbconv_m_tilde_sm_mrq as sm_mrq after fastbconv_m_tilde (up to the lazy output range), and
        // inverse_ntt_multiply_t_fast_floor_fastbconv_sk as the inverse NTT, multiplication by t, fast_floor, and
        // fastbconv_sk (for input in standard or Montgomery form)
        TEST(RNSToolTest, FusedBEHZSteps)
        {
            auto pool = MemoryManager::GetPool();
            mt19937_64 rng(2024);

            // n = 1024 exceeds the block size of the fused functions; 20 primes of 60 bits make the base conversions
            // from q split q into chunks
            for (size_t n : { size_t(2), size_t(64), size_t(1024) })
            {
                for (auto bit_sizes : { vector<int>{ 30 }, vector<int>{ 40, 50 }, vector<int>{ 60, 60, 60, 59, 58 },
                                        vector<int>(20, 60) })
                {
                    RNSBase q(CoeffModulus::Create(n, bit_sizes), pool);
                    for (const Modulus &t : { Modulus(65537), Modulus(uint64_t(1) << 20), get_prime(2 * n, 57) })
                    {
                        RNSTool rns_tool(n, q, t, pool);
                        size_t q_size = q.size();
                        size_t Bsk_size = rns_tool.base_Bsk()->size();
                        const RNSBase &Bsk = *rns_tool.base_Bsk();

                        // Steps (1)-(2), for any 64-bit input
                        vector<uint64_t> in_q(q_size * n);
                        for (size_t i = 0; i < q_size; i++)
                        {
                            for (size_t k = 0; k < n; k++)
                            {
                                in_q[i * n + k] =
                                    k % 3 == 0 ? q[i].value() - 1 : (k % 3 == 1 ? rng() : rng() % q[i].value());
                            }
                        }
                        vector<uint64_t> temp((Bsk_size + 1) * n), expected(Bsk_size * n), result(Bsk_size * n);
                        rns_tool.fastbconv_m_tilde(ConstRNSIter(in_q.data(), n), RNSIter(temp.data(), n), pool);
                        rns_tool.sm_mrq(ConstRNSIter(temp.data(), n), RNSIter(expected.data(), n), pool);
                        rns_tool.fastbconv_m_tilde_sm_mrq(
                            ConstRNSIter(in_q.data(), n), false, RNSIter(result.data(), n), pool);
                        ASSERT_EQ(expected, result);
                        rns_tool.fastbconv_m_tilde_sm_mrq(
                            ConstRNSIter(in_q.data(), n), true, RNSIter(result.data(), n), pool);
                        for (size_t j = 0; j < Bsk_size; j++)
                        {
                            for (size_t k = 0; k < n; k++)
                            {
                                uint64_t value = result[j * n + k];
                                ASSERT_LT(value, 3 * Bsk[j].value());
                                ASSERT_EQ(expected[j * n + k], value % Bsk[j].value());
                            }
                        }

                        // Steps (5)-(8), for NTT-form input in base q U Bsk in [0, 2m)
                        Pointer<NTTTables> q_ntt_tables;
                        CreateNTTTables(
                            get_power_of_two(n), vector<Modulus>(q.base(), q.base() + q_size), q_ntt_tables, pool);
                        for (bool montgomery : { false, true })
                        {
                            vector<uint64_t> in((q_size + Bsk_size) * n), ref_in((q_size + Bsk_size) * n);
                            for (size_t i = 0; i < q_size + Bsk_size; i++)
                            {
                                const Modulus &m = i < q_size ? q[i] : Bsk[i - q_size];
                                const NTTTables &tables =
                                    i < q_size ? q_ntt_tables[i] : rns_tool.base_Bsk_ntt_tables()[i - q_size];
                                for (size_t k = 0; k < n; k++)
                                {
                                    in[i * n + k] = k == 0 ? 2 * m.value() - 1 : rng() % (2 * m.value());
                                }

                                // The input holds c * 2^(-64) mod m in Montgomery form
                                CoeffIter x(ref_in.data() + i * n);
                                copy_n(in.data() + i * n, n, ref_in.data() + i * n);
                                if (montgomery)
                                {
                                    multiply_poly_scalar_coeffmod(x, n, two_pow_64_mod(m), m, x);
                                }
                                inverse_ntt_negacyclic_harvey(x, tables);
                                multiply_poly_scalar_coeffmod(x, n, t.value(), m, x);
                            }
                            vector<uint64_t> floor_Bsk(Bsk_size * n), expected_q(q_size * n), result_q(q_size * n);
                            rns_tool.fast_floor(ConstRNSIter(ref_in.data(), n), RNSIter(floor_Bsk.data(), n), pool);
                            rns_tool.fastbconv_sk(
                                ConstRNSIter(floor_Bsk.data(), n), RNSIter(expected_q.data(), n), pool);
                            rns_tool.inverse_ntt_multiply_t_fast_floor_fastbconv_sk(
                                RNSIter(in.data(), n), RNSIter(in.data() + q_size * n, n), q_ntt_tables.get(),
                                montgomery, RNSIter(result_q.data(), n), pool);
                            ASSERT_EQ(expected_q, result_q) << "n " << n << ", q size " << q_size << ", t " << t.value()
                                                            << ", montgomery " << montgomery;
                        }
                    }
                }
            }
        }

        TEST(RNSToolTest, ExactScaleAndRound)
        {
            // This function computes [round(t/q * |input|_q)]_t exactly using the gamma-correction technique.

            auto pool = MemoryManager::GetPool();
            Pointer<RNSTool> rns_tool;
            size_t poly_modulus_degree = 2;
            Modulus plain_t = 3;
            ASSERT_NO_THROW(
                rns_tool = allocate<RNSTool>(pool, poly_modulus_degree, RNSBase({ 5, 7 }, pool), plain_t, pool));

            vector<uint64_t> in(poly_modulus_degree * rns_tool->base_Bsk()->size());
            vector<uint64_t> out(poly_modulus_degree * rns_tool->base_q()->size());
            set_zero_uint(in.size(), in.data());
            ConstRNSIter in_iter(in.data(), poly_modulus_degree);
            CoeffIter out_iter(out.data());
            rns_tool->decrypt_scale_and_round(in_iter, out_iter, pool);
            for (auto val : out)
            {
                ASSERT_EQ(0, val);
            }

            // The size of Bsk is 2. Both values here are multiples of 35 (i.e., q).
            // Skip tests exceeding input bound when using HEXL in DEBUG mode
#if !defined(SEAL_DEBUG) || !defined(SEAL_USE_INTEL_HEXL)
            in[0] = 35;
            in[1] = 70;
            in[2] = 35;
            in[3] = 70;

            // We expect to get a zero output in this case
            rns_tool->decrypt_scale_and_round(in_iter, out_iter, pool);
            ASSERT_EQ(0ULL, out[0]);
            ASSERT_EQ(0ULL, out[1]);

            // Now try a non-trivial case
            in[0] = 29;
            in[1] = 30 + 35;
            in[2] = 29;
            in[3] = 30 + 35;

            // Here 29 will scale and round to 2 and 30 will scale and round to 0.
            // The added 35 should not make a difference.
            rns_tool->decrypt_scale_and_round(in_iter, out_iter, pool);
            ASSERT_EQ(2ULL, out[0]);
            ASSERT_EQ(0ULL, out[1]);
#endif
        }

        TEST(RNSToolTest, DivideAndRoundQLastInplace)
        {
            // This function approximately divides the input values by the last prime in the base q.
            // Input is in base q; the last RNS component becomes invalid.

            auto pool = MemoryManager::GetPool();
            Pointer<RNSTool> rns_tool;
            {
                size_t poly_modulus_degree = 2;
                Modulus plain_t = 0;
                ASSERT_NO_THROW(
                    rns_tool = allocate<RNSTool>(pool, poly_modulus_degree, RNSBase({ 13, 7 }, pool), plain_t, pool));

                vector<uint64_t> in(poly_modulus_degree * rns_tool->base_q()->size());
                set_zero_uint(in.size(), in.data());
                RNSIter in_iter(in.data(), poly_modulus_degree);
                rns_tool->divide_and_round_q_last_inplace(in_iter, pool);
                ASSERT_EQ(0ULL, in[0]);
                ASSERT_EQ(0ULL, in[1]);

                // The size of q is 2. We set some values here and divide by the last modulus (i.e., 7).
                in[0] = 1;
                in[1] = 2;
                in[2] = 1;
                in[3] = 2;

                // We expect to get a zero output also in this case
                rns_tool->divide_and_round_q_last_inplace(in_iter, pool);
                ASSERT_EQ(0ULL, in[0]);
                ASSERT_EQ(0ULL, in[1]);

                // Next a case with non-trivial rounding
                in[0] = 12;
                in[1] = 11;
                in[2] = 4;
                in[3] = 3;

                rns_tool->divide_and_round_q_last_inplace(in_iter, pool);
                ASSERT_EQ(4ULL, in[0]);
                ASSERT_EQ(3ULL, in[1]);

                // Input array (19, 15)
                in[0] = 6;
                in[1] = 2;
                in[2] = 5;
                in[3] = 1;

                rns_tool->divide_and_round_q_last_inplace(in_iter, pool);
                ASSERT_EQ(3ULL, in[0]);
                ASSERT_EQ(2ULL, in[1]);
            }
            {
                size_t poly_modulus_degree = 2;
                Modulus plain_t = 0;
                ASSERT_NO_THROW(
                    rns_tool =
                        allocate<RNSTool>(pool, poly_modulus_degree, RNSBase({ 3, 5, 7, 11 }, pool), plain_t, pool));

                vector<uint64_t> in(poly_modulus_degree * rns_tool->base_q()->size());
                set_zero_uint(in.size(), in.data());
                RNSIter in_iter(in.data(), poly_modulus_degree);
                rns_tool->divide_and_round_q_last_inplace(in_iter, pool);
                ASSERT_EQ(0ULL, in[0]);
                ASSERT_EQ(0ULL, in[1]);
                ASSERT_EQ(0ULL, in[2]);
                ASSERT_EQ(0ULL, in[3]);
                ASSERT_EQ(0ULL, in[4]);
                ASSERT_EQ(0ULL, in[5]);

                // The size of q is 4. We set some values here and divide by the last modulus (i.e., 11).
                in[0] = 1;
                in[1] = 2;
                in[2] = 1;
                in[3] = 2;
                in[4] = 1;
                in[5] = 2;
                in[6] = 1;
                in[7] = 2;

                // We expect to get a zero output also in this case
                rns_tool->divide_and_round_q_last_inplace(in_iter, pool);
                ASSERT_EQ(0ULL, in[0]);
                ASSERT_EQ(0ULL, in[1]);
                ASSERT_EQ(0ULL, in[2]);
                ASSERT_EQ(0ULL, in[3]);
                ASSERT_EQ(0ULL, in[4]);
                ASSERT_EQ(0ULL, in[5]);

                // Next a case with non-trivial rounding; array is (60, 70)
                in[0] = 0;
                in[1] = 1;
                in[2] = 0;
                in[3] = 0;
                in[4] = 4;
                in[5] = 0;
                in[6] = 5;
                in[7] = 4;

                // We get only approximate result in this case
                rns_tool->divide_and_round_q_last_inplace(in_iter, pool);
                ASSERT_TRUE((3ULL + 2ULL - in[0]) % 3ULL <= 1);
                ASSERT_TRUE((3ULL + 0ULL - in[1]) % 3ULL <= 1);
                ASSERT_TRUE((5ULL + 0ULL - in[2]) % 5ULL <= 1);
                ASSERT_TRUE((5ULL + 1ULL - in[3]) % 5ULL <= 1);
                ASSERT_TRUE((7ULL + 5ULL - in[4]) % 7ULL <= 1);
                ASSERT_TRUE((7ULL + 6ULL - in[5]) % 7ULL <= 1);
            }
        }

        TEST(RNSToolTest, DivideAndRoundQLastNTTInplace)
        {
            // This function approximately divides the input values by the last prime in the base q.
            // The input and output are both in NTT form. Input is in base q; the last RNS component
            // becomes invalid.

            auto pool = MemoryManager::GetPool();
            Pointer<RNSTool> rns_tool;
            size_t poly_modulus_degree = 2;
            NTTTables ntt[]{ { 1, Modulus(53) }, { 1, Modulus(13) } };
            Modulus plain_t = 0;
            ASSERT_NO_THROW(
                rns_tool = allocate<RNSTool>(pool, poly_modulus_degree, RNSBase({ 53, 13 }, pool), plain_t, pool));

            vector<uint64_t> in(poly_modulus_degree * rns_tool->base_q()->size());
            set_zero_uint(in.size(), in.data());
            RNSIter in_iter(in.data(), poly_modulus_degree);
            rns_tool->divide_and_round_q_last_ntt_inplace(in_iter, ntt, pool);
            ASSERT_EQ(0ULL, in[0]);
            ASSERT_EQ(0ULL, in[1]);

            // The size of q is 2. We set some values here and divide by the last modulus (i.e., 13).
            in[0] = 1;
            in[1] = 2;
            in[2] = 1;
            in[3] = 2;
            ntt_negacyclic_harvey(in.data(), ntt[0]);
            ntt_negacyclic_harvey(in.data() + poly_modulus_degree, ntt[1]);

            // We expect to get a zero output also in this case
            rns_tool->divide_and_round_q_last_ntt_inplace(in_iter, ntt, pool);
            inverse_ntt_negacyclic_harvey(in.data(), ntt[0]);
            ASSERT_EQ(0ULL, in[0]);
            ASSERT_EQ(0ULL, in[1]);

            // Next a case with non-trivial rounding
            in[0] = 4;
            in[1] = 12;
            in[2] = 4;
            in[3] = 12;
            ntt_negacyclic_harvey(in.data(), ntt[0]);
            ntt_negacyclic_harvey(in.data() + poly_modulus_degree, ntt[1]);

            rns_tool->divide_and_round_q_last_ntt_inplace(in_iter, ntt, pool);
            inverse_ntt_negacyclic_harvey(in.data(), ntt[0]);
            ASSERT_TRUE((53ULL + 1ULL - in[0]) % 53ULL <= 1);
            ASSERT_TRUE((53ULL + 2ULL - in[1]) % 53ULL <= 1);

            // Input array (25, 35)
            in[0] = 25;
            in[1] = 35;
            in[2] = 12;
            in[3] = 9;
            ntt_negacyclic_harvey(in.data(), ntt[0]);
            ntt_negacyclic_harvey(in.data() + poly_modulus_degree, ntt[1]);

            rns_tool->divide_and_round_q_last_ntt_inplace(in_iter, ntt, pool);
            inverse_ntt_negacyclic_harvey(in.data(), ntt[0]);
            ASSERT_TRUE((53ULL + 2ULL - in[0]) % 53ULL <= 1);
            ASSERT_TRUE((53ULL + 3ULL - in[1]) % 53ULL <= 1);
        }

        namespace
        {
            // Number of bits of the product of the given values
            int product_bit_count(const vector<uint64_t> &values)
            {
                vector<uint64_t> product{ 1 };
                for (uint64_t value : values)
                {
                    vector<uint64_t> next(product.size() + 1);
                    multiply_uint(product.data(), product.size(), value, next.size(), next.data());
                    product.swap(next);
                }
                return get_significant_bit_count_uint(product.data(), product.size());
            }
        } // namespace

        // B is the shortest prefix of the base conversion primes with
        // bits(prod(B) * m_sk) - 1 >= 5 + bits(t) + log2(n) + bits(q), and never longer than with the rule of SEAL
        // 4.6.2. (The requirement is always met with the old rule, so the logic_error thrown otherwise is unreachable.)
        TEST(RNSToolTest, TightBskSize)
        {
            auto pool = MemoryManager::GetPool();
            auto B_size = [&](size_t n, const vector<Modulus> &q_primes, const Modulus &t) {
                RNSBase q(q_primes, pool);
                RNSTool rns_tool(n, q, t, pool);
                const RNSBase &B = *rns_tool.base_B();
                int q_bit_count = get_significant_bit_count_uint(q.base_prod(), q.size());
                int required_bit_count = 5 + t.bit_count() + get_power_of_two(n) + q_bit_count;
                int q_size = static_cast<int>(q.size());
                size_t old_B_size = q.size() + (32 + t.bit_count() + q_bit_count >= 61 * q_size + 61 ? 1 : 0);
                EXPECT_LE(B.size(), old_B_size);

                vector<uint64_t> values{ rns_tool.m_sk().value() };
                for (size_t i = 0; i < B.size(); i++)
                {
                    values.push_back(B[i].value());
                }
                EXPECT_GE(product_bit_count(values) - 1, required_bit_count);
                values.pop_back();
                if (B.size() > 1)
                {
                    EXPECT_LT(product_bit_count(values) - 1, required_bit_count);
                }
                return B.size();
            };

            // Default BFV parameters with a 20-bit plain modulus
            ASSERT_EQ(size_t(2), B_size(4096, CoeffModulus::BFVDefault(4096), PlainModulus::Batching(4096, 20)));
            ASSERT_EQ(size_t(4), B_size(8192, CoeffModulus::BFVDefault(8192), PlainModulus::Batching(8192, 20)));
            ASSERT_EQ(size_t(15), B_size(32768, CoeffModulus::BFVDefault(32768), PlainModulus::Batching(32768, 20)));

            // A sweep over degrees, plain moduli (including zero), and sizes of q
            for (size_t n : { size_t(2), size_t(64), size_t(4096) })
            {
                for (int t_bit_count : { 0, 2, 20, 40, 60 })
                {
                    Modulus t =
                        t_bit_count == 0 ? Modulus(0) : (t_bit_count == 2 ? Modulus(3) : get_prime(2 * n, t_bit_count));
                    for (int q_bit_count : { 20, 50, 60 })
                    {
                        for (size_t q_size : { size_t(1), size_t(2), size_t(5), size_t(17) })
                        {
                            if (q_bit_count == 20 && q_size > 1)
                            {
                                continue;
                            }
                            auto q = get_primes(2 * n, q_bit_count, q_size);
                            if (find(q.begin(), q.end(), t) == q.end())
                            {
                                B_size(n, q, t);
                            }
                        }
                    }
                }
            }
        }

        // Steps (5)-(8) of BEHZ multiplication on extreme inputs: X = sum of 8 negacyclic products of polynomials
        // with coefficients +-(q - 1) / 2. The output must be floor(t * X / q) - u modulo q for some 0 <= u < |q|
        // (the fast floor error), which fails if the Shenoy-Kumaresan conversion with the tight base B wraps around.
        TEST(RNSToolTest, BEHZFloorExactness)
        {
            auto pool = MemoryManager::GetPool();
            MemoryPool &mpool = pool;
            mt19937_64 rng(2025);
            for (size_t n : { size_t(2), size_t(16) })
            {
                for (auto bit_sizes : { vector<int>{ 60 }, vector<int>{ 60, 60 }, vector<int>{ 30, 30, 30 },
                                        vector<int>{ 60, 60, 60, 60 } })
                {
                    RNSBase q(CoeffModulus::Create(n, bit_sizes), pool);
                    for (const Modulus &t : { get_prime(2 * n, 59), Modulus(3) })
                    {
                        RNSTool rns_tool(n, q, t, pool);
                        const size_t q_size = q.size();
                        const RNSBase &Bsk = *rns_tool.base_Bsk();
                        const size_t Bsk_size = Bsk.size();
                        Pointer<NTTTables> q_ntt_tables;
                        CreateNTTTables(
                            get_power_of_two(n), vector<Modulus>(q.base(), q.base() + q_size), q_ntt_tables, pool);

                        // h = (q - 1) / 2 and h^2
                        vector<uint64_t> h(q.base_prod(), q.base_prod() + q_size), h2(2 * q_size);
                        right_shift_uint(h.data(), 1, q_size, h.data());
                        multiply_uint(h.data(), q_size, h.data(), q_size, h2.size(), h2.data());

                        for (int pattern = 0; pattern < 3; pattern++)
                        {
                            // X = m * h^2 with m = sum of 8 negacyclic products of sign vectors: all +1 (pattern 0),
                            // all -1 times +1 (pattern 1), or random (pattern 2)
                            vector<int64_t> m(n, 0);
                            for (int k = 0; k < 8; k++)
                            {
                                vector<int64_t> a(n), b(n);
                                for (size_t i = 0; i < n; i++)
                                {
                                    a[i] = pattern == 1 ? -1 : (pattern == 2 && (rng() & 1) ? -1 : 1);
                                    b[i] = pattern == 2 && (rng() & 1) ? -1 : 1;
                                }
                                for (size_t i = 0; i < n; i++)
                                {
                                    for (size_t j = 0; j < n; j++)
                                    {
                                        int64_t product = a[i] * b[j];
                                        m[(i + j) % n] += (i + j < n) ? product : -product;
                                    }
                                }
                            }

                            // Input: X modulo every prime of q U Bsk, in NTT form, in standard or Montgomery form
                            for (bool montgomery : { false, true })
                            {
                                vector<uint64_t> in((q_size + Bsk_size) * n);
                                for (size_t i = 0; i < q_size + Bsk_size; i++)
                                {
                                    const Modulus &p = i < q_size ? q[i] : Bsk[i - q_size];
                                    const NTTTables &tables =
                                        i < q_size ? q_ntt_tables[i] : rns_tool.base_Bsk_ntt_tables()[i - q_size];
                                    uint64_t h2_mod_p = modulo_uint(h2.data(), h2.size(), p);
                                    if (montgomery)
                                    {
                                        uint64_t inv_two_pow_64;
                                        ASSERT_TRUE(try_invert_uint_mod(two_pow_64_mod(p), p, inv_two_pow_64));
                                        h2_mod_p = multiply_uint_mod(h2_mod_p, inv_two_pow_64, p);
                                    }
                                    for (size_t c = 0; c < n; c++)
                                    {
                                        uint64_t abs_m = static_cast<uint64_t>(m[c] < 0 ? -m[c] : m[c]);
                                        uint64_t x = multiply_uint_mod(abs_m, h2_mod_p, p);
                                        in[i * n + c] = m[c] < 0 ? negate_uint_mod(x, p) : x;
                                    }
                                    ntt_negacyclic_harvey(in.data() + i * n, tables);
                                }
                                vector<uint64_t> result(q_size * n);
                                rns_tool.inverse_ntt_multiply_t_fast_floor_fastbconv_sk(
                                    RNSIter(in.data(), n), RNSIter(in.data() + q_size * n, n), q_ntt_tables.get(),
                                    montgomery, RNSIter(result.data(), n), pool);

                                for (size_t c = 0; c < n; c++)
                                {
                                    // floor(t * X / q), exactly
                                    uint64_t abs_m = static_cast<uint64_t>(m[c] < 0 ? -m[c] : m[c]);
                                    size_t width = 2 * q_size + 2;
                                    vector<uint64_t> numerator(width), temp(width), q_wide(width), quotient(width),
                                        remainder(width);
                                    multiply_uint(h2.data(), h2.size(), abs_m, width, temp.data());
                                    multiply_uint(temp.data(), width, t.value(), width, numerator.data());
                                    copy_n(q.base_prod(), q_size, q_wide.begin());
                                    divide_uint(
                                        numerator.data(), q_wide.data(), width, quotient.data(), remainder.data(),
                                        mpool);
                                    if (m[c] < 0 && !is_zero_uint(remainder.data(), width))
                                    {
                                        increment_uint(quotient.data(), width, quotient.data());
                                    }
                                    vector<uint64_t> floor_mod_q = decompose_signed(q, quotient, m[c] < 0);

                                    bool found = false;
                                    for (uint64_t u = 0; u < q_size && !found; u++)
                                    {
                                        found = true;
                                        for (size_t i = 0; i < q_size; i++)
                                        {
                                            found = found &&
                                                    result[i * n + c] ==
                                                        sub_uint_mod(floor_mod_q[i], barrett_reduce_64(u, q[i]), q[i]);
                                        }
                                    }
                                    ASSERT_TRUE(found) << "n " << n << ", q size " << q_size << ", t " << t.value()
                                                       << ", pattern " << pattern << ", coefficient " << c;
                                }
                            }
                        }
                    }
                }
            }
        }

        // The result of divide_and_round_q_last is round(x / q_last) = floor((x + floor(q_last / 2)) / q_last) for the
        // integer x in [0, q) given by the input; checked in and out of place, in NTT form, and with destination
        // overlapping input as for compacting a ciphertext in place
        TEST(RNSToolTest, DivideAndRoundQLast)
        {
            auto pool = MemoryManager::GetPool();
            MemoryPool &mpool = pool;
            mt19937_64 rng(2026);
            size_t n = 64;
            for (auto bit_sizes : { vector<int>{ 40, 50, 60 }, vector<int>{ 30, 30, 60 }, vector<int>{ 60, 60, 30 },
                                    vector<int>{ 60, 20 } })
            {
                RNSBase q(CoeffModulus::Create(n, bit_sizes), pool);
                size_t q_size = q.size();
                const Modulus &q_last = q[q_size - 1];
                RNSTool rns_tool(n, q, Modulus(65537), pool);
                Pointer<NTTTables> ntt_tables;
                CreateNTTTables(get_power_of_two(n), vector<Modulus>(q.base(), q.base() + q_size), ntt_tables, pool);

                vector<uint64_t> in = random_rns_poly(q, n, rng);
                vector<uint64_t> ref((q_size - 1) * n);
                for (size_t c = 0; c < n; c++)
                {
                    vector<uint64_t> x = compose_coeff(q, in.data(), n, c), quotient(q_size + 1), remainder(q_size + 1);
                    x.push_back(0);
                    vector<uint64_t> half(q_size + 1), divisor(q_size + 1);
                    half[0] = q_last.value() >> 1;
                    divisor[0] = q_last.value();
                    add_uint(x.data(), half.data(), q_size + 1, x.data());
                    divide_uint(x.data(), divisor.data(), q_size + 1, quotient.data(), remainder.data(), mpool);
                    for (size_t i = 0; i + 1 < q_size; i++)
                    {
                        ref[i * n + c] = modulo_uint(quotient.data(), quotient.size(), q[i]);
                    }
                }

                // NTT form of the input and of the expected result
                vector<uint64_t> in_ntt = in, ref_ntt = ref;
                for (size_t i = 0; i < q_size; i++)
                {
                    ntt_negacyclic_harvey(in_ntt.data() + i * n, ntt_tables[i]);
                    if (i + 1 < q_size)
                    {
                        ntt_negacyclic_harvey(ref_ntt.data() + i * n, ntt_tables[i]);
                    }
                }

                for (bool ntt_form : { false, true })
                {
                    const vector<uint64_t> &input = ntt_form ? in_ntt : in;
                    const vector<uint64_t> &expected = ntt_form ? ref_ntt : ref;
                    auto divide = [&](ConstRNSIter source, RNSIter destination) {
                        if (ntt_form)
                        {
                            rns_tool.divide_and_round_q_last_ntt(source, ntt_tables.get(), destination, pool);
                        }
                        else
                        {
                            rns_tool.divide_and_round_q_last(source, destination, pool);
                        }
                    };

                    // Out of place
                    vector<uint64_t> out((q_size - 1) * n);
                    divide(ConstRNSIter(input.data(), n), RNSIter(out.data(), n));
                    ASSERT_EQ(expected, out) << "q size " << q_size << ", NTT form " << ntt_form;

                    // In place
                    vector<uint64_t> buffer = input;
                    if (ntt_form)
                    {
                        rns_tool.divide_and_round_q_last_ntt_inplace(RNSIter(buffer.data(), n), ntt_tables.get(), pool);
                    }
                    else
                    {
                        rns_tool.divide_and_round_q_last_inplace(RNSIter(buffer.data(), n), pool);
                    }
                    ASSERT_TRUE(equal(expected.begin(), expected.end(), buffer.begin()));
                    buffer = input;
                    divide(ConstRNSIter(buffer.data(), n), RNSIter(buffer.data(), n));
                    ASSERT_TRUE(equal(expected.begin(), expected.end(), buffer.begin()));

                    // Component i of destination at component i - 1 of input
                    buffer.assign((q_size + 1) * n, 0);
                    copy(input.begin(), input.end(), buffer.data() + n);
                    divide(ConstRNSIter(buffer.data() + n, n), RNSIter(buffer.data(), n));
                    ASSERT_TRUE(equal(expected.begin(), expected.end(), buffer.begin()));
                }
            }
        }

        // mod_t_and_divide_q_last_ntt computes (x - delta) / q_last for the integer x in [0, q) given by the input,
        // where delta = [-x * q_last^(-1)]_t * q_last + [x]_{q_last} is the multiple of t congruent to x modulo q_last;
        // checked in and out of place, and with destination overlapping input as for compacting a ciphertext in place
        TEST(RNSToolTest, ModTAndDivideQLastNTT)
        {
            auto pool = MemoryManager::GetPool();
            MemoryPool &mpool = pool;
            mt19937_64 rng(2027);
            size_t n = 64;
            for (auto bit_sizes : { vector<int>{ 40, 50, 60 }, vector<int>{ 30, 30, 60 }, vector<int>{ 60, 60, 30 } })
            {
                RNSBase q(CoeffModulus::Create(n, bit_sizes), pool);
                size_t q_size = q.size();
                const Modulus &q_last = q[q_size - 1];
                Pointer<NTTTables> ntt_tables;
                CreateNTTTables(get_power_of_two(n), vector<Modulus>(q.base(), q.base() + q_size), ntt_tables, pool);

                // t = 2 makes q_last^(-1) mod t equal to 1
                for (const Modulus &t : { Modulus(2), Modulus(65537), Modulus(uint64_t(1) << 20) })
                {
                    RNSTool rns_tool(n, q, t, pool);
                    vector<uint64_t> in = random_rns_poly(q, n, rng);
                    vector<uint64_t> ref((q_size - 1) * n);
                    uint64_t inv_q_last_mod_t = 1;
                    if (t.value() > 2)
                    {
                        ASSERT_TRUE(try_invert_uint_mod(barrett_reduce_64(q_last.value(), t), t, inv_q_last_mod_t));
                    }
                    for (size_t c = 0; c < n; c++)
                    {
                        vector<uint64_t> x = compose_coeff(q, in.data(), n, c);
                        uint64_t c_last = in[(q_size - 1) * n + c];
                        uint64_t k = multiply_uint_mod(
                            negate_uint_mod(barrett_reduce_64(c_last, t), t), barrett_reduce_64(inv_q_last_mod_t, t),
                            t);

                        // delta = k * q_last + c_last, and (x - delta) / q_last with its sign
                        vector<uint64_t> delta(q_size), diff(q_size), quotient(q_size), remainder(q_size),
                            divisor(q_size);
                        multiply_uint(&k, 1, q_last.value(), q_size, delta.data());
                        add_uint(delta.data(), q_size, c_last, delta.data());
                        bool negative = is_greater_than_uint(delta.data(), x.data(), q_size);
                        if (negative)
                        {
                            sub_uint(delta.data(), x.data(), q_size, diff.data());
                        }
                        else
                        {
                            sub_uint(x.data(), delta.data(), q_size, diff.data());
                        }
                        divisor[0] = q_last.value();
                        divide_uint(diff.data(), divisor.data(), q_size, quotient.data(), remainder.data(), mpool);
                        ASSERT_TRUE(is_zero_uint(remainder.data(), q_size));
                        vector<uint64_t> residues = decompose_signed(q, quotient, negative);
                        for (size_t i = 0; i + 1 < q_size; i++)
                        {
                            ref[i * n + c] = residues[i];
                        }
                    }
                    for (size_t i = 0; i < q_size; i++)
                    {
                        ntt_negacyclic_harvey(in.data() + i * n, ntt_tables[i]);
                        if (i + 1 < q_size)
                        {
                            ntt_negacyclic_harvey(ref.data() + i * n, ntt_tables[i]);
                        }
                    }

                    vector<uint64_t> out((q_size - 1) * n);
                    rns_tool.mod_t_and_divide_q_last_ntt(
                        ConstRNSIter(in.data(), n), ntt_tables.get(), RNSIter(out.data(), n), pool);
                    ASSERT_EQ(ref, out) << "q size " << q_size << ", t " << t.value();

                    vector<uint64_t> buffer = in;
                    rns_tool.mod_t_and_divide_q_last_ntt_inplace(RNSIter(buffer.data(), n), ntt_tables.get(), pool);
                    ASSERT_TRUE(equal(ref.begin(), ref.end(), buffer.begin()));

                    buffer.assign((q_size + 1) * n, 0);
                    copy(in.begin(), in.end(), buffer.data() + n);
                    rns_tool.mod_t_and_divide_q_last_ntt(
                        ConstRNSIter(buffer.data() + n, n), ntt_tables.get(), RNSIter(buffer.data(), n), pool);
                    ASSERT_TRUE(equal(ref.begin(), ref.end(), buffer.begin()));
                }
            }
        }

        // decrypt_scale_and_round computes round(t * x / q) mod t, and decrypt_modt the centered representative of x
        // modulo q reduced modulo t, for the integer x in [0, q) given by the input (random, so that rounding errors
        // of the approximate methods do not occur in practice)
        TEST(RNSToolTest, DecryptRandom)
        {
            auto pool = MemoryManager::GetPool();
            MemoryPool &mpool = pool;
            mt19937_64 rng(2028);
            size_t n = 1024;
            for (auto bit_sizes : { vector<int>{ 50 }, vector<int>{ 40, 50, 60 }, vector<int>(20, 60) })
            {
                RNSBase q(CoeffModulus::Create(n, bit_sizes), pool);
                size_t q_size = q.size();
                for (const Modulus &t :
                     { Modulus(2), Modulus(65537), Modulus(uint64_t(1) << 20), get_prime(2 * n, 59) })
                {
                    RNSTool rns_tool(n, q, t, pool);
                    vector<uint64_t> in = random_rns_poly(q, n, rng);
                    vector<uint64_t> scaled(n), modt(n);
                    rns_tool.decrypt_scale_and_round(ConstRNSIter(in.data(), n), CoeffIter(scaled.data()), pool);
                    rns_tool.decrypt_modt(RNSIter(in.data(), n), CoeffIter(modt.data()), pool);
                    uint64_t q_mod_t = modulo_uint(q.base_prod(), q_size, t);
                    for (size_t c = 0; c < n; c++)
                    {
                        vector<uint64_t> x = compose_coeff(q, in.data(), n, c);

                        // floor((2 * t * x + q) / (2 * q)) mod t
                        size_t width = q_size + 2;
                        vector<uint64_t> numerator(width), q2(width), quotient(width), remainder(width);
                        multiply_uint(x.data(), q_size, 2 * t.value(), width, numerator.data());
                        copy_n(q.base_prod(), q_size, q2.begin());
                        add_uint(numerator.data(), q2.data(), width, numerator.data());
                        left_shift_uint(q2.data(), 1, width, q2.data());
                        divide_uint(numerator.data(), q2.data(), width, quotient.data(), remainder.data(), mpool);
                        ASSERT_EQ(modulo_uint(quotient.data(), width, t), scaled[c]) << "c " << c;

                        // x - q if 2 * x > q
                        uint64_t expected = modulo_uint(x.data(), q_size, t);
                        vector<uint64_t> twice_x(x), q_wide(width);
                        twice_x.resize(width);
                        left_shift_uint(twice_x.data(), 1, width, twice_x.data());
                        copy_n(q.base_prod(), q_size, q_wide.begin());
                        if (is_greater_than_uint(twice_x.data(), q_wide.data(), width))
                        {
                            expected = sub_uint_mod(expected, q_mod_t, t);
                        }
                        ASSERT_EQ(expected, modt[c]) << "c " << c;
                    }
                }
            }
        }
    } // namespace util
} // namespace sealtest
