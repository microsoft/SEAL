// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include "seal/memorymanager.h"
#include "seal/util/numth.h"
#include "seal/util/rns.h"
#include "seal/util/uintarithmod.h"
#include "seal/util/uintarithsmallmod.h"
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
            auto pool = MemoryManager::GetPool(mm_prof_opt::FORCE_NEW);
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
            auto pool = MemoryManager::GetPool(mm_prof_opt::FORCE_NEW);
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
            auto pool = MemoryManager::GetPool(mm_prof_opt::FORCE_NEW);
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
                auto primes = get_primes(1024, 60, 4);
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
                auto primes = get_primes(1024, 60, 2);
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

        TEST(BaseConvToolTest, Initialize)
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

        TEST(BaseConvToolTest, Convert)
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

        TEST(BaseConvToolTest, ConvertArray)
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

        TEST(RNSToolTest, Initialize)
        {
            auto pool = MemoryManager::GetPool();

            size_t poly_modulus_degree = 32;
            size_t coeff_base_count = 4;
            int prime_bit_count = 20;

            Modulus plain_t = 65537;
            RNSBase coeff_base(get_primes(poly_modulus_degree, prime_bit_count, coeff_base_count), pool);

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

                ASSERT_EQ(temp % (*rns_tool->base_Bsk_m_tilde())[0].value(), out[0]);
                ASSERT_EQ(temp % (*rns_tool->base_Bsk_m_tilde())[0].value(), out[1]);
                ASSERT_EQ(temp % (*rns_tool->base_Bsk_m_tilde())[1].value(), out[2]);
                ASSERT_EQ(temp % (*rns_tool->base_Bsk_m_tilde())[1].value(), out[3]);
                ASSERT_EQ(temp % (*rns_tool->base_Bsk_m_tilde())[2].value(), out[4]);
                ASSERT_EQ(temp % (*rns_tool->base_Bsk_m_tilde())[2].value(), out[5]);
                ASSERT_EQ(temp % (*rns_tool->base_Bsk_m_tilde())[3].value(), out[6]);
                ASSERT_EQ(temp % (*rns_tool->base_Bsk_m_tilde())[3].value(), out[7]);
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

                // Input base is Bsk U {m_tilde}, in this case consisting of 6 primes.
                // m_tilde is always smaller than the primes in Bsk (SEAL_INTERNAL_MOD_BIT_COUNT (61) bits).
                // Set the length-2 array to have values 1*m_tilde and 2*m_tilde.
                in[0] = rns_tool->m_tilde().value();
                in[1] = 2 * rns_tool->m_tilde().value();
                in[2] = rns_tool->m_tilde().value();
                in[3] = 2 * rns_tool->m_tilde().value();
                in[4] = rns_tool->m_tilde().value();
                in[5] = 2 * rns_tool->m_tilde().value();

                // Modulo m_tilde
                in[6] = 0;
                in[7] = 0;

                // This should simply get rid of the m_tilde factor
                rns_tool->sm_mrq(in_iter, out_iter, pool);

                ASSERT_EQ(1, out[0]);
                ASSERT_EQ(2, out[1]);
                ASSERT_EQ(1, out[2]);
                ASSERT_EQ(2, out[3]);
                ASSERT_EQ(1, out[4]);
                ASSERT_EQ(2, out[5]);

                // Next add a multiple of q to the input and see if it is reduced properly
                in[0] = 15;
                in[1] = 30;
                in[2] = 15;
                in[3] = 30;
                in[4] = 15;
                in[5] = 30;
                in[6] = 15;
                in[7] = 30;

                rns_tool->sm_mrq(in_iter, out_iter, pool);
                for (auto val : out)
                {
                    ASSERT_EQ(0, val);
                }

                // Now with a multiple of m_tilde + multiple of q
                in[0] = 2 * rns_tool->m_tilde().value() + 15;
                in[1] = 2 * rns_tool->m_tilde().value() + 30;
                in[2] = 2 * rns_tool->m_tilde().value() + 15;
                in[3] = 2 * rns_tool->m_tilde().value() + 30;
                in[4] = 2 * rns_tool->m_tilde().value() + 15;
                in[5] = 2 * rns_tool->m_tilde().value() + 30;
                in[6] = 2 * rns_tool->m_tilde().value() + 15;
                in[7] = 2 * rns_tool->m_tilde().value() + 30;

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

                // The size of q U Bsk is now 5. We set the input to multiples of 15 an divide by 15 (i.e., q).
                in[0] = 15;
                in[1] = 30;
                in[2] = 15;
                in[3] = 30;
                in[4] = 15;
                in[5] = 30;
                in[6] = 15;
                in[7] = 30;
                in[8] = 15;
                in[9] = 30;

                // We get an exact result in this case
                rns_tool->fast_floor(in_iter, out_iter, pool);
                ASSERT_EQ(1ULL, out[0]);
                ASSERT_EQ(2ULL, out[1]);
                ASSERT_EQ(1ULL, out[2]);
                ASSERT_EQ(2ULL, out[3]);
                ASSERT_EQ(1ULL, out[4]);
                ASSERT_EQ(2ULL, out[5]);

                // Now a case where the floor really shows up
                in[0] = 21;
                in[1] = 32;
                in[2] = 21;
                in[3] = 32;
                in[4] = 21;
                in[5] = 32;
                in[6] = 21;
                in[7] = 32;
                in[8] = 21;
                in[9] = 32;

                // The result is not exact but differs at most by 1
                rns_tool->fast_floor(in_iter, out_iter, pool);
                ASSERT_TRUE(fabs(1ULL - out[0]) <= 1);
                ASSERT_TRUE(fabs(2ULL - out[1]) <= 1);
                ASSERT_TRUE(fabs(1ULL - out[2]) <= 1);
                ASSERT_TRUE(fabs(2ULL - out[3]) <= 1);
                ASSERT_TRUE(fabs(1ULL - out[4]) <= 1);
                ASSERT_TRUE(fabs(2ULL - out[5]) <= 1);
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

                // The size of Bsk is 3
                in[0] = 1;
                in[1] = 2;
                in[2] = 1;
                in[3] = 2;
                in[4] = 1;
                in[5] = 2;

                rns_tool->fastbconv_sk(in_iter, out_iter, pool);
                ASSERT_EQ(1ULL, out[0]);
                ASSERT_EQ(2ULL, out[1]);
                ASSERT_EQ(1ULL, out[2]);
                ASSERT_EQ(2ULL, out[3]);
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
            rns_tool->divide_and_round_q_last_inplace(in_iter, pool);
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
    } // namespace util
} // namespace sealtest
