// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include "seal/intarray.h"
#include "seal/util/numth.h"
#include "seal/util/uintarith.h"
#include "seal/util/uintarithsmallmod.h"
#include <cstdint>
#include <numeric>
#include "gtest/gtest.h"

using namespace seal;
using namespace seal::util;
using namespace std;

namespace SEALTest
{
    namespace util
    {
        TEST(NumberTheory, GCD)
        {
            ASSERT_EQ(1ULL, gcd(1, 1));
            ASSERT_EQ(1ULL, gcd(2, 1));
            ASSERT_EQ(1ULL, gcd(1, 2));
            ASSERT_EQ(2ULL, gcd(2, 2));
            ASSERT_EQ(3ULL, gcd(6, 15));
            ASSERT_EQ(3ULL, gcd(15, 6));
            ASSERT_EQ(1ULL, gcd(7, 15));
            ASSERT_EQ(1ULL, gcd(15, 7));
            ASSERT_EQ(1ULL, gcd(7, 15));
            ASSERT_EQ(3ULL, gcd(11112, 44445));
        }

        TEST(NumberTheory, ExtendedGCD)
        {
            tuple<uint64_t, int64_t, int64_t> result;

            // Corner case behavior
            result = xgcd(7, 7);
            ASSERT_TRUE(result == make_tuple<>(7, 0, 1));
            result = xgcd(2, 2);
            ASSERT_TRUE(result == make_tuple<>(2, 0, 1));

            result = xgcd(1, 1);
            ASSERT_TRUE(result == make_tuple<>(1, 0, 1));
            result = xgcd(1, 2);
            ASSERT_TRUE(result == make_tuple<>(1, 1, 0));
            result = xgcd(5, 6);
            ASSERT_TRUE(result == make_tuple<>(1, -1, 1));
            result = xgcd(13, 19);
            ASSERT_TRUE(result == make_tuple<>(1, 3, -2));
            result = xgcd(14, 21);
            ASSERT_TRUE(result == make_tuple<>(7, -1, 1));

            result = xgcd(2, 1);
            ASSERT_TRUE(result == make_tuple<>(1, 0, 1));
            result = xgcd(6, 5);
            ASSERT_TRUE(result == make_tuple<>(1, 1, -1));
            result = xgcd(19, 13);
            ASSERT_TRUE(result == make_tuple<>(1, -2, 3));
            result = xgcd(21, 14);
            ASSERT_TRUE(result == make_tuple<>(7, 1, -1));
        }

        TEST(NumberTheory, TryInvertUIntMod)
        {
            uint64_t input, modulus, result;

            input = 1, modulus = 2;
            ASSERT_TRUE(try_invert_uint_mod(input, modulus, result));
            ASSERT_EQ(result, 1ULL);

            input = 2, modulus = 2;
            ASSERT_FALSE(try_invert_uint_mod(input, modulus, result));

            input = 3, modulus = 2;
            ASSERT_TRUE(try_invert_uint_mod(input, modulus, result));
            ASSERT_EQ(result, 1ULL);

            input = 0xFFFFFF, modulus = 2;
            ASSERT_TRUE(try_invert_uint_mod(input, modulus, result));
            ASSERT_EQ(result, 1ULL);

            input = 0xFFFFFE, modulus = 2;
            ASSERT_FALSE(try_invert_uint_mod(input, modulus, result));

            input = 12345, modulus = 3;
            ASSERT_FALSE(try_invert_uint_mod(input, modulus, result));

            input = 5, modulus = 19;
            ASSERT_TRUE(try_invert_uint_mod(input, modulus, result));
            ASSERT_EQ(result, 4ULL);

            input = 4, modulus = 19;
            ASSERT_TRUE(try_invert_uint_mod(input, modulus, result));
            ASSERT_EQ(result, 5ULL);
        }

        TEST(NumberTheory, IsPrime)
        {
            ASSERT_FALSE(is_prime(0));
            ASSERT_TRUE(is_prime(2));
            ASSERT_TRUE(is_prime(3));
            ASSERT_FALSE(is_prime(4));
            ASSERT_TRUE(is_prime(5));
            ASSERT_FALSE(is_prime(221));
            ASSERT_TRUE(is_prime(65537));
            ASSERT_FALSE(is_prime(65536));
            ASSERT_TRUE(is_prime(59399));
            ASSERT_TRUE(is_prime(72307));
            ASSERT_FALSE(is_prime(72307ULL * 59399ULL));
            ASSERT_TRUE(is_prime(36893488147419103ULL));
            ASSERT_FALSE(is_prime(36893488147419107ULL));
        }

        TEST(NumberTheory, NAF)
        {
            auto naf_vec = naf(0);
            ASSERT_EQ(0, naf_vec.size());

            naf_vec = naf(1);
            ASSERT_EQ(1, naf_vec.size());
            ASSERT_EQ(1, accumulate(naf_vec.begin(), naf_vec.end(), 0));
            naf_vec = naf(-1);
            ASSERT_EQ(1, naf_vec.size());
            ASSERT_EQ(-1, accumulate(naf_vec.begin(), naf_vec.end(), 0));

            naf_vec = naf(2);
            ASSERT_EQ(1, naf_vec.size());
            ASSERT_EQ(2, accumulate(naf_vec.begin(), naf_vec.end(), 0));
            naf_vec = naf(-2);
            ASSERT_EQ(1, naf_vec.size());
            ASSERT_EQ(-2, accumulate(naf_vec.begin(), naf_vec.end(), 0));

            naf_vec = naf(3);
            ASSERT_EQ(2, naf_vec.size());
            ASSERT_EQ(3, accumulate(naf_vec.begin(), naf_vec.end(), 0));
            naf_vec = naf(-3);
            ASSERT_EQ(2, naf_vec.size());
            ASSERT_EQ(-3, accumulate(naf_vec.begin(), naf_vec.end(), 0));

            naf_vec = naf(127);
            ASSERT_EQ(2, naf_vec.size());
            ASSERT_EQ(127, accumulate(naf_vec.begin(), naf_vec.end(), 0));
            naf_vec = naf(-127);
            ASSERT_EQ(2, naf_vec.size());
            ASSERT_EQ(-127, accumulate(naf_vec.begin(), naf_vec.end(), 0));

            naf_vec = naf(123);
            ASSERT_EQ(123, accumulate(naf_vec.begin(), naf_vec.end(), 0));
            naf_vec = naf(-123);
            ASSERT_EQ(-123, accumulate(naf_vec.begin(), naf_vec.end(), 0));
        }

        TEST(NumberTheory, CRTInitialize)
        {
            seal::util::CRTTool crt;

            // Invalid configurations
            ASSERT_FALSE(crt.initialize({}));
            ASSERT_FALSE(crt.initialize({ 2, 2 }));
            ASSERT_FALSE(crt.initialize({ 3, 12 }));
            ASSERT_FALSE(crt.initialize({ 3, 4 }));
            ASSERT_FALSE(crt.initialize({ 3, 5, 7, 5 }));

            // Valid configurations
            ASSERT_TRUE(crt.initialize({ 2 }));
            ASSERT_TRUE(crt.initialize({ 2, 3 }));
            ASSERT_TRUE(crt.initialize({ 3, 5 }));
            ASSERT_TRUE(crt.initialize({ 2, 3, 5, 7 }));
            ASSERT_TRUE(
                crt.initialize({ SmallModulus(13), SmallModulus(65537), get_prime(2048, 20), get_prime(2048, 30) }));
        }

        TEST(NumberTheory, CRTComposeDecompose)
        {
            seal::util::CRTTool crt;
            MemoryPoolHandle pool = MemoryManager::GetPool();

            auto crt_test = [&crt, &pool](vector<uint64_t> in, vector<uint64_t> out) {
                auto in_copy = in;
                crt.decompose(in_copy.data(), pool);
                ASSERT_TRUE(in_copy == out);
                crt.compose(in_copy.data(), pool);
                ASSERT_TRUE(in_copy == in);
            };

            ASSERT_TRUE(crt.initialize({ 2 }));
            crt_test({ 0 }, { 0 });
            crt_test({ 1 }, { 1 });

            ASSERT_TRUE(crt.initialize({ 5 }));
            crt_test({ 0 }, { 0 });
            crt_test({ 1 }, { 1 });
            crt_test({ 2 }, { 2 });
            crt_test({ 3 }, { 3 });
            crt_test({ 4 }, { 4 });

            ASSERT_TRUE(crt.initialize({ 3, 5 }));
            crt_test({ 0, 0 }, { 0, 0 });
            crt_test({ 1, 0 }, { 1, 1 });
            crt_test({ 2, 0 }, { 2, 2 });
            crt_test({ 3, 0 }, { 0, 3 });
            crt_test({ 4, 0 }, { 1, 4 });
            crt_test({ 5, 0 }, { 2, 0 });
            crt_test({ 8, 0 }, { 2, 3 });
            crt_test({ 12, 0 }, { 0, 2 });
            crt_test({ 14, 0 }, { 2, 4 });

            ASSERT_TRUE(crt.initialize({ 2, 3, 5 }));
            crt_test({ 0, 0, 0 }, { 0, 0, 0 });
            crt_test({ 1, 0, 0 }, { 1, 1, 1 });
            crt_test({ 2, 0, 0 }, { 0, 2, 2 });
            crt_test({ 3, 0, 0 }, { 1, 0, 3 });
            crt_test({ 4, 0, 0 }, { 0, 1, 4 });
            crt_test({ 5, 0, 0 }, { 1, 2, 0 });
            crt_test({ 10, 0, 0 }, { 0, 1, 0 });
            crt_test({ 11, 0, 0 }, { 1, 2, 1 });
            crt_test({ 16, 0, 0 }, { 0, 1, 1 });
            crt_test({ 27, 0, 0 }, { 1, 0, 2 });
            crt_test({ 29, 0, 0 }, { 1, 2, 4 });

            ASSERT_TRUE(crt.initialize({ 13, 37, 53, 97 }));
            crt_test({ 0, 0, 0, 0 }, { 0, 0, 0, 0 });
            crt_test({ 1, 0, 0, 0 }, { 1, 1, 1, 1 });
            crt_test({ 2, 0, 0, 0 }, { 2, 2, 2, 2 });
            crt_test({ 12, 0, 0, 0 }, { 12, 12, 12, 12 });
            crt_test({ 321, 0, 0, 0 }, { 9, 25, 3, 30 });

            // Large example
            auto primes = get_primes(1024, 60, 4);
            vector<uint64_t> in_values{ 0xAAAAAAAAAAA, 0xBBBBBBBBBB, 0xCCCCCCCCCC, 0xDDDDDDDDDD };
            ASSERT_TRUE(crt.initialize(primes));
            crt_test(
                in_values, { modulo_uint(in_values.data(), in_values.size(), primes[0]),
                             modulo_uint(in_values.data(), in_values.size(), primes[1]),
                             modulo_uint(in_values.data(), in_values.size(), primes[2]),
                             modulo_uint(in_values.data(), in_values.size(), primes[3]) });
        }

        TEST(NumberTheory, BaseConvInitialize)
        {
            BaseConvTool bct;

            // Good cases
            ASSERT_TRUE(bct.initialize({ 2 }, { 2 }));
            ASSERT_TRUE(bct.initialize({ 2 }, { 3 }));
            ASSERT_TRUE(bct.initialize({ 2, 3, 5 }, { 2 }));
            ASSERT_TRUE(bct.initialize({ 2, 3, 5 }, { 3, 5 }));
            ASSERT_TRUE(bct.initialize({ 2, 3, 5 }, { 2, 3, 5, 7, 11 }));
            ASSERT_TRUE(bct.initialize({ 2, 3, 5 }, { 7, 11 }));

            // Coprimality issue
            ASSERT_FALSE(bct.initialize({}, {}));
            ASSERT_FALSE(bct.initialize({}, { 2 }));
            ASSERT_FALSE(bct.initialize({ 2, 2 }, { 3 }));
            ASSERT_FALSE(bct.initialize({ 2, 4 }, { 3 }));
            ASSERT_FALSE(bct.initialize({ 3 }, { 2, 2 }));
            ASSERT_FALSE(bct.initialize({ 3 }, { 2, 4 }));
            ASSERT_FALSE(bct.initialize({ 3 }, { 2, 6 }));
        }

        TEST(NumberTheory, BaseConv)
        {
            auto pool = MemoryManager::GetPool();
            BaseConvTool bct;

            auto bct_test = [&](const vector<uint64_t> &in, const vector<uint64_t> &out) {
                uint64_t in_array[3], out_array[3];
                copy(in.cbegin(), in.cend(), in_array);
                bct.fast_convert(in.data(), out_array, pool);
                for (size_t i = 0; i < out.size(); i++)
                {
                    ASSERT_EQ(out[i], out_array[i]);
                }
            };

            bct.initialize({ 2 }, { 2 });
            bct_test({ 0 }, { 0 });
            bct_test({ 1 }, { 1 });

            bct.initialize({ 2 }, { 3 });
            bct_test({ 0 }, { 0 });
            bct_test({ 1 }, { 1 });

            bct.initialize({ 3 }, { 2 });
            bct_test({ 0 }, { 0 });
            bct_test({ 1 }, { 1 });
            bct_test({ 2 }, { 0 });

            bct.initialize({ 2, 3 }, { 2 });
            bct_test({ 0, 0 }, { 0 });
            bct_test({ 1, 1 }, { 1 });
            bct_test({ 0, 2 }, { 0 });
            bct_test({ 1, 0 }, { 1 });

            bct.initialize({ 2, 3 }, { 2, 3 });
            bct_test({ 0, 0 }, { 0, 0 });
            bct_test({ 1, 1 }, { 1, 1 });
            bct_test({ 1, 2 }, { 1, 2 });
            bct_test({ 0, 2 }, { 0, 2 });

            bct.initialize({ 2, 3 }, { 3, 4, 5 });
            bct_test({ 0, 0 }, { 0, 0, 0 });
            bct_test({ 1, 1 }, { 1, 3, 2 });
            bct_test({ 1, 2 }, { 2, 1, 0 });

            bct.initialize({ 3, 4, 5 }, { 2, 3 });
            bct_test({ 0, 0, 0 }, { 0, 0 });
            bct_test({ 1, 1, 1 }, { 1, 1 });
        }

        TEST(NumberTheory, BaseConvArray)
        {
            auto pool = MemoryManager::GetPool();
            BaseConvTool bct;

            auto bct_test = [&](const vector<uint64_t> &in, const vector<uint64_t> &out) {
                uint64_t in_array[3 * 3], out_array[3 * 3];
                copy(in.cbegin(), in.cend(), in_array);
                bct.fast_convert_array(in.data(), 3, out_array, pool);
                for (size_t i = 0; i < out.size(); i++)
                {
                    ASSERT_EQ(out[i], out_array[i]);
                }
            };

            // In this test the input is an array of values in the first base and output
            // an array of values in the secnod base. Both input and output are stored in
            // array-major order, NOT modulus-major order.

            bct.initialize({ 3 }, { 2 });
            bct_test({ 0, 1, 2 }, { 0, 1, 0 });

            bct.initialize({ 2, 3 }, { 2 });
            bct_test({ 0, 1, 0, 0, 1, 2 }, { 0, 1, 0 });

            bct.initialize({ 2, 3 }, { 2, 3 });
            bct_test({ 1, 1, 0, 1, 2, 2 }, { 1, 1, 0, 1, 2, 2 });

            bct.initialize({ 2, 3 }, { 3, 4, 5 });
            bct_test({ 0, 1, 1, 0, 1, 2 }, { 0, 1, 2, 0, 3, 1, 0, 2, 0 });
        }

        TEST(NumberTheory, TryPrimitiveRootMod)
        {
            uint64_t result;
            SmallModulus mod(11);

            ASSERT_TRUE(try_primitive_root(2, mod, result));
            ASSERT_EQ(10ULL, result);

            mod = 29;
            ASSERT_TRUE(try_primitive_root(2, mod, result));
            ASSERT_EQ(28ULL, result);

            vector<uint64_t> corrects{ 12, 17 };
            ASSERT_TRUE(try_primitive_root(4, mod, result));
            ASSERT_TRUE(std::find(corrects.begin(), corrects.end(), result) != corrects.end());

            mod = 1234565441;
            ASSERT_TRUE(try_primitive_root(2, mod, result));
            ASSERT_EQ(1234565440ULL, result);
            corrects = { 984839708, 273658408, 249725733, 960907033 };
            ASSERT_TRUE(try_primitive_root(8, mod, result));
            ASSERT_TRUE(std::find(corrects.begin(), corrects.end(), result) != corrects.end());
        }

        TEST(NumberTheory, IsPrimitiveRootMod)
        {
            SmallModulus mod(11);
            ASSERT_TRUE(is_primitive_root(10, 2, mod));
            ASSERT_FALSE(is_primitive_root(9, 2, mod));
            ASSERT_FALSE(is_primitive_root(10, 4, mod));

            mod = 29;
            ASSERT_TRUE(is_primitive_root(28, 2, mod));
            ASSERT_TRUE(is_primitive_root(12, 4, mod));
            ASSERT_FALSE(is_primitive_root(12, 2, mod));
            ASSERT_FALSE(is_primitive_root(12, 8, mod));

            mod = 1234565441ULL;
            ASSERT_TRUE(is_primitive_root(1234565440ULL, 2, mod));
            ASSERT_TRUE(is_primitive_root(960907033ULL, 8, mod));
            ASSERT_TRUE(is_primitive_root(1180581915ULL, 16, mod));
            ASSERT_FALSE(is_primitive_root(1180581915ULL, 32, mod));
            ASSERT_FALSE(is_primitive_root(1180581915ULL, 8, mod));
            ASSERT_FALSE(is_primitive_root(1180581915ULL, 2, mod));
        }

        TEST(NumberTheory, TryMinimalPrimitiveRootMod)
        {
            SmallModulus mod(11);

            uint64_t result;
            ASSERT_TRUE(try_minimal_primitive_root(2, mod, result));
            ASSERT_EQ(10ULL, result);

            mod = 29;
            ASSERT_TRUE(try_minimal_primitive_root(2, mod, result));
            ASSERT_EQ(28ULL, result);
            ASSERT_TRUE(try_minimal_primitive_root(4, mod, result));
            ASSERT_EQ(12ULL, result);

            mod = 1234565441;
            ASSERT_TRUE(try_minimal_primitive_root(2, mod, result));
            ASSERT_EQ(1234565440ULL, result);
            ASSERT_TRUE(try_minimal_primitive_root(8, mod, result));
            ASSERT_EQ(249725733ULL, result);
        }

    } // namespace util
} // namespace SEALTest
