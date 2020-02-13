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
        TEST(NumberTheoryTest, GCD)
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

        TEST(NumberTheoryTest, ExtendedGCD)
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

        TEST(NumberTheoryTest, TryModInverse)
        {
            uint64_t input, modulus, result;

            input = 1, modulus = 2;
            ASSERT_TRUE(try_mod_inverse(input, modulus, result));
            ASSERT_EQ(result, 1ULL);

            input = 2, modulus = 2;
            ASSERT_FALSE(try_mod_inverse(input, modulus, result));

            input = 3, modulus = 2;
            ASSERT_TRUE(try_mod_inverse(input, modulus, result));
            ASSERT_EQ(result, 1ULL);

            input = 0xFFFFFF, modulus = 2;
            ASSERT_TRUE(try_mod_inverse(input, modulus, result));
            ASSERT_EQ(result, 1ULL);

            input = 0xFFFFFE, modulus = 2;
            ASSERT_FALSE(try_mod_inverse(input, modulus, result));

            input = 12345, modulus = 3;
            ASSERT_FALSE(try_mod_inverse(input, modulus, result));

            input = 5, modulus = 19;
            ASSERT_TRUE(try_mod_inverse(input, modulus, result));
            ASSERT_EQ(result, 4ULL);

            input = 4, modulus = 19;
            ASSERT_TRUE(try_mod_inverse(input, modulus, result));
            ASSERT_EQ(result, 5ULL);
        }

        TEST(NumberTheoryTest, IsPrime)
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

        TEST(NumberTheoryTest, NAF)
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

        TEST(NumberTheoryTest, CRTInitialize)
        {
            seal::util::CRTTool crt;

            // Invalid configurations
            crt.initialize({});
            ASSERT_FALSE(crt.is_initialized());
            crt.initialize({ 2, 2 });
            ASSERT_FALSE(crt.is_initialized());
            crt.initialize({ 3, 12 });
            ASSERT_FALSE(crt.is_initialized());
            crt.initialize({ 3, 4 });
            ASSERT_FALSE(crt.is_initialized());
            crt.initialize({ 3, 5, 7, 5 });
            ASSERT_FALSE(crt.is_initialized());

            // Valid configurations
            crt.initialize({ 2 });
            ASSERT_TRUE(crt.is_initialized());
            crt.initialize({ 2, 3 });
            ASSERT_TRUE(crt.is_initialized());
            crt.initialize({ 3, 5 });
            ASSERT_TRUE(crt.is_initialized());
            crt.initialize({ 2, 3, 5, 7 });
            ASSERT_TRUE(crt.is_initialized());
            crt.initialize({ SmallModulus(13), SmallModulus(65537), get_prime(12, 20), get_prime(12, 30) });
            ASSERT_TRUE(crt.is_initialized());
        }

        TEST(NumberTheoryTest, CRTComposeDecompose)
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
            auto primes = get_primes(10, 60, 4);
            vector<uint64_t> in_values{ 0xAAAAAAAAAAA, 0xBBBBBBBBBB, 0xCCCCCCCCCC, 0xDDDDDDDDDD };
            ASSERT_TRUE(crt.initialize(primes));
            crt_test(
                in_values, { modulo_uint(in_values.data(), in_values.size(), primes[0], pool),
                             modulo_uint(in_values.data(), in_values.size(), primes[1], pool),
                             modulo_uint(in_values.data(), in_values.size(), primes[2], pool),
                             modulo_uint(in_values.data(), in_values.size(), primes[3], pool) });
        }
    } // namespace util
} // namespace SEALTest
