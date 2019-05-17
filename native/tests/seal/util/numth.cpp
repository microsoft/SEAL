// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include "gtest/gtest.h"
#include "seal/util/numth.h"
#include <cstdint>

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
    }
}