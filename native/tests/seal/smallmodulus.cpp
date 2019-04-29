// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include "gtest/gtest.h"
#include "seal/smallmodulus.h"
#include "seal/defaultparams.h"

using namespace seal;
using namespace std;

namespace SEALTest
{
    TEST(SmallModulusTest, CreateSmallModulus)
    {
        SmallModulus mod;
        ASSERT_TRUE(mod.is_zero());
        ASSERT_EQ(0ULL, mod.value());
        ASSERT_EQ(0, mod.bit_count());
        ASSERT_EQ(1ULL, mod.uint64_count());
        ASSERT_EQ(0ULL, mod.const_ratio()[0]);
        ASSERT_EQ(0ULL, mod.const_ratio()[1]);
        ASSERT_EQ(0ULL, mod.const_ratio()[2]);
        ASSERT_FALSE(mod.is_prime());

        mod = 3;
        ASSERT_FALSE(mod.is_zero());
        ASSERT_EQ(3ULL, mod.value());
        ASSERT_EQ(2, mod.bit_count());
        ASSERT_EQ(1ULL, mod.uint64_count());
        ASSERT_EQ(6148914691236517205ULL, mod.const_ratio()[0]);
        ASSERT_EQ(6148914691236517205ULL, mod.const_ratio()[1]);
        ASSERT_EQ(1ULL, mod.const_ratio()[2]);
        ASSERT_TRUE(mod.is_prime());


        SmallModulus mod2(2);
        SmallModulus mod3(3);
        ASSERT_TRUE(mod != mod2);
        ASSERT_TRUE(mod == mod3);

        mod = 0;
        ASSERT_TRUE(mod.is_zero());
        ASSERT_EQ(0ULL, mod.value());
        ASSERT_EQ(0, mod.bit_count());
        ASSERT_EQ(1ULL, mod.uint64_count());
        ASSERT_EQ(0ULL, mod.const_ratio()[0]);
        ASSERT_EQ(0ULL, mod.const_ratio()[1]);
        ASSERT_EQ(0ULL, mod.const_ratio()[2]);

        mod = 0xF00000F00000F;
        ASSERT_FALSE(mod.is_zero());
        ASSERT_EQ(0xF00000F00000FULL, mod.value());
        ASSERT_EQ(52, mod.bit_count());
        ASSERT_EQ(1ULL, mod.uint64_count());
        ASSERT_EQ(1224979098644774929ULL, mod.const_ratio()[0]);
        ASSERT_EQ(4369ULL, mod.const_ratio()[1]);
        ASSERT_EQ(281470698520321ULL, mod.const_ratio()[2]);
        ASSERT_FALSE(mod.is_prime());

        mod = 0xF00000F000079;
        ASSERT_FALSE(mod.is_zero());
        ASSERT_EQ(0xF00000F000079ULL, mod.value());
        ASSERT_EQ(52, mod.bit_count());
        ASSERT_EQ(1ULL, mod.uint64_count());
        ASSERT_EQ(1224979096621368355ULL, mod.const_ratio()[0]);
        ASSERT_EQ(4369ULL, mod.const_ratio()[1]);
        ASSERT_EQ(1144844808538997ULL, mod.const_ratio()[2]);
        ASSERT_TRUE(mod.is_prime());
    }

    TEST(SmallModulusTest, SaveLoadSmallModulus)
    {
        stringstream stream;

        SmallModulus mod;
        mod.save(stream);

        SmallModulus mod2;
        mod2.load(stream);
        ASSERT_EQ(mod2.value(), mod.value());
        ASSERT_EQ(mod2.bit_count(), mod.bit_count());
        ASSERT_EQ(mod2.uint64_count(), mod.uint64_count());
        ASSERT_EQ(mod2.const_ratio()[0], mod.const_ratio()[0]);
        ASSERT_EQ(mod2.const_ratio()[1], mod.const_ratio()[1]);
        ASSERT_EQ(mod2.const_ratio()[2], mod.const_ratio()[2]);
        ASSERT_EQ(mod2.is_prime(), mod.is_prime());

        mod = 3;
        mod.save(stream);
        mod2.load(stream);
        ASSERT_EQ(mod2.value(), mod.value());
        ASSERT_EQ(mod2.bit_count(), mod.bit_count());
        ASSERT_EQ(mod2.uint64_count(), mod.uint64_count());
        ASSERT_EQ(mod2.const_ratio()[0], mod.const_ratio()[0]);
        ASSERT_EQ(mod2.const_ratio()[1], mod.const_ratio()[1]);
        ASSERT_EQ(mod2.const_ratio()[2], mod.const_ratio()[2]);
        ASSERT_EQ(mod2.is_prime(), mod.is_prime());

        mod = 0xF00000F00000F;
        mod.save(stream);
        mod2.load(stream);
        ASSERT_EQ(mod2.value(), mod.value());
        ASSERT_EQ(mod2.bit_count(), mod.bit_count());
        ASSERT_EQ(mod2.uint64_count(), mod.uint64_count());
        ASSERT_EQ(mod2.const_ratio()[0], mod.const_ratio()[0]);
        ASSERT_EQ(mod2.const_ratio()[1], mod.const_ratio()[1]);
        ASSERT_EQ(mod2.const_ratio()[2], mod.const_ratio()[2]);
        ASSERT_EQ(mod2.is_prime(), mod.is_prime());

        mod = 0xF00000F000079;
        mod.save(stream);
        mod2.load(stream);
        ASSERT_EQ(mod2.value(), mod.value());
        ASSERT_EQ(mod2.bit_count(), mod.bit_count());
        ASSERT_EQ(mod2.uint64_count(), mod.uint64_count());
        ASSERT_EQ(mod2.const_ratio()[0], mod.const_ratio()[0]);
        ASSERT_EQ(mod2.const_ratio()[1], mod.const_ratio()[1]);
        ASSERT_EQ(mod2.const_ratio()[2], mod.const_ratio()[2]);
        ASSERT_EQ(mod2.is_prime(), mod.is_prime());
    }

    TEST(SmallModulusTest, GeneratePrimes)
    {
        SmallModulus mod;
        mod = DefaultParams::small_mods_30bit(0);
        ASSERT_TRUE(mod.is_prime());

        mod = DefaultParams::small_mods_30bit(0).value() *
            DefaultParams::small_mods_30bit(1).value();
        ASSERT_FALSE(mod.is_prime());

        vector<SmallModulus> primes = SmallModulus::GetPrimes(50, 8, size_t(1) << 16);
        ASSERT_EQ(primes.size(), 8);
        for (size_t i = 0; i < primes.size(); i++)
        {
            if (i)
            {
                ASSERT_TRUE(primes[i].value() < primes[i - 1].value());
            }
            ASSERT_EQ(primes[i].bit_count(), 50);
            ASSERT_TRUE(primes[i].is_prime());
        }
    }
}
