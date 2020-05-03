// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include "seal/util/uintarithmod.h"
#include "seal/util/uintcore.h"
#include <algorithm>
#include <cstdint>
#include "gtest/gtest.h"

using namespace seal::util;
using namespace std;

namespace sealtest
{
    namespace util
    {
        TEST(UIntArithMod, IncrementUIntMod)
        {
            MemoryPool &pool = *global_variables::global_memory_pool;
            auto value(allocate_uint(2, pool));
            auto modulus(allocate_uint(2, pool));
            value[0] = 0;
            value[1] = 0;
            modulus[0] = 3;
            modulus[1] = 0;
            increment_uint_mod(value.get(), modulus.get(), 2, value.get());
            ASSERT_EQ(1ULL, value[0]);
            ASSERT_EQ(static_cast<uint64_t>(0), value[1]);
            increment_uint_mod(value.get(), modulus.get(), 2, value.get());
            ASSERT_EQ(static_cast<uint64_t>(2), value[0]);
            ASSERT_EQ(static_cast<uint64_t>(0), value[1]);
            increment_uint_mod(value.get(), modulus.get(), 2, value.get());
            ASSERT_EQ(static_cast<uint64_t>(0), value[0]);
            ASSERT_EQ(static_cast<uint64_t>(0), value[1]);

            value[0] = 0xFFFFFFFFFFFFFFFD;
            value[1] = 0xFFFFFFFFFFFFFFFF;
            modulus[0] = 0xFFFFFFFFFFFFFFFF;
            modulus[1] = 0xFFFFFFFFFFFFFFFF;
            increment_uint_mod(value.get(), modulus.get(), 2, value.get());
            ASSERT_EQ(static_cast<uint64_t>(0xFFFFFFFFFFFFFFFE), value[0]);
            ASSERT_EQ(static_cast<uint64_t>(0xFFFFFFFFFFFFFFFF), value[1]);
            increment_uint_mod(value.get(), modulus.get(), 2, value.get());
            ASSERT_EQ(static_cast<uint64_t>(0), value[0]);
            ASSERT_EQ(static_cast<uint64_t>(0), value[1]);
            increment_uint_mod(value.get(), modulus.get(), 2, value.get());
            ASSERT_EQ(1ULL, value[0]);
            ASSERT_EQ(static_cast<uint64_t>(0), value[1]);
        }

        TEST(UIntArithMod, DecrementUIntMod)
        {
            MemoryPool &pool = *global_variables::global_memory_pool;
            auto value(allocate_uint(2, pool));
            auto modulus(allocate_uint(2, pool));
            value[0] = 2;
            value[1] = 0;
            modulus[0] = 3;
            modulus[1] = 0;
            decrement_uint_mod(value.get(), modulus.get(), 2, value.get());
            ASSERT_EQ(1ULL, value[0]);
            ASSERT_EQ(static_cast<uint64_t>(0), value[1]);
            decrement_uint_mod(value.get(), modulus.get(), 2, value.get());
            ASSERT_EQ(static_cast<uint64_t>(0), value[0]);
            ASSERT_EQ(static_cast<uint64_t>(0), value[1]);
            decrement_uint_mod(value.get(), modulus.get(), 2, value.get());
            ASSERT_EQ(static_cast<uint64_t>(2), value[0]);
            ASSERT_EQ(static_cast<uint64_t>(0), value[1]);

            value[0] = 1;
            value[1] = 0;
            modulus[0] = 0xFFFFFFFFFFFFFFFF;
            modulus[1] = 0xFFFFFFFFFFFFFFFF;
            decrement_uint_mod(value.get(), modulus.get(), 2, value.get());
            ASSERT_EQ(static_cast<uint64_t>(0), value[0]);
            ASSERT_EQ(static_cast<uint64_t>(0), value[1]);
            decrement_uint_mod(value.get(), modulus.get(), 2, value.get());
            ASSERT_EQ(static_cast<uint64_t>(0xFFFFFFFFFFFFFFFE), value[0]);
            ASSERT_EQ(static_cast<uint64_t>(0xFFFFFFFFFFFFFFFF), value[1]);
            decrement_uint_mod(value.get(), modulus.get(), 2, value.get());
            ASSERT_EQ(static_cast<uint64_t>(0xFFFFFFFFFFFFFFFD), value[0]);
            ASSERT_EQ(static_cast<uint64_t>(0xFFFFFFFFFFFFFFFF), value[1]);
        }

        TEST(UIntArithMod, NegateUIntMod)
        {
            MemoryPool &pool = *global_variables::global_memory_pool;
            auto value(allocate_uint(2, pool));
            auto modulus(allocate_uint(2, pool));
            value[0] = 0;
            value[1] = 0;
            modulus[0] = 3;
            modulus[1] = 0;
            negate_uint_mod(value.get(), modulus.get(), 2, value.get());
            ASSERT_EQ(static_cast<uint64_t>(0), value[0]);
            ASSERT_EQ(static_cast<uint64_t>(0), value[1]);

            value[0] = 1;
            value[1] = 0;
            modulus[0] = 3;
            modulus[1] = 0;
            negate_uint_mod(value.get(), modulus.get(), 2, value.get());
            ASSERT_EQ(static_cast<uint64_t>(2), value[0]);
            ASSERT_EQ(static_cast<uint64_t>(0), value[1]);
            negate_uint_mod(value.get(), modulus.get(), 2, value.get());
            ASSERT_EQ(1ULL, value[0]);
            ASSERT_EQ(static_cast<uint64_t>(0), value[1]);

            value[0] = 2;
            value[1] = 0;
            modulus[0] = 0xFFFFFFFFFFFFFFFF;
            modulus[1] = 0xFFFFFFFFFFFFFFFF;
            negate_uint_mod(value.get(), modulus.get(), 2, value.get());
            ASSERT_EQ(static_cast<uint64_t>(0xFFFFFFFFFFFFFFFD), value[0]);
            ASSERT_EQ(static_cast<uint64_t>(0xFFFFFFFFFFFFFFFF), value[1]);
            negate_uint_mod(value.get(), modulus.get(), 2, value.get());
            ASSERT_EQ(static_cast<uint64_t>(2), value[0]);
            ASSERT_EQ(static_cast<uint64_t>(0), value[1]);
        }

        TEST(UIntArithMod, Div2UIntMod)
        {
            MemoryPool &pool = *global_variables::global_memory_pool;
            auto value(allocate_uint(2, pool));
            auto modulus(allocate_uint(2, pool));
            value[0] = 0;
            value[1] = 0;
            modulus[0] = 3;
            modulus[1] = 0;
            div2_uint_mod(value.get(), modulus.get(), 2, value.get());
            ASSERT_EQ(0ULL, value[0]);
            ASSERT_EQ(0ULL, value[1]);

            value[0] = 1;
            value[1] = 0;
            modulus[0] = 3;
            modulus[1] = 0;
            div2_uint_mod(value.get(), modulus.get(), 2, value.get());
            ASSERT_EQ(2ULL, value[0]);
            ASSERT_EQ(0ULL, value[1]);

            value[0] = 8;
            value[1] = 0;
            modulus[0] = 17;
            modulus[1] = 0;
            div2_uint_mod(value.get(), modulus.get(), 2, value.get());
            ASSERT_EQ(4ULL, value[0]);
            ASSERT_EQ(0ULL, value[1]);

            value[0] = 5;
            value[1] = 0;
            modulus[0] = 17;
            modulus[1] = 0;
            div2_uint_mod(value.get(), modulus.get(), 2, value.get());
            ASSERT_EQ(11ULL, value[0]);
            ASSERT_EQ(0ULL, value[1]);

            value[0] = 1;
            value[1] = 0;
            modulus[0] = 0xFFFFFFFFFFFFFFFFULL;
            modulus[1] = 0xFFFFFFFFFFFFFFFFULL;
            div2_uint_mod(value.get(), modulus.get(), 2, value.get());
            ASSERT_EQ(0ULL, value[0]);
            ASSERT_EQ(0x8000000000000000ULL, value[1]);

            value[0] = 3;
            value[1] = 0;
            modulus[0] = 0xFFFFFFFFFFFFFFFFULL;
            modulus[1] = 0xFFFFFFFFFFFFFFFFULL;
            div2_uint_mod(value.get(), modulus.get(), 2, value.get());
            ASSERT_EQ(1ULL, value[0]);
            ASSERT_EQ(0x8000000000000000ULL, value[1]);
        }

        TEST(UIntArithMod, AddUIntMod)
        {
            MemoryPool &pool = *global_variables::global_memory_pool;
            auto value1(allocate_uint(2, pool));
            auto value2(allocate_uint(2, pool));
            auto modulus(allocate_uint(2, pool));
            value1[0] = 0;
            value1[1] = 0;
            value2[0] = 0;
            value2[1] = 0;
            modulus[0] = 3;
            modulus[1] = 0;
            add_uint_uint_mod(value1.get(), value2.get(), modulus.get(), 2, value1.get());
            ASSERT_EQ(static_cast<uint64_t>(0), value1[0]);
            ASSERT_EQ(static_cast<uint64_t>(0), value1[1]);

            value1[0] = 1;
            value1[1] = 0;
            value2[0] = 1;
            value2[1] = 0;
            modulus[0] = 3;
            modulus[1] = 0;
            add_uint_uint_mod(value1.get(), value2.get(), modulus.get(), 2, value1.get());
            ASSERT_EQ(static_cast<uint64_t>(2), value1[0]);
            ASSERT_EQ(static_cast<uint64_t>(0), value1[1]);

            value1[0] = 1;
            value1[1] = 0;
            value2[0] = 2;
            value2[1] = 0;
            modulus[0] = 3;
            modulus[1] = 0;
            add_uint_uint_mod(value1.get(), value2.get(), modulus.get(), 2, value1.get());
            ASSERT_EQ(static_cast<uint64_t>(0), value1[0]);
            ASSERT_EQ(static_cast<uint64_t>(0), value1[1]);

            value1[0] = 2;
            value1[1] = 0;
            value2[0] = 2;
            value2[1] = 0;
            modulus[0] = 3;
            modulus[1] = 0;
            add_uint_uint_mod(value1.get(), value2.get(), modulus.get(), 2, value1.get());
            ASSERT_EQ(1ULL, value1[0]);
            ASSERT_EQ(static_cast<uint64_t>(0), value1[1]);

            value1[0] = 0xFFFFFFFFFFFFFFFE;
            value1[1] = 0xFFFFFFFFFFFFFFFF;
            value2[0] = 0xFFFFFFFFFFFFFFFE;
            value2[1] = 0xFFFFFFFFFFFFFFFF;
            modulus[0] = 0xFFFFFFFFFFFFFFFF;
            modulus[1] = 0xFFFFFFFFFFFFFFFF;
            add_uint_uint_mod(value1.get(), value2.get(), modulus.get(), 2, value1.get());
            ASSERT_EQ(static_cast<uint64_t>(0xFFFFFFFFFFFFFFFD), value1[0]);
            ASSERT_EQ(static_cast<uint64_t>(0xFFFFFFFFFFFFFFFF), value1[1]);
        }

        TEST(UIntArithMod, SubUIntMod)
        {
            MemoryPool &pool = *global_variables::global_memory_pool;
            auto value1(allocate_uint(2, pool));
            auto value2(allocate_uint(2, pool));
            auto modulus(allocate_uint(2, pool));
            value1[0] = 0;
            value1[1] = 0;
            value2[0] = 0;
            value2[1] = 0;
            modulus[0] = 3;
            modulus[1] = 0;
            sub_uint_uint_mod(value1.get(), value2.get(), modulus.get(), 2, value1.get());
            ASSERT_EQ(static_cast<uint64_t>(0), value1[0]);
            ASSERT_EQ(static_cast<uint64_t>(0), value1[1]);

            value1[0] = 2;
            value1[1] = 0;
            value2[0] = 1;
            value2[1] = 0;
            modulus[0] = 3;
            modulus[1] = 0;
            sub_uint_uint_mod(value1.get(), value2.get(), modulus.get(), 2, value1.get());
            ASSERT_EQ(1ULL, value1[0]);
            ASSERT_EQ(static_cast<uint64_t>(0), value1[1]);

            value1[0] = 1;
            value1[1] = 0;
            value2[0] = 2;
            value2[1] = 0;
            modulus[0] = 3;
            modulus[1] = 0;
            sub_uint_uint_mod(value1.get(), value2.get(), modulus.get(), 2, value1.get());
            ASSERT_EQ(static_cast<uint64_t>(2), value1[0]);
            ASSERT_EQ(static_cast<uint64_t>(0), value1[1]);

            value1[0] = 2;
            value1[1] = 0;
            value2[0] = 2;
            value2[1] = 0;
            modulus[0] = 3;
            modulus[1] = 0;
            sub_uint_uint_mod(value1.get(), value2.get(), modulus.get(), 2, value1.get());
            ASSERT_EQ(static_cast<uint64_t>(0), value1[0]);
            ASSERT_EQ(static_cast<uint64_t>(0), value1[1]);

            value1[0] = 1;
            value1[1] = 0;
            value2[0] = 0xFFFFFFFFFFFFFFFE;
            value2[1] = 0xFFFFFFFFFFFFFFFF;
            modulus[0] = 0xFFFFFFFFFFFFFFFF;
            modulus[1] = 0xFFFFFFFFFFFFFFFF;
            sub_uint_uint_mod(value1.get(), value2.get(), modulus.get(), 2, value1.get());
            ASSERT_EQ(static_cast<uint64_t>(2), value1[0]);
            ASSERT_EQ(static_cast<uint64_t>(0), value1[1]);
        }

        TEST(UIntArithMod, TryInvertUIntMod)
        {
            MemoryPool &pool = *global_variables::global_memory_pool;
            auto value(allocate_uint(2, pool));
            auto modulus(allocate_uint(2, pool));
            value[0] = 0;
            value[1] = 0;
            modulus[0] = 5;
            modulus[1] = 0;
            ASSERT_FALSE(try_invert_uint_mod(value.get(), modulus.get(), 2, value.get(), pool));

            value[0] = 1;
            value[1] = 0;
            modulus[0] = 5;
            modulus[1] = 0;
            ASSERT_TRUE(try_invert_uint_mod(value.get(), modulus.get(), 2, value.get(), pool));
            ASSERT_EQ(1ULL, value[0]);
            ASSERT_EQ(static_cast<uint64_t>(0), value[1]);

            value[0] = 2;
            value[1] = 0;
            modulus[0] = 5;
            modulus[1] = 0;
            ASSERT_TRUE(try_invert_uint_mod(value.get(), modulus.get(), 2, value.get(), pool));
            ASSERT_EQ(static_cast<uint64_t>(3), value[0]);
            ASSERT_EQ(static_cast<uint64_t>(0), value[1]);

            value[0] = 3;
            value[1] = 0;
            modulus[0] = 5;
            modulus[1] = 0;
            ASSERT_TRUE(try_invert_uint_mod(value.get(), modulus.get(), 2, value.get(), pool));
            ASSERT_EQ(static_cast<uint64_t>(2), value[0]);
            ASSERT_EQ(static_cast<uint64_t>(0), value[1]);

            value[0] = 4;
            value[1] = 0;
            modulus[0] = 5;
            modulus[1] = 0;
            ASSERT_TRUE(try_invert_uint_mod(value.get(), modulus.get(), 2, value.get(), pool));
            ASSERT_EQ(static_cast<uint64_t>(4), value[0]);
            ASSERT_EQ(static_cast<uint64_t>(0), value[1]);

            value[0] = 2;
            value[1] = 0;
            modulus[0] = 6;
            modulus[1] = 0;
            ASSERT_FALSE(try_invert_uint_mod(value.get(), modulus.get(), 2, value.get(), pool));

            value[0] = 3;
            value[1] = 0;
            modulus[0] = 6;
            modulus[1] = 0;
            ASSERT_FALSE(try_invert_uint_mod(value.get(), modulus.get(), 2, value.get(), pool));

            value[0] = 331975426;
            value[1] = 0;
            modulus[0] = 1351315121;
            modulus[1] = 0;
            ASSERT_TRUE(try_invert_uint_mod(value.get(), modulus.get(), 2, value.get(), pool));
            ASSERT_EQ(static_cast<uint64_t>(1052541512), value[0]);
            ASSERT_EQ(static_cast<uint64_t>(0), value[1]);
        }
    } // namespace util
} // namespace sealtest
