// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include "gtest/gtest.h"
#include "seal/util/uintcore.h"
#include "seal/util/polycore.h"
#include "seal/util/polyarithmod.h"
#include <cstdint>

using namespace seal;
using namespace seal::util;
using namespace std;

namespace SEALTest
{
   namespace util
   {
        TEST(PolyArithMod, NegatePolyCoeffMod)
        {
            MemoryPool &pool = *global_variables::global_memory_pool;
            auto poly(allocate_zero_poly(3, 2, pool));
            auto modulus(allocate_uint(2, pool));
            poly[0] = 2;
            poly[2] = 3;
            poly[4] = 4;
            modulus[0] = 15;
            modulus[1] = 0;
            negate_poly_coeffmod(poly.get(), 3, modulus.get(), 2, poly.get());
            ASSERT_EQ(static_cast<uint64_t>(13), poly[0]);
            ASSERT_EQ(static_cast<uint64_t>(0), poly[1]);
            ASSERT_EQ(static_cast<uint64_t>(12), poly[2]);
            ASSERT_EQ(static_cast<uint64_t>(0), poly[3]);
            ASSERT_EQ(static_cast<uint64_t>(11), poly[4]);
            ASSERT_EQ(static_cast<uint64_t>(0), poly[5]);

            poly[0] = 2;
            poly[2] = 3;
            poly[4] = 4;
            modulus[0] = 0xFFFFFFFFFFFFFFFF;
            modulus[1] = 0xFFFFFFFFFFFFFFFF;
            negate_poly_coeffmod(poly.get(), 3, modulus.get(), 2, poly.get());
            ASSERT_EQ(static_cast<uint64_t>(0xFFFFFFFFFFFFFFFD), poly[0]);
            ASSERT_EQ(static_cast<uint64_t>(0xFFFFFFFFFFFFFFFF), poly[1]);
            ASSERT_EQ(static_cast<uint64_t>(0xFFFFFFFFFFFFFFFC), poly[2]);
            ASSERT_EQ(static_cast<uint64_t>(0xFFFFFFFFFFFFFFFF), poly[3]);
            ASSERT_EQ(static_cast<uint64_t>(0xFFFFFFFFFFFFFFFB), poly[4]);
            ASSERT_EQ(static_cast<uint64_t>(0xFFFFFFFFFFFFFFFF), poly[5]);
        }

        TEST(PolyArithMod, AddPolyPolyCoeffMod)
        {
            MemoryPool &pool = *global_variables::global_memory_pool;
            auto poly1(allocate_zero_poly(3, 2, pool));
            auto poly2(allocate_zero_poly(3, 2, pool));
            auto modulus(allocate_uint(2, pool));
            poly1[0] = 1;
            poly1[2] = 3;
            poly1[4] = 4;
            poly2[0] = 1;
            poly2[2] = 2;
            poly2[4] = 4;
            modulus[0] = 5;
            modulus[1] = 0;
            add_poly_poly_coeffmod(poly1.get(), poly2.get(), 3, modulus.get(), 2, poly1.get());
            ASSERT_EQ(static_cast<uint64_t>(2), poly1[0]);
            ASSERT_EQ(static_cast<uint64_t>(0), poly1[1]);
            ASSERT_EQ(static_cast<uint64_t>(0), poly1[2]);
            ASSERT_EQ(static_cast<uint64_t>(0), poly1[3]);
            ASSERT_EQ(static_cast<uint64_t>(3), poly1[4]);
            ASSERT_EQ(static_cast<uint64_t>(0), poly1[5]);
        }

        TEST(PolyArithMod, SubPolyPolyCoeffMod)
        {
            MemoryPool &pool = *global_variables::global_memory_pool;
            auto poly1(allocate_zero_poly(3, 2, pool));
            auto poly2(allocate_zero_poly(3, 2, pool));
            auto modulus(allocate_uint(2, pool));
            poly1[0] = 4;
            poly1[2] = 3;
            poly1[4] = 2;
            poly2[0] = 2;
            poly2[2] = 3;
            poly2[4] = 4;
            modulus[0] = 5;
            modulus[1] = 0;
            sub_poly_poly_coeffmod(poly1.get(), poly2.get(), 3, modulus.get(), 2, poly1.get());
            ASSERT_EQ(static_cast<uint64_t>(2), poly1[0]);
            ASSERT_EQ(static_cast<uint64_t>(0), poly1[1]);
            ASSERT_EQ(static_cast<uint64_t>(0), poly1[2]);
            ASSERT_EQ(static_cast<uint64_t>(0), poly1[3]);
            ASSERT_EQ(static_cast<uint64_t>(3), poly1[4]);
            ASSERT_EQ(static_cast<uint64_t>(0), poly1[5]);
        }
   }
}
