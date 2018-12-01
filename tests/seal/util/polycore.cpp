// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include "gtest/gtest.h"
#include "seal/util/polycore.h"
#include "seal/util/uintarith.h"
#include <cstdint>

using namespace seal::util;
using namespace std;

namespace SEALTest
{
   namespace util
   {
        TEST(PolyCore, AllocatePoly)
        {
            MemoryPool &pool = *global_variables::global_memory_pool;
            auto ptr(allocate_poly(0, 0, pool));
            ASSERT_TRUE(nullptr == ptr.get());

            ptr = allocate_poly(1, 0, pool);
            ASSERT_TRUE(nullptr == ptr.get());

            ptr = allocate_poly(0, 1, pool);
            ASSERT_TRUE(nullptr == ptr.get());

            ptr = allocate_poly(1, 1, pool);
            ASSERT_TRUE(nullptr != ptr.get());

            ptr = allocate_poly(2, 1, pool);
            ASSERT_TRUE(nullptr != ptr.get());
        }

        TEST(PolyCore, SetZeroPoly)
        {
            set_zero_poly(0, 0, nullptr);

            MemoryPool &pool = *global_variables::global_memory_pool;
            auto ptr(allocate_poly(1, 1, pool));
            ptr[0] = 0x1234567812345678;
            set_zero_poly(1, 1, ptr.get());
            ASSERT_EQ(static_cast<uint64_t>(0), ptr[0]);

            ptr = allocate_poly(2, 3, pool);
            for (size_t i = 0; i < 6; ++i)
            {
                ptr[i] = 0x1234567812345678;
            }
            set_zero_poly(2, 3, ptr.get());
            for (size_t i = 0; i < 6; ++i)
            {
                ASSERT_EQ(static_cast<uint64_t>(0), ptr[i]);
            }
        }

        TEST(PolyCore, AllocateZeroPoly)
        {
            MemoryPool &pool = *global_variables::global_memory_pool;
            auto ptr(allocate_zero_poly(0, 0, pool));
            ASSERT_TRUE(nullptr == ptr.get());

            ptr = allocate_zero_poly(1, 1, pool);
            ASSERT_TRUE(nullptr != ptr.get());
            ASSERT_EQ(static_cast<uint64_t>(0), ptr[0]);

            ptr = allocate_zero_poly(2, 3, pool);
            ASSERT_TRUE(nullptr != ptr.get());
            for (size_t i = 0; i < 6; ++i)
            {
                ASSERT_EQ(static_cast<uint64_t>(0), ptr[i]);
            }
        }

        TEST(PolyCore, GetPolyCoeff)
        {
            MemoryPool &pool = *global_variables::global_memory_pool;
            auto ptr(allocate_zero_poly(2, 3, pool));
            *get_poly_coeff(ptr.get(), 0, 3) = 1;
            *get_poly_coeff(ptr.get(), 1, 3) = 2;
            ASSERT_EQ(1ULL, ptr[0]);
            ASSERT_EQ(static_cast<uint64_t>(2), ptr[3]);
            ASSERT_EQ(1ULL, *get_poly_coeff(ptr.get(), 0, 3));
            ASSERT_EQ(static_cast<uint64_t>(2), *get_poly_coeff(ptr.get(), 1, 3));
        }

        TEST(PolyCore, SetPolyPoly)
        {
            MemoryPool &pool = *global_variables::global_memory_pool;
            auto ptr1(allocate_poly(2, 3, pool));
            auto ptr2(allocate_zero_poly(2, 3, pool));
            for (size_t i = 0; i < 6; ++i)
            {
                ptr1[i] = static_cast<uint64_t>(i + 1);
            }
            set_poly_poly(ptr1.get(), 2, 3, ptr2.get());
            for (size_t i = 0; i < 6; ++i)
            {
                ASSERT_EQ(static_cast<uint64_t>(i + 1), ptr2[i]);
            }

            set_poly_poly(ptr1.get(), 2, 3, ptr1.get());
            for (size_t i = 0; i < 6; ++i)
            {
                ASSERT_EQ(static_cast<uint64_t>(i + 1), ptr2[i]);
            }

            ptr2 = allocate_poly(3, 4, pool);
            for (size_t i = 0; i < 12; ++i)
            {
                ptr2[i] = 1ULL;
            }
            set_poly_poly(ptr1.get(), 2, 3, 3, 4, ptr2.get());
            ASSERT_EQ(1ULL, ptr2[0]);
            ASSERT_EQ(static_cast<uint64_t>(2), ptr2[1]);
            ASSERT_EQ(static_cast<uint64_t>(3), ptr2[2]);
            ASSERT_EQ(static_cast<uint64_t>(0), ptr2[3]);
            ASSERT_EQ(static_cast<uint64_t>(4), ptr2[4]);
            ASSERT_EQ(static_cast<uint64_t>(5), ptr2[5]);
            ASSERT_EQ(static_cast<uint64_t>(6), ptr2[6]);
            ASSERT_EQ(static_cast<uint64_t>(0), ptr2[7]);
            ASSERT_EQ(static_cast<uint64_t>(0), ptr2[8]);
            ASSERT_EQ(static_cast<uint64_t>(0), ptr2[9]);
            ASSERT_EQ(static_cast<uint64_t>(0), ptr2[10]);
            ASSERT_EQ(static_cast<uint64_t>(0), ptr2[11]);

            ptr2 = allocate_poly(1, 2, pool);
            ptr2[0] = 1;
            ptr2[1] = 1;
            set_poly_poly(ptr1.get(), 2, 3, 1, 2, ptr2.get());
            ASSERT_EQ(1ULL, ptr2[0]);
            ASSERT_EQ(static_cast<uint64_t>(2), ptr2[1]);
        }

        TEST(PolyCore, IsZeroPoly)
        {
            ASSERT_TRUE(is_zero_poly(nullptr, 0, 0));

            MemoryPool &pool = *global_variables::global_memory_pool;
            auto ptr(allocate_poly(2, 3, pool));
            for (size_t i = 0; i < 6; ++i)
            {
                ptr[i] = 0;
            }
            ASSERT_TRUE(is_zero_poly(ptr.get(), 2, 3));
            for (size_t i = 0; i < 6; ++i)
            {
                ptr[i] = 1;
                ASSERT_FALSE(is_zero_poly(ptr.get(), 2, 3));
                ptr[i] = 0;
            }
        }

        TEST(PolyCore, IsEqualPolyPoly)
        {
            ASSERT_TRUE(is_equal_poly_poly(nullptr, nullptr, 0, 0));

            MemoryPool &pool = *global_variables::global_memory_pool;
            auto ptr1(allocate_poly(2, 3, pool));
            auto ptr2(allocate_poly(2, 3, pool));
            for (size_t i = 0; i < 6; ++i)
            {
                ptr2[i] = ptr1[i] = static_cast<uint64_t>(i + 1);
            }
            ASSERT_TRUE(is_equal_poly_poly(ptr1.get(), ptr2.get(), 2, 3));
            for (size_t i = 0; i < 6; ++i)
            {
                ptr2[i]--;
                ASSERT_FALSE(is_equal_poly_poly(ptr1.get(), ptr2.get(), 2, 3));
                ptr2[i]++;
            }
        }

        TEST(PolyCore, IsOneZeroOnePoly)
        {
            ASSERT_FALSE(is_one_zero_one_poly(nullptr, 0, 0));

            MemoryPool &pool = *global_variables::global_memory_pool;
            auto poly(allocate_zero_poly(4, 2, pool));
            ASSERT_FALSE(is_one_zero_one_poly(poly.get(), 0, 2));
            ASSERT_FALSE(is_one_zero_one_poly(poly.get(), 1, 2));
            ASSERT_FALSE(is_one_zero_one_poly(poly.get(), 2, 2));
            ASSERT_FALSE(is_one_zero_one_poly(poly.get(), 3, 2));

            poly[0] = 2;
            ASSERT_FALSE(is_one_zero_one_poly(poly.get(), 1, 2));
            ASSERT_FALSE(is_one_zero_one_poly(poly.get(), 2, 2));

            poly[0] = 1;
            ASSERT_TRUE(is_one_zero_one_poly(poly.get(), 1, 2));
            ASSERT_FALSE(is_one_zero_one_poly(poly.get(), 2, 2));

            poly[2] = 2;
            ASSERT_FALSE(is_one_zero_one_poly(poly.get(), 2, 2));
            ASSERT_FALSE(is_one_zero_one_poly(poly.get(), 3, 2));

            poly[2] = 1;
            ASSERT_TRUE(is_one_zero_one_poly(poly.get(), 2, 2));
            ASSERT_FALSE(is_one_zero_one_poly(poly.get(), 3, 2));

            poly[4] = 1;
            ASSERT_FALSE(is_one_zero_one_poly(poly.get(), 3, 2));
            ASSERT_FALSE(is_one_zero_one_poly(poly.get(), 4, 2));

            poly[2] = 0;
            ASSERT_TRUE(is_one_zero_one_poly(poly.get(), 3, 2));
            ASSERT_FALSE(is_one_zero_one_poly(poly.get(), 4, 2));

            poly[6] = 2;
            ASSERT_FALSE(is_one_zero_one_poly(poly.get(), 4, 2));

            poly[6] = 1;
            ASSERT_FALSE(is_one_zero_one_poly(poly.get(), 4, 2));

            poly[4] = 0;
            ASSERT_TRUE(is_one_zero_one_poly(poly.get(), 4, 2));
        }

        TEST(PolyCore, GetSignificantCoeffCountPoly)
        {
            ASSERT_EQ(0ULL, get_significant_coeff_count_poly(nullptr, 0, 0));

            MemoryPool &pool = *global_variables::global_memory_pool;
            auto ptr(allocate_zero_poly(3, 2, pool));
            ASSERT_EQ(0ULL, get_significant_coeff_count_poly(ptr.get(), 3, 2));
            ptr[0] = 1;
            ASSERT_EQ(1ULL, get_significant_coeff_count_poly(ptr.get(), 3, 2));
            ptr[1] = 1;
            ASSERT_EQ(1ULL, get_significant_coeff_count_poly(ptr.get(), 3, 2));
            ptr[4] = 1;
            ASSERT_EQ(3ULL, get_significant_coeff_count_poly(ptr.get(), 3, 2));
            ptr[4] = 0;
            ptr[5] = 1;
            ASSERT_EQ(3ULL, get_significant_coeff_count_poly(ptr.get(), 3, 2));
        }

        TEST(PolyCore, DuplicatePolyIfNeeded)
        {
            ASSERT_EQ(0ULL, get_significant_coeff_count_poly(nullptr, 0, 0));

            MemoryPool &pool = *global_variables::global_memory_pool;
            auto poly(allocate_poly(3, 2, pool));
            for (size_t i = 0; i < 6; i++)
            {
                poly[i] = i + 1;
            }

            auto ptr = duplicate_poly_if_needed(poly.get(), 3, 2, 3, 2, false, pool);
            ASSERT_TRUE(ptr.get() == poly.get());
            ptr = duplicate_poly_if_needed(poly.get(), 3, 2, 2, 2, false, pool);
            ASSERT_TRUE(ptr.get() == poly.get());
            ptr = duplicate_poly_if_needed(poly.get(), 3, 2, 2, 3, false, pool);
            ASSERT_TRUE(ptr.get() != poly.get());
            ASSERT_EQ(1ULL, ptr[0]);
            ASSERT_EQ(static_cast<uint64_t>(2), ptr[1]);
            ASSERT_EQ(static_cast<uint64_t>(0), ptr[2]);
            ASSERT_EQ(static_cast<uint64_t>(3), ptr[3]);
            ASSERT_EQ(static_cast<uint64_t>(4), ptr[4]);
            ASSERT_EQ(static_cast<uint64_t>(0), ptr[5]);

            ptr = duplicate_poly_if_needed(poly.get(), 3, 2, 3, 2, true, pool);
            ASSERT_TRUE(ptr.get() != poly.get());
            for (size_t i = 0; i < 6; i++)
            {
                ASSERT_EQ(static_cast<uint64_t>(i + 1), ptr[i]);
            }
        }

        TEST(PolyCore, ArePolyCoeffsLessThan)
        {
            MemoryPool &pool = *global_variables::global_memory_pool;
            auto poly(allocate_zero_poly(3, 2, pool));
            poly[0] = 3;
            poly[2] = 5;
            poly[4] = 4;

            auto max(allocate_uint(1, pool));
            max[0] = 1;
            ASSERT_FALSE(are_poly_coefficients_less_than(poly.get(), 3, 2, max.get(), 1));
            max[0] = 5;
            ASSERT_FALSE(are_poly_coefficients_less_than(poly.get(), 3, 2, max.get(), 1));
            max[0] = 6;
            ASSERT_TRUE(are_poly_coefficients_less_than(poly.get(), 3, 2, max.get(), 1));
            max[0] = 10;
            ASSERT_TRUE(are_poly_coefficients_less_than(poly.get(), 3, 2, max.get(), 1));
        }
   }
}
