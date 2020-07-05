// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include "seal/util/polycore.h"
#include "seal/util/uintarith.h"
#include <cstdint>
#include "gtest/gtest.h"

using namespace seal::util;
using namespace std;

namespace sealtest
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

        TEST(PolyCore, AllocatePolyArray)
        {
            MemoryPool &pool = *global_variables::global_memory_pool;
            auto ptr(allocate_poly_array(0, 0, 0, pool));
            ASSERT_TRUE(nullptr == ptr.get());

            ptr = allocate_poly_array(1, 0, 0, pool);
            ASSERT_TRUE(nullptr == ptr.get());

            ptr = allocate_poly_array(0, 1, 0, pool);
            ASSERT_TRUE(nullptr == ptr.get());

            ptr = allocate_poly_array(0, 0, 1, pool);
            ASSERT_TRUE(nullptr == ptr.get());

            ptr = allocate_poly_array(1, 0, 1, pool);
            ASSERT_TRUE(nullptr == ptr.get());

            ptr = allocate_poly_array(0, 1, 1, pool);
            ASSERT_TRUE(nullptr == ptr.get());

            ptr = allocate_poly_array(1, 1, 0, pool);
            ASSERT_TRUE(nullptr == ptr.get());

            ptr = allocate_poly_array(1, 1, 1, pool);
            ASSERT_TRUE(nullptr != ptr.get());

            ptr = allocate_poly_array(2, 1, 1, pool);
            ASSERT_TRUE(nullptr != ptr.get());
        }

        TEST(PolyCore, SetZeroPolyArray)
        {
            set_zero_poly_array(0, 0, 0, nullptr);

            MemoryPool &pool = *global_variables::global_memory_pool;
            auto ptr(allocate_poly_array(1, 1, 1, pool));
            ptr[0] = 0x1234567812345678;
            set_zero_poly_array(1, 1, 1, ptr.get());
            ASSERT_EQ(static_cast<uint64_t>(0), ptr[0]);

            ptr = allocate_poly_array(2, 3, 4, pool);
            for (size_t i = 0; i < 24; ++i)
            {
                ptr[i] = 0x1234567812345678;
            }
            set_zero_poly_array(2, 3, 4, ptr.get());
            for (size_t i = 0; i < 24; ++i)
            {
                ASSERT_EQ(static_cast<uint64_t>(0), ptr[i]);
            }
        }

        TEST(PolyCore, AllocateZeroPolyArray)
        {
            MemoryPool &pool = *global_variables::global_memory_pool;
            auto ptr(allocate_zero_poly_array(0, 0, 0, pool));
            ASSERT_TRUE(nullptr == ptr.get());

            ptr = allocate_zero_poly_array(1, 1, 1, pool);
            ASSERT_TRUE(nullptr != ptr.get());
            ASSERT_EQ(static_cast<uint64_t>(0), ptr[0]);

            ptr = allocate_zero_poly_array(2, 3, 4, pool);
            ASSERT_TRUE(nullptr != ptr.get());
            for (size_t i = 0; i < 24; ++i)
            {
                ASSERT_EQ(static_cast<uint64_t>(0), ptr[i]);
            }
        }

        TEST(PolyCore, SetPoly)
        {
            MemoryPool &pool = *global_variables::global_memory_pool;
            auto ptr1(allocate_poly(2, 3, pool));
            auto ptr2(allocate_zero_poly(2, 3, pool));
            for (size_t i = 0; i < 6; ++i)
            {
                ptr1[i] = static_cast<uint64_t>(i + 1);
            }
            set_poly(ptr1.get(), 2, 3, ptr2.get());
            for (size_t i = 0; i < 6; ++i)
            {
                ASSERT_EQ(static_cast<uint64_t>(i + 1), ptr2[i]);
            }

            set_poly(ptr1.get(), 2, 3, ptr1.get());
            for (size_t i = 0; i < 6; ++i)
            {
                ASSERT_EQ(static_cast<uint64_t>(i + 1), ptr2[i]);
            }
        }

        TEST(PolyCore, SetPolyArray)
        {
            MemoryPool &pool = *global_variables::global_memory_pool;
            auto ptr1(allocate_poly_array(1, 2, 3, pool));
            auto ptr2(allocate_zero_poly_array(1, 2, 3, pool));
            for (size_t i = 0; i < 6; ++i)
            {
                ptr1[i] = static_cast<uint64_t>(i + 1);
            }
            set_poly_array(ptr1.get(), 1, 2, 3, ptr2.get());
            for (size_t i = 0; i < 6; ++i)
            {
                ASSERT_EQ(static_cast<uint64_t>(i + 1), ptr2[i]);
            }

            set_poly_array(ptr1.get(), 1, 2, 3, ptr1.get());
            for (size_t i = 0; i < 6; ++i)
            {
                ASSERT_EQ(static_cast<uint64_t>(i + 1), ptr2[i]);
            }

            ptr2 = allocate_poly_array(2, 3, 4, pool);
            for (size_t i = 0; i < 24; ++i)
            {
                ptr2[i] = 1ULL;
            }
            auto ptr3(allocate_zero_poly_array(2, 3, 4, pool));

            set_poly_array(ptr2.get(), 2, 3, 4, ptr3.get());
            for (size_t i = 0; i < 24; i++)
            {
                ASSERT_EQ(ptr2[i], ptr3[i]);
            }
        }
    } // namespace util
} // namespace sealtest
