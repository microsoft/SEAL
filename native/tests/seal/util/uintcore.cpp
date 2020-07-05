// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include "seal/util/uintcore.h"
#include <cstdint>
#include "gtest/gtest.h"

using namespace seal::util;
using namespace std;

namespace sealtest
{
    namespace util
    {
        TEST(UIntCore, AllocateUInt)
        {
            MemoryPool &pool = *global_variables::global_memory_pool;
            auto ptr(allocate_uint(0, pool));
            ASSERT_TRUE(nullptr == ptr.get());

            ptr = allocate_uint(1, pool);
            ASSERT_TRUE(nullptr != ptr.get());

            ptr = allocate_uint(2, pool);
            ASSERT_TRUE(nullptr != ptr.get());
        }

        TEST(UIntCore, SetZeroUInt)
        {
            set_zero_uint(0, nullptr);

            MemoryPool &pool = *global_variables::global_memory_pool;
            auto ptr(allocate_uint(1, pool));
            ptr[0] = 0x1234567812345678;
            set_zero_uint(1, ptr.get());
            ASSERT_EQ(static_cast<uint64_t>(0), ptr[0]);

            ptr = allocate_uint(2, pool);
            ptr[0] = 0x1234567812345678;
            ptr[1] = 0x1234567812345678;
            set_zero_uint(2, ptr.get());
            ASSERT_EQ(static_cast<uint64_t>(0), ptr[0]);
            ASSERT_EQ(static_cast<uint64_t>(0), ptr[1]);
        }

        TEST(UIntCore, AllocateZeroUInt)
        {
            MemoryPool &pool = *global_variables::global_memory_pool;
            auto ptr(allocate_zero_uint(0, pool));
            ASSERT_TRUE(nullptr == ptr.get());

            ptr = allocate_zero_uint(1, pool);
            ASSERT_TRUE(nullptr != ptr.get());
            ASSERT_EQ(static_cast<uint64_t>(0), ptr[0]);

            ptr = allocate_zero_uint(2, pool);
            ASSERT_TRUE(nullptr != ptr.get());
            ASSERT_EQ(static_cast<uint64_t>(0), ptr[0]);
            ASSERT_EQ(static_cast<uint64_t>(0), ptr[1]);
        }

        TEST(UIntCore, SetUInt)
        {
            MemoryPool &pool = *global_variables::global_memory_pool;
            auto ptr(allocate_uint(1, pool));
            ptr[0] = 0xFFFFFFFFFFFFFFFF;
            set_uint(1, 1, ptr.get());
            ASSERT_EQ(1ULL, ptr[0]);

            ptr[0] = 0xFFFFFFFFFFFFFFFF;
            set_uint(0x1234567812345678, 1, ptr.get());
            ASSERT_EQ(static_cast<uint64_t>(0x1234567812345678), ptr[0]);

            ptr = allocate_uint(2, pool);
            ptr[0] = 0xFFFFFFFFFFFFFFFF;
            ptr[1] = 0xFFFFFFFFFFFFFFFF;
            set_uint(1, 2, ptr.get());
            ASSERT_EQ(1ULL, ptr[0]);
            ASSERT_EQ(static_cast<uint64_t>(0), ptr[1]);

            ptr[0] = 0xFFFFFFFFFFFFFFFF;
            ptr[1] = 0xFFFFFFFFFFFFFFFF;
            set_uint(0x1234567812345678, 2, ptr.get());
            ASSERT_EQ(static_cast<uint64_t>(0x1234567812345678), ptr[0]);
            ASSERT_EQ(static_cast<uint64_t>(0), ptr[1]);
        }

        TEST(UIntCore, SetUInt2)
        {
            set_uint(nullptr, 0, nullptr);

            MemoryPool &pool = *global_variables::global_memory_pool;
            auto ptr1(allocate_uint(1, pool));
            ptr1[0] = 0x1234567887654321;
            auto ptr2(allocate_uint(1, pool));
            ptr2[0] = 0xFFFFFFFFFFFFFFFF;
            set_uint(ptr1.get(), 1, ptr2.get());
            ASSERT_EQ(static_cast<uint64_t>(0x1234567887654321), ptr2[0]);

            ptr1[0] = 0x1231231231231231;
            set_uint(ptr1.get(), 1, ptr1.get());
            ASSERT_EQ(static_cast<uint64_t>(0x1231231231231231), ptr1[0]);

            ptr1 = allocate_uint(2, pool);
            ptr2 = allocate_uint(2, pool);
            ptr1[0] = 0x1234567887654321;
            ptr1[1] = 0x8765432112345678;
            ptr2[0] = 0xFFFFFFFFFFFFFFFF;
            ptr2[1] = 0xFFFFFFFFFFFFFFFF;
            set_uint(ptr1.get(), 2, ptr2.get());
            ASSERT_EQ(static_cast<uint64_t>(0x1234567887654321), ptr2[0]);
            ASSERT_EQ(static_cast<uint64_t>(0x8765432112345678), ptr2[1]);

            ptr1[0] = 0x1231231231231321;
            ptr1[1] = 0x3213213213213211;
            set_uint(ptr1.get(), 2, ptr1.get());
            ASSERT_EQ(static_cast<uint64_t>(0x1231231231231321), ptr1[0]);
            ASSERT_EQ(static_cast<uint64_t>(0x3213213213213211), ptr1[1]);
        }

        TEST(UIntCore, SetUInt3)
        {
            set_uint(nullptr, 0, 0, nullptr);

            MemoryPool &pool = *global_variables::global_memory_pool;
            auto ptr1(allocate_uint(1, pool));
            ptr1[0] = 0x1234567887654321;
            set_uint(nullptr, 0, 1, ptr1.get());
            ASSERT_EQ(static_cast<uint64_t>(0), ptr1[0]);

            auto ptr2(allocate_uint(1, pool));
            ptr1[0] = 0x1234567887654321;
            ptr2[0] = 0xFFFFFFFFFFFFFFFF;
            set_uint(ptr1.get(), 1, 1, ptr2.get());
            ASSERT_EQ(static_cast<uint64_t>(0x1234567887654321), ptr2[0]);

            ptr1[0] = 0x1231231231231231;
            set_uint(ptr1.get(), 1, 1, ptr1.get());
            ASSERT_EQ(static_cast<uint64_t>(0x1231231231231231), ptr1[0]);

            ptr1 = allocate_uint(2, pool);
            ptr2 = allocate_uint(2, pool);
            ptr1[0] = 0x1234567887654321;
            ptr1[1] = 0x8765432112345678;
            set_uint(nullptr, 0, 2, ptr1.get());
            ASSERT_EQ(static_cast<uint64_t>(0), ptr1[0]);
            ASSERT_EQ(static_cast<uint64_t>(0), ptr1[1]);

            ptr1[0] = 0x1234567887654321;
            ptr1[1] = 0x8765432112345678;
            ptr2[0] = 0xFFFFFFFFFFFFFFFF;
            ptr2[1] = 0xFFFFFFFFFFFFFFFF;
            set_uint(ptr1.get(), 1, 2, ptr2.get());
            ASSERT_EQ(static_cast<uint64_t>(0x1234567887654321), ptr2[0]);
            ASSERT_EQ(static_cast<uint64_t>(0), ptr2[1]);

            ptr2[0] = 0xFFFFFFFFFFFFFFFF;
            ptr2[1] = 0xFFFFFFFFFFFFFFFF;
            set_uint(ptr1.get(), 2, 2, ptr2.get());
            ASSERT_EQ(static_cast<uint64_t>(0x1234567887654321), ptr2[0]);
            ASSERT_EQ(static_cast<uint64_t>(0x8765432112345678), ptr2[1]);

            ptr1[0] = 0x1231231231231321;
            ptr1[1] = 0x3213213213213211;
            set_uint(ptr1.get(), 2, 2, ptr1.get());
            ASSERT_EQ(static_cast<uint64_t>(0x1231231231231321), ptr1[0]);
            ASSERT_EQ(static_cast<uint64_t>(0x3213213213213211), ptr1[1]);

            set_uint(ptr1.get(), 1, 2, ptr1.get());
            ASSERT_EQ(static_cast<uint64_t>(0x1231231231231321), ptr1[0]);
            ASSERT_EQ(static_cast<uint64_t>(0), ptr1[1]);
        }

        TEST(UIntCore, IsZeroUInt)
        {
            ASSERT_TRUE(is_zero_uint(nullptr, 0));

            MemoryPool &pool = *global_variables::global_memory_pool;
            auto ptr(allocate_uint(1, pool));
            ptr[0] = 1;
            ASSERT_FALSE(is_zero_uint(ptr.get(), 1));
            ptr[0] = 0;
            ASSERT_TRUE(is_zero_uint(ptr.get(), 1));

            ptr = allocate_uint(2, pool);
            ptr[0] = 0x8000000000000000;
            ptr[1] = 0x8000000000000000;
            ASSERT_FALSE(is_zero_uint(ptr.get(), 2));
            ptr[0] = 0;
            ptr[1] = 0x8000000000000000;
            ASSERT_FALSE(is_zero_uint(ptr.get(), 2));
            ptr[0] = 0x8000000000000000;
            ptr[1] = 0;
            ASSERT_FALSE(is_zero_uint(ptr.get(), 2));
            ptr[0] = 0;
            ptr[1] = 0;
            ASSERT_TRUE(is_zero_uint(ptr.get(), 2));
        }

        TEST(UIntCore, IsEqualUInt)
        {
            MemoryPool &pool = *global_variables::global_memory_pool;
            auto ptr(allocate_uint(1, pool));
            ptr[0] = 1;
            ASSERT_TRUE(is_equal_uint(ptr.get(), 1, 1));
            ASSERT_FALSE(is_equal_uint(ptr.get(), 1, 0));
            ASSERT_FALSE(is_equal_uint(ptr.get(), 1, 2));

            ptr = allocate_uint(2, pool);
            ptr[0] = 1;
            ptr[1] = 1;
            ASSERT_FALSE(is_equal_uint(ptr.get(), 2, 1));
            ptr[0] = 1;
            ptr[1] = 0;
            ASSERT_TRUE(is_equal_uint(ptr.get(), 2, 1));
            ptr[0] = 0x1234567887654321;
            ptr[1] = 0;
            ASSERT_TRUE(is_equal_uint(ptr.get(), 2, 0x1234567887654321));
            ASSERT_FALSE(is_equal_uint(ptr.get(), 2, 0x2234567887654321));
        }

        TEST(UIntCore, IsBitSetUInt)
        {
            MemoryPool &pool = *global_variables::global_memory_pool;
            auto ptr(allocate_uint(2, pool));
            ptr[0] = 0;
            ptr[1] = 0;
            for (int i = 0; i < 128; ++i)
            {
                ASSERT_FALSE(is_bit_set_uint(ptr.get(), 2, i));
            }
            ptr[0] = 0xFFFFFFFFFFFFFFFF;
            ptr[1] = 0xFFFFFFFFFFFFFFFF;
            for (int i = 0; i < 128; ++i)
            {
                ASSERT_TRUE(is_bit_set_uint(ptr.get(), 2, i));
            }

            ptr[0] = 0x0000000000000001;
            ptr[1] = 0x8000000000000000;
            for (int i = 0; i < 128; ++i)
            {
                if (i == 0 || i == 127)
                {
                    ASSERT_TRUE(is_bit_set_uint(ptr.get(), 2, i));
                }
                else
                {
                    ASSERT_FALSE(is_bit_set_uint(ptr.get(), 2, i));
                }
            }
        }

        TEST(UIntCore, IsHighBitSetUInt)
        {
            MemoryPool &pool = *global_variables::global_memory_pool;
            auto ptr(allocate_uint(2, pool));
            ptr[0] = 0;
            ptr[1] = 0;
            ASSERT_FALSE(is_high_bit_set_uint(ptr.get(), 2));

            ptr[0] = 0xFFFFFFFFFFFFFFFF;
            ptr[1] = 0xFFFFFFFFFFFFFFFF;
            ASSERT_TRUE(is_high_bit_set_uint(ptr.get(), 2));

            ptr[0] = 0;
            ptr[1] = 0x8000000000000000;
            ASSERT_TRUE(is_high_bit_set_uint(ptr.get(), 2));

            ptr[0] = 0xFFFFFFFFFFFFFFFF;
            ptr[1] = 0x7FFFFFFFFFFFFFFF;
            ASSERT_FALSE(is_high_bit_set_uint(ptr.get(), 2));
        }

        TEST(UIntCore, SetBitUInt)
        {
            MemoryPool &pool = *global_variables::global_memory_pool;
            auto ptr(allocate_uint(2, pool));
            ptr[0] = 0;
            ptr[1] = 0;
            set_bit_uint(ptr.get(), 2, 0);
            ASSERT_EQ(1ULL, ptr[0]);
            ASSERT_EQ(static_cast<uint64_t>(0), ptr[1]);

            set_bit_uint(ptr.get(), 2, 127);
            ASSERT_EQ(1ULL, ptr[0]);
            ASSERT_EQ(static_cast<uint64_t>(0x8000000000000000), ptr[1]);

            set_bit_uint(ptr.get(), 2, 63);
            ASSERT_EQ(static_cast<uint64_t>(0x8000000000000001), ptr[0]);
            ASSERT_EQ(static_cast<uint64_t>(0x8000000000000000), ptr[1]);

            set_bit_uint(ptr.get(), 2, 64);
            ASSERT_EQ(static_cast<uint64_t>(0x8000000000000001), ptr[0]);
            ASSERT_EQ(static_cast<uint64_t>(0x8000000000000001), ptr[1]);

            set_bit_uint(ptr.get(), 2, 3);
            ASSERT_EQ(static_cast<uint64_t>(0x8000000000000009), ptr[0]);
            ASSERT_EQ(static_cast<uint64_t>(0x8000000000000001), ptr[1]);
        }

        TEST(UIntCore, GetSignificantBitCountUInt)
        {
            MemoryPool &pool = *global_variables::global_memory_pool;
            auto ptr(allocate_uint(2, pool));
            ptr[0] = 0;
            ptr[1] = 0;
            ASSERT_EQ(0, get_significant_bit_count_uint(ptr.get(), 2));

            ptr[0] = 1;
            ptr[1] = 0;
            ASSERT_EQ(1, get_significant_bit_count_uint(ptr.get(), 2));

            ptr[0] = 2;
            ptr[1] = 0;
            ASSERT_EQ(2, get_significant_bit_count_uint(ptr.get(), 2));

            ptr[0] = 3;
            ptr[1] = 0;
            ASSERT_EQ(2, get_significant_bit_count_uint(ptr.get(), 2));

            ptr[0] = 29;
            ptr[1] = 0;
            ASSERT_EQ(5, get_significant_bit_count_uint(ptr.get(), 2));

            ptr[0] = 4;
            ptr[1] = 0;
            ASSERT_EQ(3, get_significant_bit_count_uint(ptr.get(), 2));

            ptr[0] = 0xFFFFFFFFFFFFFFFF;
            ptr[1] = 0;
            ASSERT_EQ(64, get_significant_bit_count_uint(ptr.get(), 2));

            ptr[0] = 0;
            ptr[1] = 1;
            ASSERT_EQ(65, get_significant_bit_count_uint(ptr.get(), 2));

            ptr[0] = 0xFFFFFFFFFFFFFFFF;
            ptr[1] = 1;
            ASSERT_EQ(65, get_significant_bit_count_uint(ptr.get(), 2));

            ptr[0] = 0xFFFFFFFFFFFFFFFF;
            ptr[1] = 0x7000000000000000;
            ASSERT_EQ(127, get_significant_bit_count_uint(ptr.get(), 2));

            ptr[0] = 0xFFFFFFFFFFFFFFFF;
            ptr[1] = 0x8000000000000000;
            ASSERT_EQ(128, get_significant_bit_count_uint(ptr.get(), 2));

            ptr[0] = 0xFFFFFFFFFFFFFFFF;
            ptr[1] = 0xFFFFFFFFFFFFFFFF;
            ASSERT_EQ(128, get_significant_bit_count_uint(ptr.get(), 2));
        }

        TEST(UIntCore, GetSignificantUInt64CountUInt)
        {
            MemoryPool &pool = *global_variables::global_memory_pool;
            auto ptr(allocate_uint(2, pool));
            ptr[0] = 0;
            ptr[1] = 0;
            ASSERT_EQ(0ULL, get_significant_uint64_count_uint(ptr.get(), 2));

            ptr[0] = 1;
            ptr[1] = 0;
            ASSERT_EQ(1ULL, get_significant_uint64_count_uint(ptr.get(), 2));

            ptr[0] = 2;
            ptr[1] = 0;
            ASSERT_EQ(1ULL, get_significant_uint64_count_uint(ptr.get(), 2));

            ptr[0] = 0xFFFFFFFFFFFFFFFF;
            ptr[1] = 0;
            ASSERT_EQ(1ULL, get_significant_uint64_count_uint(ptr.get(), 2));

            ptr[0] = 0;
            ptr[1] = 1;
            ASSERT_EQ(2ULL, get_significant_uint64_count_uint(ptr.get(), 2));

            ptr[0] = 0xFFFFFFFFFFFFFFFF;
            ptr[1] = 1;
            ASSERT_EQ(2ULL, get_significant_uint64_count_uint(ptr.get(), 2));

            ptr[0] = 0xFFFFFFFFFFFFFFFF;
            ptr[1] = 0x8000000000000000;
            ASSERT_EQ(2ULL, get_significant_uint64_count_uint(ptr.get(), 2));

            ptr[0] = 0xFFFFFFFFFFFFFFFF;
            ptr[1] = 0xFFFFFFFFFFFFFFFF;
            ASSERT_EQ(2ULL, get_significant_uint64_count_uint(ptr.get(), 2));
        }

        TEST(UIntCore, GetNonzeroUInt64CountUInt)
        {
            MemoryPool &pool = *global_variables::global_memory_pool;
            auto ptr(allocate_uint(2, pool));
            ptr[0] = 0;
            ptr[1] = 0;
            ASSERT_EQ(0ULL, get_nonzero_uint64_count_uint(ptr.get(), 2));

            ptr[0] = 1;
            ptr[1] = 0;
            ASSERT_EQ(1ULL, get_nonzero_uint64_count_uint(ptr.get(), 2));

            ptr[0] = 2;
            ptr[1] = 0;
            ASSERT_EQ(1ULL, get_nonzero_uint64_count_uint(ptr.get(), 2));

            ptr[0] = 0xFFFFFFFFFFFFFFFF;
            ptr[1] = 0;
            ASSERT_EQ(1ULL, get_nonzero_uint64_count_uint(ptr.get(), 2));

            ptr[0] = 0;
            ptr[1] = 1;
            ASSERT_EQ(1ULL, get_nonzero_uint64_count_uint(ptr.get(), 2));

            ptr[0] = 0xFFFFFFFFFFFFFFFF;
            ptr[1] = 1;
            ASSERT_EQ(2ULL, get_nonzero_uint64_count_uint(ptr.get(), 2));

            ptr[0] = 0xFFFFFFFFFFFFFFFF;
            ptr[1] = 0x8000000000000000;
            ASSERT_EQ(2ULL, get_nonzero_uint64_count_uint(ptr.get(), 2));

            ptr[0] = 0xFFFFFFFFFFFFFFFF;
            ptr[1] = 0xFFFFFFFFFFFFFFFF;
            ASSERT_EQ(2ULL, get_nonzero_uint64_count_uint(ptr.get(), 2));
        }

        TEST(UIntCore, FilterHighBitsUInt)
        {
            filter_highbits_uint(nullptr, 0, 0);

            MemoryPool &pool = *global_variables::global_memory_pool;
            auto ptr(allocate_uint(2, pool));
            ptr[0] = 0xFFFFFFFFFFFFFFFF;
            ptr[1] = 0xFFFFFFFFFFFFFFFF;
            filter_highbits_uint(ptr.get(), 2, 0);
            ASSERT_EQ(static_cast<uint64_t>(0), ptr[0]);
            ASSERT_EQ(static_cast<uint64_t>(0), ptr[1]);

            ptr[0] = 0xFFFFFFFFFFFFFFFF;
            ptr[1] = 0xFFFFFFFFFFFFFFFF;
            filter_highbits_uint(ptr.get(), 2, 128);
            ASSERT_EQ(static_cast<uint64_t>(0xFFFFFFFFFFFFFFFF), ptr[0]);
            ASSERT_EQ(static_cast<uint64_t>(0xFFFFFFFFFFFFFFFF), ptr[1]);
            filter_highbits_uint(ptr.get(), 2, 127);
            ASSERT_EQ(static_cast<uint64_t>(0xFFFFFFFFFFFFFFFF), ptr[0]);
            ASSERT_EQ(static_cast<uint64_t>(0x7FFFFFFFFFFFFFFF), ptr[1]);
            filter_highbits_uint(ptr.get(), 2, 126);
            ASSERT_EQ(static_cast<uint64_t>(0xFFFFFFFFFFFFFFFF), ptr[0]);
            ASSERT_EQ(static_cast<uint64_t>(0x3FFFFFFFFFFFFFFF), ptr[1]);
            filter_highbits_uint(ptr.get(), 2, 64);
            ASSERT_EQ(static_cast<uint64_t>(0xFFFFFFFFFFFFFFFF), ptr[0]);
            ASSERT_EQ(static_cast<uint64_t>(0), ptr[1]);
            filter_highbits_uint(ptr.get(), 2, 63);
            ASSERT_EQ(static_cast<uint64_t>(0x7FFFFFFFFFFFFFFF), ptr[0]);
            ASSERT_EQ(static_cast<uint64_t>(0), ptr[1]);
            filter_highbits_uint(ptr.get(), 2, 2);
            ASSERT_EQ(static_cast<uint64_t>(0x3), ptr[0]);
            ASSERT_EQ(static_cast<uint64_t>(0), ptr[1]);
            filter_highbits_uint(ptr.get(), 2, 1);
            ASSERT_EQ(static_cast<uint64_t>(0x1), ptr[0]);
            ASSERT_EQ(static_cast<uint64_t>(0), ptr[1]);
            filter_highbits_uint(ptr.get(), 2, 0);
            ASSERT_EQ(static_cast<uint64_t>(0), ptr[0]);
            ASSERT_EQ(static_cast<uint64_t>(0), ptr[1]);

            filter_highbits_uint(ptr.get(), 2, 128);
            ASSERT_EQ(static_cast<uint64_t>(0), ptr[0]);
            ASSERT_EQ(static_cast<uint64_t>(0), ptr[1]);
        }

        TEST(UIntCore, CompareUInt)
        {
            ASSERT_EQ(0, compare_uint(nullptr, nullptr, 0));
            ASSERT_TRUE(is_equal_uint(nullptr, nullptr, 0));
            ASSERT_FALSE(is_greater_than_uint(nullptr, nullptr, 0));
            ASSERT_FALSE(is_less_than_uint(nullptr, nullptr, 0));
            ASSERT_TRUE(is_greater_than_or_equal_uint(nullptr, nullptr, 0));
            ASSERT_TRUE(is_less_than_or_equal_uint(nullptr, nullptr, 0));

            MemoryPool &pool = *global_variables::global_memory_pool;
            auto ptr1(allocate_uint(2, pool));
            auto ptr2(allocate_uint(2, pool));
            ptr1[0] = 0;
            ptr1[1] = 0;
            ptr2[0] = 0;
            ptr2[1] = 0;
            ASSERT_EQ(0, compare_uint(ptr1.get(), ptr2.get(), 2));
            ASSERT_TRUE(is_equal_uint(ptr1.get(), ptr2.get(), 2));
            ASSERT_FALSE(is_greater_than_uint(ptr1.get(), ptr2.get(), 2));
            ASSERT_FALSE(is_less_than_uint(ptr1.get(), ptr2.get(), 2));
            ASSERT_TRUE(is_greater_than_or_equal_uint(ptr1.get(), ptr2.get(), 2));
            ASSERT_TRUE(is_less_than_or_equal_uint(ptr1.get(), ptr2.get(), 2));

            ptr1[0] = 0x1234567887654321;
            ptr1[1] = 0x8765432112345678;
            ptr2[0] = 0x1234567887654321;
            ptr2[1] = 0x8765432112345678;
            ASSERT_EQ(0, compare_uint(ptr1.get(), ptr2.get(), 2));
            ASSERT_TRUE(is_equal_uint(ptr1.get(), ptr2.get(), 2));
            ASSERT_FALSE(is_greater_than_uint(ptr1.get(), ptr2.get(), 2));
            ASSERT_FALSE(is_less_than_uint(ptr1.get(), ptr2.get(), 2));
            ASSERT_TRUE(is_greater_than_or_equal_uint(ptr1.get(), ptr2.get(), 2));
            ASSERT_TRUE(is_less_than_or_equal_uint(ptr1.get(), ptr2.get(), 2));

            ptr1[0] = 1;
            ptr1[1] = 0;
            ptr2[0] = 2;
            ptr2[1] = 0;
            ASSERT_EQ(-1, compare_uint(ptr1.get(), ptr2.get(), 2));
            ASSERT_FALSE(is_equal_uint(ptr1.get(), ptr2.get(), 2));
            ASSERT_FALSE(is_greater_than_uint(ptr1.get(), ptr2.get(), 2));
            ASSERT_TRUE(is_less_than_uint(ptr1.get(), ptr2.get(), 2));
            ASSERT_FALSE(is_greater_than_or_equal_uint(ptr1.get(), ptr2.get(), 2));
            ASSERT_TRUE(is_less_than_or_equal_uint(ptr1.get(), ptr2.get(), 2));

            ptr1[0] = 1;
            ptr1[1] = 0xFFFFFFFFFFFFFFFF;
            ptr2[0] = 2;
            ptr2[1] = 0xFFFFFFFFFFFFFFFF;
            ASSERT_EQ(-1, compare_uint(ptr1.get(), ptr2.get(), 2));
            ASSERT_FALSE(is_equal_uint(ptr1.get(), ptr2.get(), 2));
            ASSERT_FALSE(is_greater_than_uint(ptr1.get(), ptr2.get(), 2));
            ASSERT_TRUE(is_less_than_uint(ptr1.get(), ptr2.get(), 2));
            ASSERT_FALSE(is_greater_than_or_equal_uint(ptr1.get(), ptr2.get(), 2));
            ASSERT_TRUE(is_less_than_or_equal_uint(ptr1.get(), ptr2.get(), 2));

            ptr1[0] = 0xFFFFFFFFFFFFFFFF;
            ptr1[1] = 0x0000000000000001;
            ptr2[0] = 0x0000000000000000;
            ptr2[1] = 0x0000000000000002;
            ASSERT_EQ(-1, compare_uint(ptr1.get(), ptr2.get(), 2));
            ASSERT_FALSE(is_equal_uint(ptr1.get(), ptr2.get(), 2));
            ASSERT_FALSE(is_greater_than_uint(ptr1.get(), ptr2.get(), 2));
            ASSERT_TRUE(is_less_than_uint(ptr1.get(), ptr2.get(), 2));
            ASSERT_FALSE(is_greater_than_or_equal_uint(ptr1.get(), ptr2.get(), 2));
            ASSERT_TRUE(is_less_than_or_equal_uint(ptr1.get(), ptr2.get(), 2));

            ptr1[0] = 2;
            ptr1[1] = 0;
            ptr2[0] = 1;
            ptr2[1] = 0;
            ASSERT_EQ(1, compare_uint(ptr1.get(), ptr2.get(), 2));
            ASSERT_FALSE(is_equal_uint(ptr1.get(), ptr2.get(), 2));
            ASSERT_TRUE(is_greater_than_uint(ptr1.get(), ptr2.get(), 2));
            ASSERT_FALSE(is_less_than_uint(ptr1.get(), ptr2.get(), 2));
            ASSERT_TRUE(is_greater_than_or_equal_uint(ptr1.get(), ptr2.get(), 2));
            ASSERT_FALSE(is_less_than_or_equal_uint(ptr1.get(), ptr2.get(), 2));

            ptr1[0] = 2;
            ptr1[1] = 0xFFFFFFFFFFFFFFFF;
            ptr2[0] = 1;
            ptr2[1] = 0xFFFFFFFFFFFFFFFF;
            ASSERT_EQ(1, compare_uint(ptr1.get(), ptr2.get(), 2));
            ASSERT_FALSE(is_equal_uint(ptr1.get(), ptr2.get(), 2));
            ASSERT_TRUE(is_greater_than_uint(ptr1.get(), ptr2.get(), 2));
            ASSERT_FALSE(is_less_than_uint(ptr1.get(), ptr2.get(), 2));
            ASSERT_TRUE(is_greater_than_or_equal_uint(ptr1.get(), ptr2.get(), 2));
            ASSERT_FALSE(is_less_than_or_equal_uint(ptr1.get(), ptr2.get(), 2));

            ptr1[0] = 0xFFFFFFFFFFFFFFFF;
            ptr1[1] = 0x0000000000000003;
            ptr2[0] = 0x0000000000000000;
            ptr2[1] = 0x0000000000000002;
            ASSERT_EQ(1, compare_uint(ptr1.get(), ptr2.get(), 2));
            ASSERT_FALSE(is_equal_uint(ptr1.get(), ptr2.get(), 2));
            ASSERT_TRUE(is_greater_than_uint(ptr1.get(), ptr2.get(), 2));
            ASSERT_FALSE(is_less_than_uint(ptr1.get(), ptr2.get(), 2));
            ASSERT_TRUE(is_greater_than_or_equal_uint(ptr1.get(), ptr2.get(), 2));
            ASSERT_FALSE(is_less_than_or_equal_uint(ptr1.get(), ptr2.get(), 2));
        }

        TEST(UIntCore, GetPowerOfTwo)
        {
            ASSERT_EQ(-1, get_power_of_two(0));
            ASSERT_EQ(0, get_power_of_two(1));
            ASSERT_EQ(1, get_power_of_two(2));
            ASSERT_EQ(-1, get_power_of_two(3));
            ASSERT_EQ(2, get_power_of_two(4));
            ASSERT_EQ(-1, get_power_of_two(5));
            ASSERT_EQ(-1, get_power_of_two(6));
            ASSERT_EQ(-1, get_power_of_two(7));
            ASSERT_EQ(3, get_power_of_two(8));
            ASSERT_EQ(-1, get_power_of_two(15));
            ASSERT_EQ(4, get_power_of_two(16));
            ASSERT_EQ(-1, get_power_of_two(17));
            ASSERT_EQ(-1, get_power_of_two(255));
            ASSERT_EQ(8, get_power_of_two(256));
            ASSERT_EQ(-1, get_power_of_two(257));
            ASSERT_EQ(10, get_power_of_two(1 << 10));
            ASSERT_EQ(30, get_power_of_two(1 << 30));
            ASSERT_EQ(32, get_power_of_two(1ULL << 32));
            ASSERT_EQ(62, get_power_of_two(1ULL << 62));
            ASSERT_EQ(63, get_power_of_two(1ULL << 63));
        }

        TEST(UIntCore, DuplicateUIntIfNeeded)
        {
            // MemoryPool &pool = *global_variables::global_memory_pool;
            MemoryPoolST pool;
            auto ptr(allocate_uint(2, pool));
            ptr[0] = 0xF0F0F0F0F0;
            ptr[1] = 0xABABABABAB;
            auto ptr2 = duplicate_uint_if_needed(ptr.get(), 0, 0, false, pool);
            // No forcing and sizes are same (although zero) so just alias
            ASSERT_TRUE(ptr2.get() == ptr.get());

            ptr2 = duplicate_uint_if_needed(ptr.get(), 0, 0, true, pool);
            // Forcing and size is zero so return nullptr
            ASSERT_TRUE(ptr2.get() == nullptr);

            ptr2 = duplicate_uint_if_needed(ptr.get(), 1, 0, false, pool);
            ASSERT_TRUE(ptr2.get() == ptr.get());

            ptr2 = duplicate_uint_if_needed(ptr.get(), 1, 0, true, pool);
            ASSERT_TRUE(ptr2.get() == nullptr);

            ptr2 = duplicate_uint_if_needed(ptr.get(), 1, 1, false, pool);
            ASSERT_TRUE(ptr2.get() == ptr.get());

            ptr2 = duplicate_uint_if_needed(ptr.get(), 1, 1, true, pool);
            ASSERT_TRUE(ptr2.get() != ptr.get());
            ASSERT_EQ(ptr[0], ptr2[0]);

            ptr2 = duplicate_uint_if_needed(ptr.get(), 2, 2, true, pool);
            ASSERT_TRUE(ptr2.get() != ptr.get());
            ASSERT_EQ(ptr[0], ptr2[0]);
            ASSERT_EQ(ptr[1], ptr2[1]);

            ptr2 = duplicate_uint_if_needed(ptr.get(), 2, 2, false, pool);
            ASSERT_TRUE(ptr2.get() == ptr.get());

            ptr2 = duplicate_uint_if_needed(ptr.get(), 2, 1, false, pool);
            ASSERT_TRUE(ptr2.get() == ptr.get());

            ptr2 = duplicate_uint_if_needed(ptr.get(), 1, 2, false, pool);
            ASSERT_TRUE(ptr2.get() != ptr.get());
            ASSERT_EQ(ptr[0], ptr2[0]);
            ASSERT_EQ(0ULL, ptr2[1]);

            ptr2 = duplicate_uint_if_needed(ptr.get(), 1, 2, true, pool);
            ASSERT_TRUE(ptr2.get() != ptr.get());
            ASSERT_EQ(ptr[0], ptr2[0]);
            ASSERT_EQ(0ULL, ptr2[1]);
        }
    } // namespace util
} // namespace sealtest
