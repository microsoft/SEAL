// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include "gtest/gtest.h"
#include "seal/util/uintarith.h"
#include <cstdint>

using namespace seal::util;
using namespace std;

namespace SEALTest
{
   namespace util
   {
        TEST(UIntArith, AddUInt64Generic)
        {
            unsigned long long result;
            ASSERT_FALSE(add_uint64_generic(0ULL, 0ULL, 0, &result));
            ASSERT_EQ(0ULL, result);
            ASSERT_FALSE(add_uint64_generic(1ULL, 1ULL, 0, &result));
            ASSERT_EQ(2ULL, result);
            ASSERT_FALSE(add_uint64_generic(1ULL, 0ULL, 1, &result));
            ASSERT_EQ(2ULL, result);
            ASSERT_FALSE(add_uint64_generic(0ULL, 1ULL, 1, &result));
            ASSERT_EQ(2ULL, result);
            ASSERT_FALSE(add_uint64_generic(1ULL, 1ULL, 1, &result));
            ASSERT_EQ(3ULL, result);
            ASSERT_TRUE(add_uint64_generic(0xFFFFFFFFFFFFFFFFULL, 1ULL, 0, &result));
            ASSERT_EQ(0ULL, result);
            ASSERT_TRUE(add_uint64_generic(1ULL, 0xFFFFFFFFFFFFFFFFULL, 0, &result));
            ASSERT_EQ(0ULL, result);
            ASSERT_TRUE(add_uint64_generic(1ULL, 0xFFFFFFFFFFFFFFFFULL, 1, &result));
            ASSERT_EQ(1ULL, result);
            ASSERT_TRUE(add_uint64_generic(2ULL, 0xFFFFFFFFFFFFFFFEULL, 0, &result));
            ASSERT_EQ(0ULL, result);
            ASSERT_TRUE(add_uint64_generic(2ULL, 0xFFFFFFFFFFFFFFFEULL, 1, &result));
            ASSERT_EQ(1ULL, result);
            ASSERT_FALSE(add_uint64_generic(0xF00F00F00F00F00FULL, 0x0FF0FF0FF0FF0FF0ULL, 0, &result));
            ASSERT_EQ(0xFFFFFFFFFFFFFFFFULL, result);
            ASSERT_TRUE(add_uint64_generic(0xF00F00F00F00F00FULL, 0x0FF0FF0FF0FF0FF0ULL, 1, &result));
            ASSERT_EQ(0x0ULL, result);
        }

#if SEAL_COMPILER == SEAL_COMPILER_MSVC
#pragma optimize ("", off)
#elif SEAL_COMPILER == SEAL_COMPILER_GCC
#pragma GCC push_options
#pragma GCC optimize ("O0")
#elif SEAL_COMPILER == SEAL_COMPILER_CLANG
#pragma clang optimize off
#endif

        TEST(UIntArith, AddUInt64)
        {
            unsigned long long result;
            ASSERT_FALSE(add_uint64(0ULL, 0ULL, 0, &result));
            ASSERT_EQ(0ULL, result);
            ASSERT_FALSE(add_uint64(1ULL, 1ULL, 0, &result));
            ASSERT_EQ(2ULL, result);
            ASSERT_FALSE(add_uint64(1ULL, 0ULL, 1, &result));
            ASSERT_EQ(2ULL, result);
            ASSERT_FALSE(add_uint64(0ULL, 1ULL, 1, &result));
            ASSERT_EQ(2ULL, result);
            ASSERT_FALSE(add_uint64(1ULL, 1ULL, 1, &result));
            ASSERT_EQ(3ULL, result);
            ASSERT_TRUE(add_uint64(0xFFFFFFFFFFFFFFFFULL, 1ULL, 0, &result));
            ASSERT_EQ(0ULL, result);
            ASSERT_TRUE(add_uint64(1ULL, 0xFFFFFFFFFFFFFFFFULL, 0, &result));
            ASSERT_EQ(0ULL, result);
            ASSERT_TRUE(add_uint64(1ULL, 0xFFFFFFFFFFFFFFFFULL, 1, &result));
            ASSERT_EQ(1ULL, result);
            ASSERT_TRUE(add_uint64(2ULL, 0xFFFFFFFFFFFFFFFEULL, 0, &result));
            ASSERT_EQ(0ULL, result);
            ASSERT_TRUE(add_uint64(2ULL, 0xFFFFFFFFFFFFFFFEULL, 1, &result));
            ASSERT_EQ(1ULL, result);
            ASSERT_FALSE(add_uint64(0xF00F00F00F00F00FULL, 0x0FF0FF0FF0FF0FF0ULL, 0, &result));
            ASSERT_EQ(0xFFFFFFFFFFFFFFFFULL, result);
            ASSERT_TRUE(add_uint64(0xF00F00F00F00F00FULL, 0x0FF0FF0FF0FF0FF0ULL, 1, &result));
            ASSERT_EQ(0x0ULL, result);
        }

#if SEAL_COMPILER == SEAL_COMPILER_MSVC
#pragma optimize ("", on)
#elif SEAL_COMPILER == SEAL_COMPILER_GCC
#pragma GCC pop_options
#elif SEAL_COMPILER == SEAL_COMPILER_CLANG
#pragma clang optimize on
#endif

        TEST(UIntArith, SubUInt64Generic)
        {
            unsigned long long result;
            ASSERT_FALSE(sub_uint64_generic(0ULL, 0ULL, 0, &result));
            ASSERT_EQ(0ULL, result);
            ASSERT_FALSE(sub_uint64_generic(1ULL, 1ULL, 0, &result));
            ASSERT_EQ(0ULL, result);
            ASSERT_FALSE(sub_uint64_generic(1ULL, 0ULL, 1, &result));
            ASSERT_EQ(0ULL, result);
            ASSERT_TRUE(sub_uint64_generic(0ULL, 1ULL, 1, &result));
            ASSERT_EQ(0xFFFFFFFFFFFFFFFEULL, result);
            ASSERT_TRUE(sub_uint64_generic(1ULL, 1ULL, 1, &result));
            ASSERT_EQ(0xFFFFFFFFFFFFFFFFULL, result);
            ASSERT_FALSE(sub_uint64_generic(0xFFFFFFFFFFFFFFFFULL, 1ULL, 0, &result));
            ASSERT_EQ(0xFFFFFFFFFFFFFFFEULL, result);
            ASSERT_TRUE(sub_uint64_generic(1ULL, 0xFFFFFFFFFFFFFFFFULL, 0, &result));
            ASSERT_EQ(2ULL, result);
            ASSERT_TRUE(sub_uint64_generic(1ULL, 0xFFFFFFFFFFFFFFFFULL, 1, &result));
            ASSERT_EQ(1ULL, result);
            ASSERT_TRUE(sub_uint64_generic(2ULL, 0xFFFFFFFFFFFFFFFEULL, 0, &result));
            ASSERT_EQ(4ULL, result);
            ASSERT_TRUE(sub_uint64_generic(2ULL, 0xFFFFFFFFFFFFFFFEULL, 1, &result));
            ASSERT_EQ(3ULL, result);
            ASSERT_FALSE(sub_uint64_generic(0xF00F00F00F00F00FULL, 0x0FF0FF0FF0FF0FF0ULL, 0, &result));
            ASSERT_EQ(0xE01E01E01E01E01FULL, result);
            ASSERT_FALSE(sub_uint64_generic(0xF00F00F00F00F00FULL, 0x0FF0FF0FF0FF0FF0ULL, 1, &result));
            ASSERT_EQ(0xE01E01E01E01E01EULL, result);
        }

        TEST(UIntArith, SubUInt64)
        {
            unsigned long long result;
            ASSERT_FALSE(sub_uint64(0ULL, 0ULL, 0, &result));
            ASSERT_EQ(0ULL, result);
            ASSERT_FALSE(sub_uint64(1ULL, 1ULL, 0, &result));
            ASSERT_EQ(0ULL, result);
            ASSERT_FALSE(sub_uint64(1ULL, 0ULL, 1, &result));
            ASSERT_EQ(0ULL, result);
            ASSERT_TRUE(sub_uint64(0ULL, 1ULL, 1, &result));
            ASSERT_EQ(0xFFFFFFFFFFFFFFFEULL, result);
            ASSERT_TRUE(sub_uint64(1ULL, 1ULL, 1, &result));
            ASSERT_EQ(0xFFFFFFFFFFFFFFFFULL, result);
            ASSERT_FALSE(sub_uint64(0xFFFFFFFFFFFFFFFFULL, 1ULL, 0, &result));
            ASSERT_EQ(0xFFFFFFFFFFFFFFFEULL, result);
            ASSERT_TRUE(sub_uint64(1ULL, 0xFFFFFFFFFFFFFFFFULL, 0, &result));
            ASSERT_EQ(2ULL, result);
            ASSERT_TRUE(sub_uint64(1ULL, 0xFFFFFFFFFFFFFFFFULL, 1, &result));
            ASSERT_EQ(1ULL, result);
            ASSERT_TRUE(sub_uint64(2ULL, 0xFFFFFFFFFFFFFFFEULL, 0, &result));
            ASSERT_EQ(4ULL, result);
            ASSERT_TRUE(sub_uint64(2ULL, 0xFFFFFFFFFFFFFFFEULL, 1, &result));
            ASSERT_EQ(3ULL, result);
            ASSERT_FALSE(sub_uint64(0xF00F00F00F00F00FULL, 0x0FF0FF0FF0FF0FF0ULL, 0, &result));
            ASSERT_EQ(0xE01E01E01E01E01FULL, result);
            ASSERT_FALSE(sub_uint64(0xF00F00F00F00F00FULL, 0x0FF0FF0FF0FF0FF0ULL, 1, &result));
            ASSERT_EQ(0xE01E01E01E01E01EULL, result);
        }

        TEST(UIntArith, AddUIntUInt)
        {
            MemoryPool &pool = *global_variables::global_memory_pool;
            auto ptr(allocate_uint(2, pool));
            auto ptr2(allocate_uint(2, pool));
            auto ptr3(allocate_uint(2, pool));
            ptr[0] = 0;
            ptr[1] = 0;
            ptr2[0] = 0;
            ptr2[1] = 0;
            ptr3[0] = 0xFFFFFFFFFFFFFFFF;
            ptr3[1] = 0xFFFFFFFFFFFFFFFF;
            ASSERT_FALSE(add_uint_uint(ptr.get(), ptr2.get(), 2, ptr3.get()) != 0);
            ASSERT_EQ(static_cast<uint64_t>(0), ptr3[0]);
            ASSERT_EQ(static_cast<uint64_t>(0), ptr3[1]);

            ptr[0] = 0xFFFFFFFFFFFFFFFF;
            ptr[1] = 0xFFFFFFFFFFFFFFFF;
            ptr2[0] = 0;
            ptr2[1] = 0;
            ptr3[0] = 0;
            ptr3[1] = 0;
            ASSERT_FALSE(add_uint_uint(ptr.get(), ptr2.get(), 2, ptr3.get()) != 0);
            ASSERT_EQ(static_cast<uint64_t>(0xFFFFFFFFFFFFFFFF), ptr3[0]);
            ASSERT_EQ(static_cast<uint64_t>(0xFFFFFFFFFFFFFFFF), ptr3[1]);

            ptr[0] = 0xFFFFFFFFFFFFFFFE;
            ptr[1] = 0xFFFFFFFFFFFFFFFF;
            ptr2[0] = 1;
            ptr2[1] = 0;
            ptr3[0] = 0;
            ptr3[1] = 0;
            ASSERT_FALSE(add_uint_uint(ptr.get(), ptr2.get(), 2, ptr3.get()) != 0);
            ASSERT_EQ(static_cast<uint64_t>(0xFFFFFFFFFFFFFFFF), ptr3[0]);
            ASSERT_EQ(static_cast<uint64_t>(0xFFFFFFFFFFFFFFFF), ptr3[1]);

            ptr[0] = 0xFFFFFFFFFFFFFFFF;
            ptr[1] = 0xFFFFFFFFFFFFFFFF;
            ptr2[0] = 1;
            ptr2[1] = 0;
            ptr3[0] = 0xFFFFFFFFFFFFFFFF;
            ptr3[1] = 0xFFFFFFFFFFFFFFFF;
            ASSERT_TRUE(add_uint_uint(ptr.get(), ptr2.get(), 2, ptr3.get()) != 0);
            ASSERT_EQ(static_cast<uint64_t>(0), ptr3[0]);
            ASSERT_EQ(static_cast<uint64_t>(0), ptr3[1]);

            ptr[0] = 0xFFFFFFFFFFFFFFFF;
            ptr[1] = 0xFFFFFFFFFFFFFFFF;
            ptr2[0] = 0xFFFFFFFFFFFFFFFF;
            ptr2[1] = 0xFFFFFFFFFFFFFFFF;
            ptr3[0] = 0;
            ptr3[1] = 0;

            ASSERT_TRUE(add_uint_uint(ptr.get(), ptr2.get(), 2, ptr3.get()) != 0);
            ASSERT_EQ(static_cast<uint64_t>(0xFFFFFFFFFFFFFFFE), ptr3[0]);
            ASSERT_EQ(static_cast<uint64_t>(0xFFFFFFFFFFFFFFFF), ptr3[1]);
            ASSERT_TRUE(add_uint_uint(ptr.get(), ptr2.get(), 2, ptr.get()) != 0);
            ASSERT_EQ(static_cast<uint64_t>(0xFFFFFFFFFFFFFFFE), ptr[0]);
            ASSERT_EQ(static_cast<uint64_t>(0xFFFFFFFFFFFFFFFF), ptr[1]);

            ptr[0] = 0xFFFFFFFFFFFFFFFF;
            ptr[1] = 0;
            ptr2[0] = 1;
            ptr2[1] = 0;
            ptr3[0] = 0;
            ptr3[1] = 0;
            ASSERT_FALSE(add_uint_uint(ptr.get(), ptr2.get(), 2, ptr3.get()) != 0);
            ASSERT_EQ(static_cast<uint64_t>(0), ptr3[0]);
            ASSERT_EQ(1ULL, ptr3[1]);

            ptr[0] = 0xFFFFFFFFFFFFFFFF;
            ptr[1] = 5;
            ptr2[0] = 1;
            ptr2[1] = 0;
            ptr3[0] = 0;
            ptr3[1] = 0;
            ASSERT_FALSE(add_uint_uint(ptr.get(), 2, ptr2.get(), 1, false, 2, ptr3.get()) != 0);
            ASSERT_EQ(static_cast<uint64_t>(0), ptr3[0]);
            ASSERT_EQ(static_cast<uint64_t>(6), ptr3[1]);
            ASSERT_FALSE(add_uint_uint(ptr.get(), 2, ptr2.get(), 1, true, 2, ptr3.get()) != 0);
            ASSERT_EQ(1ULL, ptr3[0]);
            ASSERT_EQ(static_cast<uint64_t>(6), ptr3[1]);
        }

        TEST(UIntArith, SubUIntUInt)
        {
            MemoryPool &pool = *global_variables::global_memory_pool;
            auto ptr(allocate_uint(2, pool));
            auto ptr2(allocate_uint(2, pool));
            auto ptr3(allocate_uint(2, pool));
            ptr[0] = 0;
            ptr[1] = 0;
            ptr2[0] = 0;
            ptr2[1] = 0;
            ptr3[0] = 0xFFFFFFFFFFFFFFFF;
            ptr3[1] = 0xFFFFFFFFFFFFFFFF;
            ASSERT_FALSE(sub_uint_uint(ptr.get(), ptr2.get(), 2, ptr3.get()) != 0);
            ASSERT_EQ(static_cast<uint64_t>(0), ptr3[0]);
            ASSERT_EQ(static_cast<uint64_t>(0), ptr3[1]);

            ptr[0] = 0xFFFFFFFFFFFFFFFF;
            ptr[1] = 0xFFFFFFFFFFFFFFFF;
            ptr2[0] = 0;
            ptr2[1] = 0;
            ptr3[0] = 0;
            ptr3[1] = 0;
            ASSERT_FALSE(sub_uint_uint(ptr.get(), ptr2.get(), 2, ptr3.get()) != 0);
            ASSERT_EQ(static_cast<uint64_t>(0xFFFFFFFFFFFFFFFF), ptr3[0]);
            ASSERT_EQ(static_cast<uint64_t>(0xFFFFFFFFFFFFFFFF), ptr3[1]);

            ptr[0] = 0xFFFFFFFFFFFFFFFF;
            ptr[1] = 0xFFFFFFFFFFFFFFFF;
            ptr2[0] = 1;
            ptr2[1] = 0;
            ptr3[0] = 0;
            ptr3[1] = 0;
            ASSERT_FALSE(sub_uint_uint(ptr.get(), ptr2.get(), 2, ptr3.get()) != 0);
            ASSERT_EQ(static_cast<uint64_t>(0xFFFFFFFFFFFFFFFE), ptr3[0]);
            ASSERT_EQ(static_cast<uint64_t>(0xFFFFFFFFFFFFFFFF), ptr3[1]);

            ptr[0] = 0;
            ptr[1] = 0;
            ptr2[0] = 1;
            ptr2[1] = 0;
            ptr3[0] = 0;
            ptr3[1] = 0;
            ASSERT_TRUE(sub_uint_uint(ptr.get(), ptr2.get(), 2, ptr3.get()) != 0);
            ASSERT_EQ(static_cast<uint64_t>(0xFFFFFFFFFFFFFFFF), ptr3[0]);
            ASSERT_EQ(static_cast<uint64_t>(0xFFFFFFFFFFFFFFFF), ptr3[1]);
            ASSERT_TRUE(sub_uint_uint(ptr.get(), ptr2.get(), 2, ptr.get()) != 0);
            ASSERT_EQ(static_cast<uint64_t>(0xFFFFFFFFFFFFFFFF), ptr[0]);
            ASSERT_EQ(static_cast<uint64_t>(0xFFFFFFFFFFFFFFFF), ptr[1]);

            ptr[0] = 0xFFFFFFFFFFFFFFFF;
            ptr[1] = 0xFFFFFFFFFFFFFFFF;
            ptr2[0] = 0xFFFFFFFFFFFFFFFF;
            ptr2[1] = 0xFFFFFFFFFFFFFFFF;
            ptr3[0] = 0;
            ptr3[1] = 0;
            ASSERT_FALSE(sub_uint_uint(ptr.get(), ptr2.get(), 2, ptr3.get()) != 0);
            ASSERT_EQ(static_cast<uint64_t>(0), ptr3[0]);
            ASSERT_EQ(static_cast<uint64_t>(0), ptr3[1]);
            ASSERT_FALSE(sub_uint_uint(ptr.get(), ptr2.get(), 2, ptr.get()) != 0);
            ASSERT_EQ(static_cast<uint64_t>(0), ptr[0]);
            ASSERT_EQ(static_cast<uint64_t>(0), ptr[1]);

            ptr[0] = 0xFFFFFFFFFFFFFFFE;
            ptr[1] = 0xFFFFFFFFFFFFFFFF;
            ptr2[0] = 0xFFFFFFFFFFFFFFFF;
            ptr2[1] = 0xFFFFFFFFFFFFFFFF;
            ptr3[0] = 0;
            ptr3[1] = 0;
            ASSERT_TRUE(sub_uint_uint(ptr.get(), ptr2.get(), 2, ptr3.get()) != 0);
            ASSERT_EQ(static_cast<uint64_t>(0xFFFFFFFFFFFFFFFF), ptr3[0]);
            ASSERT_EQ(static_cast<uint64_t>(0xFFFFFFFFFFFFFFFF), ptr3[1]);

            ptr[0] = 0;
            ptr[1] = 1;
            ptr2[0] = 1;
            ptr2[1] = 0;
            ptr3[0] = 0;
            ptr3[1] = 0;
            ASSERT_FALSE(sub_uint_uint(ptr.get(), ptr2.get(), 2, ptr3.get()) != 0);
            ASSERT_EQ(static_cast<uint64_t>(0xFFFFFFFFFFFFFFFF), ptr3[0]);
            ASSERT_EQ(static_cast<uint64_t>(0), ptr3[1]);

            ptr[0] = 0;
            ptr[1] = 1;
            ptr2[0] = 1;
            ptr2[1] = 0;
            ptr3[0] = 0;
            ptr3[1] = 0;
            ASSERT_FALSE(sub_uint_uint(ptr.get(), 2, ptr2.get(), 1, false, 2, ptr3.get()) != 0);
            ASSERT_EQ(static_cast<uint64_t>(0xFFFFFFFFFFFFFFFF), ptr3[0]);
            ASSERT_EQ(static_cast<uint64_t>(0), ptr3[1]);
            ASSERT_FALSE(sub_uint_uint(ptr.get(), 2, ptr2.get(), 1, true, 2, ptr3.get()) != 0);
            ASSERT_EQ(static_cast<uint64_t>(0xFFFFFFFFFFFFFFFE), ptr3[0]);
            ASSERT_EQ(static_cast<uint64_t>(0), ptr3[1]);
        }

        TEST(UIntArith, AddUIntUInt64)
        {
            MemoryPool &pool = *global_variables::global_memory_pool;
            auto ptr(allocate_uint(2, pool));
            auto ptr2(allocate_uint(2, pool));

            ptr[0] = 0ULL;
            ptr[1] = 0ULL;
            ASSERT_FALSE(add_uint_uint64(ptr.get(), 0ULL, 2, ptr2.get()));
            ASSERT_EQ(0ULL, ptr2[0]);
            ASSERT_EQ(0ULL, ptr2[1]);

            ptr[0] = 0xFFFFFFFF00000000ULL;
            ptr[1] = 0ULL;
            ASSERT_FALSE(add_uint_uint64(ptr.get(), 0xFFFFFFFFULL, 2, ptr2.get()));
            ASSERT_EQ(0xFFFFFFFFFFFFFFFFULL, ptr2[0]);
            ASSERT_EQ(0ULL, ptr2[1]);

            ptr[0] = 0xFFFFFFFF00000000ULL;
            ptr[1] = 0xFFFFFFFF00000000ULL;
            ASSERT_FALSE(add_uint_uint64(ptr.get(), 0x100000000ULL, 2, ptr2.get()));
            ASSERT_EQ(0ULL, ptr2[0]);
            ASSERT_EQ(0xFFFFFFFF00000001ULL, ptr2[1]);

            ptr[0] = 0xFFFFFFFFFFFFFFFFULL;
            ptr[1] = 0xFFFFFFFFFFFFFFFFULL;
            ASSERT_TRUE(add_uint_uint64(ptr.get(), 1ULL, 2, ptr2.get()));
            ASSERT_EQ(0ULL, ptr2[0]);
            ASSERT_EQ(0ULL, ptr2[1]);
        }

        TEST(UIntArith, SubUIntUInt64)
        {
            MemoryPool &pool = *global_variables::global_memory_pool;
            auto ptr(allocate_uint(2, pool));
            auto ptr2(allocate_uint(2, pool));

            ptr[0] = 0ULL;
            ptr[1] = 0ULL;
            ASSERT_FALSE(sub_uint_uint64(ptr.get(), 0ULL, 2, ptr2.get()));
            ASSERT_EQ(0ULL, ptr2[0]);
            ASSERT_EQ(0ULL, ptr2[1]);

            ptr[0] = 0ULL;
            ptr[1] = 0ULL;
            ASSERT_TRUE(sub_uint_uint64(ptr.get(), 1ULL, 2, ptr2.get()));
            ASSERT_EQ(0xFFFFFFFFFFFFFFFFULL, ptr2[0]);
            ASSERT_EQ(0xFFFFFFFFFFFFFFFFULL, ptr2[1]);

            ptr[0] = 1ULL;
            ptr[1] = 0ULL;
            ASSERT_TRUE(sub_uint_uint64(ptr.get(), 2ULL, 2, ptr2.get()));
            ASSERT_EQ(0xFFFFFFFFFFFFFFFFULL, ptr2[0]);
            ASSERT_EQ(0xFFFFFFFFFFFFFFFFULL, ptr2[1]);

            ptr[0] = 0xFFFFFFFF00000000ULL;
            ptr[1] = 0ULL;
            ASSERT_FALSE(sub_uint_uint64(ptr.get(), 0xFFFFFFFFULL, 2, ptr2.get()));
            ASSERT_EQ(0xFFFFFFFE00000001ULL, ptr2[0]);
            ASSERT_EQ(0ULL, ptr2[1]);

            ptr[0] = 0xFFFFFFFF00000000ULL;
            ptr[1] = 0xFFFFFFFF00000000ULL;
            ASSERT_FALSE(sub_uint_uint64(ptr.get(), 0x100000000ULL, 2, ptr2.get()));
            ASSERT_EQ(0xFFFFFFFE00000000ULL, ptr2[0]);
            ASSERT_EQ(0xFFFFFFFF00000000ULL, ptr2[1]);

            ptr[0] = 0xFFFFFFFFFFFFFFFFULL;
            ptr[1] = 0xFFFFFFFFFFFFFFFFULL;
            ASSERT_FALSE(sub_uint_uint64(ptr.get(), 1ULL, 2, ptr2.get()));
            ASSERT_EQ(0xFFFFFFFFFFFFFFFEULL, ptr2[0]);
            ASSERT_EQ(0xFFFFFFFFFFFFFFFFULL, ptr2[1]);
        }

        TEST(UIntArith, IncrementUInt)
        {
            MemoryPool &pool = *global_variables::global_memory_pool;
            auto ptr1(allocate_uint(2, pool));
            auto ptr2(allocate_uint(2, pool));
            ptr1[0] = 0;
            ptr1[1] = 0;
            ASSERT_FALSE(increment_uint(ptr1.get(), 2, ptr2.get()) != 0);
            ASSERT_EQ(1ULL, ptr2[0]);
            ASSERT_EQ(static_cast<uint64_t>(0), ptr2[1]);
            ASSERT_FALSE(increment_uint(ptr2.get(), 2, ptr1.get()) != 0);
            ASSERT_EQ(static_cast<uint64_t>(2), ptr1[0]);
            ASSERT_EQ(static_cast<uint64_t>(0), ptr1[1]);

            ptr1[0] = 0xFFFFFFFFFFFFFFFF;
            ptr1[1] = 0;
            ASSERT_FALSE(increment_uint(ptr1.get(), 2, ptr2.get()) != 0);
            ASSERT_EQ(static_cast<uint64_t>(0), ptr2[0]);
            ASSERT_EQ(1ULL, ptr2[1]);
            ASSERT_FALSE(increment_uint(ptr2.get(), 2, ptr1.get()) != 0);
            ASSERT_EQ(1ULL, ptr1[0]);
            ASSERT_EQ(1ULL, ptr1[1]);

            ptr1[0] = 0xFFFFFFFFFFFFFFFF;
            ptr1[1] = 1;
            ASSERT_FALSE(increment_uint(ptr1.get(), 2, ptr2.get()) != 0);
            ASSERT_EQ(static_cast<uint64_t>(0), ptr2[0]);
            ASSERT_EQ(static_cast<uint64_t>(2), ptr2[1]);
            ASSERT_FALSE(increment_uint(ptr2.get(), 2, ptr1.get()) != 0);
            ASSERT_EQ(1ULL, ptr1[0]);
            ASSERT_EQ(static_cast<uint64_t>(2), ptr1[1]);

            ptr1[0] = 0xFFFFFFFFFFFFFFFE;
            ptr1[1] = 0xFFFFFFFFFFFFFFFF;
            ASSERT_FALSE(increment_uint(ptr1.get(), 2, ptr2.get()) != 0);
            ASSERT_EQ(static_cast<uint64_t>(0xFFFFFFFFFFFFFFFF), ptr2[0]);
            ASSERT_EQ(static_cast<uint64_t>(0xFFFFFFFFFFFFFFFF), ptr2[1]);
            ASSERT_TRUE(increment_uint(ptr2.get(), 2, ptr1.get()) != 0);
            ASSERT_EQ(static_cast<uint64_t>(0), ptr1[0]);
            ASSERT_EQ(static_cast<uint64_t>(0), ptr1[1]);
            ASSERT_FALSE(increment_uint(ptr1.get(), 2, ptr2.get()) != 0);
            ASSERT_EQ(1ULL, ptr2[0]);
            ASSERT_EQ(static_cast<uint64_t>(0), ptr2[1]);
        }

        TEST(UIntArith, DecrementUInt)
        {
            MemoryPool &pool = *global_variables::global_memory_pool;
            auto ptr1(allocate_uint(2, pool));
            auto ptr2(allocate_uint(2, pool));
            ptr1[0] = 2;
            ptr1[1] = 2;
            ASSERT_FALSE(decrement_uint(ptr1.get(), 2, ptr2.get()) != 0);
            ASSERT_EQ(1ULL, ptr2[0]);
            ASSERT_EQ(static_cast<uint64_t>(2), ptr2[1]);
            ASSERT_FALSE(decrement_uint(ptr2.get(), 2, ptr1.get()) != 0);
            ASSERT_EQ(static_cast<uint64_t>(0), ptr1[0]);
            ASSERT_EQ(static_cast<uint64_t>(2), ptr1[1]);
            ASSERT_FALSE(decrement_uint(ptr1.get(), 2, ptr2.get()) != 0);
            ASSERT_EQ(static_cast<uint64_t>(0xFFFFFFFFFFFFFFFF), ptr2[0]);
            ASSERT_EQ(1ULL, ptr2[1]);
            ASSERT_FALSE(decrement_uint(ptr2.get(), 2, ptr1.get()) != 0);
            ASSERT_EQ(static_cast<uint64_t>(0xFFFFFFFFFFFFFFFE), ptr1[0]);
            ASSERT_EQ(1ULL, ptr1[1]);

            ptr1[0] = 2;
            ptr1[1] = 1;
            ASSERT_FALSE(decrement_uint(ptr1.get(), 2, ptr2.get()) != 0);
            ASSERT_EQ(1ULL, ptr2[0]);
            ASSERT_EQ(1ULL, ptr2[1]);
            ASSERT_FALSE(decrement_uint(ptr2.get(), 2, ptr1.get()) != 0);
            ASSERT_EQ(static_cast<uint64_t>(0), ptr1[0]);
            ASSERT_EQ(1ULL, ptr1[1]);
            ASSERT_FALSE(decrement_uint(ptr1.get(), 2, ptr2.get()) != 0);
            ASSERT_EQ(static_cast<uint64_t>(0xFFFFFFFFFFFFFFFF), ptr2[0]);
            ASSERT_EQ(static_cast<uint64_t>(0), ptr2[1]);
            ASSERT_FALSE(decrement_uint(ptr2.get(), 2, ptr1.get()) != 0);
            ASSERT_EQ(static_cast<uint64_t>(0xFFFFFFFFFFFFFFFE), ptr1[0]);
            ASSERT_EQ(static_cast<uint64_t>(0), ptr1[1]);

            ptr1[0] = 2;
            ptr1[1] = 0;
            ASSERT_FALSE(decrement_uint(ptr1.get(), 2, ptr2.get()) != 0);
            ASSERT_EQ(1ULL, ptr2[0]);
            ASSERT_EQ(static_cast<uint64_t>(0), ptr2[1]);
            ASSERT_FALSE(decrement_uint(ptr2.get(), 2, ptr1.get()) != 0);
            ASSERT_EQ(static_cast<uint64_t>(0), ptr1[0]);
            ASSERT_EQ(static_cast<uint64_t>(0), ptr1[1]);
            ASSERT_TRUE(decrement_uint(ptr1.get(), 2, ptr2.get()) != 0);
            ASSERT_EQ(static_cast<uint64_t>(0xFFFFFFFFFFFFFFFF), ptr2[0]);
            ASSERT_EQ(static_cast<uint64_t>(0xFFFFFFFFFFFFFFFF), ptr2[1]);
            ASSERT_FALSE(decrement_uint(ptr2.get(), 2, ptr1.get()) != 0);
            ASSERT_EQ(static_cast<uint64_t>(0xFFFFFFFFFFFFFFFE), ptr1[0]);
            ASSERT_EQ(static_cast<uint64_t>(0xFFFFFFFFFFFFFFFF), ptr1[1]);
        }

        TEST(UIntArith, NegateUInt)
        {
            MemoryPool &pool = *global_variables::global_memory_pool;
            auto ptr(allocate_uint(2, pool));
            ptr[0] = 0;
            ptr[1] = 0;
            negate_uint(ptr.get(), 2, ptr.get());
            ASSERT_EQ(static_cast<uint64_t>(0), ptr[0]);
            ASSERT_EQ(static_cast<uint64_t>(0), ptr[1]);

            ptr[0] = 1;
            ptr[1] = 0;
            negate_uint(ptr.get(), 2, ptr.get());
            ASSERT_EQ(static_cast<uint64_t>(0xFFFFFFFFFFFFFFFF), ptr[0]);
            ASSERT_EQ(static_cast<uint64_t>(0xFFFFFFFFFFFFFFFF), ptr[1]);
            negate_uint(ptr.get(), 2, ptr.get());
            ASSERT_EQ(1ULL, ptr[0]);
            ASSERT_EQ(static_cast<uint64_t>(0), ptr[1]);

            ptr[0] = 2;
            ptr[1] = 0;
            negate_uint(ptr.get(), 2, ptr.get());
            ASSERT_EQ(static_cast<uint64_t>(0xFFFFFFFFFFFFFFFE), ptr[0]);
            ASSERT_EQ(static_cast<uint64_t>(0xFFFFFFFFFFFFFFFF), ptr[1]);
            negate_uint(ptr.get(), 2, ptr.get());
            ASSERT_EQ(static_cast<uint64_t>(2), ptr[0]);
            ASSERT_EQ(static_cast<uint64_t>(0), ptr[1]);

            ptr[0] = 0;
            ptr[1] = 1;
            negate_uint(ptr.get(), 2, ptr.get());
            ASSERT_EQ(static_cast<uint64_t>(0), ptr[0]);
            ASSERT_EQ(static_cast<uint64_t>(0xFFFFFFFFFFFFFFFF), ptr[1]);
            negate_uint(ptr.get(), 2, ptr.get());
            ASSERT_EQ(static_cast<uint64_t>(0), ptr[0]);
            ASSERT_EQ(1ULL, ptr[1]);

            ptr[0] = 0;
            ptr[1] = 2;
            negate_uint(ptr.get(), 2, ptr.get());
            ASSERT_EQ(static_cast<uint64_t>(0), ptr[0]);
            ASSERT_EQ(static_cast<uint64_t>(0xFFFFFFFFFFFFFFFE), ptr[1]);
            negate_uint(ptr.get(), 2, ptr.get());
            ASSERT_EQ(static_cast<uint64_t>(0), ptr[0]);
            ASSERT_EQ(static_cast<uint64_t>(2), ptr[1]);

            ptr[0] = 1;
            ptr[1] = 1;
            negate_uint(ptr.get(), 2, ptr.get());
            ASSERT_EQ(static_cast<uint64_t>(0xFFFFFFFFFFFFFFFF), ptr[0]);
            ASSERT_EQ(static_cast<uint64_t>(0xFFFFFFFFFFFFFFFE), ptr[1]);
            negate_uint(ptr.get(), 2, ptr.get());
            ASSERT_EQ(1ULL, ptr[0]);
            ASSERT_EQ(1ULL, ptr[1]);
        }

        TEST(UIntArith, LeftShiftUInt)
        {
            MemoryPool &pool = *global_variables::global_memory_pool;
            auto ptr(allocate_uint(2, pool));
            auto ptr2(allocate_uint(2, pool));
            ptr[0] = 0;
            ptr[1] = 0;
            ptr2[0] = 0xFFFFFFFFFFFFFFFF;
            ptr2[1] = 0xFFFFFFFFFFFFFFFF;
            left_shift_uint(ptr.get(), 0, 2, ptr2.get());
            ASSERT_EQ(static_cast<uint64_t>(0), ptr2[0]);
            ASSERT_EQ(static_cast<uint64_t>(0), ptr2[1]);
            ptr2[0] = 0xFFFFFFFFFFFFFFFF;
            ptr2[1] = 0xFFFFFFFFFFFFFFFF;
            left_shift_uint(ptr.get(), 10, 2, ptr2.get());
            ASSERT_EQ(static_cast<uint64_t>(0), ptr2[0]);
            ASSERT_EQ(static_cast<uint64_t>(0), ptr2[1]);
            left_shift_uint(ptr.get(), 10, 2, ptr.get());
            ASSERT_EQ(static_cast<uint64_t>(0), ptr[0]);
            ASSERT_EQ(static_cast<uint64_t>(0), ptr[1]);

            ptr[0] = 0x5555555555555555;
            ptr[1] = 0xAAAAAAAAAAAAAAAA;
            left_shift_uint(ptr.get(), 0, 2, ptr2.get());
            ASSERT_EQ(static_cast<uint64_t>(0x5555555555555555), ptr2[0]);
            ASSERT_EQ(static_cast<uint64_t>(0xAAAAAAAAAAAAAAAA), ptr2[1]);
            left_shift_uint(ptr.get(), 0, 2, ptr.get());
            ASSERT_EQ(static_cast<uint64_t>(0x5555555555555555), ptr[0]);
            ASSERT_EQ(static_cast<uint64_t>(0xAAAAAAAAAAAAAAAA), ptr[1]);
            left_shift_uint(ptr.get(), 1, 2, ptr2.get());
            ASSERT_EQ(static_cast<uint64_t>(0xAAAAAAAAAAAAAAAA), ptr2[0]);
            ASSERT_EQ(static_cast<uint64_t>(0x5555555555555554), ptr2[1]);
            left_shift_uint(ptr.get(), 2, 2, ptr2.get());
            ASSERT_EQ(static_cast<uint64_t>(0x5555555555555554), ptr2[0]);
            ASSERT_EQ(static_cast<uint64_t>(0xAAAAAAAAAAAAAAA9), ptr2[1]);
            left_shift_uint(ptr.get(), 64, 2, ptr2.get());
            ASSERT_EQ(static_cast<uint64_t>(0), ptr2[0]);
            ASSERT_EQ(static_cast<uint64_t>(0x5555555555555555), ptr2[1]);
            left_shift_uint(ptr.get(), 65, 2, ptr2.get());
            ASSERT_EQ(static_cast<uint64_t>(0), ptr2[0]);
            ASSERT_EQ(static_cast<uint64_t>(0xAAAAAAAAAAAAAAAA), ptr2[1]);
            left_shift_uint(ptr.get(), 127, 2, ptr2.get());
            ASSERT_EQ(static_cast<uint64_t>(0), ptr2[0]);
            ASSERT_EQ(static_cast<uint64_t>(0x8000000000000000), ptr2[1]);

            left_shift_uint(ptr.get(), 2, 2, ptr.get());
            ASSERT_EQ(static_cast<uint64_t>(0x5555555555555554), ptr[0]);
            ASSERT_EQ(static_cast<uint64_t>(0xAAAAAAAAAAAAAAA9), ptr[1]);
            left_shift_uint(ptr.get(), 64, 2, ptr.get());
            ASSERT_EQ(static_cast<uint64_t>(0), ptr[0]);
            ASSERT_EQ(static_cast<uint64_t>(0x5555555555555554), ptr[1]);
        }

        TEST(UIntArith, LeftShiftUInt128)
        {
            MemoryPool &pool = *global_variables::global_memory_pool;
            auto ptr(allocate_uint(2, pool));
            auto ptr2(allocate_uint(2, pool));
            ptr[0] = 0;
            ptr[1] = 0;
            ptr2[0] = 0xFFFFFFFFFFFFFFFF;
            ptr2[1] = 0xFFFFFFFFFFFFFFFF;
            left_shift_uint128(ptr.get(), 0, ptr2.get());
            ASSERT_EQ(static_cast<uint64_t>(0), ptr2[0]);
            ASSERT_EQ(static_cast<uint64_t>(0), ptr2[1]);
            ptr2[0] = 0xFFFFFFFFFFFFFFFF;
            ptr2[1] = 0xFFFFFFFFFFFFFFFF;
            left_shift_uint128(ptr.get(), 10, ptr2.get());
            ASSERT_EQ(static_cast<uint64_t>(0), ptr2[0]);
            ASSERT_EQ(static_cast<uint64_t>(0), ptr2[1]);
            left_shift_uint128(ptr.get(), 10, ptr.get());
            ASSERT_EQ(static_cast<uint64_t>(0), ptr[0]);
            ASSERT_EQ(static_cast<uint64_t>(0), ptr[1]);

            ptr[0] = 0x5555555555555555;
            ptr[1] = 0xAAAAAAAAAAAAAAAA;
            left_shift_uint128(ptr.get(), 0, ptr2.get());
            ASSERT_EQ(static_cast<uint64_t>(0x5555555555555555), ptr2[0]);
            ASSERT_EQ(static_cast<uint64_t>(0xAAAAAAAAAAAAAAAA), ptr2[1]);
            left_shift_uint128(ptr.get(), 0, ptr.get());
            ASSERT_EQ(static_cast<uint64_t>(0x5555555555555555), ptr[0]);
            ASSERT_EQ(static_cast<uint64_t>(0xAAAAAAAAAAAAAAAA), ptr[1]);
            left_shift_uint128(ptr.get(), 1, ptr2.get());
            ASSERT_EQ(static_cast<uint64_t>(0xAAAAAAAAAAAAAAAA), ptr2[0]);
            ASSERT_EQ(static_cast<uint64_t>(0x5555555555555554), ptr2[1]);
            left_shift_uint128(ptr.get(), 2, ptr2.get());
            ASSERT_EQ(static_cast<uint64_t>(0x5555555555555554), ptr2[0]);
            ASSERT_EQ(static_cast<uint64_t>(0xAAAAAAAAAAAAAAA9), ptr2[1]);
            left_shift_uint128(ptr.get(), 64, ptr2.get());
            ASSERT_EQ(static_cast<uint64_t>(0), ptr2[0]);
            ASSERT_EQ(static_cast<uint64_t>(0x5555555555555555), ptr2[1]);
            left_shift_uint128(ptr.get(), 65, ptr2.get());
            ASSERT_EQ(static_cast<uint64_t>(0), ptr2[0]);
            ASSERT_EQ(static_cast<uint64_t>(0xAAAAAAAAAAAAAAAA), ptr2[1]);
            left_shift_uint128(ptr.get(), 127, ptr2.get());
            ASSERT_EQ(static_cast<uint64_t>(0), ptr2[0]);
            ASSERT_EQ(static_cast<uint64_t>(0x8000000000000000), ptr2[1]);

            left_shift_uint128(ptr.get(), 2, ptr.get());
            ASSERT_EQ(static_cast<uint64_t>(0x5555555555555554), ptr[0]);
            ASSERT_EQ(static_cast<uint64_t>(0xAAAAAAAAAAAAAAA9), ptr[1]);
            left_shift_uint128(ptr.get(), 64, ptr.get());
            ASSERT_EQ(static_cast<uint64_t>(0), ptr[0]);
            ASSERT_EQ(static_cast<uint64_t>(0x5555555555555554), ptr[1]);
        }

        TEST(UIntArith, LeftShiftUInt192)
        {
            MemoryPool &pool = *global_variables::global_memory_pool;
            auto ptr(allocate_uint(3, pool));
            auto ptr2(allocate_uint(3, pool));
            ptr[0] = 0;
            ptr[1] = 0;
            ptr[2] = 0;
            ptr2[0] = 0xFFFFFFFFFFFFFFFF;
            ptr2[1] = 0xFFFFFFFFFFFFFFFF;
            ptr2[2] = 0xFFFFFFFFFFFFFFFF;
            left_shift_uint192(ptr.get(), 0, ptr2.get());
            ASSERT_EQ(static_cast<uint64_t>(0), ptr2[0]);
            ASSERT_EQ(static_cast<uint64_t>(0), ptr2[1]);
            ASSERT_EQ(static_cast<uint64_t>(0), ptr2[2]);
            ptr2[0] = 0xFFFFFFFFFFFFFFFF;
            ptr2[1] = 0xFFFFFFFFFFFFFFFF;
            ptr2[2] = 0xFFFFFFFFFFFFFFFF;
            left_shift_uint192(ptr.get(), 10, ptr2.get());
            ASSERT_EQ(static_cast<uint64_t>(0), ptr2[0]);
            ASSERT_EQ(static_cast<uint64_t>(0), ptr2[1]);
            ASSERT_EQ(static_cast<uint64_t>(0), ptr2[2]);
            left_shift_uint192(ptr.get(), 10, ptr.get());
            ASSERT_EQ(static_cast<uint64_t>(0), ptr[0]);
            ASSERT_EQ(static_cast<uint64_t>(0), ptr[1]);
            ASSERT_EQ(static_cast<uint64_t>(0), ptr[2]);

            ptr[0] = 0x5555555555555555;
            ptr[1] = 0xAAAAAAAAAAAAAAAA;
            ptr[2] = 0xCDCDCDCDCDCDCDCD;
            left_shift_uint192(ptr.get(), 0, ptr2.get());
            ASSERT_EQ(static_cast<uint64_t>(0x5555555555555555), ptr2[0]);
            ASSERT_EQ(static_cast<uint64_t>(0xAAAAAAAAAAAAAAAA), ptr2[1]);
            ASSERT_EQ(static_cast<uint64_t>(0xCDCDCDCDCDCDCDCD), ptr2[2]);
            left_shift_uint192(ptr.get(), 0, ptr.get());
            ASSERT_EQ(static_cast<uint64_t>(0x5555555555555555), ptr[0]);
            ASSERT_EQ(static_cast<uint64_t>(0xAAAAAAAAAAAAAAAA), ptr[1]);
            ASSERT_EQ(static_cast<uint64_t>(0xCDCDCDCDCDCDCDCD), ptr[2]);
            left_shift_uint192(ptr.get(), 1, ptr2.get());
            ASSERT_EQ(static_cast<uint64_t>(0xAAAAAAAAAAAAAAAA), ptr2[0]);
            ASSERT_EQ(static_cast<uint64_t>(0x5555555555555554), ptr2[1]);
            ASSERT_EQ(static_cast<uint64_t>(0x9B9B9B9B9B9B9B9B), ptr2[2]);
            left_shift_uint192(ptr.get(), 2, ptr2.get());
            ASSERT_EQ(static_cast<uint64_t>(0x5555555555555554), ptr2[0]);
            ASSERT_EQ(static_cast<uint64_t>(0xAAAAAAAAAAAAAAA9), ptr2[1]);
            ASSERT_EQ(static_cast<uint64_t>(0x3737373737373736), ptr2[2]);
            left_shift_uint192(ptr.get(), 64, ptr2.get());
            ASSERT_EQ(static_cast<uint64_t>(0), ptr2[0]);
            ASSERT_EQ(static_cast<uint64_t>(0x5555555555555555), ptr2[1]);
            ASSERT_EQ(static_cast<uint64_t>(0xAAAAAAAAAAAAAAAA), ptr2[2]);
            left_shift_uint192(ptr.get(), 65, ptr2.get());
            ASSERT_EQ(static_cast<uint64_t>(0), ptr2[0]);
            ASSERT_EQ(static_cast<uint64_t>(0xAAAAAAAAAAAAAAAA), ptr2[1]);
            ASSERT_EQ(static_cast<uint64_t>(0x5555555555555554), ptr2[2]);
            left_shift_uint192(ptr.get(), 191, ptr2.get());
            ASSERT_EQ(static_cast<uint64_t>(0), ptr2[0]);
            ASSERT_EQ(static_cast<uint64_t>(0), ptr2[1]);
            ASSERT_EQ(static_cast<uint64_t>(0x8000000000000000), ptr2[2]);

            left_shift_uint192(ptr.get(), 2, ptr.get());
            ASSERT_EQ(static_cast<uint64_t>(0x5555555555555554), ptr[0]);
            ASSERT_EQ(static_cast<uint64_t>(0xAAAAAAAAAAAAAAA9), ptr[1]);
            ASSERT_EQ(static_cast<uint64_t>(0x3737373737373736), ptr[2]);

            left_shift_uint192(ptr.get(), 64, ptr.get());
            ASSERT_EQ(static_cast<uint64_t>(0), ptr[0]);
            ASSERT_EQ(static_cast<uint64_t>(0x5555555555555554), ptr[1]);
            ASSERT_EQ(static_cast<uint64_t>(0xAAAAAAAAAAAAAAA9), ptr[2]);
        }

        TEST(UIntArith, RightShiftUInt)
        {
            MemoryPool &pool = *global_variables::global_memory_pool;
            auto ptr(allocate_uint(2, pool));
            auto ptr2(allocate_uint(2, pool));
            ptr[0] = 0;
            ptr[1] = 0;
            ptr2[0] = 0xFFFFFFFFFFFFFFFF;
            ptr2[1] = 0xFFFFFFFFFFFFFFFF;
            right_shift_uint(ptr.get(), 0, 2, ptr2.get());
            ASSERT_EQ(static_cast<uint64_t>(0), ptr2[0]);
            ASSERT_EQ(static_cast<uint64_t>(0), ptr2[1]);
            ptr2[0] = 0xFFFFFFFFFFFFFFFF;
            ptr2[1] = 0xFFFFFFFFFFFFFFFF;
            right_shift_uint(ptr.get(), 10, 2, ptr2.get());
            ASSERT_EQ(static_cast<uint64_t>(0), ptr2[0]);
            ASSERT_EQ(static_cast<uint64_t>(0), ptr2[1]);
            right_shift_uint(ptr.get(), 10, 2, ptr.get());
            ASSERT_EQ(static_cast<uint64_t>(0), ptr[0]);
            ASSERT_EQ(static_cast<uint64_t>(0), ptr[1]);

            ptr[0] = 0x5555555555555555;
            ptr[1] = 0xAAAAAAAAAAAAAAAA;
            right_shift_uint(ptr.get(), 0, 2, ptr2.get());
            ASSERT_EQ(static_cast<uint64_t>(0x5555555555555555), ptr2[0]);
            ASSERT_EQ(static_cast<uint64_t>(0xAAAAAAAAAAAAAAAA), ptr2[1]);
            right_shift_uint(ptr.get(), 0, 2, ptr.get());
            ASSERT_EQ(static_cast<uint64_t>(0x5555555555555555), ptr[0]);
            ASSERT_EQ(static_cast<uint64_t>(0xAAAAAAAAAAAAAAAA), ptr[1]);
            right_shift_uint(ptr.get(), 1, 2, ptr2.get());
            ASSERT_EQ(static_cast<uint64_t>(0x2AAAAAAAAAAAAAAA), ptr2[0]);
            ASSERT_EQ(static_cast<uint64_t>(0x5555555555555555), ptr2[1]);
            right_shift_uint(ptr.get(), 2, 2, ptr2.get());
            ASSERT_EQ(static_cast<uint64_t>(0x9555555555555555), ptr2[0]);
            ASSERT_EQ(static_cast<uint64_t>(0x2AAAAAAAAAAAAAAA), ptr2[1]);
            right_shift_uint(ptr.get(), 64, 2, ptr2.get());
            ASSERT_EQ(static_cast<uint64_t>(0xAAAAAAAAAAAAAAAA), ptr2[0]);
            ASSERT_EQ(static_cast<uint64_t>(0), ptr2[1]);
            right_shift_uint(ptr.get(), 65, 2, ptr2.get());
            ASSERT_EQ(static_cast<uint64_t>(0x5555555555555555), ptr2[0]);
            ASSERT_EQ(static_cast<uint64_t>(0), ptr2[1]);
            right_shift_uint(ptr.get(), 127, 2, ptr2.get());
            ASSERT_EQ(1ULL, ptr2[0]);
            ASSERT_EQ(static_cast<uint64_t>(0), ptr2[1]);

            right_shift_uint(ptr.get(), 2, 2, ptr.get());
            ASSERT_EQ(static_cast<uint64_t>(0x9555555555555555), ptr[0]);
            ASSERT_EQ(static_cast<uint64_t>(0x2AAAAAAAAAAAAAAA), ptr[1]);
            right_shift_uint(ptr.get(), 64, 2, ptr.get());
            ASSERT_EQ(static_cast<uint64_t>(0x2AAAAAAAAAAAAAAA), ptr[0]);
            ASSERT_EQ(static_cast<uint64_t>(0), ptr[1]);
        }

        TEST(UIntArith, RightShiftUInt128)
        {
            MemoryPool &pool = *global_variables::global_memory_pool;
            auto ptr(allocate_uint(2, pool));
            auto ptr2(allocate_uint(2, pool));
            ptr[0] = 0;
            ptr[1] = 0;
            ptr2[0] = 0xFFFFFFFFFFFFFFFF;
            ptr2[1] = 0xFFFFFFFFFFFFFFFF;
            right_shift_uint128(ptr.get(), 0, ptr2.get());
            ASSERT_EQ(static_cast<uint64_t>(0), ptr2[0]);
            ASSERT_EQ(static_cast<uint64_t>(0), ptr2[1]);
            ptr2[0] = 0xFFFFFFFFFFFFFFFF;
            ptr2[1] = 0xFFFFFFFFFFFFFFFF;
            right_shift_uint128(ptr.get(), 10, ptr2.get());
            ASSERT_EQ(static_cast<uint64_t>(0), ptr2[0]);
            ASSERT_EQ(static_cast<uint64_t>(0), ptr2[1]);
            right_shift_uint128(ptr.get(), 10, ptr.get());
            ASSERT_EQ(static_cast<uint64_t>(0), ptr[0]);
            ASSERT_EQ(static_cast<uint64_t>(0), ptr[1]);

            ptr[0] = 0x5555555555555555;
            ptr[1] = 0xAAAAAAAAAAAAAAAA;
            right_shift_uint128(ptr.get(), 0, ptr2.get());
            ASSERT_EQ(static_cast<uint64_t>(0x5555555555555555), ptr2[0]);
            ASSERT_EQ(static_cast<uint64_t>(0xAAAAAAAAAAAAAAAA), ptr2[1]);
            right_shift_uint128(ptr.get(), 0, ptr.get());
            ASSERT_EQ(static_cast<uint64_t>(0x5555555555555555), ptr[0]);
            ASSERT_EQ(static_cast<uint64_t>(0xAAAAAAAAAAAAAAAA), ptr[1]);
            right_shift_uint128(ptr.get(), 1, ptr2.get());
            ASSERT_EQ(static_cast<uint64_t>(0x2AAAAAAAAAAAAAAA), ptr2[0]);
            ASSERT_EQ(static_cast<uint64_t>(0x5555555555555555), ptr2[1]);
            right_shift_uint128(ptr.get(), 2, ptr2.get());
            ASSERT_EQ(static_cast<uint64_t>(0x9555555555555555), ptr2[0]);
            ASSERT_EQ(static_cast<uint64_t>(0x2AAAAAAAAAAAAAAA), ptr2[1]);
            right_shift_uint128(ptr.get(), 64, ptr2.get());
            ASSERT_EQ(static_cast<uint64_t>(0xAAAAAAAAAAAAAAAA), ptr2[0]);
            ASSERT_EQ(static_cast<uint64_t>(0), ptr2[1]);
            right_shift_uint128(ptr.get(), 65, ptr2.get());
            ASSERT_EQ(static_cast<uint64_t>(0x5555555555555555), ptr2[0]);
            ASSERT_EQ(static_cast<uint64_t>(0), ptr2[1]);
            right_shift_uint128(ptr.get(), 127, ptr2.get());
            ASSERT_EQ(1ULL, ptr2[0]);
            ASSERT_EQ(static_cast<uint64_t>(0), ptr2[1]);

            right_shift_uint128(ptr.get(), 2, ptr.get());
            ASSERT_EQ(static_cast<uint64_t>(0x9555555555555555), ptr[0]);
            ASSERT_EQ(static_cast<uint64_t>(0x2AAAAAAAAAAAAAAA), ptr[1]);
            right_shift_uint128(ptr.get(), 64, ptr.get());
            ASSERT_EQ(static_cast<uint64_t>(0x2AAAAAAAAAAAAAAA), ptr[0]);
            ASSERT_EQ(static_cast<uint64_t>(0), ptr[1]);
        }

        TEST(UIntArith, RightShiftUInt192)
        {
            MemoryPool &pool = *global_variables::global_memory_pool;
            auto ptr(allocate_uint(3, pool));
            auto ptr2(allocate_uint(3, pool));
            ptr[0] = 0;
            ptr[1] = 0;
            ptr[2] = 0;
            ptr2[0] = 0xFFFFFFFFFFFFFFFF;
            ptr2[1] = 0xFFFFFFFFFFFFFFFF;
            ptr2[2] = 0xFFFFFFFFFFFFFFFF;
            right_shift_uint192(ptr.get(), 0, ptr2.get());
            ASSERT_EQ(static_cast<uint64_t>(0), ptr2[0]);
            ASSERT_EQ(static_cast<uint64_t>(0), ptr2[1]);
            ASSERT_EQ(static_cast<uint64_t>(0), ptr2[2]);
            ptr2[0] = 0xFFFFFFFFFFFFFFFF;
            ptr2[1] = 0xFFFFFFFFFFFFFFFF;
            ptr2[2] = 0xFFFFFFFFFFFFFFFF;
            right_shift_uint192(ptr.get(), 10, ptr2.get());
            ASSERT_EQ(static_cast<uint64_t>(0), ptr2[0]);
            ASSERT_EQ(static_cast<uint64_t>(0), ptr2[1]);
            ASSERT_EQ(static_cast<uint64_t>(0), ptr2[2]);
            right_shift_uint192(ptr.get(), 10, ptr.get());
            ASSERT_EQ(static_cast<uint64_t>(0), ptr[0]);
            ASSERT_EQ(static_cast<uint64_t>(0), ptr[1]);
            ASSERT_EQ(static_cast<uint64_t>(0), ptr[2]);

            ptr[0] = 0x5555555555555555;
            ptr[1] = 0xAAAAAAAAAAAAAAAA;
            ptr[2] = 0xCDCDCDCDCDCDCDCD;

            right_shift_uint192(ptr.get(), 0, ptr2.get());
            ASSERT_EQ(static_cast<uint64_t>(0x5555555555555555), ptr2[0]);
            ASSERT_EQ(static_cast<uint64_t>(0xAAAAAAAAAAAAAAAA), ptr2[1]);
            ASSERT_EQ(static_cast<uint64_t>(0xCDCDCDCDCDCDCDCD), ptr2[2]);
            right_shift_uint192(ptr.get(), 0, ptr.get());
            ASSERT_EQ(static_cast<uint64_t>(0x5555555555555555), ptr[0]);
            ASSERT_EQ(static_cast<uint64_t>(0xAAAAAAAAAAAAAAAA), ptr[1]);
            ASSERT_EQ(static_cast<uint64_t>(0xCDCDCDCDCDCDCDCD), ptr[2]);
            right_shift_uint192(ptr.get(), 1, ptr2.get());
            ASSERT_EQ(static_cast<uint64_t>(0x2AAAAAAAAAAAAAAA), ptr2[0]);
            ASSERT_EQ(static_cast<uint64_t>(0xD555555555555555), ptr2[1]);
            ASSERT_EQ(static_cast<uint64_t>(0x66E6E6E6E6E6E6E6), ptr2[2]);
            right_shift_uint192(ptr.get(), 2, ptr2.get());
            ASSERT_EQ(static_cast<uint64_t>(0x9555555555555555), ptr2[0]);
            ASSERT_EQ(static_cast<uint64_t>(0x6AAAAAAAAAAAAAAA), ptr2[1]);
            ASSERT_EQ(static_cast<uint64_t>(0x3373737373737373), ptr2[2]);
            right_shift_uint192(ptr.get(), 64, ptr2.get());
            ASSERT_EQ(static_cast<uint64_t>(0xAAAAAAAAAAAAAAAA), ptr2[0]);
            ASSERT_EQ(static_cast<uint64_t>(0xCDCDCDCDCDCDCDCD), ptr2[1]);
            ASSERT_EQ(static_cast<uint64_t>(0), ptr2[2]);
            right_shift_uint192(ptr.get(), 65, ptr2.get());
            ASSERT_EQ(static_cast<uint64_t>(0xD555555555555555), ptr2[0]);
            ASSERT_EQ(static_cast<uint64_t>(0x66E6E6E6E6E6E6E6), ptr2[1]);
            ASSERT_EQ(static_cast<uint64_t>(0), ptr2[2]);
            right_shift_uint192(ptr.get(), 191, ptr2.get());
            ASSERT_EQ(1ULL, ptr2[0]);
            ASSERT_EQ(static_cast<uint64_t>(0), ptr2[1]);
            ASSERT_EQ(static_cast<uint64_t>(0), ptr2[2]);

            right_shift_uint192(ptr.get(), 2, ptr.get());
            ASSERT_EQ(static_cast<uint64_t>(0x9555555555555555), ptr[0]);
            ASSERT_EQ(static_cast<uint64_t>(0x6AAAAAAAAAAAAAAA), ptr[1]);
            ASSERT_EQ(static_cast<uint64_t>(0x3373737373737373), ptr[2]);
            right_shift_uint192(ptr.get(), 64, ptr.get());
            ASSERT_EQ(static_cast<uint64_t>(0x6AAAAAAAAAAAAAAA), ptr[0]);
            ASSERT_EQ(static_cast<uint64_t>(0x3373737373737373), ptr[1]);
            ASSERT_EQ(static_cast<uint64_t>(0), ptr[2]);
        }

        TEST(UIntArith, HalfRoundUpUInt)
        {
            half_round_up_uint(nullptr, 0, nullptr);

            MemoryPool &pool = *global_variables::global_memory_pool;
            auto ptr(allocate_uint(2, pool));
            auto ptr2(allocate_uint(2, pool));
            ptr[0] = 0;
            ptr[1] = 0;
            ptr2[0] = 0xFFFFFFFFFFFFFFFF;
            ptr2[1] = 0xFFFFFFFFFFFFFFFF;
            half_round_up_uint(ptr.get(), 2, ptr2.get());
            ASSERT_EQ(static_cast<uint64_t>(0), ptr2[0]);
            ASSERT_EQ(static_cast<uint64_t>(0), ptr2[1]);
            half_round_up_uint(ptr.get(), 2, ptr.get());
            ASSERT_EQ(static_cast<uint64_t>(0), ptr[0]);
            ASSERT_EQ(static_cast<uint64_t>(0), ptr[1]);

            ptr[0] = 1;
            ptr[1] = 0;
            ptr2[0] = 0xFFFFFFFFFFFFFFFF;
            ptr2[1] = 0xFFFFFFFFFFFFFFFF;
            half_round_up_uint(ptr.get(), 2, ptr2.get());
            ASSERT_EQ(1ULL, ptr2[0]);
            ASSERT_EQ(static_cast<uint64_t>(0), ptr2[1]);
            half_round_up_uint(ptr.get(), 2, ptr.get());
            ASSERT_EQ(1ULL, ptr[0]);
            ASSERT_EQ(static_cast<uint64_t>(0), ptr[1]);

            ptr[0] = 2;
            ptr[1] = 0;
            ptr2[0] = 0xFFFFFFFFFFFFFFFF;
            ptr2[1] = 0xFFFFFFFFFFFFFFFF;
            half_round_up_uint(ptr.get(), 2, ptr2.get());
            ASSERT_EQ(1ULL, ptr2[0]);
            ASSERT_EQ(static_cast<uint64_t>(0), ptr2[1]);
            half_round_up_uint(ptr.get(), 2, ptr.get());
            ASSERT_EQ(1ULL, ptr[0]);
            ASSERT_EQ(static_cast<uint64_t>(0), ptr[1]);

            ptr[0] = 3;
            ptr[1] = 0;
            ptr2[0] = 0xFFFFFFFFFFFFFFFF;
            ptr2[1] = 0xFFFFFFFFFFFFFFFF;
            half_round_up_uint(ptr.get(), 2, ptr2.get());
            ASSERT_EQ(static_cast<uint64_t>(2), ptr2[0]);
            ASSERT_EQ(static_cast<uint64_t>(0), ptr2[1]);

            ptr[0] = 4;
            ptr[1] = 0;
            ptr2[0] = 0xFFFFFFFFFFFFFFFF;
            ptr2[1] = 0xFFFFFFFFFFFFFFFF;
            half_round_up_uint(ptr.get(), 2, ptr2.get());
            ASSERT_EQ(static_cast<uint64_t>(2), ptr2[0]);
            ASSERT_EQ(static_cast<uint64_t>(0), ptr2[1]);

            ptr[0] = 0xFFFFFFFFFFFFFFFF;
            ptr[1] = 0xFFFFFFFFFFFFFFFF;
            ptr2[0] = 0xFFFFFFFFFFFFFFFF;
            ptr2[1] = 0xFFFFFFFFFFFFFFFF;
            half_round_up_uint(ptr.get(), 2, ptr2.get());
            ASSERT_EQ(static_cast<uint64_t>(0), ptr2[0]);
            ASSERT_EQ(static_cast<uint64_t>(0x8000000000000000), ptr2[1]);
            half_round_up_uint(ptr.get(), 2, ptr.get());
            ASSERT_EQ(static_cast<uint64_t>(0), ptr[0]);
            ASSERT_EQ(static_cast<uint64_t>(0x8000000000000000), ptr[1]);
        }

        TEST(UIntArith, NotUInt)
        {
            not_uint(nullptr, 0, nullptr);

            MemoryPool &pool = *global_variables::global_memory_pool;
            auto ptr(allocate_uint(2, pool));
            ptr[0] = 0xFFFFFFFFFFFFFFFF;
            ptr[1] = 0;
            not_uint(ptr.get(), 2, ptr.get());
            ASSERT_EQ(static_cast<uint64_t>(0), ptr[0]);
            ASSERT_EQ(static_cast<uint64_t>(0xFFFFFFFFFFFFFFFF), ptr[1]);

            ptr[0] = 0xFFFFFFFF00000000;
            ptr[1] = 0xFFFF0000FFFF0000;
            not_uint(ptr.get(), 2, ptr.get());
            ASSERT_EQ(static_cast<uint64_t>(0x00000000FFFFFFFF), ptr[0]);
            ASSERT_EQ(static_cast<uint64_t>(0x0000FFFF0000FFFF), ptr[1]);
        }

        TEST(UIntArith, AndUIntUInt)
        {
            and_uint_uint(nullptr, nullptr, 0, nullptr);

            MemoryPool &pool = *global_variables::global_memory_pool;
            auto ptr(allocate_uint(2, pool));
            auto ptr2(allocate_uint(2, pool));
            auto ptr3(allocate_uint(2, pool));
            ptr[0] = 0xFFFFFFFFFFFFFFFF;
            ptr[1] = 0;
            ptr2[0] = 0;
            ptr2[1] = 0xFFFFFFFFFFFFFFFF;
            ptr3[0] = 0xFFFFFFFFFFFFFFFF;
            ptr3[1] = 0xFFFFFFFFFFFFFFFF;
            and_uint_uint(ptr.get(), ptr2.get(), 2, ptr3.get());
            ASSERT_EQ(static_cast<uint64_t>(0), ptr3[0]);
            ASSERT_EQ(static_cast<uint64_t>(0), ptr3[1]);

            ptr[0] = 0xFFFFFFFF00000000;
            ptr[1] = 0xFFFF0000FFFF0000;
            ptr2[0] = 0x0000FFFF0000FFFF;
            ptr2[1] = 0xFF00FF00FF00FF00;
            ptr3[0] = 0;
            ptr3[1] = 0;
            and_uint_uint(ptr.get(), ptr2.get(), 2, ptr3.get());
            ASSERT_EQ(static_cast<uint64_t>(0x0000FFFF00000000), ptr3[0]);
            ASSERT_EQ(static_cast<uint64_t>(0xFF000000FF000000), ptr3[1]);
            and_uint_uint(ptr.get(), ptr2.get(), 2, ptr.get());
            ASSERT_EQ(static_cast<uint64_t>(0x0000FFFF00000000), ptr[0]);
            ASSERT_EQ(static_cast<uint64_t>(0xFF000000FF000000), ptr[1]);
        }

        TEST(UIntArith, OrUIntUInt)
        {
            or_uint_uint(nullptr, nullptr, 0, nullptr);

            MemoryPool &pool = *global_variables::global_memory_pool;
            auto ptr(allocate_uint(2, pool));
            auto ptr2(allocate_uint(2, pool));
            auto ptr3(allocate_uint(2, pool));
            ptr[0] = 0xFFFFFFFFFFFFFFFF;
            ptr[1] = 0;
            ptr2[0] = 0;
            ptr2[1] = 0xFFFFFFFFFFFFFFFF;
            ptr3[0] = 0;
            ptr3[1] = 0;
            or_uint_uint(ptr.get(), ptr2.get(), 2, ptr3.get());
            ASSERT_EQ(static_cast<uint64_t>(0xFFFFFFFFFFFFFFFF), ptr3[0]);
            ASSERT_EQ(static_cast<uint64_t>(0xFFFFFFFFFFFFFFFF), ptr3[1]);

            ptr[0] = 0xFFFFFFFF00000000;
            ptr[1] = 0xFFFF0000FFFF0000;
            ptr2[0] = 0x0000FFFF0000FFFF;
            ptr2[1] = 0xFF00FF00FF00FF00;
            ptr3[0] = 0;
            ptr3[1] = 0;
            or_uint_uint(ptr.get(), ptr2.get(), 2, ptr3.get());
            ASSERT_EQ(static_cast<uint64_t>(0xFFFFFFFF0000FFFF), ptr3[0]);
            ASSERT_EQ(static_cast<uint64_t>(0xFFFFFF00FFFFFF00), ptr3[1]);
            or_uint_uint(ptr.get(), ptr2.get(), 2, ptr.get());
            ASSERT_EQ(static_cast<uint64_t>(0xFFFFFFFF0000FFFF), ptr[0]);
            ASSERT_EQ(static_cast<uint64_t>(0xFFFFFF00FFFFFF00), ptr[1]);
        }

        TEST(UIntArith, XorUIntUInt)
        {
            xor_uint_uint(nullptr, nullptr, 0, nullptr);

            MemoryPool &pool = *global_variables::global_memory_pool;
            auto ptr(allocate_uint(2, pool));
            auto ptr2(allocate_uint(2, pool));
            auto ptr3(allocate_uint(2, pool));
            ptr[0] = 0xFFFFFFFFFFFFFFFF;
            ptr[1] = 0;
            ptr2[0] = 0;
            ptr2[1] = 0xFFFFFFFFFFFFFFFF;
            ptr3[0] = 0;
            ptr3[1] = 0;
            xor_uint_uint(ptr.get(), ptr2.get(), 2, ptr3.get());
            ASSERT_EQ(static_cast<uint64_t>(0xFFFFFFFFFFFFFFFF), ptr3[0]);
            ASSERT_EQ(static_cast<uint64_t>(0xFFFFFFFFFFFFFFFF), ptr3[1]);

            ptr[0] = 0xFFFFFFFF00000000;
            ptr[1] = 0xFFFF0000FFFF0000;
            ptr2[0] = 0x0000FFFF0000FFFF;
            ptr2[1] = 0xFF00FF00FF00FF00;
            ptr3[0] = 0;
            ptr3[1] = 0;
            xor_uint_uint(ptr.get(), ptr2.get(), 2, ptr3.get());
            ASSERT_EQ(static_cast<uint64_t>(0xFFFF00000000FFFF), ptr3[0]);
            ASSERT_EQ(static_cast<uint64_t>(0x00FFFF0000FFFF00), ptr3[1]);
            xor_uint_uint(ptr.get(), ptr2.get(), 2, ptr.get());
            ASSERT_EQ(static_cast<uint64_t>(0xFFFF00000000FFFF), ptr[0]);
            ASSERT_EQ(static_cast<uint64_t>(0x00FFFF0000FFFF00), ptr[1]);
        }

        TEST(UIntArith, MultiplyUInt64Generic)
        {
            unsigned long long result[2];

            multiply_uint64_generic(0ULL, 0ULL, result);
            ASSERT_EQ(0ULL, result[0]);
            ASSERT_EQ(0ULL, result[1]);
            multiply_uint64_generic(0ULL, 1ULL, result);
            ASSERT_EQ(0ULL, result[0]);
            ASSERT_EQ(0ULL, result[1]);
            multiply_uint64_generic(1ULL, 0ULL, result);
            ASSERT_EQ(0ULL, result[0]);
            ASSERT_EQ(0ULL, result[1]);
            multiply_uint64_generic(1ULL, 1ULL, result);
            ASSERT_EQ(1ULL, result[0]);
            ASSERT_EQ(0ULL, result[1]);
            multiply_uint64_generic(0x100000000ULL, 0xFAFABABAULL, result);
            ASSERT_EQ(0xFAFABABA00000000ULL, result[0]);
            ASSERT_EQ(0ULL, result[1]);
            multiply_uint64_generic(0x1000000000ULL, 0xFAFABABAULL, result);
            ASSERT_EQ(0xAFABABA000000000ULL, result[0]);
            ASSERT_EQ(0xFULL, result[1]);
            multiply_uint64_generic(1111222233334444ULL, 5555666677778888ULL, result);
            ASSERT_EQ(4140785562324247136ULL, result[0]);
            ASSERT_EQ(334670460471ULL, result[1]);
        }

        TEST(UIntArith, MultiplyUInt64)
        {
            unsigned long long result[2];

            multiply_uint64(0ULL, 0ULL, result);
            ASSERT_EQ(0ULL, result[0]);
            ASSERT_EQ(0ULL, result[1]);
            multiply_uint64(0ULL, 1ULL, result);
            ASSERT_EQ(0ULL, result[0]);
            ASSERT_EQ(0ULL, result[1]);
            multiply_uint64(1ULL, 0ULL, result);
            ASSERT_EQ(0ULL, result[0]);
            ASSERT_EQ(0ULL, result[1]);
            multiply_uint64(1ULL, 1ULL, result);
            ASSERT_EQ(1ULL, result[0]);
            ASSERT_EQ(0ULL, result[1]);
            multiply_uint64(0x100000000ULL, 0xFAFABABAULL, result);
            ASSERT_EQ(0xFAFABABA00000000ULL, result[0]);
            ASSERT_EQ(0ULL, result[1]);
            multiply_uint64(0x1000000000ULL, 0xFAFABABAULL, result);
            ASSERT_EQ(0xAFABABA000000000ULL, result[0]);
            ASSERT_EQ(0xFULL, result[1]);
            multiply_uint64(1111222233334444ULL, 5555666677778888ULL, result);
            ASSERT_EQ(4140785562324247136ULL, result[0]);
            ASSERT_EQ(334670460471ULL, result[1]);
        }

        TEST(UIntArith, MultiplyUInt64HW64Generic)
        {
            unsigned long long result;

            multiply_uint64_hw64_generic(0ULL, 0ULL, &result);
            ASSERT_EQ(0ULL, result);
            multiply_uint64_hw64_generic(0ULL, 1ULL, &result);
            ASSERT_EQ(0ULL, result);
            multiply_uint64_hw64_generic(1ULL, 0ULL, &result);
            ASSERT_EQ(0ULL, result);
            multiply_uint64_hw64_generic(1ULL, 1ULL, &result);
            ASSERT_EQ(0ULL, result);
            multiply_uint64_hw64_generic(0x100000000ULL, 0xFAFABABAULL, &result);
            ASSERT_EQ(0ULL, result);
            multiply_uint64_hw64_generic(0x1000000000ULL, 0xFAFABABAULL, &result);
            ASSERT_EQ(0xFULL, result);
            multiply_uint64_hw64_generic(1111222233334444ULL, 5555666677778888ULL, &result);
            ASSERT_EQ(334670460471ULL, result);
        }

        TEST(UIntArith, MultiplyUInt64HW64)
        {
            unsigned long long result;

            multiply_uint64_hw64(0ULL, 0ULL, &result);
            ASSERT_EQ(0ULL, result);
            multiply_uint64_hw64(0ULL, 1ULL, &result);
            ASSERT_EQ(0ULL, result);
            multiply_uint64_hw64(1ULL, 0ULL, &result);
            ASSERT_EQ(0ULL, result);
            multiply_uint64_hw64(1ULL, 1ULL, &result);
            ASSERT_EQ(0ULL, result);
            multiply_uint64_hw64(0x100000000ULL, 0xFAFABABAULL, &result);
            ASSERT_EQ(0ULL, result);
            multiply_uint64_hw64(0x1000000000ULL, 0xFAFABABAULL, &result);
            ASSERT_EQ(0xFULL, result);
            multiply_uint64_hw64(1111222233334444ULL, 5555666677778888ULL, &result);
            ASSERT_EQ(334670460471ULL, result);
        }

        TEST(UIntArith, MultiplyUIntUInt)
        {
            MemoryPool &pool = *global_variables::global_memory_pool;
            auto ptr(allocate_uint(2, pool));
            auto ptr2(allocate_uint(2, pool));
            auto ptr3(allocate_uint(4, pool));
            ptr[0] = 0;
            ptr[1] = 0;
            ptr2[0] = 0;
            ptr2[1] = 0;
            ptr3[0] = 0xFFFFFFFFFFFFFFFF;
            ptr3[1] = 0xFFFFFFFFFFFFFFFF;
            ptr3[2] = 0xFFFFFFFFFFFFFFFF;
            ptr3[3] = 0xFFFFFFFFFFFFFFFF;
            multiply_uint_uint(ptr.get(), ptr2.get(), 2, ptr3.get());
            ASSERT_EQ(static_cast<uint64_t>(0), ptr3[0]);
            ASSERT_EQ(static_cast<uint64_t>(0), ptr3[1]);
            ASSERT_EQ(static_cast<uint64_t>(0), ptr3[2]);
            ASSERT_EQ(static_cast<uint64_t>(0), ptr3[3]);

            ptr[0] = 0xFFFFFFFFFFFFFFFF;
            ptr[1] = 0xFFFFFFFFFFFFFFFF;
            ptr2[0] = 0;
            ptr2[1] = 0;
            ptr3[0] = 0xFFFFFFFFFFFFFFFF;
            ptr3[1] = 0xFFFFFFFFFFFFFFFF;
            ptr3[2] = 0xFFFFFFFFFFFFFFFF;
            ptr3[3] = 0xFFFFFFFFFFFFFFFF;
            multiply_uint_uint(ptr.get(), ptr2.get(), 2, ptr3.get());
            ASSERT_EQ(static_cast<uint64_t>(0), ptr3[0]);
            ASSERT_EQ(static_cast<uint64_t>(0), ptr3[1]);
            ASSERT_EQ(static_cast<uint64_t>(0), ptr3[2]);
            ASSERT_EQ(static_cast<uint64_t>(0), ptr3[3]);

            ptr[0] = 0xFFFFFFFFFFFFFFFF;
            ptr[1] = 0xFFFFFFFFFFFFFFFF;
            ptr2[0] = 1;
            ptr2[1] = 0;
            ptr3[0] = 0;
            ptr3[1] = 0;
            ptr3[2] = 0;
            ptr3[3] = 0;
            multiply_uint_uint(ptr.get(), ptr2.get(), 2, ptr3.get());
            ASSERT_EQ(static_cast<uint64_t>(0xFFFFFFFFFFFFFFFF), ptr3[0]);
            ASSERT_EQ(static_cast<uint64_t>(0xFFFFFFFFFFFFFFFF), ptr3[1]);
            ASSERT_EQ(static_cast<uint64_t>(0), ptr3[2]);
            ASSERT_EQ(static_cast<uint64_t>(0), ptr3[3]);

            ptr[0] = 0xFFFFFFFFFFFFFFFF;
            ptr[1] = 0xFFFFFFFFFFFFFFFF;
            ptr2[0] = 0;
            ptr2[1] = 1;
            ptr3[0] = 0;
            ptr3[1] = 0;
            ptr3[2] = 0;
            ptr3[3] = 0;
            multiply_uint_uint(ptr.get(), ptr2.get(), 2, ptr3.get());
            ASSERT_EQ(static_cast<uint64_t>(0), ptr3[0]);
            ASSERT_EQ(static_cast<uint64_t>(0xFFFFFFFFFFFFFFFF), ptr3[1]);
            ASSERT_EQ(static_cast<uint64_t>(0xFFFFFFFFFFFFFFFF), ptr3[2]);
            ASSERT_EQ(static_cast<uint64_t>(0), ptr3[3]);

            ptr[0] = 0xFFFFFFFFFFFFFFFF;
            ptr[1] = 0xFFFFFFFFFFFFFFFF;
            ptr2[0] = 0xFFFFFFFFFFFFFFFF;
            ptr2[1] = 0xFFFFFFFFFFFFFFFF;
            ptr3[0] = 0;
            ptr3[1] = 0;
            ptr3[2] = 0;
            ptr3[3] = 0;
            multiply_uint_uint(ptr.get(), ptr2.get(), 2, ptr3.get());
            ASSERT_EQ(1ULL, ptr3[0]);
            ASSERT_EQ(static_cast<uint64_t>(0), ptr3[1]);
            ASSERT_EQ(static_cast<uint64_t>(0xFFFFFFFFFFFFFFFE), ptr3[2]);
            ASSERT_EQ(static_cast<uint64_t>(0xFFFFFFFFFFFFFFFF), ptr3[3]);

            ptr[0] = 9756571004902751654ul;
            ptr[1] = 731952007397389984;
            ptr2[0] = 701538366196406307;
            ptr2[1] = 1699883529753102283;
            ptr3[0] = 0;
            ptr3[1] = 0;
            ptr3[2] = 0;
            ptr3[3] = 0;
            multiply_uint_uint(ptr.get(), ptr2.get(), 2, ptr3.get());
            ASSERT_EQ(static_cast<uint64_t>(9585656442714717618ul), ptr3[0]);
            ASSERT_EQ(static_cast<uint64_t>(1817697005049051848), ptr3[1]);
            ASSERT_EQ(static_cast<uint64_t>(14447416709120365380ul), ptr3[2]);
            ASSERT_EQ(static_cast<uint64_t>(67450014862939159), ptr3[3]);

            ptr[0] = 0xFFFFFFFFFFFFFFFF;
            ptr[1] = 0xFFFFFFFFFFFFFFFF;
            ptr2[0] = 0xFFFFFFFFFFFFFFFF;
            ptr2[1] = 0xFFFFFFFFFFFFFFFF;
            ptr3[0] = 0;
            ptr3[1] = 0;
            ptr3[2] = 0;
            ptr3[3] = 0;
            multiply_uint_uint(ptr.get(), 2, ptr2.get(), 1, 2, ptr3.get());
            ASSERT_EQ(1ULL, ptr3[0]);
            ASSERT_EQ(static_cast<uint64_t>(0xFFFFFFFFFFFFFFFF), ptr3[1]);
            ASSERT_EQ(static_cast<uint64_t>(0), ptr3[2]);
            ASSERT_EQ(static_cast<uint64_t>(0), ptr3[3]);

            ptr[0] = 0xFFFFFFFFFFFFFFFF;
            ptr[1] = 0xFFFFFFFFFFFFFFFF;
            ptr2[0] = 0xFFFFFFFFFFFFFFFF;
            ptr2[1] = 0xFFFFFFFFFFFFFFFF;
            ptr3[0] = 0;
            ptr3[1] = 0;
            ptr3[2] = 0;
            ptr3[3] = 0;
            multiply_uint_uint(ptr.get(), 2, ptr2.get(), 1, 3, ptr3.get());
            ASSERT_EQ(1ULL, ptr3[0]);
            ASSERT_EQ(static_cast<uint64_t>(0xFFFFFFFFFFFFFFFF), ptr3[1]);
            ASSERT_EQ(static_cast<uint64_t>(0xFFFFFFFFFFFFFFFE), ptr3[2]);
            ASSERT_EQ(static_cast<uint64_t>(0), ptr3[3]);

            ptr[0] = 0xFFFFFFFFFFFFFFFF;
            ptr[1] = 0;
            ptr2[0] = 0xFFFFFFFFFFFFFFFF;
            ptr2[1] = 0xFFFFFFFFFFFFFFFF;
            ptr3[0] = 0;
            ptr3[1] = 0;
            ptr3[2] = 0;
            ptr3[3] = 0;
            multiply_truncate_uint_uint(ptr.get(), ptr2.get(), 2, ptr3.get());
            ASSERT_EQ(1ULL, ptr3[0]);
            ASSERT_EQ(static_cast<uint64_t>(0xFFFFFFFFFFFFFFFF), ptr3[1]);
            ASSERT_EQ(static_cast<uint64_t>(0), ptr3[2]);
            ASSERT_EQ(static_cast<uint64_t>(0), ptr3[3]);
        }

        TEST(UIntArith, MultiplyUIntUInt64)
        {
            MemoryPool &pool = *global_variables::global_memory_pool;
            auto ptr(allocate_uint(3, pool));
            auto result(allocate_uint(4, pool));

            ptr[0] = 0;
            ptr[1] = 0;
            ptr[2] = 0;
            multiply_uint_uint64(ptr.get(), 3, 0ULL, 4, result.get());
            ASSERT_EQ(0ULL, result[0]);
            ASSERT_EQ(0ULL, result[1]);
            ASSERT_EQ(0ULL, result[2]);
            ASSERT_EQ(0ULL, result[3]);

            ptr[0] = 0xFFFFFFFFF;
            ptr[1] = 0xAAAAAAAAA;
            ptr[2] = 0x111111111;
            multiply_uint_uint64(ptr.get(), 3, 0ULL, 4, result.get());
            ASSERT_EQ(0ULL, result[0]);
            ASSERT_EQ(0ULL, result[1]);
            ASSERT_EQ(0ULL, result[2]);
            ASSERT_EQ(0ULL, result[3]);

            ptr[0] = 0xFFFFFFFFF;
            ptr[1] = 0xAAAAAAAAA;
            ptr[2] = 0x111111111;
            multiply_uint_uint64(ptr.get(), 3, 1ULL, 4, result.get());
            ASSERT_EQ(0xFFFFFFFFFULL, result[0]);
            ASSERT_EQ(0xAAAAAAAAAULL, result[1]);
            ASSERT_EQ(0x111111111ULL, result[2]);
            ASSERT_EQ(0ULL, result[3]);

            ptr[0] = 0xFFFFFFFFF;
            ptr[1] = 0xAAAAAAAAA;
            ptr[2] = 0x111111111;
            multiply_uint_uint64(ptr.get(), 3, 0x10000ULL, 4, result.get());
            ASSERT_EQ(0xFFFFFFFFF0000ULL, result[0]);
            ASSERT_EQ(0xAAAAAAAAA0000ULL, result[1]);
            ASSERT_EQ(0x1111111110000ULL, result[2]);
            ASSERT_EQ(0ULL, result[3]);

            ptr[0] = 0xFFFFFFFFF;
            ptr[1] = 0xAAAAAAAAA;
            ptr[2] = 0x111111111;
            multiply_uint_uint64(ptr.get(), 3, 0x100000000ULL, 4, result.get());
            ASSERT_EQ(0xFFFFFFFF00000000ULL, result[0]);
            ASSERT_EQ(0xAAAAAAAA0000000FULL, result[1]);
            ASSERT_EQ(0x111111110000000AULL, result[2]);
            ASSERT_EQ(1ULL, result[3]);

            ptr[0] = 5656565656565656ULL;
            ptr[1] = 3434343434343434ULL;
            ptr[2] = 1212121212121212ULL;
            multiply_uint_uint64(ptr.get(), 3, 7878787878787878ULL, 4, result.get());
            ASSERT_EQ(8891370032116156560ULL, result[0]);
            ASSERT_EQ(127835914414679452ULL, result[1]);
            ASSERT_EQ(9811042505314082702ULL, result[2]);
            ASSERT_EQ(517709026347ULL, result[3]);
        }

        TEST(UIntArith, DivideUIntUInt)
        {
            MemoryPool &pool = *global_variables::global_memory_pool;
            divide_uint_uint_inplace(nullptr, nullptr, 0, nullptr, pool);
            divide_uint_uint(nullptr, nullptr, 0, nullptr, nullptr, pool);

            auto ptr(allocate_uint(4, pool));
            auto ptr2(allocate_uint(4, pool));
            auto ptr3(allocate_uint(4, pool));
            auto ptr4(allocate_uint(4, pool));
            ptr[0] = 0;
            ptr[1] = 0;
            ptr2[0] = 0;
            ptr2[1] = 1;
            ptr3[0] = 0xFFFFFFFFFFFFFFFF;
            ptr3[1] = 0xFFFFFFFFFFFFFFFF;
            divide_uint_uint_inplace(ptr.get(), ptr2.get(), 2, ptr3.get(), pool);
            ASSERT_EQ(static_cast<uint64_t>(0), ptr[0]);
            ASSERT_EQ(static_cast<uint64_t>(0), ptr[1]);
            ASSERT_EQ(static_cast<uint64_t>(0), ptr3[0]);
            ASSERT_EQ(static_cast<uint64_t>(0), ptr3[1]);

            ptr[0] = 0;
            ptr[1] = 0;
            ptr2[0] = 0xFFFFFFFFFFFFFFFF;
            ptr2[1] = 0xFFFFFFFFFFFFFFFF;
            ptr3[0] = 0xFFFFFFFFFFFFFFFF;
            ptr3[1] = 0xFFFFFFFFFFFFFFFF;
            divide_uint_uint_inplace(ptr.get(), ptr2.get(), 2, ptr3.get(), pool);
            ASSERT_EQ(static_cast<uint64_t>(0), ptr[0]);
            ASSERT_EQ(static_cast<uint64_t>(0), ptr[1]);
            ASSERT_EQ(static_cast<uint64_t>(0), ptr3[0]);
            ASSERT_EQ(static_cast<uint64_t>(0), ptr3[1]);

            ptr[0] = 0xFFFFFFFFFFFFFFFE;
            ptr[1] = 0xFFFFFFFFFFFFFFFF;
            ptr2[0] = 0xFFFFFFFFFFFFFFFF;
            ptr2[1] = 0xFFFFFFFFFFFFFFFF;
            ptr3[0] = 0xFFFFFFFFFFFFFFFF;
            ptr3[1] = 0xFFFFFFFFFFFFFFFF;
            divide_uint_uint_inplace(ptr.get(), ptr2.get(), 2, ptr3.get(), pool);
            ASSERT_EQ(static_cast<uint64_t>(0xFFFFFFFFFFFFFFFE), ptr[0]);
            ASSERT_EQ(static_cast<uint64_t>(0xFFFFFFFFFFFFFFFF), ptr[1]);
            ASSERT_EQ(static_cast<uint64_t>(0), ptr3[0]);
            ASSERT_EQ(static_cast<uint64_t>(0), ptr3[1]);

            ptr[0] = 0xFFFFFFFFFFFFFFFF;
            ptr[1] = 0xFFFFFFFFFFFFFFFF;
            ptr2[0] = 0xFFFFFFFFFFFFFFFF;
            ptr2[1] = 0xFFFFFFFFFFFFFFFF;
            ptr3[0] = 0xFFFFFFFFFFFFFFFF;
            ptr3[1] = 0xFFFFFFFFFFFFFFFF;
            divide_uint_uint_inplace(ptr.get(), ptr2.get(), 2, ptr3.get(), pool);
            ASSERT_EQ(static_cast<uint64_t>(0), ptr[0]);
            ASSERT_EQ(static_cast<uint64_t>(0), ptr[1]);
            ASSERT_EQ(1ULL, ptr3[0]);
            ASSERT_EQ(static_cast<uint64_t>(0), ptr3[1]);

            ptr[0] = 14;
            ptr[1] = 0;
            ptr2[0] = 3;
            ptr2[1] = 0;
            ptr3[0] = 0xFFFFFFFFFFFFFFFF;
            ptr3[1] = 0xFFFFFFFFFFFFFFFF;
            divide_uint_uint_inplace(ptr.get(), ptr2.get(), 2, ptr3.get(), pool);
            ASSERT_EQ(static_cast<uint64_t>(2), ptr[0]);
            ASSERT_EQ(static_cast<uint64_t>(0), ptr[1]);
            ASSERT_EQ(static_cast<uint64_t>(4), ptr3[0]);
            ASSERT_EQ(static_cast<uint64_t>(0), ptr3[1]);

            ptr[0] = 9585656442714717620ul;
            ptr[1] = 1817697005049051848;
            ptr[2] = 14447416709120365380ul;
            ptr[3] = 67450014862939159;
            ptr2[0] = 701538366196406307;
            ptr2[1] = 1699883529753102283;
            ptr2[2] = 0;
            ptr2[3] = 0;
            ptr3[0] = 0xFFFFFFFFFFFFFFFF;
            ptr3[1] = 0xFFFFFFFFFFFFFFFF;
            ptr3[2] = 0xFFFFFFFFFFFFFFFF;
            ptr3[3] = 0xFFFFFFFFFFFFFFFF;
            ptr4[0] = 0xFFFFFFFFFFFFFFFF;
            ptr4[1] = 0xFFFFFFFFFFFFFFFF;
            ptr4[2] = 0xFFFFFFFFFFFFFFFF;
            ptr4[3] = 0xFFFFFFFFFFFFFFFF;
            divide_uint_uint(ptr.get(), ptr2.get(), 4, ptr3.get(), ptr4.get(), pool);
            ASSERT_EQ(static_cast<uint64_t>(2), ptr4[0]);
            ASSERT_EQ(static_cast<uint64_t>(0), ptr4[1]);
            ASSERT_EQ(static_cast<uint64_t>(0), ptr4[2]);
            ASSERT_EQ(static_cast<uint64_t>(0), ptr4[3]);
            ASSERT_EQ(static_cast<uint64_t>(9756571004902751654ul), ptr3[0]);
            ASSERT_EQ(static_cast<uint64_t>(731952007397389984), ptr3[1]);
            ASSERT_EQ(static_cast<uint64_t>(0), ptr3[2]);
            ASSERT_EQ(static_cast<uint64_t>(0), ptr3[3]);

            divide_uint_uint_inplace(ptr.get(), ptr2.get(), 4, ptr3.get(), pool);
            ASSERT_EQ(static_cast<uint64_t>(2), ptr[0]);
            ASSERT_EQ(static_cast<uint64_t>(0), ptr[1]);
            ASSERT_EQ(static_cast<uint64_t>(0), ptr[2]);
            ASSERT_EQ(static_cast<uint64_t>(0), ptr[3]);
            ASSERT_EQ(static_cast<uint64_t>(9756571004902751654ul), ptr3[0]);
            ASSERT_EQ(static_cast<uint64_t>(731952007397389984), ptr3[1]);
            ASSERT_EQ(static_cast<uint64_t>(0), ptr3[2]);
            ASSERT_EQ(static_cast<uint64_t>(0), ptr3[3]);
        }

        TEST(UIntArith, DivideUInt128UInt64)
        {
            uint64_t input[2];
            uint64_t quotient[2];

            input[0] = 0;
            input[1] = 0;
            divide_uint128_uint64_inplace(input, 1ULL, quotient);
            ASSERT_EQ(0ULL, input[0]);
            ASSERT_EQ(0ULL, input[1]);
            ASSERT_EQ(0ULL, quotient[0]);
            ASSERT_EQ(0ULL, quotient[1]);

            input[0] = 1;
            input[1] = 0;
            divide_uint128_uint64_inplace(input, 1ULL, quotient);
            ASSERT_EQ(0ULL, input[0]);
            ASSERT_EQ(0ULL, input[1]);
            ASSERT_EQ(1ULL, quotient[0]);
            ASSERT_EQ(0ULL, quotient[1]);

            input[0] = 0x10101010;
            input[1] = 0x2B2B2B2B;
            divide_uint128_uint64_inplace(input, 0x1000ULL, quotient);
            ASSERT_EQ(0x10ULL, input[0]);
            ASSERT_EQ(0ULL, input[1]);
            ASSERT_EQ(0xB2B0000000010101ULL, quotient[0]);
            ASSERT_EQ(0x2B2B2ULL, quotient[1]);

            input[0] = 1212121212121212ULL;
            input[1] = 3434343434343434ULL;
            divide_uint128_uint64_inplace(input, 5656565656565656ULL, quotient);
            ASSERT_EQ(5252525252525252ULL, input[0]);
            ASSERT_EQ(0ULL, input[1]);
            ASSERT_EQ(11199808901895084909ULL, quotient[0]);
            ASSERT_EQ(0ULL, quotient[1]);
        }

        TEST(UIntArith, DivideUInt192UInt64)
        {
            uint64_t input[3];
            uint64_t quotient[3];

            input[0] = 0;
            input[1] = 0;
            input[2] = 0;
            divide_uint192_uint64_inplace(input, 1ULL, quotient);
            ASSERT_EQ(0ULL, input[0]);
            ASSERT_EQ(0ULL, input[1]);
            ASSERT_EQ(0ULL, input[2]);
            ASSERT_EQ(0ULL, quotient[0]);
            ASSERT_EQ(0ULL, quotient[1]);
            ASSERT_EQ(0ULL, quotient[2]);

            input[0] = 1;
            input[1] = 0;
            input[2] = 0;
            divide_uint192_uint64_inplace(input, 1ULL, quotient);
            ASSERT_EQ(0ULL, input[0]);
            ASSERT_EQ(0ULL, input[1]);
            ASSERT_EQ(0ULL, input[2]);
            ASSERT_EQ(1ULL, quotient[0]);
            ASSERT_EQ(0ULL, quotient[1]);
            ASSERT_EQ(0ULL, quotient[2]);

            input[0] = 0x10101010;
            input[1] = 0x2B2B2B2B;
            input[2] = 0xF1F1F1F1;
            divide_uint192_uint64_inplace(input, 0x1000ULL, quotient);
            ASSERT_EQ(0x10ULL, input[0]);
            ASSERT_EQ(0ULL, input[1]);
            ASSERT_EQ(0ULL, input[2]);
            ASSERT_EQ(0xB2B0000000010101ULL, quotient[0]);
            ASSERT_EQ(0x1F1000000002B2B2ULL, quotient[1]);
            ASSERT_EQ(0xF1F1FULL, quotient[2]);

            input[0] = 1212121212121212ULL;
            input[1] = 3434343434343434ULL;
            input[2] = 5656565656565656ULL;
            divide_uint192_uint64_inplace(input, 7878787878787878ULL, quotient);
            ASSERT_EQ(7272727272727272ULL, input[0]);
            ASSERT_EQ(0ULL, input[1]);
            ASSERT_EQ(0ULL, input[2]);
            ASSERT_EQ(17027763760347278414ULL, quotient[0]);
            ASSERT_EQ(13243816258047883211ULL, quotient[1]);
            ASSERT_EQ(0ULL, quotient[2]);
        }

        TEST(UIntArith, ExponentiateUInt)
        {
            MemoryPool &pool = *global_variables::global_memory_pool;
            auto input(allocate_zero_uint(2, pool));
            auto result(allocate_zero_uint(8, pool));

            result[0] = 1, result[1] = 2, result[2] = 3, result[3] = 4;
            result[4] = 5, result[5] = 6, result[6] = 7, result[7] = 8;

            uint64_t exponent[2]{ 0, 0 };

            input[0] = 0xFFF;
            input[1] = 0;
            exponentiate_uint(input.get(), 2, exponent, 1, 1, result.get(), pool);
            ASSERT_EQ(1ULL, result[0]);
            ASSERT_EQ(2ULL, result[1]);

            exponentiate_uint(input.get(), 2, exponent, 1, 2, result.get(), pool);
            ASSERT_EQ(1ULL, result[0]);
            ASSERT_EQ(0ULL, result[1]);

            exponentiate_uint(input.get(), 1, exponent, 1, 4, result.get(), pool);
            ASSERT_EQ(1ULL, result[0]);
            ASSERT_EQ(0ULL, result[1]);
            ASSERT_EQ(0ULL, result[2]);
            ASSERT_EQ(0ULL, result[3]);

            input[0] = 123;
            exponent[0] = 5;
            exponentiate_uint(input.get(), 1, exponent, 2, 2, result.get(), pool);
            ASSERT_EQ(28153056843ULL, result[0]);
            ASSERT_EQ(0ULL, result[1]);

            input[0] = 1;
            exponent[0] = 1;
            exponent[1] = 1;
            exponentiate_uint(input.get(), 1, exponent, 2, 2, result.get(), pool);
            ASSERT_EQ(1ULL, result[0]);
            ASSERT_EQ(0ULL, result[1]);

            input[0] = 0;
            input[1] = 1;
            exponent[0] = 7;
            exponent[1] = 0;
            exponentiate_uint(input.get(), 2, exponent, 2, 8, result.get(), pool);
            ASSERT_EQ(0ULL, result[0]);
            ASSERT_EQ(0ULL, result[1]);
            ASSERT_EQ(0ULL, result[2]);
            ASSERT_EQ(0ULL, result[3]);
            ASSERT_EQ(0ULL, result[4]);
            ASSERT_EQ(0ULL, result[5]);
            ASSERT_EQ(0ULL, result[6]);
            ASSERT_EQ(1ULL, result[7]);

            input[0] = 121212;
            input[1] = 343434;
            exponent[0] = 3;
            exponent[1] = 0;
            exponentiate_uint(input.get(), 2, exponent, 2, 8, result.get(), pool);
            ASSERT_EQ(1780889000200128ULL, result[0]);
            ASSERT_EQ(15137556501701088ULL, result[1]);
            ASSERT_EQ(42889743421486416ULL, result[2]);
            ASSERT_EQ(40506979898070504ULL, result[3]);
            ASSERT_EQ(0ULL, result[4]);
            ASSERT_EQ(0ULL, result[5]);
            ASSERT_EQ(0ULL, result[6]);
            ASSERT_EQ(0ULL, result[7]);
        }

        TEST(UIntArith, ExponentiateUInt64)
        {
            ASSERT_EQ(0ULL, exponentiate_uint64(0ULL, 1ULL));
            ASSERT_EQ(1ULL, exponentiate_uint64(1ULL, 0ULL));
            ASSERT_EQ(0ULL, exponentiate_uint64(0ULL, 0xFFFFFFFFFFFFFFFFULL));
            ASSERT_EQ(1ULL, exponentiate_uint64(0xFFFFFFFFFFFFFFFFULL, 0ULL));
            ASSERT_EQ(25ULL, exponentiate_uint64(5ULL, 2ULL));
            ASSERT_EQ(32ULL, exponentiate_uint64(2ULL, 5ULL));
            ASSERT_EQ(0x1000000000000000ULL, exponentiate_uint64(0x10ULL, 15ULL));
            ASSERT_EQ(0ULL, exponentiate_uint64(0x10ULL, 16ULL));
            ASSERT_EQ(12389286314587456613ULL, exponentiate_uint64(123456789ULL, 13ULL));
        }
   }
}
