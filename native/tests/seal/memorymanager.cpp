// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include "seal/intarray.h"
#include "seal/memorymanager.h"
#include "seal/util/pointer.h"
#include "seal/util/uintcore.h"
#include "gtest/gtest.h"

using namespace seal;
using namespace seal::util;
using namespace std;

namespace sealtest
{
    TEST(MemoryPoolHandleTest, MemoryPoolHandleConstructAssign)
    {
        MemoryPoolHandle pool;
        ASSERT_FALSE(pool);
        pool = MemoryPoolHandle::Global();
        ASSERT_TRUE(&static_cast<MemoryPool &>(pool) == global_variables::global_memory_pool.get());
        pool = MemoryPoolHandle::New();
        ASSERT_FALSE(&pool.operator seal::util::MemoryPool &() == global_variables::global_memory_pool.get());
        MemoryPoolHandle pool2 = MemoryPoolHandle::New();
        ASSERT_FALSE(pool == pool2);

        pool = pool2;
        ASSERT_TRUE(pool == pool2);
        pool = MemoryPoolHandle::Global();
        ASSERT_FALSE(pool == pool2);
        pool2 = MemoryPoolHandle::Global();
        ASSERT_TRUE(pool == pool2);
    }

    TEST(MemoryPoolHandleTest, MemoryPoolHandleAllocate)
    {
        MemoryPoolHandle pool = MemoryPoolHandle::New();
        ASSERT_TRUE(0LL == pool.alloc_byte_count());
        {
            auto ptr(allocate_uint(5, pool));
            ASSERT_TRUE(5LL * bytes_per_uint64 == pool.alloc_byte_count());
        }

        pool = MemoryPoolHandle::New();
        ASSERT_TRUE(0LL * bytes_per_uint64 == pool.alloc_byte_count());
        {
            auto ptr(allocate_uint(5, pool));
            ASSERT_TRUE(5LL * bytes_per_uint64 == pool.alloc_byte_count());

            ptr = allocate_uint(8, pool);
            ASSERT_TRUE(13LL * bytes_per_uint64 == pool.alloc_byte_count());

            auto ptr2(allocate_uint(2, pool));
            ASSERT_TRUE(15LL * bytes_per_uint64 == pool.alloc_byte_count());
        }
    }

    TEST(MemoryPoolHandleTest, UseCount)
    {
        MemoryPoolHandle pool = MemoryPoolHandle::New();
        ASSERT_EQ(1L, pool.use_count());
        {
            IntArray<int> arr(pool);
            ASSERT_EQ(2L, pool.use_count());
            IntArray<int> arr2(pool);
            ASSERT_EQ(3L, pool.use_count());
        }
        ASSERT_EQ(1L, pool.use_count());
    }
} // namespace sealtest