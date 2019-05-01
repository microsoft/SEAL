// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include "gtest/gtest.h"
#include "seal/util/mempool.h"
#include "seal/util/pointer.h"
#include "seal/util/common.h"
#include <memory>

using namespace seal;
using namespace seal::util;
using namespace std;

namespace SEALTest
{
   namespace util
   {
        TEST(MemoryPoolTests, TestMemoryPoolMT)
        {
            {
                MemoryPoolMT pool;
                ASSERT_TRUE(0LL == pool.pool_count());

                Pointer<uint64_t> pointer{ pool.get_for_byte_count(bytes_per_uint64 * 0) };
                ASSERT_FALSE(pointer.is_set());
                pointer.release();
                ASSERT_TRUE(0LL == pool.pool_count());

                pointer = pool.get_for_byte_count(bytes_per_uint64 * 2);
                uint64_t *allocation1 = pointer.get();
                ASSERT_TRUE(pointer.is_set());
                pointer.release();
                ASSERT_FALSE(pointer.is_set());
                ASSERT_TRUE(1LL == pool.pool_count());

                pointer = pool.get_for_byte_count(bytes_per_uint64 * 2);
                ASSERT_TRUE(allocation1 == pointer.get());
                ASSERT_TRUE(pointer.is_set());
                pointer.release();
                ASSERT_FALSE(pointer.is_set());
                ASSERT_TRUE(1LL == pool.pool_count());

                pointer = pool.get_for_byte_count(bytes_per_uint64 * 1);
                ASSERT_FALSE(allocation1 == pointer.get());
                ASSERT_TRUE(pointer.is_set());
                pointer.release();
                ASSERT_FALSE(pointer.is_set());
                ASSERT_TRUE(2LL == pool.pool_count());

                pointer = pool.get_for_byte_count(bytes_per_uint64 * 2);
                ASSERT_TRUE(allocation1 == pointer.get());
                Pointer<uint64_t> pointer2 = pool.get_for_byte_count(bytes_per_uint64 * 2);
                uint64_t *allocation2 = pointer2.get();
                ASSERT_FALSE(allocation2 == pointer.get());
                ASSERT_TRUE(pointer.is_set());
                pointer.release();
                pointer2.release();
                ASSERT_TRUE(2LL == pool.pool_count());

                pointer = pool.get_for_byte_count(bytes_per_uint64 * 2);
                ASSERT_TRUE(allocation2 == pointer.get());
                pointer2 = pool.get_for_byte_count(bytes_per_uint64 * 2);
                ASSERT_TRUE(allocation1 == pointer2.get());
                Pointer<uint64_t> pointer3 = pool.get_for_byte_count(bytes_per_uint64 * 1);
                pointer.release();
                pointer2.release();
                pointer3.release();
                ASSERT_TRUE(2LL == pool.pool_count());

                Pointer<SEAL_BYTE> pointer4 = pool.get_for_byte_count(1);
                Pointer<SEAL_BYTE> pointer5 = pool.get_for_byte_count(2);
                Pointer<SEAL_BYTE> pointer6 = pool.get_for_byte_count(1);
                pointer4.release();
                pointer5.release();
                pointer6.release();
                ASSERT_TRUE(4LL == pool.pool_count());
            }
            {
                MemoryPoolMT pool;
                ASSERT_TRUE(0LL == pool.pool_count());

                Pointer<int> pointer{ pool.get_for_byte_count(4 * 0) };
                ASSERT_FALSE(pointer.is_set());
                pointer.release();
                ASSERT_TRUE(0LL == pool.pool_count());

                pointer = pool.get_for_byte_count(4 * 2);
                int *allocation1 = pointer.get();
                ASSERT_TRUE(pointer.is_set());
                pointer.release();
                ASSERT_FALSE(pointer.is_set());
                ASSERT_TRUE(1LL == pool.pool_count());

                pointer = pool.get_for_byte_count(4 * 2);
                ASSERT_TRUE(allocation1 == pointer.get());
                ASSERT_TRUE(pointer.is_set());
                pointer.release();
                ASSERT_FALSE(pointer.is_set());
                ASSERT_TRUE(1LL == pool.pool_count());

                pointer = pool.get_for_byte_count(4 * 1);
                ASSERT_FALSE(allocation1 == pointer.get());
                ASSERT_TRUE(pointer.is_set());
                pointer.release();
                ASSERT_FALSE(pointer.is_set());
                ASSERT_TRUE(2LL == pool.pool_count());

                pointer = pool.get_for_byte_count(4 * 2);
                ASSERT_TRUE(allocation1 == pointer.get());
                Pointer<int> pointer2 = pool.get_for_byte_count(4 * 2);
                int *allocation2 = pointer2.get();
                ASSERT_FALSE(allocation2 == pointer.get());
                ASSERT_TRUE(pointer.is_set());
                pointer.release();
                pointer2.release();
                ASSERT_TRUE(2LL == pool.pool_count());

                pointer = pool.get_for_byte_count(4 * 2);
                ASSERT_TRUE(allocation2 == pointer.get());
                pointer2 = pool.get_for_byte_count(4 * 2);
                ASSERT_TRUE(allocation1 == pointer2.get());
                Pointer<int> pointer3 = pool.get_for_byte_count(4 * 1);
                pointer.release();
                pointer2.release();
                pointer3.release();
                ASSERT_TRUE(2LL == pool.pool_count());

                Pointer<SEAL_BYTE> pointer4 = pool.get_for_byte_count(1);
                Pointer<SEAL_BYTE> pointer5 = pool.get_for_byte_count(2);
                Pointer<SEAL_BYTE> pointer6 = pool.get_for_byte_count(1);
                pointer4.release();
                pointer5.release();
                pointer6.release();
                ASSERT_TRUE(4LL == pool.pool_count());
            }
            {
                MemoryPoolMT pool;
                ASSERT_TRUE(0LL == pool.pool_count());

                Pointer<SEAL_BYTE> pointer = pool.get_for_byte_count(0);
                ASSERT_FALSE(pointer.is_set());
                pointer.release();
                ASSERT_TRUE(0LL == pool.pool_count());

                pointer = pool.get_for_byte_count(2);
                SEAL_BYTE *allocation1 = pointer.get();
                ASSERT_TRUE(pointer.is_set());
                pointer.release();
                ASSERT_FALSE(pointer.is_set());
                ASSERT_TRUE(1LL == pool.pool_count());

                pointer = pool.get_for_byte_count(2);
                ASSERT_TRUE(allocation1 == pointer.get());
                ASSERT_TRUE(pointer.is_set());
                pointer.release();
                ASSERT_FALSE(pointer.is_set());
                ASSERT_TRUE(1LL == pool.pool_count());

                pointer = pool.get_for_byte_count(1);
                ASSERT_FALSE(allocation1 == pointer.get());
                ASSERT_TRUE(pointer.is_set());
                pointer.release();
                ASSERT_FALSE(pointer.is_set());
                ASSERT_TRUE(2LL == pool.pool_count());

                pointer = pool.get_for_byte_count(2);
                ASSERT_TRUE(allocation1 == pointer.get());
                Pointer<SEAL_BYTE> pointer2 = pool.get_for_byte_count(2);
                SEAL_BYTE *allocation2 = pointer2.get();
                ASSERT_FALSE(allocation2 == pointer.get());
                ASSERT_TRUE(pointer.is_set());
                pointer.release();
                pointer2.release();
                ASSERT_TRUE(2LL == pool.pool_count());

                pointer = pool.get_for_byte_count(2);
                ASSERT_TRUE(allocation2 == pointer.get());
                pointer2 = pool.get_for_byte_count(2);
                ASSERT_TRUE(allocation1 == pointer2.get());
                Pointer<SEAL_BYTE> pointer3 = pool.get_for_byte_count(1);
                pointer.release();
                pointer2.release();
                pointer3.release();
                ASSERT_TRUE(2LL == pool.pool_count());
            }
        }

        TEST(MemoryPoolTests, PointerTestsMT)
        {
            MemoryPool &pool = *global_variables::global_memory_pool;
            {
                Pointer<uint64_t> p1;
                ASSERT_FALSE(p1.is_set());
                ASSERT_TRUE(p1.get() == nullptr);

                p1 = pool.get_for_byte_count(bytes_per_uint64 * 1);
                uint64_t *allocation1 = p1.get();
                ASSERT_TRUE(p1.is_set());
                ASSERT_TRUE(p1.get() != nullptr);

                p1.release();
                ASSERT_FALSE(p1.is_set());
                ASSERT_TRUE(p1.get() == nullptr);

                p1 = pool.get_for_byte_count(bytes_per_uint64 * 1);
                ASSERT_TRUE(p1.is_set());
                ASSERT_TRUE(p1.get() == allocation1);

                Pointer<uint64_t> p2;
                p2.acquire(p1);
                ASSERT_FALSE(p1.is_set());
                ASSERT_TRUE(p2.is_set());
                ASSERT_TRUE(p2.get() == allocation1);

                ConstPointer<uint64_t> cp2;
                cp2.acquire(p2);
                ASSERT_FALSE(p2.is_set());
                ASSERT_TRUE(cp2.is_set());
                ASSERT_TRUE(cp2.get() == allocation1);
                cp2.release();

                Pointer<uint64_t> p3 = pool.get_for_byte_count(bytes_per_uint64 * 1);
                ASSERT_TRUE(p3.is_set());
                ASSERT_TRUE(p3.get() == allocation1);

                Pointer<uint64_t> p4 = pool.get_for_byte_count(bytes_per_uint64 * 2);
                ASSERT_TRUE(p4.is_set());
                uint64_t *allocation2 = p4.get();
                swap(p3, p4);
                ASSERT_TRUE(p3.is_set());
                ASSERT_TRUE(p3.get() == allocation2);
                ASSERT_TRUE(p4.is_set());
                ASSERT_TRUE(p4.get() == allocation1);
                p3.release();
                p4.release();
            }
            {
                Pointer<SEAL_BYTE> p1;
                ASSERT_FALSE(p1.is_set());
                ASSERT_TRUE(p1.get() == nullptr);

                p1 = pool.get_for_byte_count(bytes_per_uint64 * 1);
                SEAL_BYTE *allocation1 = p1.get();
                ASSERT_TRUE(p1.is_set());
                ASSERT_TRUE(p1.get() != nullptr);

                p1.release();
                ASSERT_FALSE(p1.is_set());
                ASSERT_TRUE(p1.get() == nullptr);

                p1 = pool.get_for_byte_count(bytes_per_uint64 * 1);
                ASSERT_TRUE(p1.is_set());
                ASSERT_TRUE(p1.get() == allocation1);

                Pointer<SEAL_BYTE> p2;
                p2.acquire(p1);
                ASSERT_FALSE(p1.is_set());
                ASSERT_TRUE(p2.is_set());
                ASSERT_TRUE(p2.get() == allocation1);

                ConstPointer<SEAL_BYTE> cp2;
                cp2.acquire(p2);
                ASSERT_FALSE(p2.is_set());
                ASSERT_TRUE(cp2.is_set());
                ASSERT_TRUE(cp2.get() == allocation1);
                cp2.release();

                Pointer<SEAL_BYTE> p3 = pool.get_for_byte_count(bytes_per_uint64 * 1);
                ASSERT_TRUE(p3.is_set());
                ASSERT_TRUE(p3.get() == allocation1);

                Pointer<SEAL_BYTE> p4 = pool.get_for_byte_count(bytes_per_uint64 * 2);
                ASSERT_TRUE(p4.is_set());
                SEAL_BYTE *allocation2 = p4.get();
                swap(p3, p4);
                ASSERT_TRUE(p3.is_set());
                ASSERT_TRUE(p3.get() == allocation2);
                ASSERT_TRUE(p4.is_set());
                ASSERT_TRUE(p4.get() == allocation1);
                p3.release();
                p4.release();
            }
        }

        TEST(MemoryPoolTests, DuplicateIfNeededMT)
        {
            {
                unique_ptr<uint64_t[]> allocation(new uint64_t[2]);
                allocation[0] = 0x1234567812345678;
                allocation[1] = 0x8765432187654321;

                MemoryPoolMT pool;
                Pointer<uint64_t> p1 = duplicate_if_needed(allocation.get(), 2, false, pool);
                ASSERT_TRUE(p1.is_set());
                ASSERT_TRUE(p1.get() == allocation.get());
                ASSERT_TRUE(0LL == pool.pool_count());

                p1 = duplicate_if_needed(allocation.get(), 2, true, pool);
                ASSERT_TRUE(p1.is_set());
                ASSERT_FALSE(p1.get() == allocation.get());
                ASSERT_TRUE(1LL == pool.pool_count());
                ASSERT_TRUE(p1.get()[0] == 0x1234567812345678);
                ASSERT_TRUE(p1.get()[1] == 0x8765432187654321);
                p1.release();
            }
            {
                unique_ptr<int64_t[]> allocation(new int64_t[2]);
                allocation[0] = 0x234567812345678;
                allocation[1] = 0x765432187654321;

                MemoryPoolMT pool;
                Pointer<int64_t> p1 = duplicate_if_needed(allocation.get(), 2, false, pool);
                ASSERT_TRUE(p1.is_set());
                ASSERT_TRUE(p1.get() == allocation.get());
                ASSERT_TRUE(0LL == pool.pool_count());

                p1 = duplicate_if_needed(allocation.get(), 2, true, pool);
                ASSERT_TRUE(p1.is_set());
                ASSERT_FALSE(p1.get() == allocation.get());
                ASSERT_TRUE(1LL == pool.pool_count());
                ASSERT_TRUE(p1.get()[0] == 0x234567812345678);
                ASSERT_TRUE(p1.get()[1] == 0x765432187654321);
                p1.release();
            }
            {
                unique_ptr<int[]> allocation(new int[2]);
                allocation[0] = 0x123;
                allocation[1] = 0x876;

                MemoryPoolMT pool;
                Pointer<int> p1 = duplicate_if_needed(allocation.get(), 2, false, pool);
                ASSERT_TRUE(p1.is_set());
                ASSERT_TRUE(p1.get() == allocation.get());
                ASSERT_TRUE(0LL == pool.pool_count());

                p1 = duplicate_if_needed(allocation.get(), 2, true, pool);
                ASSERT_TRUE(p1.is_set());
                ASSERT_FALSE(p1.get() == allocation.get());
                ASSERT_TRUE(1LL == pool.pool_count());
                ASSERT_TRUE(p1.get()[0] == 0x123);
                ASSERT_TRUE(p1.get()[1] == 0x876);
                p1.release();
            }
        }

        TEST(MemoryPoolTests, TestMemoryPoolST)
        {
            {
                MemoryPoolST pool;
                ASSERT_TRUE(0LL == pool.pool_count());

                Pointer<uint64_t> pointer{ pool.get_for_byte_count(bytes_per_uint64 * 0) };
                ASSERT_FALSE(pointer.is_set());
                pointer.release();
                ASSERT_TRUE(0LL == pool.pool_count());

                pointer = pool.get_for_byte_count(bytes_per_uint64 * 2);
                uint64_t *allocation1 = pointer.get();
                ASSERT_TRUE(pointer.is_set());
                pointer.release();
                ASSERT_FALSE(pointer.is_set());
                ASSERT_TRUE(1LL == pool.pool_count());

                pointer = pool.get_for_byte_count(bytes_per_uint64 * 2);
                ASSERT_TRUE(allocation1 == pointer.get());
                ASSERT_TRUE(pointer.is_set());
                pointer.release();
                ASSERT_FALSE(pointer.is_set());
                ASSERT_TRUE(1LL == pool.pool_count());

                pointer = pool.get_for_byte_count(bytes_per_uint64 * 1);
                ASSERT_FALSE(allocation1 == pointer.get());
                ASSERT_TRUE(pointer.is_set());
                pointer.release();
                ASSERT_FALSE(pointer.is_set());
                ASSERT_TRUE(2LL == pool.pool_count());

                pointer = pool.get_for_byte_count(bytes_per_uint64 * 2);
                ASSERT_TRUE(allocation1 == pointer.get());
                Pointer<uint64_t> pointer2 = pool.get_for_byte_count(bytes_per_uint64 * 2);
                uint64_t *allocation2 = pointer2.get();
                ASSERT_FALSE(allocation2 == pointer.get());
                ASSERT_TRUE(pointer.is_set());
                pointer.release();
                pointer2.release();
                ASSERT_TRUE(2LL == pool.pool_count());

                pointer = pool.get_for_byte_count(bytes_per_uint64 * 2);
                ASSERT_TRUE(allocation2 == pointer.get());
                pointer2 = pool.get_for_byte_count(bytes_per_uint64 * 2);
                ASSERT_TRUE(allocation1 == pointer2.get());
                Pointer<uint64_t> pointer3 = pool.get_for_byte_count(bytes_per_uint64 * 1);
                pointer.release();
                pointer2.release();
                pointer3.release();
                ASSERT_TRUE(2LL == pool.pool_count());

                Pointer<SEAL_BYTE> pointer4 = pool.get_for_byte_count(1);
                Pointer<SEAL_BYTE> pointer5 = pool.get_for_byte_count(2);
                Pointer<SEAL_BYTE> pointer6 = pool.get_for_byte_count(1);
                pointer4.release();
                pointer5.release();
                pointer6.release();
                ASSERT_TRUE(4LL == pool.pool_count());
            }
            {
                MemoryPoolST pool;
                ASSERT_TRUE(0LL == pool.pool_count());

                Pointer<int> pointer{ pool.get_for_byte_count(4 * 0) };
                ASSERT_FALSE(pointer.is_set());
                pointer.release();
                ASSERT_TRUE(0LL == pool.pool_count());

                pointer = pool.get_for_byte_count(4 * 2);
                int *allocation1 = pointer.get();
                ASSERT_TRUE(pointer.is_set());
                pointer.release();
                ASSERT_FALSE(pointer.is_set());
                ASSERT_TRUE(1LL == pool.pool_count());

                pointer = pool.get_for_byte_count(4 * 2);
                ASSERT_TRUE(allocation1 == pointer.get());
                ASSERT_TRUE(pointer.is_set());
                pointer.release();
                ASSERT_FALSE(pointer.is_set());
                ASSERT_TRUE(1LL == pool.pool_count());

                pointer = pool.get_for_byte_count(4 * 1);
                ASSERT_FALSE(allocation1 == pointer.get());
                ASSERT_TRUE(pointer.is_set());
                pointer.release();
                ASSERT_FALSE(pointer.is_set());
                ASSERT_TRUE(2LL == pool.pool_count());

                pointer = pool.get_for_byte_count(4 * 2);
                ASSERT_TRUE(allocation1 == pointer.get());
                Pointer<int> pointer2 = pool.get_for_byte_count(4 * 2);
                int *allocation2 = pointer2.get();
                ASSERT_FALSE(allocation2 == pointer.get());
                ASSERT_TRUE(pointer.is_set());
                pointer.release();
                pointer2.release();
                ASSERT_TRUE(2LL == pool.pool_count());

                pointer = pool.get_for_byte_count(4 * 2);
                ASSERT_TRUE(allocation2 == pointer.get());
                pointer2 = pool.get_for_byte_count(4 * 2);
                ASSERT_TRUE(allocation1 == pointer2.get());
                Pointer<int> pointer3 = pool.get_for_byte_count(4 * 1);
                pointer.release();
                pointer2.release();
                pointer3.release();
                ASSERT_TRUE(2LL == pool.pool_count());

                Pointer<SEAL_BYTE> pointer4 = pool.get_for_byte_count(1);
                Pointer<SEAL_BYTE> pointer5 = pool.get_for_byte_count(2);
                Pointer<SEAL_BYTE> pointer6 = pool.get_for_byte_count(1);
                pointer4.release();
                pointer5.release();
                pointer6.release();
                ASSERT_TRUE(4LL == pool.pool_count());
            }
            {
                MemoryPoolST pool;
                ASSERT_TRUE(0LL == pool.pool_count());

                Pointer<SEAL_BYTE> pointer = pool.get_for_byte_count(0);
                ASSERT_FALSE(pointer.is_set());
                pointer.release();
                ASSERT_TRUE(0LL == pool.pool_count());

                pointer = pool.get_for_byte_count(2);
                SEAL_BYTE *allocation1 = pointer.get();
                ASSERT_TRUE(pointer.is_set());
                pointer.release();
                ASSERT_FALSE(pointer.is_set());
                ASSERT_TRUE(1LL == pool.pool_count());

                pointer = pool.get_for_byte_count(2);
                ASSERT_TRUE(allocation1 == pointer.get());
                ASSERT_TRUE(pointer.is_set());
                pointer.release();
                ASSERT_FALSE(pointer.is_set());
                ASSERT_TRUE(1LL == pool.pool_count());

                pointer = pool.get_for_byte_count(1);
                ASSERT_FALSE(allocation1 == pointer.get());
                ASSERT_TRUE(pointer.is_set());
                pointer.release();
                ASSERT_FALSE(pointer.is_set());
                ASSERT_TRUE(2LL == pool.pool_count());

                pointer = pool.get_for_byte_count(2);
                ASSERT_TRUE(allocation1 == pointer.get());
                Pointer<SEAL_BYTE> pointer2 = pool.get_for_byte_count(2);
                SEAL_BYTE *allocation2 = pointer2.get();
                ASSERT_FALSE(allocation2 == pointer.get());
                ASSERT_TRUE(pointer.is_set());
                pointer.release();
                pointer2.release();
                ASSERT_TRUE(2LL == pool.pool_count());

                pointer = pool.get_for_byte_count(2);
                ASSERT_TRUE(allocation2 == pointer.get());
                pointer2 = pool.get_for_byte_count(2);
                ASSERT_TRUE(allocation1 == pointer2.get());
                Pointer<SEAL_BYTE> pointer3 = pool.get_for_byte_count(1);
                pointer.release();
                pointer2.release();
                pointer3.release();
                ASSERT_TRUE(2LL == pool.pool_count());
            }
        }

        TEST(MemoryPoolTests, PointerTestsST)
        {
            MemoryPoolST pool;
            {
                Pointer<uint64_t> p1;
                ASSERT_FALSE(p1.is_set());
                ASSERT_TRUE(p1.get() == nullptr);

                p1 = pool.get_for_byte_count(bytes_per_uint64 * 1);
                uint64_t *allocation1 = p1.get();
                ASSERT_TRUE(p1.is_set());
                ASSERT_TRUE(p1.get() != nullptr);

                p1.release();
                ASSERT_FALSE(p1.is_set());
                ASSERT_TRUE(p1.get() == nullptr);

                p1 = pool.get_for_byte_count(bytes_per_uint64 * 1);
                ASSERT_TRUE(p1.is_set());
                ASSERT_TRUE(p1.get() == allocation1);

                Pointer<uint64_t> p2;
                p2.acquire(p1);
                ASSERT_FALSE(p1.is_set());
                ASSERT_TRUE(p2.is_set());
                ASSERT_TRUE(p2.get() == allocation1);

                ConstPointer<uint64_t> cp2;
                cp2.acquire(p2);
                ASSERT_FALSE(p2.is_set());
                ASSERT_TRUE(cp2.is_set());
                ASSERT_TRUE(cp2.get() == allocation1);
                cp2.release();

                Pointer<uint64_t> p3 = pool.get_for_byte_count(bytes_per_uint64 * 1);
                ASSERT_TRUE(p3.is_set());
                ASSERT_TRUE(p3.get() == allocation1);

                Pointer<uint64_t> p4 = pool.get_for_byte_count(bytes_per_uint64 * 2);
                ASSERT_TRUE(p4.is_set());
                uint64_t *allocation2 = p4.get();
                swap(p3, p4);
                ASSERT_TRUE(p3.is_set());
                ASSERT_TRUE(p3.get() == allocation2);
                ASSERT_TRUE(p4.is_set());
                ASSERT_TRUE(p4.get() == allocation1);
                p3.release();
                p4.release();
            }
            {
                Pointer<SEAL_BYTE> p1;
                ASSERT_FALSE(p1.is_set());
                ASSERT_TRUE(p1.get() == nullptr);

                p1 = pool.get_for_byte_count(bytes_per_uint64 * 1);
                SEAL_BYTE *allocation1 = p1.get();
                ASSERT_TRUE(p1.is_set());
                ASSERT_TRUE(p1.get() != nullptr);

                p1.release();
                ASSERT_FALSE(p1.is_set());
                ASSERT_TRUE(p1.get() == nullptr);

                p1 = pool.get_for_byte_count(bytes_per_uint64 * 1);
                ASSERT_TRUE(p1.is_set());
                ASSERT_TRUE(p1.get() == allocation1);

                Pointer<SEAL_BYTE> p2;
                p2.acquire(p1);
                ASSERT_FALSE(p1.is_set());
                ASSERT_TRUE(p2.is_set());
                ASSERT_TRUE(p2.get() == allocation1);

                ConstPointer<SEAL_BYTE> cp2;
                cp2.acquire(p2);
                ASSERT_FALSE(p2.is_set());
                ASSERT_TRUE(cp2.is_set());
                ASSERT_TRUE(cp2.get() == allocation1);
                cp2.release();

                Pointer<SEAL_BYTE> p3 = pool.get_for_byte_count(bytes_per_uint64 * 1);
                ASSERT_TRUE(p3.is_set());
                ASSERT_TRUE(p3.get() == allocation1);

                Pointer<SEAL_BYTE> p4 = pool.get_for_byte_count(bytes_per_uint64 * 2);
                ASSERT_TRUE(p4.is_set());
                SEAL_BYTE *allocation2 = p4.get();
                swap(p3, p4);
                ASSERT_TRUE(p3.is_set());
                ASSERT_TRUE(p3.get() == allocation2);
                ASSERT_TRUE(p4.is_set());
                ASSERT_TRUE(p4.get() == allocation1);
                p3.release();
                p4.release();
            }
        }

        TEST(MemoryPoolTests, DuplicateIfNeededST)
        {
            {
                unique_ptr<uint64_t[]> allocation(new uint64_t[2]);
                allocation[0] = 0x1234567812345678;
                allocation[1] = 0x8765432187654321;

                MemoryPoolST pool;
                Pointer<uint64_t> p1 = duplicate_if_needed(allocation.get(), 2, false, pool);
                ASSERT_TRUE(p1.is_set());
                ASSERT_TRUE(p1.get() == allocation.get());
                ASSERT_TRUE(0LL == pool.pool_count());

                p1 = duplicate_if_needed(allocation.get(), 2, true, pool);
                ASSERT_TRUE(p1.is_set());
                ASSERT_FALSE(p1.get() == allocation.get());
                ASSERT_TRUE(1LL == pool.pool_count());
                ASSERT_TRUE(p1.get()[0] == 0x1234567812345678);
                ASSERT_TRUE(p1.get()[1] == 0x8765432187654321);
                p1.release();
            }
            {
                unique_ptr<int64_t[]> allocation(new int64_t[2]);
                allocation[0] = 0x234567812345678;
                allocation[1] = 0x765432187654321;

                MemoryPoolST pool;
                Pointer<int64_t> p1 = duplicate_if_needed(allocation.get(), 2, false, pool);
                ASSERT_TRUE(p1.is_set());
                ASSERT_TRUE(p1.get() == allocation.get());
                ASSERT_TRUE(0LL == pool.pool_count());

                p1 = duplicate_if_needed(allocation.get(), 2, true, pool);
                ASSERT_TRUE(p1.is_set());
                ASSERT_FALSE(p1.get() == allocation.get());
                ASSERT_TRUE(1LL == pool.pool_count());
                ASSERT_TRUE(p1.get()[0] == 0x234567812345678);
                ASSERT_TRUE(p1.get()[1] == 0x765432187654321);
                p1.release();
            }
            {
                unique_ptr<int[]> allocation(new int[2]);
                allocation[0] = 0x123;
                allocation[1] = 0x876;

                MemoryPoolST pool;
                Pointer<int> p1 = duplicate_if_needed(allocation.get(), 2, false, pool);
                ASSERT_TRUE(p1.is_set());
                ASSERT_TRUE(p1.get() == allocation.get());
                ASSERT_TRUE(0LL == pool.pool_count());

                p1 = duplicate_if_needed(allocation.get(), 2, true, pool);
                ASSERT_TRUE(p1.is_set());
                ASSERT_FALSE(p1.get() == allocation.get());
                ASSERT_TRUE(1LL == pool.pool_count());
                ASSERT_TRUE(p1.get()[0] == 0x123);
                ASSERT_TRUE(p1.get()[1] == 0x876);
                p1.release();
            }
        }
   }
}