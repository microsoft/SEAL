// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include "gtest/gtest.h"
#include "seal/intarray.h"
#include "seal/memorymanager.h"
#include <sstream>

using namespace seal;
using namespace std;

namespace SEALTest
{
    TEST(IntArrayTest, IntArrayBasics)
    {
        {
            auto pool = MemoryPoolHandle::New();
            MemoryManager::SwitchProfile(new MMProfFixed(pool));
            IntArray<int32_t> arr;
            ASSERT_TRUE(arr.begin() == nullptr);
            ASSERT_TRUE(arr.end() == nullptr);
            ASSERT_EQ(0ULL, arr.size());
            ASSERT_EQ(0ULL, arr.capacity());
            ASSERT_TRUE(arr.empty());

            arr.resize(1);
            ASSERT_FALSE(arr.begin() == nullptr);
            ASSERT_FALSE(arr.end() == nullptr);
            ASSERT_FALSE(arr.begin() == arr.end());
            ASSERT_EQ(1, static_cast<int>(arr.end() - arr.begin()));
            ASSERT_EQ(1ULL, arr.size());
            ASSERT_EQ(1ULL, arr.capacity());
            ASSERT_FALSE(arr.empty());
            ASSERT_EQ(0, arr[0]);
            arr.at(0) = 1;
            ASSERT_EQ(1, arr[0]);
            ASSERT_EQ(4, static_cast<int>(pool.alloc_byte_count()));

            arr.reserve(6);
            ASSERT_FALSE(arr.begin() == nullptr);
            ASSERT_FALSE(arr.end() == nullptr);
            ASSERT_FALSE(arr.begin() == arr.end());
            ASSERT_EQ(1, static_cast<int>(arr.end() - arr.begin()));
            ASSERT_EQ(1ULL, arr.size());
            ASSERT_EQ(6ULL, arr.capacity());
            ASSERT_FALSE(arr.empty());
            ASSERT_EQ(1, arr[0]);
            ASSERT_EQ(28, static_cast<int>(pool.alloc_byte_count()));

            arr.resize(4);
            ASSERT_FALSE(arr.begin() == nullptr);
            ASSERT_FALSE(arr.end() == nullptr);
            ASSERT_FALSE(arr.begin() == arr.end());
            ASSERT_EQ(4, static_cast<int>(arr.end() - arr.begin()));
            ASSERT_EQ(4ULL, arr.size());
            ASSERT_EQ(6ULL, arr.capacity());
            ASSERT_FALSE(arr.empty());
            arr.at(0) = 0;
            arr.at(1) = 1;
            arr.at(2) = 2;
            arr.at(3) = 3;
            ASSERT_EQ(0, arr[0]);
            ASSERT_EQ(1, arr[1]);
            ASSERT_EQ(2, arr[2]);
            ASSERT_EQ(3, arr[3]);
            ASSERT_EQ(28, static_cast<int>(pool.alloc_byte_count()));

            arr.shrink_to_fit();
            ASSERT_FALSE(arr.begin() == nullptr);
            ASSERT_FALSE(arr.end() == nullptr);
            ASSERT_FALSE(arr.begin() == arr.end());
            ASSERT_EQ(4, static_cast<int>(arr.end() - arr.begin()));
            ASSERT_EQ(4ULL, arr.size());
            ASSERT_EQ(4ULL, arr.capacity());
            ASSERT_FALSE(arr.empty());
            ASSERT_EQ(0, arr[0]);
            ASSERT_EQ(1, arr[1]);
            ASSERT_EQ(2, arr[2]);
            ASSERT_EQ(3, arr[3]);
            ASSERT_EQ(44, static_cast<int>(pool.alloc_byte_count()));
        }
        {
            auto pool = MemoryPoolHandle::New();
            MemoryManager::SwitchProfile(new MMProfFixed(pool));
            IntArray<uint64_t> arr;
            ASSERT_TRUE(arr.begin() == nullptr);
            ASSERT_TRUE(arr.end() == nullptr);
            ASSERT_EQ(0ULL, arr.size());
            ASSERT_EQ(0ULL, arr.capacity());
            ASSERT_TRUE(arr.empty());

            arr.resize(1);
            ASSERT_FALSE(arr.begin() == nullptr);
            ASSERT_FALSE(arr.end() == nullptr);
            ASSERT_FALSE(arr.begin() == arr.end());
            ASSERT_EQ(1, static_cast<int>(arr.end() - arr.begin()));
            ASSERT_EQ(1ULL, arr.size());
            ASSERT_EQ(1ULL, arr.capacity());
            ASSERT_FALSE(arr.empty());
            ASSERT_EQ(0ULL, arr[0]);
            arr.at(0) = 1;
            ASSERT_EQ(1ULL, arr[0]);
            ASSERT_EQ(8, static_cast<int>(pool.alloc_byte_count()));

            arr.reserve(6);
            ASSERT_FALSE(arr.begin() == nullptr);
            ASSERT_FALSE(arr.end() == nullptr);
            ASSERT_FALSE(arr.begin() == arr.end());
            ASSERT_EQ(1, static_cast<int>(arr.end() - arr.begin()));
            ASSERT_EQ(1ULL, arr.size());
            ASSERT_EQ(6ULL, arr.capacity());
            ASSERT_FALSE(arr.empty());
            ASSERT_EQ(1ULL, arr[0]);
            ASSERT_EQ(56, static_cast<int>(pool.alloc_byte_count()));

            arr.resize(4);
            ASSERT_FALSE(arr.begin() == nullptr);
            ASSERT_FALSE(arr.end() == nullptr);
            ASSERT_FALSE(arr.begin() == arr.end());
            ASSERT_EQ(4, static_cast<int>(arr.end() - arr.begin()));
            ASSERT_EQ(4ULL, arr.size());
            ASSERT_EQ(6ULL, arr.capacity());
            ASSERT_FALSE(arr.empty());
            arr.at(0) = 0;
            arr.at(1) = 1;
            arr.at(2) = 2;
            arr.at(3) = 3;
            ASSERT_EQ(0ULL, arr[0]);
            ASSERT_EQ(1ULL, arr[1]);
            ASSERT_EQ(2ULL, arr[2]);
            ASSERT_EQ(3ULL, arr[3]);
            ASSERT_EQ(56, static_cast<int>(pool.alloc_byte_count()));

            arr.shrink_to_fit();
            ASSERT_FALSE(arr.begin() == nullptr);
            ASSERT_FALSE(arr.end() == nullptr);
            ASSERT_FALSE(arr.begin() == arr.end());
            ASSERT_EQ(4, static_cast<int>(arr.end() - arr.begin()));
            ASSERT_EQ(4ULL, arr.size());
            ASSERT_EQ(4ULL, arr.capacity());
            ASSERT_FALSE(arr.empty());
            ASSERT_EQ(0ULL, arr[0]);
            ASSERT_EQ(1ULL, arr[1]);
            ASSERT_EQ(2ULL, arr[2]);
            ASSERT_EQ(3ULL, arr[3]);
            ASSERT_EQ(88, static_cast<int>(pool.alloc_byte_count()));
        }
    }

    TEST(IntArrayTest, SaveLoadIntArray)
    {
        IntArray<int32_t> arr(6, 4);
        arr.at(0) = 0;
        arr.at(1) = 1;
        arr.at(2) = 2;
        arr.at(3) = 3;
        stringstream ss;
        arr.save(ss);
        IntArray<int32_t> arr2;
        arr2.load(ss);

        ASSERT_EQ(arr.size(), arr2.size());
        ASSERT_EQ(arr.size(), arr2.capacity());
        ASSERT_EQ(arr[0], arr2[0]);
        ASSERT_EQ(arr[1], arr2[1]);
        ASSERT_EQ(arr[2], arr2[2]);
        ASSERT_EQ(arr[3], arr2[3]);

        arr.resize(2);
        arr[0] = 5;
        arr[1] = 6;
        arr.save(ss);
        arr2.load(ss);

        ASSERT_EQ(arr.size(), arr2.size());
        ASSERT_EQ(4ULL, arr2.capacity());
        ASSERT_EQ(arr[0], arr2[0]);
        ASSERT_EQ(arr[1], arr2[1]);
    }
}
