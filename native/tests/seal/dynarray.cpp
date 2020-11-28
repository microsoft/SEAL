// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include "seal/dynarray.h"
#include "seal/memorymanager.h"
#include <sstream>
#ifdef SEAL_USE_MSGSL
#include "gsl/span"
#endif
#include "gtest/gtest.h"

using namespace seal;
using namespace std;

namespace sealtest
{
    TEST(DynArrayTest, DynArrayBasics)
    {
        {
            auto pool = MemoryPoolHandle::New();
            MemoryManager::SwitchProfile(new MMProfFixed(pool));
            DynArray<int32_t> arr;
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
            DynArray<uint64_t> arr;
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
#ifdef SEAL_USE_MSGSL
    TEST(DynArrayTest, FromSpan)
    {
        // Constructors
        vector<int> coeffs{};
        DynArray<int> arr(coeffs);
        ASSERT_TRUE(arr.empty());

        coeffs = { 0 };
        arr = DynArray<int>(coeffs);
        ASSERT_EQ(1ULL, arr.size());
        ASSERT_EQ(1ULL, arr.capacity());
        ASSERT_TRUE(equal(coeffs.begin(), coeffs.end(), arr.begin()));

        arr = DynArray<int>(coeffs, 2);
        ASSERT_EQ(1ULL, arr.size());
        ASSERT_EQ(2ULL, arr.capacity());
        ASSERT_TRUE(equal(coeffs.begin(), coeffs.end(), arr.begin()));

        coeffs = { 1, 2 };
        arr = DynArray<int>(coeffs);
        ASSERT_EQ(2ULL, arr.size());
        ASSERT_EQ(2ULL, arr.capacity());
        ASSERT_TRUE(equal(coeffs.begin(), coeffs.end(), arr.begin()));

        arr = DynArray<int>(coeffs, 3);
        ASSERT_EQ(2ULL, arr.size());
        ASSERT_EQ(3ULL, arr.capacity());
        ASSERT_TRUE(equal(coeffs.begin(), coeffs.end(), arr.begin()));

        // Setter
        coeffs = {};
        arr = coeffs;
        ASSERT_EQ(0ULL, arr.size());
        ASSERT_EQ(3ULL, arr.capacity());

        coeffs = { 5, 4, 3, 2, 1 };
        arr = coeffs;
        ASSERT_EQ(5ULL, arr.size());
        ASSERT_EQ(5ULL, arr.capacity());
        ASSERT_TRUE(equal(coeffs.begin(), coeffs.end(), arr.begin()));
    }
#endif
    TEST(DynArrayTest, SaveLoadDynArray)
    {
        DynArray<int32_t> arr(6, 4);
        arr.at(0) = 0;
        arr.at(1) = 1;
        arr.at(2) = 2;
        arr.at(3) = 3;
        stringstream ss;
        arr.save(ss);
        DynArray<int32_t> arr2;
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

    TEST(DynArrayTest, Assign)
    {
        DynArray<char> arr(MemoryManager::GetPool(mm_prof_opt::mm_force_new));
        DynArray<char> arr2(MemoryManager::GetPool(mm_prof_opt::mm_force_new));
        ASSERT_NE(&static_cast<util::MemoryPool &>(arr.pool()), &static_cast<util::MemoryPool &>(arr2.pool()));

        arr = arr2;
        util::MemoryPool *addr = &static_cast<util::MemoryPool &>(arr.pool());
        ASSERT_EQ(&static_cast<util::MemoryPool &>(arr.pool()), addr);

        addr = &static_cast<util::MemoryPool &>(arr2.pool());
        arr = move(arr2);
        ASSERT_EQ(&static_cast<util::MemoryPool &>(arr.pool()), addr);
    }
} // namespace sealtest
