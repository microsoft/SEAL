// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include "seal/util/hash.h"
#include <cstdint>
#include "gtest/gtest.h"

using namespace seal::util;
using namespace std;

namespace sealtest
{
    namespace util
    {
        namespace
        {
            void hash(uint64_t value, HashFunction::hash_block_type &destination)
            {
                HashFunction::hash(&value, 1, destination);
            }
        } // namespace

        TEST(HashTest, Hash)
        {
            uint64_t input[3]{ 0, 0, 0 };
            HashFunction::hash_block_type hash1, hash2;
            hash(0, hash1);

            HashFunction::hash(input, 0, hash2);
            ASSERT_TRUE(hash1 != hash2);

            HashFunction::hash(input, 1, hash2);
            ASSERT_TRUE(hash1 == hash2);

            HashFunction::hash(input, 2, hash2);
            ASSERT_TRUE(hash1 != hash2);

            hash(0x123456, hash1);
            hash(0x023456, hash2);
            ASSERT_TRUE(hash1 != hash2);

            input[0] = 0x123456;
            input[1] = 1;
            hash(0x123456, hash1);
            HashFunction::hash(input, 2, hash2);
            ASSERT_TRUE(hash1 != hash2);
        }
    } // namespace util
} // namespace sealtest
