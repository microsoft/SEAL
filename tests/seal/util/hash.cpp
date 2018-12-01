// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include "gtest/gtest.h"
#include "seal/util/hash.h"
#include <cstdint>

using namespace seal::util;
using namespace std;

namespace SEALTest
{
   namespace util
   {
        TEST(HashTest, SHA3Hash)
        {
            uint64_t input[3]{ 0, 0, 0 };
            HashFunction::sha3_block_type hash1, hash2;
            HashFunction::sha3_hash(0, hash1);

            HashFunction::sha3_hash(input, 0, hash2);
            ASSERT_TRUE(hash1 != hash2);

            HashFunction::sha3_hash(input, 1, hash2);
            ASSERT_TRUE(hash1 == hash2);

            HashFunction::sha3_hash(input, 2, hash2);
            ASSERT_TRUE(hash1 != hash2);

            HashFunction::sha3_hash(0x123456, hash1);
            HashFunction::sha3_hash(0x023456, hash2);
            ASSERT_TRUE(hash1 != hash2);

            input[0] = 0x123456;
            input[1] = 1;
            HashFunction::sha3_hash(0x123456, hash1);
            HashFunction::sha3_hash(input, 2, hash2);
            ASSERT_TRUE(hash1 != hash2);
        }
    }
}
