// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include "seal/util/hash.h"

using namespace std;

namespace seal
{
    namespace util
    {
        // Required for C++14 compliance: static constexpr member variables are not necessarily inlined so need to
        // ensure symbol is created.
        constexpr size_t HashFunction::hash_block_uint64_count;

        // Required for C++14 compliance: static constexpr member variables are not necessarily inlined so need to
        // ensure symbol is created.
        constexpr size_t HashFunction::hash_block_byte_count;

        // Required for C++14 compliance: static constexpr member variables are not necessarily inlined so need to
        // ensure symbol is created.
        constexpr HashFunction::hash_block_type HashFunction::hash_zero_block;
    } // namespace util
} // namespace seal
