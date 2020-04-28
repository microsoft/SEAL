// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include "seal/randomgen.h"
#include "seal/util/blake2.h"
#include <algorithm>
#include <iostream>
#include <random>
#if SEAL_SYSTEM == SEAL_SYSTEM_WINDOWS
#include <Windows.h>
#include <bcrypt.h>
#endif

using namespace std;

namespace seal
{
    uint64_t random_uint64()
    {
        uint64_t result;
#if SEAL_SYSTEM == SEAL_SYSTEM_UNIX_LIKE
        random_device rd("/dev/urandom");
        result = (static_cast<uint64_t>(rd()) << 32) + static_cast<uint64_t>(rd());
#elif SEAL_SYSTEM == SEAL_SYSTEM_WINDOWS
        if (!BCRYPT_SUCCESS(BCryptGenRandom(
                NULL, reinterpret_cast<unsigned char *>(&result), sizeof(result), BCRYPT_USE_SYSTEM_PREFERRED_RNG)))
        {
            throw runtime_error("BCryptGenRandom failed");
        }
#elif SEAL_SYSTEM == SEAL_SYSTEM_OTHER
#warning "SECURITY WARNING: System detection failed; falling back to a potentially insecure randomness source!"
        random_device rd;
        result = (static_cast<uint64_t>(rd()) << 32) + static_cast<uint64_t>(rd());
#endif
        return result;
    }

    void UniformRandomGenerator::generate(size_t byte_count, SEAL_BYTE *destination)
    {
        lock_guard<mutex> lock(mutex_);
        while (byte_count)
        {
            size_t current_bytes = min(byte_count, static_cast<size_t>(distance(buffer_head_, buffer_end_)));
            copy_n(buffer_head_, current_bytes, destination);
            buffer_head_ += current_bytes;
            destination += current_bytes;
            byte_count -= current_bytes;

            if (buffer_head_ == buffer_end_)
            {
                refill_buffer();
                buffer_head_ = buffer_begin_;
            }
        }
    }

    auto UniformRandomGeneratorFactory::DefaultFactory() -> const shared_ptr<UniformRandomGeneratorFactory>
    {
        static const shared_ptr<UniformRandomGeneratorFactory> default_factory{ new SEAL_DEFAULT_RNG_FACTORY };
        return default_factory;
    }

    void BlakePRNG::refill_buffer()
    {
        // Fill the randomness buffer
        if (blake2xb(
                buffer_begin_, buffer_size_, reinterpret_cast<const SEAL_BYTE *>(&counter_), sizeof(counter_),
                seed_.cbegin(), seed_.size() * sizeof(decltype(seed_)::T)) != 0)
        {
            throw runtime_error("blake2xb failed");
        }
        counter_++;
    }
} // namespace seal
