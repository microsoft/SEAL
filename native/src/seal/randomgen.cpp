// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <algorithm>
#include <random>
#include <iostream>
#include "seal/randomgen.h"
#include "seal/util/blake2.h"
#ifdef _WIN32
#include <Windows.h>
#include <bcrypt.h>
#endif

using namespace std;

namespace seal
{
    uint64_t random_uint64()
    {
        uint64_t result;
#if defined(__linux__) || (defined(__APPLE__) && defined(__MACH__))
        random_device rd("/dev/urandom");
        result = (static_cast<std::uint64_t>(rd()) << 32)
            + static_cast<std::uint64_t>(rd());
#elif defined(_WIN32)
        if (!BCRYPT_SUCCESS(BCryptGenRandom(
            NULL,
            reinterpret_cast<unsigned char*>(&result),
            sizeof(result),
            BCRYPT_USE_SYSTEM_PREFERRED_RNG)))
        {
            throw runtime_error("BCryptGenRandom failed");
        }
#endif
        return result;
    }

    void UniformRandomGenerator::generate(
        size_t byte_count, SEAL_BYTE *destination)
    {
        while (byte_count)
        {
            size_t current_bytes = min(
                byte_count,
                static_cast<size_t>(distance(buffer_head_, buffer_.cend())));
            copy_n(buffer_head_, current_bytes, destination);
            buffer_head_ += current_bytes;
            destination += current_bytes;
            byte_count -= current_bytes;

            if (buffer_head_ == buffer_.end())
            {
                refresh();
            }
        }
    }

    auto UniformRandomGeneratorFactory::default_factory()
        -> const shared_ptr<UniformRandomGeneratorFactory>
    {
        static const shared_ptr<UniformRandomGeneratorFactory>
            default_factory{ new SEAL_DEFAULT_RNG_FACTORY };
        return default_factory;
    }
#ifdef SEAL_USE_AES_NI_PRNG
    auto FastPRNGFactory::create() -> shared_ptr<UniformRandomGenerator>
    {
        if (!(seed_[0] | seed_[1]))
        {
            return make_shared<FastPRNG>(random_uint64(), random_uint64());
        }
        else
        {
            return make_shared<FastPRNG>(seed_[0], seed_[1]);
        }
    }

    void FastPRNG::refill_buffer()
    {
        // Fill the randomness buffer
        aes_block *buffer_ptr = reinterpret_cast<aes_block*>(buffer_.data());
        aes_enc_.counter_encrypt(counter_, buffer_block_count_, buffer_ptr);
        counter_ += buffer_block_count_;
    }
#endif
    auto BlakePRNGFactory::create() -> shared_ptr<UniformRandomGenerator>
    {
        if (!(seed_[0] | seed_[1]))
        {
            return make_shared<BlakePRNG>(random_uint64(), random_uint64());
        }
        else
        {
            return make_shared<BlakePRNG>(seed_[0], seed_[1]);
        }
    }

    void BlakePRNG::refill_buffer()
    {
        // Fill the randomness buffer
        if (blake2xb(
            reinterpret_cast<SEAL_BYTE*>(buffer_.data()),
            buffer_byte_count_,
            reinterpret_cast<const SEAL_BYTE*>(&counter_),
            sizeof(counter_),
            seed_.data(), sizeof(seed_)) != 0)
        {
            throw runtime_error("blake2xb failed");
        }
        counter_++;
    }
}
