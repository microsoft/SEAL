// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include "seal/randomgen.h"
#include "seal/util/blake2.h"
#include "seal/util/aes.h"
#ifdef SEAL_USE_SYSTEM_RNG
#include <thread>
#include <chrono>
#if SEAL_COMPILER == SEAL_COMPILER_MSVC
#include <bcrypt.h>
#elif (SEAL_COMPILER == SEAL_COMPILER_GCC) || (SEAL_COMPILER == SEAL_COMPILER_CLANG)
#include <fstream>
#endif
#endif

using namespace std;

namespace seal
{
    std::uint64_t random_uint64()
    {
        uint64_t result;
#ifdef SEAL_USE_SYSTEM_RNG
        using namespace chrono_literals;
#if SEAL_COMPILER == SEAL_COMPILER_MSVC
        while(!BCRYPT_SUCCESS(BCryptGenRandom(
            NULL, static_cast<char*>(&result), buffer_byte_count_,
            BCRYPT_USE_SYSTEM_PREFERRED_RNG)))
        {
            // Wait and retry
            this_thread::sleep_for(10ns);
        }
#elif (SEAL_COMPILER == SEAL_COMPILER_GCC) || (SEAL_COMPILER == SEAL_COMPILER_CLANG)
        while (!([](uint64_t &out) -> bool {
                ifstream fs("/dev/random", ios::binary);
                if (!fs)
                {
                    return false;
                }
                fs.read(reinterpret_cast<char*>(&out), util::bytes_per_uint64);
                if (fs.gcount() != util::bytes_per_uint64)
                {
                    return false;
                }
                return true;
            }(result)))
        {
            // Wait and retry
            this_thread::sleep_for(10ns);
        }
#endif
#else
        std::random_device rd;
        result = (static_cast<std::uint64_t>(rd()) << 32)
            + static_cast<std::uint64_t>(rd());
#endif
        return result;
    }

    /**
    Returns the default random number generator factory. This instance should
    not be destroyed.
    */
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
        buffer_head_ = buffer_.cbegin();
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
        blake2b(
            reinterpret_cast<SEAL_BYTE*>(buffer_.data()),
            buffer_byte_count_,
            reinterpret_cast<const SEAL_BYTE*>(&counter_),
            sizeof(counter_),
            seed_.data(), sizeof(seed_));
        counter_++;
        buffer_head_ = buffer_.cbegin();
    }
}
