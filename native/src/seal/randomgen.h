// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#pragma once

#include <array>
#include <memory>
#include <random>
#include <algorithm>
#include "seal/util/defines.h"
#include "seal/util/common.h"
#include "seal/util/aes.h"

namespace seal
{
    /**
    Provides the base class for a uniform random number generator. Instances of
    this class are typically returned from the UniformRandomGeneratorFactory class.
    This class is meant for users to sub-class to implement their own random number
    generators. The implementation should provide a uniform random unsigned 32-bit
    value for each call to generate(). Note that the library will never make
    concurrent calls to generate() to the same instance (but individual instances
    of the same class may have concurrent calls). The uniformity and unpredictability
    of the numbers generated is essential for making a secure cryptographic system.

    @see UniformRandomGeneratorFactory for the base class of a factory class that
    generates UniformRandomGenerator instances.
    */
    class UniformRandomGenerator
    {
    public:
        /**
        Generates a new uniform unsigned 32-bit random number. Note that the
        implementation does not need to be thread-safe.
        */
        virtual std::uint32_t generate() = 0;

        /**
        Destroys the random number generator.
        */
        virtual ~UniformRandomGenerator() = default;
    };

    /**
    Provides the base class for a factory instance that creates instances of
    UniformRandomGenerator. This class is meant for users to sub-class to implement
    their own random number generators. Note that each instance returned may be
    used concurrently across separate threads, but each individual instance does
    not need to be thread-safe.

    @see UniformRandomGenerator for details relating to the random number generator
    instances.
    @see StandardRandomAdapterFactory for an implementation of
    UniformRandomGeneratorFactory that supports the standard C++ library's
    random number generators.
    */
    class UniformRandomGeneratorFactory
    {
    public:
        /**
        Creates a new uniform random number generator.
        */
        virtual auto create()
            -> std::shared_ptr<UniformRandomGenerator> = 0;

        /**
        Destroys the random number generator factory.
        */
        virtual ~UniformRandomGeneratorFactory() = default;

        /**
        Returns the default random number generator factory. This instance should
        not be destroyed.
        */
        static auto default_factory()
            -> const std::shared_ptr<UniformRandomGeneratorFactory>;

    private:
    };
#ifdef SEAL_USE_AES_NI_PRNG
    /**
    Provides an implementation of UniformRandomGenerator for using very fast
    AES-NI randomness with given 128-bit seed.
    */
    class FastPRNG : public UniformRandomGenerator
    {
    public:
        /**
        Creates a new FastPRNGFactory instance that initializes every FastPRNG
        instance it creates with the given seed.
        */
        FastPRNG(std::uint64_t seed_lw, std::uint64_t seed_hw) :
            aes_enc_{ seed_lw, seed_hw }
        {
            refill_buffer();
        }

        /**
        Generates a new uniform unsigned 32-bit random number. Note that the
        implementation does not need to be thread-safe.
        */
        virtual std::uint32_t generate() override
        {
            std::uint32_t result;
            std::copy_n(buffer_head_, util::bytes_per_uint32,
                reinterpret_cast<SEAL_BYTE*>(&result));
            buffer_head_ += util::bytes_per_uint32;
            if (buffer_head_ == buffer_.cend())
            {
                refill_buffer();
            }
            return result;
        }

        /**
        Destroys the random number generator.
        */
        virtual ~FastPRNG() override = default;

    private:
        AESEncryptor aes_enc_;

        static constexpr std::size_t bytes_per_block_ =
            sizeof(aes_block) / sizeof(SEAL_BYTE);

        static constexpr std::size_t buffer_block_size_ = 8;

        static constexpr std::size_t buffer_size_ =
            buffer_block_size_ * bytes_per_block_;

        std::array<SEAL_BYTE, buffer_size_> buffer_;

        std::size_t counter_ = 0;

        typename decltype(buffer_)::const_iterator buffer_head_;

        void refill_buffer()
        {
            // Fill the randomness buffer
            aes_block *buffer_ptr = reinterpret_cast<aes_block*>(&*buffer_.begin());
            aes_enc_.counter_encrypt(counter_, buffer_block_size_, buffer_ptr);
            counter_ += buffer_block_size_;
            buffer_head_ = buffer_.cbegin();
        }
    };

    class FastPRNGFactory : public UniformRandomGeneratorFactory
    {
    public:
        /**
        Creates a new FastPRNGFactory instance that initializes every FastPRNG
        instance it creates with the given seed. A zero seed (default value)
        signals that each random number generator created by the factory should
        use a different random seed obtained from std::random_device.

        @param[in] seed_lw Low-word for seed for the PRNG
        @param[in] seed_hw High-word for seed for the PRNG
        */
        FastPRNGFactory(std::uint64_t seed_lw = 0, std::uint64_t seed_hw = 0) :
            seed_{ seed_lw, seed_hw }
        {
        }

        /**
        Creates a new uniform random number generator. The caller of create needs
        to ensure the returned instance is destroyed once it is no longer in-use
        to prevent a memory leak.
        */
        virtual auto create() -> std::shared_ptr<UniformRandomGenerator> override;

        /**
        Destroys the random number generator factory.
        */
        virtual ~FastPRNGFactory() = default;

    private:
        std::uint64_t random_uint64() const noexcept
        {
            std::random_device rd;
            return (static_cast<std::uint64_t>(rd()) << 32)
                + static_cast<std::uint64_t>(rd());
        }

        std::uint64_t seed_[2];
    };
#endif //SEAL_USE_AES_NI_PRNG
    /**
    Provides an implementation of UniformRandomGenerator for the standard C++
    library's uniform random number generators.

    @tparam RNG specifies the type of the standard C++ library's random number
    generator (e.g., std::default_random_engine)
    */
    template<typename RNG>
    class StandardRandomAdapter : public UniformRandomGenerator
    {
    public:
        /**
        Creates a new random number generator (of type RNG).
        */
        StandardRandomAdapter() = default;

        /**
        Returns a reference to the random number generator.
        */
        inline const RNG &generator() const noexcept
        {
            return generator_;
        }

        /**
        Returns a reference to the random number generator.
        */
        inline RNG &generator() noexcept
        {
            return generator_;
        }

        /**
        Generates a new uniform unsigned 32-bit random number.
        */
        std::uint32_t generate() noexcept override
        {
            SEAL_IF_CONSTEXPR (RNG::min() == 0 && RNG::max() >= UINT32_MAX)
            {
                return static_cast<std::uint32_t>(generator_());
            }
            else SEAL_IF_CONSTEXPR (RNG::max() - RNG::min() >= UINT32_MAX)
            {
                return static_cast<std::uint32_t>(generator_() - RNG::min());
            }
            else SEAL_IF_CONSTEXPR (RNG::min() == 0)
            {
                std::uint64_t max_value = RNG::max();
                std::uint64_t value = static_cast<std::uint64_t>(generator_());
                std::uint64_t max = max_value;
                while (max < UINT32_MAX)
                {
                    value *= max_value;
                    max *= max_value;
                    value += static_cast<std::uint64_t>(generator_());
                }
                return static_cast<std::uint32_t>(value);
            }
            else
            {
                std::uint64_t max_value = RNG::max() - RNG::min();
                std::uint64_t value = static_cast<std::uint64_t>(generator_() - RNG::min());
                std::uint64_t max = max_value;
                while (max < UINT32_MAX)
                {
                    value *= max_value;
                    max *= max_value;
                    value += static_cast<std::uint64_t>(generator_() - RNG::min());
                }
                return static_cast<std::uint32_t>(value);
            }
        }

    private:
        RNG generator_;
    };

    /**
    Provides an implementation of UniformRandomGeneratorFactory for the standard
    C++ library's random number generators.

    @tparam RNG specifies the type of the standard C++ library's random number
    generator (e.g., std::default_random_engine)
    */
    template<typename RNG>
    class StandardRandomAdapterFactory : public UniformRandomGeneratorFactory
    {
    public:
        /**
        Creates a new uniform random number generator.
        */
        auto create() -> std::shared_ptr<UniformRandomGenerator> override
        {
            return std::shared_ptr<UniformRandomGenerator>{
                new StandardRandomAdapter<RNG>() };
        }

    private:
    };
}
