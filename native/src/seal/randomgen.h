// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#pragma once

#include <array>
#include <iterator>
#include <memory>
#include "seal/util/defines.h"
#include "seal/util/common.h"
#include "seal/util/aes.h"

namespace seal
{
    SEAL_NODISCARD std::uint64_t random_uint64();

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
        Fills a given buffer with a given number of bytes of randomness. Note that
        the implementation does not need to be thread-safe.
        */
        void generate(std::size_t byte_count, SEAL_BYTE *destination);

        /**
        Generates a new uniform unsigned 32-bit random number. Note that the
        implementation does not need to be thread-safe.
        */
        SEAL_NODISCARD inline std::uint32_t generate()
        {
            std::uint32_t result;
            generate(sizeof(result), reinterpret_cast<SEAL_BYTE*>(&result));
            return result;
        }

        /**
        Discards the contents of the current randomness buffer and refills it
        with fresh randomness.
        */
        inline void refresh()
        {
            refill_buffer();
            buffer_head_ = buffer_.cbegin();
        }

        /**
        Destroys the random number generator.
        */
        virtual ~UniformRandomGenerator() = default;

    protected:
        static constexpr std::size_t buffer_uint64_count_ = 1024;

        static constexpr std::size_t buffer_byte_count_ =
            buffer_uint64_count_ * util::bytes_per_uint64;

        alignas(16) std::array<SEAL_BYTE, buffer_byte_count_> buffer_;

        virtual void refill_buffer() = 0;

    private:
        typename decltype(buffer_)::const_iterator buffer_head_ = buffer_.cend();
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
        SEAL_NODISCARD virtual auto create()
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
        Creates a new FastPRNG instance initialized with the given seed.
        */
        FastPRNG(std::uint64_t seed_lw, std::uint64_t seed_hw) :
            aes_enc_{ seed_lw, seed_hw }
        {
        }

        /**
        Destroys the random number generator.
        */
        virtual ~FastPRNG() override = default;

    protected:
        virtual void refill_buffer() override;

    private:
        AESEncryptor aes_enc_;

        static constexpr std::size_t aes_block_byte_count_ = 16;

        static constexpr std::size_t buffer_block_count_ =
            buffer_byte_count_ / aes_block_byte_count_;

        std::size_t counter_ = 0;
    };

    class FastPRNGFactory : public UniformRandomGeneratorFactory
    {
    public:
        /**
        Creates a new FastPRNGFactory instance that initializes every FastPRNG
        instance it creates with the given seed. A zero seed (default value)
        signals that each random number generator created by the factory should
        use a different random seed.

        @param[in] seed_lw Low-word for seed for the PRNG
        @param[in] seed_hw High-word for seed for the PRNG
        */
        FastPRNGFactory(std::uint64_t seed_lw = 0, std::uint64_t seed_hw = 0) :
            seed_{ seed_lw, seed_hw }
        {
        }

        /**
        Creates a new uniform random number generator.
        */
        SEAL_NODISCARD virtual auto create()
            -> std::shared_ptr<UniformRandomGenerator> override;

        /**
        Destroys the random number generator factory.
        */
        virtual ~FastPRNGFactory() = default;

    private:
        std::array<std::uint64_t, 2> seed_;
    };
#endif //SEAL_USE_AES_NI_PRNG
    /**
    Provides an implementation of UniformRandomGenerator for using Blake2xb for
    generating randomness with given 128-bit seed.
    */
    class BlakePRNG : public UniformRandomGenerator
    {
    public:
        /**
        Creates a new BlakePRNG instance initialized with the given seed.
        */
        BlakePRNG(std::uint64_t seed_lw, std::uint64_t seed_hw) :
            seed_{ seed_lw, seed_hw }
        {
        }

        /**
        Destroys the random number generator.
        */
        virtual ~BlakePRNG() override = default;

    protected:
        virtual void refill_buffer() override;

    private:
        std::array<std::uint64_t, 2> seed_;

        std::size_t counter_ = 0;
    };

    class BlakePRNGFactory : public UniformRandomGeneratorFactory
    {
    public:
        /**
        Creates a new BlakePRNGFactory instance that initializes every BlakePRNG
        instance it creates with the given seed. A zero seed (default value)
        signals that each random number generator created by the factory should
        use a different random seed.

        @param[in] seed_lw Low-word for seed for the PRNG
        @param[in] seed_hw High-word for seed for the PRNG
        */
        BlakePRNGFactory(std::uint64_t seed_lw = 0, std::uint64_t seed_hw = 0) :
            seed_{ seed_lw, seed_hw }
        {
        }

        /**
        Creates a new uniform random number generator.
        */
        SEAL_NODISCARD virtual auto create()
            -> std::shared_ptr<UniformRandomGenerator> override;

        /**
        Destroys the random number generator factory.
        */
        virtual ~BlakePRNGFactory() = default;

    private:
        std::array<std::uint64_t, 2> seed_;
    };
}
