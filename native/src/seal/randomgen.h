// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#pragma once

#include "seal/intarray.h"
#include "seal/memorymanager.h"
#include "seal/util/common.h"
#include "seal/util/defines.h"
#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <iterator>
#include <memory>
#include <mutex>
#include <stdexcept>

namespace seal
{
    using random_seed_type = std::array<std::uint64_t, 8>;

    /**
    Returns a random 64-bit integer.
    */
    SEAL_NODISCARD std::uint64_t random_uint64();

    /**
    Provides the base class for a seeded uniform random number generator. Instances
    of this class are meant to be created by an instance of the factory class
    UniformRandomGeneratorFactory. This class is meant for users to sub-class to
    implement their own random number generators.

    @see UniformRandomGeneratorFactory for the base class of a factory class that
    generates UniformRandomGenerator instances.
    */
    class UniformRandomGenerator
    {
    public:
        /**
        Creates a new UniformRandomGenerator instance initialized with the given seed.

        @param[in] seed The seed for the random number generator
        */
        UniformRandomGenerator(random_seed_type seed)
            : seed_([&seed]() {
                  // Create a new seed allocation
                  IntArray<std::uint64_t> new_seed(seed.size(), MemoryManager::GetPool(mm_prof_opt::FORCE_NEW, true));

                  // Assign the given seed and return
                  std::copy(seed.cbegin(), seed.cend(), new_seed.begin());
                  return new_seed;
              }()),
              buffer_(buffer_size_, MemoryManager::GetPool(mm_prof_opt::FORCE_NEW, true)),
              buffer_begin_(buffer_.begin()), buffer_end_(buffer_.end()), buffer_head_(buffer_.end())
        {}

        SEAL_NODISCARD inline random_seed_type seed() const noexcept
        {
            random_seed_type ret;
            std::copy(seed_.cbegin(), seed_.cend(), ret.begin());
            return ret;
        }

        /**
        Fills a given buffer with a given number of bytes of randomness.
        */
        void generate(std::size_t byte_count, SEAL_BYTE *destination);

        /**
        Generates a new unsigned 32-bit random number.
        */
        SEAL_NODISCARD inline std::uint32_t generate()
        {
            std::uint32_t result;
            generate(sizeof(result), reinterpret_cast<SEAL_BYTE *>(&result));
            return result;
        }

        /**
        Discards the contents of the current randomness buffer and refills it
        with fresh randomness.
        */
        inline void refresh()
        {
            std::lock_guard<std::mutex> lock(mutex_);
            refill_buffer();
            buffer_head_ = buffer_begin_;
        }

        /**
        Destroys the random number generator.
        */
        virtual ~UniformRandomGenerator() = default;

    protected:
        virtual void refill_buffer() = 0;

        const IntArray<std::uint64_t> seed_;

        const std::size_t buffer_size_ = 4096;

    private:
        IntArray<SEAL_BYTE> buffer_;

        std::mutex mutex_;

    protected:
        decltype(buffer_)::T *const buffer_begin_;

        decltype(buffer_)::T *const buffer_end_;

        decltype(buffer_)::T *buffer_head_;
    };

    /**
    Provides the base class for a factory instance that creates instances of
    UniformRandomGenerator. This class is meant for users to sub-class to implement
    their own random number generators.

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
        Creates a new UniformRandomGeneratorFactory. The seed will be sampled
        randomly for each UniformRandomGenerator instance created by the factory
        instance, which is desirable in most normal use-cases.
        */
        UniformRandomGeneratorFactory() : use_random_seed_(true)
        {}

        /**
        Creates a new UniformRandomGeneratorFactory and sets the default seed to
        the given value. For debugging purposes it may sometimes be convenient to
        have the same randomness be used deterministically and repeatedly. Such
        randomness sampling is naturally insecure and must be strictly restricted
        to debugging situations. Thus, most users should never have a reason to
        use this constructor.

        @param[in] default_seed The default value for a seed to be used by all
        created instances of UniformRandomGenerator
        */
        UniformRandomGeneratorFactory(random_seed_type default_seed)
            : default_seed_(default_seed), use_random_seed_(false)
        {}

        /**
        Creates a new uniform random number generator.
        */
        SEAL_NODISCARD auto create() -> std::shared_ptr<UniformRandomGenerator>
        {
            return use_random_seed_
                       ? create_impl({ random_uint64(), random_uint64(), random_uint64(), random_uint64(),
                                       random_uint64(), random_uint64(), random_uint64(), random_uint64() })
                       : create_impl(default_seed_);
        }

        /**
        Creates a new uniform random number generator seeded with the given seed,
        overriding the default seed for this factory instance.

        @param[in] seed The seed to be used for the created random number generator
        */
        SEAL_NODISCARD auto create(random_seed_type seed) -> std::shared_ptr<UniformRandomGenerator>
        {
            return create_impl(seed);
        }

        /**
        Destroys the random number generator factory.
        */
        virtual ~UniformRandomGeneratorFactory() = default;

        /**
        Returns the default random number generator factory. This instance should
        not be destroyed.
        */
        static auto DefaultFactory() -> const std::shared_ptr<UniformRandomGeneratorFactory>;

    protected:
        SEAL_NODISCARD virtual auto create_impl(random_seed_type seed) -> std::shared_ptr<UniformRandomGenerator> = 0;

    private:
        random_seed_type default_seed_ = {};

        bool use_random_seed_ = false;
    };

    /**
    Provides an implementation of UniformRandomGenerator for using Blake2xb for
    generating randomness with given 128-bit seed.
    */
    class BlakePRNG : public UniformRandomGenerator
    {
    public:
        /**
        Creates a new BlakePRNG instance initialized with the given seed.

        @param[in] seed The seed for the random number generator
        */
        BlakePRNG(random_seed_type seed) : UniformRandomGenerator(seed)
        {}

        /**
        Destroys the random number generator.
        */
        virtual ~BlakePRNG() override = default;

    protected:
        virtual void refill_buffer() override;

    private:
        std::uint64_t counter_ = 0;
    };

    class BlakePRNGFactory : public UniformRandomGeneratorFactory
    {
    public:
        /**
        Creates a new BlakePRNGFactory. The seed will be sampled randomly for each
        BlakePRNG instance created by the factory instance, which is desirable in
        most normal use-cases.
        */
        BlakePRNGFactory() : UniformRandomGeneratorFactory()
        {}

        /**
        Creates a new BlakePRNGFactory and sets the default seed to the given value.
        For debugging purposes it may sometimes be convenient to have the same
        randomness be used deterministically and repeatedly. Such randomness
        sampling is naturally insecure and must be strictly restricted to debugging
        situations. Thus, most users should never have a reason to use this
        constructor.

        @param[in] default_seed The default value for a seed to be used by all
        created instances of BlakePRNG
        */
        BlakePRNGFactory(random_seed_type default_seed) : UniformRandomGeneratorFactory(default_seed)
        {}

        /**
        Destroys the random number generator factory.
        */
        virtual ~BlakePRNGFactory() = default;

    protected:
        SEAL_NODISCARD virtual auto create_impl(random_seed_type seed)
            -> std::shared_ptr<UniformRandomGenerator> override
        {
            return std::make_shared<BlakePRNG>(seed);
        }

    private:
    };
} // namespace seal
