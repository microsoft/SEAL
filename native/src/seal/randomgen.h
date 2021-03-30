// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#pragma once

#include "seal/dynarray.h"
#include "seal/memorymanager.h"
#include "seal/version.h"
#include "seal/util/common.h"
#include "seal/util/defines.h"
#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <mutex>

namespace seal
{
    constexpr std::size_t prng_seed_uint64_count = 8;

    constexpr std::size_t prng_seed_byte_count = prng_seed_uint64_count * util::bytes_per_uint64;

    using prng_seed_type = std::array<std::uint64_t, prng_seed_uint64_count>;

    /**
    A type indicating a specific pseud-random number generator.
    */
    enum class prng_type : std::uint8_t
    {
        unknown = 0,

        blake2xb = 1,

        shake256 = 2
    };

    /**
    Fills a buffer with random bytes.
    */
    void random_bytes(seal_byte *buf, std::size_t count);

    /**
    Returns a random 64-bit unsigned integer.
    */
    SEAL_NODISCARD inline std::uint64_t random_uint64()
    {
        std::uint64_t result;
        random_bytes(reinterpret_cast<seal_byte *>(&result), sizeof(result));
        return result;
    }

    class UniformRandomGenerator;

    class UniformRandomGeneratorInfo
    {
        friend class UniformRandomGenerator;

    public:
        /**
        Creates a new UniformRandomGeneratorInfo.
        */
        UniformRandomGeneratorInfo() = default;

        /**
        Creates a new UniformRandomGeneratorInfo.

        @param[in] type The PRNG type
        @param[in] seed The PRNG seed
        */
        UniformRandomGeneratorInfo(prng_type type, prng_seed_type seed) : type_(type), seed_(std::move(seed))
        {}

        /**
        Creates a new UniformRandomGeneratorInfo by copying a given one.

        @param[in] copy The UniformRandomGeneratorInfo to copy from
        */
        UniformRandomGeneratorInfo(const UniformRandomGeneratorInfo &copy) = default;

        /**
        Copies a given UniformRandomGeneratorInfo to the current one.

        @param[in] assign The UniformRandomGeneratorInfo to copy from
        */
        UniformRandomGeneratorInfo &operator=(const UniformRandomGeneratorInfo &assign) = default;

        /**
        Compares two UniformRandomGeneratorInfo instances.

        @param[in] compare The UniformRandomGeneratorInfo to compare against
        */
        SEAL_NODISCARD inline bool operator==(const UniformRandomGeneratorInfo &compare) const noexcept
        {
            return (seed_ == compare.seed_) && (type_ == compare.type_);
        }

        /**
        Compares two UniformRandomGeneratorInfo instances.

        @param[in] compare The UniformRandomGeneratorInfo to compare against
        */
        SEAL_NODISCARD inline bool operator!=(const UniformRandomGeneratorInfo &compare) const noexcept
        {
            return !operator==(compare);
        }

        /**
        Clears all data in the UniformRandomGeneratorInfo.
        */
        void clear() noexcept
        {
            type_ = prng_type::unknown;
            util::seal_memzero(seed_.data(), prng_seed_byte_count);
        }

        /**
        Destroys the UniformRandomGeneratorInfo.
        */
        ~UniformRandomGeneratorInfo()
        {
            clear();
        }

        /**
        Creates a new UniformRandomGenerator object of type indicated by the PRNG
        type and seeded with the current seed. If the current PRNG type is not
        an official Microsoft SEAL PRNG type, the return value is nullptr.
        */
        std::shared_ptr<UniformRandomGenerator> make_prng() const;

        /**
        Returns whether this object holds a valid PRNG type.
        */
        SEAL_NODISCARD inline bool has_valid_prng_type() const noexcept
        {
            switch (type_)
            {
            case prng_type::blake2xb:
                /* fall through */

            case prng_type::shake256:
                /* fall through */

            case prng_type::unknown:
                return true;
            }
            return false;
        }

        /**
        Returns the PRNG type.
        */
        SEAL_NODISCARD inline prng_type type() const noexcept
        {
            return type_;
        }

        /**
        Returns a reference to the PRNG type.
        */
        SEAL_NODISCARD inline prng_type &type() noexcept
        {
            return type_;
        }

        /**
        Returns a reference to the PRNG seed.
        */
        SEAL_NODISCARD inline const prng_seed_type &seed() const noexcept
        {
            return seed_;
        }

        /**
        Returns a reference to the PRNG seed.
        */
        SEAL_NODISCARD inline prng_seed_type &seed() noexcept
        {
            return seed_;
        }

        /**
        Returns an upper bound on the size of the UniformRandomGeneratorInfo, as
        if it was written to an output stream.

        @param[in] compr_mode The compression mode
        @throws std::invalid_argument if the compression mode is not supported
        @throws std::logic_error if the size does not fit in the return type
        */
        SEAL_NODISCARD static inline std::streamoff SaveSize(
            compr_mode_type compr_mode = Serialization::compr_mode_default)
        {
            std::size_t members_size =
                Serialization::ComprSizeEstimate(sizeof(prng_type) + prng_seed_byte_count, compr_mode);
            return static_cast<std::streamoff>(sizeof(Serialization::SEALHeader) + members_size);
        }

        /**
        Returns an upper bound on the size of the UniformRandomGeneratorInfo, as
        if it was written to an output stream.

        @param[in] compr_mode The compression mode
        @throws std::invalid_argument if the compression mode is not supported
        @throws std::logic_error if the size does not fit in the return type
        */
        SEAL_NODISCARD inline std::streamoff save_size(
            compr_mode_type compr_mode = Serialization::compr_mode_default) const
        {
            return UniformRandomGeneratorInfo::SaveSize(compr_mode);
        }

        /**
        Saves the UniformRandomGeneratorInfo to an output stream. The output is
        in binary format and is not human-readable. The output stream must have
        the "binary" flag set.

        @param[out] stream The stream to save the UniformRandomGeneratorInfo to
        @param[in] compr_mode The desired compression mode
        @throws std::invalid_argument if the compression mode is not supported
        @throws std::logic_error if the data to be saved is invalid, or if
        compression failed
        @throws std::runtime_error if I/O operations failed
        */
        inline std::streamoff save(
            std::ostream &stream, compr_mode_type compr_mode = Serialization::compr_mode_default) const
        {
            using namespace std::placeholders;
            return Serialization::Save(
                std::bind(&UniformRandomGeneratorInfo::save_members, this, _1), save_size(compr_mode_type::none),
                stream, compr_mode, true);
        }

        /**
        Loads a UniformRandomGeneratorInfo from an input stream overwriting the
        current UniformRandomGeneratorInfo.

        @param[in] stream The stream to load the UniformRandomGeneratorInfo from
        @throws std::logic_error if the data cannot be loaded by this version of
        Microsoft SEAL, if the loaded data is invalid, or if decompression failed
        @throws std::runtime_error if I/O operations failed
        */
        inline std::streamoff load(std::istream &stream)
        {
            using namespace std::placeholders;
            UniformRandomGeneratorInfo new_info;
            auto in_size = Serialization::Load(
                std::bind(&UniformRandomGeneratorInfo::load_members, &new_info, _1, _2), stream, true);
            std::swap(*this, new_info);
            return in_size;
        }

        /**
        Saves the UniformRandomGeneratorInfo to a given memory location. The output
        is in binary format and is not human-readable.

        @param[out] out The memory location to write the UniformRandomGeneratorInfo to
        @param[in] size The number of bytes available in the given memory location
        @param[in] compr_mode The desired compression mode
        @throws std::invalid_argument if out is null or if size is too small to
        contain a SEALHeader, or if the compression mode is not supported
        @throws std::logic_error if the data to be saved is invalid, or if
        compression failed
        @throws std::runtime_error if I/O operations failed
        */
        inline std::streamoff save(
            seal_byte *out, std::size_t size, compr_mode_type compr_mode = Serialization::compr_mode_default) const
        {
            using namespace std::placeholders;
            return Serialization::Save(
                std::bind(&UniformRandomGeneratorInfo::save_members, this, _1), save_size(compr_mode_type::none), out,
                size, compr_mode, true);
        }

        /**
        Loads a UniformRandomGeneratorInfo from a given memory location overwriting
        the current UniformRandomGeneratorInfo.

        @param[in] in The memory location to load the UniformRandomGeneratorInfo from
        @param[in] size The number of bytes available in the given memory location
        @throws std::invalid_argument if in is null or if size is too small to
        contain a SEALHeader
        @throws std::logic_error if the data cannot be loaded by this version of
        Microsoft SEAL, if the loaded data is invalid, or if decompression failed
        @throws std::runtime_error if I/O operations failed
        */
        inline std::streamoff load(const seal_byte *in, std::size_t size)
        {
            using namespace std::placeholders;
            UniformRandomGeneratorInfo new_info;
            auto in_size = Serialization::Load(
                std::bind(&UniformRandomGeneratorInfo::load_members, &new_info, _1, _2), in, size, true);
            std::swap(*this, new_info);
            return in_size;
        }

    public:
        void save_members(std::ostream &stream) const;

        void load_members(std::istream &stream, SEALVersion version);

        prng_type type_ = prng_type::unknown;

        prng_seed_type seed_ = {};
    };

    /**
    Provides the base class for a seeded uniform random number generator. Instances
    of this class are meant to be created by an instance of the factory class
    UniformRandomGeneratorFactory. This class is meant for users to sub-class to
    implement their own random number generators.
    */
    class UniformRandomGenerator
    {
    public:
        /**
        Creates a new UniformRandomGenerator instance initialized with the given seed.

        @param[in] seed The seed for the random number generator
        */
        UniformRandomGenerator(prng_seed_type seed)
            : seed_([&seed]() {
                  // Create a new seed allocation
                  DynArray<std::uint64_t> new_seed(
                      seed.size(), MemoryManager::GetPool(mm_prof_opt::mm_force_new, true));

                  // Assign the given seed and return
                  std::copy(seed.cbegin(), seed.cend(), new_seed.begin());
                  return new_seed;
              }()),
              buffer_(buffer_size_, MemoryManager::GetPool(mm_prof_opt::mm_force_new, true)),
              buffer_begin_(buffer_.begin()), buffer_end_(buffer_.end()), buffer_head_(buffer_.end())
        {}

        SEAL_NODISCARD inline prng_seed_type seed() const noexcept
        {
            prng_seed_type ret{};
            std::copy(seed_.cbegin(), seed_.cend(), ret.begin());
            return ret;
        }

        /**
        Fills a given buffer with a given number of bytes of randomness.
        */
        void generate(std::size_t byte_count, seal_byte *destination);

        /**
        Generates a new unsigned 32-bit random number.
        */
        SEAL_NODISCARD inline std::uint32_t generate()
        {
            std::uint32_t result;
            generate(sizeof(result), reinterpret_cast<seal_byte *>(&result));
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
        Returns a UniformRandomGeneratorInfo object representing this PRNG.
        */
        SEAL_NODISCARD inline UniformRandomGeneratorInfo info() const noexcept
        {
            UniformRandomGeneratorInfo result;
            std::copy_n(seed_.cbegin(), prng_seed_uint64_count, result.seed_.begin());
            result.type_ = type();
            return result;
        }

        /**
        Destroys the random number generator.
        */
        virtual ~UniformRandomGenerator() = default;

    protected:
        SEAL_NODISCARD virtual prng_type type() const noexcept = 0;

        virtual void refill_buffer() = 0;

        const DynArray<std::uint64_t> seed_;

        const std::size_t buffer_size_ = 4096;

    private:
        DynArray<seal_byte> buffer_;

        std::mutex mutex_;

    protected:
        seal_byte *const buffer_begin_;

        seal_byte *const buffer_end_;

        seal_byte *buffer_head_;
    };

    /**
    Provides the base class for a factory instance that creates instances of
    UniformRandomGenerator. This class is meant for users to sub-class to implement
    their own random number generators.
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
        UniformRandomGeneratorFactory(prng_seed_type default_seed)
            : default_seed_(default_seed), use_random_seed_(false)
        {}

        /**
        Creates a new uniform random number generator.
        */
        SEAL_NODISCARD auto create() -> std::shared_ptr<UniformRandomGenerator>
        {
            return use_random_seed_ ? create_impl([]() {
                prng_seed_type seed;
                random_bytes(reinterpret_cast<seal_byte *>(seed.data()), prng_seed_byte_count);
                return seed;
            }())
                                    : create_impl(default_seed_);
        }

        /**
        Creates a new uniform random number generator seeded with the given seed,
        overriding the default seed for this factory instance.

        @param[in] seed The seed to be used for the created random number generator
        */
        SEAL_NODISCARD auto create(prng_seed_type seed) -> std::shared_ptr<UniformRandomGenerator>
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
        static auto DefaultFactory() -> std::shared_ptr<UniformRandomGeneratorFactory>;

        /**
        Returns whether the random number generator factory creates random number
        generators seeded with a random seed, or if a default seed is used.
        */
        SEAL_NODISCARD inline bool use_random_seed() noexcept
        {
            return use_random_seed_;
        }

        /**
        Returns the default seed used to seed every random number generator created
        by this random number generator factory. If use_random_seed() is false, then
        the returned seed has no meaning.
        */
        SEAL_NODISCARD inline prng_seed_type default_seed() noexcept
        {
            return default_seed_;
        }

    protected:
        SEAL_NODISCARD virtual auto create_impl(prng_seed_type seed) -> std::shared_ptr<UniformRandomGenerator> = 0;

    private:
        prng_seed_type default_seed_ = {};

        bool use_random_seed_ = false;
    };

    /**
    Provides an implementation of UniformRandomGenerator for using Blake2xb for
    generating randomness with given 128-bit seed.
    */
    class Blake2xbPRNG : public UniformRandomGenerator
    {
    public:
        /**
        Creates a new Blake2xbPRNG instance initialized with the given seed.

        @param[in] seed The seed for the random number generator
        */
        Blake2xbPRNG(prng_seed_type seed) : UniformRandomGenerator(seed)
        {}

        /**
        Destroys the random number generator.
        */
        ~Blake2xbPRNG() = default;

    protected:
        SEAL_NODISCARD prng_type type() const noexcept override
        {
            return prng_type::blake2xb;
        }

        void refill_buffer() override;

    private:
        std::uint64_t counter_ = 0;
    };

    class Blake2xbPRNGFactory : public UniformRandomGeneratorFactory
    {
    public:
        /**
        Creates a new Blake2xbPRNGFactory. The seed will be sampled randomly
        for each Blake2xbPRNG instance created by the factory instance, which is
        desirable in most normal use-cases.
        */
        Blake2xbPRNGFactory() : UniformRandomGeneratorFactory()
        {}

        /**
        Creates a new Blake2xbPRNGFactory and sets the default seed to the given
        value. For debugging purposes it may sometimes be convenient to have the
        same randomness be used deterministically and repeatedly. Such randomness
        sampling is naturally insecure and must be strictly restricted to debugging
        situations. Thus, most users should never use this constructor.

        @param[in] default_seed The default value for a seed to be used by all
        created instances of Blake2xbPRNG
        */
        Blake2xbPRNGFactory(prng_seed_type default_seed) : UniformRandomGeneratorFactory(default_seed)
        {}

        /**
        Destroys the random number generator factory.
        */
        ~Blake2xbPRNGFactory() = default;

    protected:
        SEAL_NODISCARD auto create_impl(prng_seed_type seed) -> std::shared_ptr<UniformRandomGenerator> override
        {
            return std::make_shared<Blake2xbPRNG>(seed);
        }

    private:
    };

    /**
    Provides an implementation of UniformRandomGenerator for using SHAKE-256 for
    generating randomness with given 128-bit seed.
    */
    class Shake256PRNG : public UniformRandomGenerator
    {
    public:
        /**
        Creates a new Shake256PRNG instance initialized with the given seed.

        @param[in] seed The seed for the random number generator
        */
        Shake256PRNG(prng_seed_type seed) : UniformRandomGenerator(seed)
        {}

        /**
        Destroys the random number generator.
        */
        ~Shake256PRNG() = default;

    protected:
        SEAL_NODISCARD prng_type type() const noexcept override
        {
            return prng_type::shake256;
        }

        void refill_buffer() override;

    private:
        std::uint64_t counter_ = 0;
    };

    class Shake256PRNGFactory : public UniformRandomGeneratorFactory
    {
    public:
        /**
        Creates a new Shake256PRNGFactory. The seed will be sampled randomly for
        each Shake256PRNG instance created by the factory instance, which is
        desirable in most normal use-cases.
        */
        Shake256PRNGFactory() : UniformRandomGeneratorFactory()
        {}

        /**
        Creates a new Shake256PRNGFactory and sets the default seed to the given
        value. For debugging purposes it may sometimes be convenient to have the
        same randomness be used deterministically and repeatedly. Such randomness
        sampling is naturally insecure and must be strictly restricted to debugging
        situations. Thus, most users should never use this constructor.

        @param[in] default_seed The default value for a seed to be used by all
        created instances of Shake256PRNG
        */
        Shake256PRNGFactory(prng_seed_type default_seed) : UniformRandomGeneratorFactory(default_seed)
        {}

        /**
        Destroys the random number generator factory.
        */
        ~Shake256PRNGFactory() = default;

    protected:
        SEAL_NODISCARD auto create_impl(prng_seed_type seed) -> std::shared_ptr<UniformRandomGenerator> override
        {
            return std::make_shared<Shake256PRNG>(seed);
        }

    private:
    };
} // namespace seal
