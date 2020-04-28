// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#pragma once

#include "seal/randomgen.h"
#include <cstdint>
#include <limits>
#include <memory>
#include <stdexcept>

namespace seal
{
    /**
    A simple wrapper class to implement C++ UniformRandomBitGenerator type properties
    for a given polymorphic UniformRandomGenerator instance. The resulting object can
    be used as a randomness source in C++ standard random number distribution classes,
    such as std::uniform_int_distribution, std::normal_distribution, or any of the
    standard RandomNumberEngine classes.
    */
    class RandomToStandardAdapter
    {
    public:
        using result_type = std::uint32_t;

        /**
        Creates a new RandomToStandardAdapter backed by a given UniformRandomGenerator.

        @param[in] generator A backing UniformRandomGenerator instance
        @throws std::invalid_argument if generator is null
        */
        RandomToStandardAdapter(std::shared_ptr<UniformRandomGenerator> generator) : generator_(generator)
        {
            if (!generator_)
            {
                throw std::invalid_argument("generator cannot be null");
            }
        }

        /**
        Returns a new random number from the backing UniformRandomGenerator.
        */
        SEAL_NODISCARD inline result_type operator()()
        {
            return generator_->generate();
        }

        /**
        Returns the backing UniformRandomGenerator.
        */
        SEAL_NODISCARD inline auto generator() const noexcept
        {
            return generator_;
        }

        /**
        Returns the smallest possible output value.
        */
        SEAL_NODISCARD inline static constexpr result_type min() noexcept
        {
            return std::numeric_limits<result_type>::min();
        }

        /**
        Returns the largest possible output value.
        */
        SEAL_NODISCARD static constexpr result_type max() noexcept
        {
            return std::numeric_limits<result_type>::max();
        }

    private:
        std::shared_ptr<UniformRandomGenerator> generator_;
    };
} // namespace seal
