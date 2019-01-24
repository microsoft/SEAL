// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#pragma once

#include <cstdint>
#include <memory>
#include <limits>
#include "seal/randomgen.h"

namespace seal
{
    namespace util
    {
        class RandomToStandardAdapter
        {
        public:
            typedef std::uint32_t result_type;

            RandomToStandardAdapter() : generator_(nullptr)
            {
            }

            RandomToStandardAdapter(
                std::shared_ptr<UniformRandomGenerator> generator) : 
                generator_(generator)
            {
            }

            auto generator() const noexcept
            {
                return generator_;
            }

            auto generator() noexcept
            {
                return generator_;
            }

            result_type operator()()
            {
                return generator_->generate();
            }

            static constexpr result_type min() noexcept
            {
                return 0;
            }

            static constexpr result_type max() noexcept
            {
                return std::numeric_limits<std::uint32_t>::max();
            }

        private:
            std::shared_ptr<UniformRandomGenerator> generator_;
        };
    }
}
