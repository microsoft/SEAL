// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#pragma once

#include <cstdint>
#include "seal/context.h"

namespace seal
{
    namespace util
    {
        void multiply_plain_with_scaling_variant(
            const std::uint64_t *plain, std::size_t plain_coeff_count,
            const SEALContext::ContextData &context_data, std::uint64_t *destination);

        void divide_plain_by_scaling_variant(std::uint64_t *plain,
            const SEALContext::ContextData &context_data, std::uint64_t *destination,
            MemoryPoolHandle pool);
    }
}