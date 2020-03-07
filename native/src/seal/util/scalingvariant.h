// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#pragma once

#include "seal/context.h"
#include "seal/memorymanager.h"
#include "seal/plaintext.h"
#include <cstdint>

namespace seal
{
    namespace util
    {
        void multiply_add_plain_with_scaling_variant(
            const Plaintext &plain, const SEALContext::ContextData &context_data, std::uint64_t *destination);

        void multiply_sub_plain_with_scaling_variant(
            const Plaintext &plain, const SEALContext::ContextData &context_data, std::uint64_t *destination);
    } // namespace util
} // namespace seal
