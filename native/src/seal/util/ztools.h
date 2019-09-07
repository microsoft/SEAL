// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#pragma once

#include <iostream>
#include <ios>
#include "seal/memorymanager.h"

namespace seal
{
    namespace util
    {
        namespace ztools
        {
            constexpr std::size_t buf_size = 16384;

            int deflate_stream(std::istream &in_stream,
                std::streamoff in_size, std::ostream &out_stream,
                MemoryPoolHandle pool);

            int inflate_stream(std::istream &in_stream,
                std::streamoff in_size, std::ostream &out_stream,
                MemoryPoolHandle pool);

            SEAL_NODISCARD std::size_t deflate_size_bound(std::size_t in_size) noexcept;
        }
    }
}
