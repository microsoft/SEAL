// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#pragma once

#include <iostream>
#include <functional>
#include "seal/util/defines.h"

namespace seal
{
    enum class compr_mode_type : std::uint8_t
    {
        none = 0,
#ifdef SEAL_USE_ZLIB
        deflate = 1
#endif
    };

    constexpr compr_mode_type compr_mode_default = compr_mode_type::none;

    class Serialization
    {
    public:
        static std::streamoff Save(
            std::function<void(std::ostream &stream)> save_members,
            std::ostream &stream,
            compr_mode_type compr_mode);

        static std::streamoff Load(
            std::function<void(std::istream &stream)> load_members,
            std::istream &stream);

    private:
        Serialization() = delete;
    };
}