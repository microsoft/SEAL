// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#pragma once

#include "seal/util/defines.h"
#include <cstdint>

namespace seal
{
    /**
    Holds Microsoft SEAL version information. A SEALVersion contains four values:

        1. The major version number;
        2. The minor version number;
        3. The patch version number;
        4. The tweak version number.

    Two versions of the library with the same major and minor versions are fully
    compatible with each other. They are guaranteed to have the same public API.
    Changes in the patch version number indicate totally internal changes, such
    as bug fixes that require no changes to the public API. The tweak version
    number is currently not used, and is expected to be 0.
    */
    struct SEALVersion
    {
        /**
        Holds the major version number.
        */
        std::uint8_t major = SEAL_VERSION_MAJOR;

        /**
        Holds the minor version number.
        */
        std::uint8_t minor = SEAL_VERSION_MINOR;

        /**
        Holds the patch version number.
        */
        std::uint8_t patch = SEAL_VERSION_PATCH;

        std::uint8_t tweak = 0;
    };
} // namespace seal
