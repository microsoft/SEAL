// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include "seal/util/streambuf.h"

namespace seal
{
    namespace util
    {
        // Required for C++14 compliance: static constexpr member variables are not necessarily inlined so need to
        // ensure symbol is created.
        constexpr double SafeByteBuffer::expansion_factor_;
    } // namespace util
} // namespace seal
