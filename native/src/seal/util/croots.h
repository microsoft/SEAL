// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#pragma once

#include <cstddef>
#include <complex>
#include <stdexcept>
#include "seal/util/defines.h"
#include "seal/util/uintcore.h"

namespace seal
{
    class ComplexRoots
    {
    public:
        ComplexRoots() = delete;

        SEAL_NODISCARD static inline std::complex<double> get_root(std::size_t index, std::size_t of_roots)
        {
#ifdef SEAL_DEBUG
            if (util::get_power_of_two(of_roots) < 0)
            {
                throw std::invalid_argument("of_roots must be a power of two");
            }
            if (of_roots > root_fidelity_)
            {
                throw std::invalid_argument("of_roots is too large");
            }
#endif
            index &= of_roots - 1;
            return get_root(util::mul_safe(index, root_fidelity_ / of_roots));
        }

    private:
        SEAL_NODISCARD static std::complex<double> get_root(std::size_t index);

        static constexpr std::size_t root_fidelity_ = 131072;

        static constexpr double PI_ = 3.1415926535897932384626433832795028842;

        //static const double complex_roots_re_[root_fidelity_ / 8 + 1];

        //static const double complex_roots_im_[root_fidelity_ / 8 + 1];
    };
}
