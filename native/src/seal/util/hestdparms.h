// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#pragma once

/**
Largest allowed bit counts for coeff_modulus based on the security estimates from
HomomorphicEncryption.org security standard. Microsoft SEAL samples the secret key
from a ternary {-1, 0, 1} distribution.
*/
// Ternary secret; 128 bits classical security
constexpr int SEAL_HE_STD_PARMS_128_TC(std::size_t poly_modulus_degree) noexcept
{
    switch (poly_modulus_degree)
    {
        case std::size_t(1024):      return 27;
        case std::size_t(2048):      return 54;
        case std::size_t(4096):      return 109;
        case std::size_t(8192):      return 218;
        case std::size_t(16384):     return 438;
        case std::size_t(32768):     return 881;
    }
    return 0;
}

// Ternary secret; 192 bits classical security
constexpr int SEAL_HE_STD_PARMS_192_TC(std::size_t poly_modulus_degree) noexcept
{
    switch (poly_modulus_degree)
    {
        case std::size_t(1024):      return 19;
        case std::size_t(2048):      return 37;
        case std::size_t(4096):      return 75;
        case std::size_t(8192):      return 152;
        case std::size_t(16384):     return 305;
        case std::size_t(32768):     return 611;
    }
    return 0;
}

// Ternary secret; 256 bits classical security
constexpr int SEAL_HE_STD_PARMS_256_TC(std::size_t poly_modulus_degree) noexcept
{
    switch (poly_modulus_degree)
    {
        case std::size_t(1024):      return 14;
        case std::size_t(2048):      return 29;
        case std::size_t(4096):      return 58;
        case std::size_t(8192):      return 118;
        case std::size_t(16384):     return 237;
        case std::size_t(32768):     return 476;
    }
    return 0;
}

// Ternary secret; 128 bits quantum security
constexpr int SEAL_HE_STD_PARMS_128_TQ(std::size_t poly_modulus_degree) noexcept
{
    switch (poly_modulus_degree)
    {
        case std::size_t(1024):      return 25;
        case std::size_t(2048):      return 51;
        case std::size_t(4096):      return 101;
        case std::size_t(8192):      return 202;
        case std::size_t(16384):     return 411;
        case std::size_t(32768):     return 827;
    }
    return 0;
}

// Ternary secret; 192 bits quantum security
constexpr int SEAL_HE_STD_PARMS_192_TQ(std::size_t poly_modulus_degree) noexcept
{
    switch (poly_modulus_degree)
    {
        case std::size_t(1024):      return 17;
        case std::size_t(2048):      return 35;
        case std::size_t(4096):      return 70;
        case std::size_t(8192):      return 141;
        case std::size_t(16384):     return 284;
        case std::size_t(32768):     return 571;
    }
    return 0;
}

// Ternary secret; 256 bits quantum security
constexpr int SEAL_HE_STD_PARMS_256_TQ(std::size_t poly_modulus_degree) noexcept
{
    switch (poly_modulus_degree)
    {
        case std::size_t(1024):      return 13;
        case std::size_t(2048):      return 27;
        case std::size_t(4096):      return 54;
        case std::size_t(8192):      return 109;
        case std::size_t(16384):     return 220;
        case std::size_t(32768):     return 443;
    }
    return 0;
}

// Standard deviation for error distribution
constexpr double SEAL_HE_STD_PARMS_ERROR_STD_DEV = 3.20;