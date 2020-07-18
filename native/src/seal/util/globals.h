// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#pragma once

#include "seal/util/defines.h"
#include "seal/util/hestdparms.h"
#include <cstddef>
#include <cstdint>
#include <map>
#include <memory>
#include <vector>

namespace seal
{
    class Modulus;

    namespace util
    {
        class MemoryPool;

        namespace global_variables
        {
            extern std::shared_ptr<MemoryPool> const global_memory_pool;

/*
For .NET Framework wrapper support (C++/CLI) we need to
    (1) compile the MemoryManager class as thread-unsafe because C++
        mutexes cannot be brought through C++/CLI layer;
    (2) disable thread-safe memory pools.
*/
#ifndef _M_CEE
            extern thread_local std::shared_ptr<MemoryPool> const tls_memory_pool;
#endif
            /**
            Default value for the standard deviation of the noise (error) distribution.
            */
            constexpr double noise_standard_deviation = SEAL_HE_STD_PARMS_ERROR_STD_DEV;

            constexpr double noise_distribution_width_multiplier = 6;

            constexpr double noise_max_deviation = noise_standard_deviation * noise_distribution_width_multiplier;

            /**
            This data structure is a key-value storage that maps degrees of the polynomial modulus
            to vectors of Modulus elements so that when used with the default value for the
            standard deviation of the noise distribution (noise_standard_deviation), the security
            level is at least 128 bits according to http://HomomorphicEncryption.org. This makes
            it easy for non-expert users to select secure parameters.
            */
            const std::map<std::size_t, std::vector<Modulus>> &GetDefaultCoeffModulus128();

            /**
            This data structure is a key-value storage that maps degrees of the polynomial modulus
            to vectors of Modulus elements so that when used with the default value for the
            standard deviation of the noise distribution (noise_standard_deviation), the security
            level is at least 192 bits according to http://HomomorphicEncryption.org. This makes
            it easy for non-expert users to select secure parameters.
            */
            const std::map<std::size_t, std::vector<Modulus>> &GetDefaultCoeffModulus192();

            /**
            This data structure is a key-value storage that maps degrees of the polynomial modulus
            to vectors of Modulus elements so that when used with the default value for the
            standard deviation of the noise distribution (noise_standard_deviation), the security
            level is at least 256 bits according to http://HomomorphicEncryption.org. This makes
            it easy for non-expert users to select secure parameters.
            */
            const std::map<std::size_t, std::vector<Modulus>> &GetDefaultCoeffModulus256();
        } // namespace global_variables
    }     // namespace util
} // namespace seal
