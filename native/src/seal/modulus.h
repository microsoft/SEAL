// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#pragma once

#include <cstddef>
#include <vector>
#include <numeric>
#include "seal/smallmodulus.h"
#include "seal/util/hestdparms.h"

namespace seal
{
    /**
    Represents a standard security level according to the HomomorphicEncryption.org
    security standard. The value sec_level_type::none signals that no standard
    security level should be imposed. The value sec_level_type::tc128 provides
    a very high level of security and is the default security level enforced by
    Microsoft SEAL when constructing a SEALContext object. Normal users should not
    have to specify the security level explicitly anywhere.
    */
    enum class sec_level_type : int
    {
        /**
        No security level specified.
        */
        none = 0,

        /**
        128-bit security level according to HomomorphicEncryption.org standard.
        */
        tc128 = 128,

        /**
        192-bit security level according to HomomorphicEncryption.org standard.
        */
        tc192 = 192,

        /**
        256-bit security level according to HomomorphicEncryption.org standard.
        */
        tc256 = 256
    };

    /**
    This class contains static methods for creating a coefficient modulus easily.
    Note that while these functions take a sec_level_type argument, all security
    guarantees are lost if the output is used with encryption parameters with
    a mismatching value for the poly_modulus_degree.

    The default value sec_level_type::tc128 provides a very high level of security
    and is the default security level enforced by Microsoft SEAL when constructing
    a SEALContext object. Normal users should not have to specify the security
    level explicitly anywhere.
    */
    class CoeffModulus
    {
    public:
        CoeffModulus() = delete;

        /**
        Returns the largest bit-length of the coefficient modulus, i.e., bit-length
        of the product of the primes in the coefficient modulus, that guarantees
        a given security level when using a given poly_modulus_degree, according
        to the HomomorphicEncryption.org security standard.

        @param[in] poly_modulus_degree The value of the poly_modulus_degree
        encryption parameter
        @param[in] sec_level The desired standard security level
        */
        static constexpr int MaxBitCount(
            std::size_t poly_modulus_degree,
            sec_level_type sec_level = sec_level_type::tc128) noexcept
        {
            switch (sec_level)
            {
            case sec_level_type::tc128:
                return SEAL_HE_STD_PARMS_128_TC(poly_modulus_degree);

            case sec_level_type::tc192:
                return SEAL_HE_STD_PARMS_192_TC(poly_modulus_degree);

            case sec_level_type::tc256:
                return SEAL_HE_STD_PARMS_256_TC(poly_modulus_degree);

            case sec_level_type::none:
                return std::numeric_limits<int>::max();

            default:
                return 0;
            }
        }

        /**
        Returns a default coefficient modulus for the BFV scheme that guarantees
        a given security level when using a given poly_modulus_degree, according
        to the HomomorphicEncryption.org security standard. Note that all security
        guarantees are lost if the output is used with encryption parameters with
        a mismatching value for the poly_modulus_degree.

        The coefficient modulus returned by this function will not perform well
        if used with the CKKS scheme.

        @param[in] poly_modulus_degree The value of the poly_modulus_degree
        encryption parameter
        @param[in] sec_level The desired standard security level
        @throws std::invalid_argument if poly_modulus_degree is not a power-of-two
        or is too large
        @throws std::invalid_argument if sec_level is sec_level_type::none
        */
        static std::vector<SmallModulus> BFVDefault(
            std::size_t poly_modulus_degree,
            sec_level_type sec_level = sec_level_type::tc128);

        /**
        Returns a custom coefficient modulus suitable for use with the specified
        poly_modulus_degree. The return value will be a vector consisting of
        SmallModulus elements representing distinct prime numbers of bit-lengths
        as given in the bit_sizes parameter. The bit sizes of the prime numbers
        can be at most 60 bits.

        @param[in] poly_modulus_degree The value of the poly_modulus_degree
        encryption parameter
        @param[in] bit_sizes The bit-lengths of the primes to be generated
        @throws std::invalid_argument if poly_modulus_degree is not a power-of-two
        or is too large
        @throws std::invalid_argument if bit_sizes is too large or if its elements
        are out of bounds
        @throws std::logic_error if not enough suitable primes could be found
        */
        static std::vector<SmallModulus> Create(
            std::size_t poly_modulus_degree,
            std::vector<int> bit_sizes);
    };

    /**
    This class contains static methods for creating a plaintext modulus easily.
    */
    class PlainModulus
    {
    public:
        PlainModulus() = delete;

        /**
        Creates a prime number SmallModulus for use as plain_modulus encryption
        parameter that supports batching with a given poly_modulus_degree.

        @param[in] poly_modulus_degree The value of the poly_modulus_degree
        encryption parameter
        @param[in] bit_size The bit-length of the prime to be generated
        @throws std::invalid_argument if poly_modulus_degree is not a power-of-two
        or is too large
        @throws std::invalid_argument if bit_size is out of bounds
        @throws std::logic_error if a suitable prime could not be found
        */
        static inline SmallModulus Batching(
            std::size_t poly_modulus_degree,
            int bit_size)
        {
            return CoeffModulus::Create(poly_modulus_degree, { bit_size })[0];
        }


        /**
        Creates several prime number SmallModulus elements that can be used as
        plain_modulus encryption parameters, each supporting batching with a given
        poly_modulus_degree.

        @param[in] poly_modulus_degree The value of the poly_modulus_degree
        encryption parameter
        @param[in] bit_sizes The bit-lengths of the primes to be generated
        @throws std::invalid_argument if poly_modulus_degree is not a power-of-two
        or is too large
        @throws std::invalid_argument if bit_sizes is too large or if its elements
        are out of bounds
        @throws std::logic_error if not enough suitable primes could be found
        */
        static inline std::vector<SmallModulus> Batching(
            std::size_t poly_modulus_degree,
            std::vector<int> bit_sizes)
        {
            return CoeffModulus::Create(poly_modulus_degree, bit_sizes);
        }
    };
}
