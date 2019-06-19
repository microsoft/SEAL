// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#pragma once

#include <iostream>
#include <numeric>
#include <memory>
#include "seal/util/defines.h"
#include "seal/util/globals.h"
#include "seal/randomgen.h"
#include "seal/smallmodulus.h"
#include "seal/util/hash.h"
#include "seal/memorymanager.h"

namespace seal
{
    /**
    Describes the type of encryption scheme to be used.
    */
    enum class scheme_type : std::uint8_t
    {
        // Brakerski/Fan-Vercauteren scheme
        BFV = 0x1,

        // Cheon-Kim-Kim-Song scheme
        CKKS = 0x2
    };

    /**
    The data type to store unique identifiers of encryption parameters.
    */
    using parms_id_type = util::HashFunction::sha3_block_type;

    /**
    A parms_id_type value consisting of zeros.
    */
    static constexpr parms_id_type parms_id_zero =
        util::HashFunction::sha3_zero_block;

    /**
    Represents user-customizable encryption scheme settings. The parameters (most
    importantly poly_modulus, coeff_modulus, plain_modulus) significantly affect
    the performance, capabilities, and security of the encryption scheme. Once
    an instance of EncryptionParameters is populated with appropriate parameters,
    it can be used to create an instance of the SEALContext class, which verifies
    the validity of the parameters, and performs necessary pre-computations.

    Picking appropriate encryption parameters is essential to enable a particular
    application while balancing performance and security. Some encryption settings
    will not allow some inputs (e.g. attempting to encrypt a polynomial with more
    coefficients than poly_modulus or larger coefficients than plain_modulus) or,
    support the desired computations (with noise growing too fast due to too large
    plain_modulus and too small coeff_modulus).

    @par parms_id
    The EncryptionParameters class maintains at all times a 256-bit SHA-3 hash of
    the currently set encryption parameters called the parms_id. This hash acts as
    a unique identifier of the encryption parameters and is used by all further
    objects created for these encryption parameters. The parms_id is not intended
    to be directly modified by the user but is used internally for pre-computation
    data lookup and input validity checks. In modulus switching the user can use
    the parms_id to keep track of the chain of encryption parameters. The parms_id
    is not exposed in the public API of EncryptionParameters, but can be accessed
    through the SEALContext::ContextData class once the SEALContext has been created.

    @par Thread Safety
    In general, reading from EncryptionParameters is thread-safe, while mutating
    is not.

    @warning Choosing inappropriate encryption parameters may lead to an encryption
    scheme that is not secure, does not perform well, and/or does not support the
    input and computation of the desired application. We highly recommend consulting
    an expert in RLWE-based encryption when selecting parameters, as this is where
    inexperienced users seem to most often make critical mistakes.
    */
    class EncryptionParameters
    {
        friend class SEALContext;

    public:
        /**
        Creates an empty set of encryption parameters. At a minimum, the user needs
        to specify the parameters poly_modulus, coeff_modulus, and plain_modulus
        for the parameters to be usable.
        */
        EncryptionParameters(scheme_type scheme) : scheme_(scheme)
        {
            compute_parms_id();
        }

        /**
        Creates an empty set of encryption parameters. At a minimum, the user needs
        to specify the parameters poly_modulus, coeff_modulus, and plain_modulus
        for the parameters to be usable.

        @throws std::invalid_argument if scheme is not supported
        @see scheme_type for the supported schemes
        */
        EncryptionParameters(std::uint8_t scheme)
        {
            // Check that a valid scheme is given
            if (!is_valid_scheme(scheme))
            {
                throw std::invalid_argument("unsupported scheme");
            }

            scheme_ = static_cast<scheme_type>(scheme);
            compute_parms_id();
        }

        /**
        Creates a copy of a given instance of EncryptionParameters.

        @param[in] copy The EncryptionParameters to copy from
        */
        EncryptionParameters(const EncryptionParameters &copy) = default;

        /**
        Overwrites the EncryptionParameters instance with a copy of a given instance.

        @param[in] assign The EncryptionParameters to copy from
        */
        EncryptionParameters &operator =(const EncryptionParameters &assign) = default;

        /**
        Creates a new EncryptionParameters instance by moving a given instance.

        @param[in] source The EncryptionParameters to move from
        */
        EncryptionParameters(EncryptionParameters &&source) = default;

        /**
        Overwrites the EncryptionParameters instance by moving a given instance.

        @param[in] assign The EncryptionParameters to move from
        */
        EncryptionParameters &operator =(EncryptionParameters &&assign) = default;

        /**
        Sets the degree of the polynomial modulus parameter to the specified value.
        The polynomial modulus directly affects the number of coefficients in
        plaintext polynomials, the size of ciphertext elements, the computational
        performance of the scheme (bigger is worse), and the security level (bigger
        is better). In Microsoft SEAL the degree of the polynomial modulus must be a power
        of 2 (e.g.  1024, 2048, 4096, 8192, 16384, or 32768).

        @param[in] poly_modulus_degree The new polynomial modulus degree
        */
        inline void set_poly_modulus_degree(std::size_t poly_modulus_degree)
        {
            // Set the degree
            poly_modulus_degree_ = poly_modulus_degree;

            // Re-compute the parms_id
            compute_parms_id();
        }

        /**
        Sets the coefficient modulus parameter. The coefficient modulus consists
        of a list of distinct prime numbers, and is represented by a vector of
        SmallModulus objects. The coefficient modulus directly affects the size
        of ciphertext elements, the amount of computation that the scheme can perform
        (bigger is better), and the security level (bigger is worse). In Microsoft SEAL each
        of the prime numbers in the coefficient modulus must be at most 60 bits,
        and must be congruent to 1 modulo 2*degree(poly_modulus).

        @param[in] coeff_modulus The new coefficient modulus
        @throws std::invalid_argument if size of coeff_modulus is invalid
        */
        inline void set_coeff_modulus(const std::vector<SmallModulus> &coeff_modulus)
        {
            // Set the coeff_modulus_
            if (coeff_modulus.size() > SEAL_COEFF_MOD_COUNT_MAX ||
                coeff_modulus.size() < SEAL_COEFF_MOD_COUNT_MIN)
            {
                throw std::invalid_argument("coeff_modulus is invalid");
            }

            coeff_modulus_ = coeff_modulus;

            // Re-compute the parms_id
            compute_parms_id();
        }

        /**
        Sets the plaintext modulus parameter. The plaintext modulus is an integer
        modulus represented by the SmallModulus class. The plaintext modulus
        determines the largest coefficient that plaintext polynomials can represent.
        It also affects the amount of computation that the scheme can perform
        (bigger is worse). In Microsoft SEAL the plaintext modulus can be at most 60 bits
        long, but can otherwise be any integer. Note, however, that some features
        (e.g. batching) require the plaintext modulus to be of a particular form.

        @param[in] plain_modulus The new plaintext modulus
        @throws std::logic_error if scheme is not scheme_type::BFV
        */
        inline void set_plain_modulus(const SmallModulus &plain_modulus)
        {
            // CKKS does not use plain_modulus
            if (scheme_ != scheme_type::BFV)
            {
                throw std::logic_error("unsupported scheme");
            }

            plain_modulus_ = plain_modulus;

            // Re-compute the parms_id
            compute_parms_id();
        }

        /**
        Sets the plaintext modulus parameter. The plaintext modulus is an integer
        modulus represented by the SmallModulus class. This constructor instead
        takes a std::uint64_t and automatically creates the SmallModulus object.
        The plaintext modulus determines the largest coefficient that plaintext
        polynomials can represent. It also affects the amount of computation that
        the scheme can perform (bigger is worse). In Microsoft SEAL the plaintext modulus
        can be at most 60 bits long, but can otherwise be any integer. Note,
        however, that some features (e.g. batching) require the plaintext modulus
        to be of a particular form.

        @param[in] plain_modulus The new plaintext modulus
        @throws std::invalid_argument if plain_modulus is invalid
        */
        inline void set_plain_modulus(std::uint64_t plain_modulus)
        {
            set_plain_modulus(SmallModulus(plain_modulus));
        }

        /**
        Sets the random number generator factory to use for encryption. By default,
        the random generator is set to UniformRandomGeneratorFactory::default_factory().
        Setting this value allows a user to specify a custom random number generator
        source.

        @param[in] random_generator Pointer to the random generator factory
        */
        inline void set_random_generator(
            std::shared_ptr<UniformRandomGeneratorFactory> random_generator) noexcept
        {
            random_generator_ = std::move(random_generator);
        }

        /**
        Returns the encryption scheme type.
        */
        inline scheme_type scheme() const noexcept
        {
            return scheme_;
        }

        /**
        Returns the degree of the polynomial modulus parameter.
        */
        inline std::size_t poly_modulus_degree() const noexcept
        {
            return poly_modulus_degree_;
        }

        /**
        Returns a const reference to the currently set coefficient modulus parameter.
        */
        inline const std::vector<SmallModulus> &coeff_modulus() const noexcept
        {
            return coeff_modulus_;
        }

        /**
        Returns a const reference to the currently set plaintext modulus parameter.
        */
        inline const SmallModulus &plain_modulus() const noexcept
        {
            return plain_modulus_;
        }

        /**
        Returns a pointer to the random number generator factory to use for encryption.
        */
        inline std::shared_ptr<UniformRandomGeneratorFactory> random_generator() const noexcept
        {
            return random_generator_;
        }

        /**
        Compares a given set of encryption parameters to the current set of
        encryption parameters. The comparison is performed by comparing the
        parms_ids of the parameter sets rather than comparing the parameters
        individually.

        @parms[in] other The EncryptionParameters to compare against
        */
        inline bool operator ==(const EncryptionParameters &other) const noexcept
        {
            return (parms_id_ == other.parms_id_);
        }

        /**
        Compares a given set of encryption parameters to the current set of
        encryption parameters. The comparison is performed by comparing
        parms_ids of the parameter sets rather than comparing the parameters
        individually.

        @parms[in] other The EncryptionParameters to compare against
        */
        inline bool operator !=(const EncryptionParameters &other) const noexcept
        {
            return (parms_id_ != other.parms_id_);
        }

        /**
        Saves EncryptionParameters to an output stream. The output is in binary
        format and is not human-readable. The output stream must have the "binary"
        flag set.

        @param[in] stream The stream to save the EncryptionParameters to
        @throws std::exception if the EncryptionParameters could not be written
        to stream
        */
        static void Save(const EncryptionParameters &parms, std::ostream &stream);

        /**
        Loads EncryptionParameters from an input stream.

        @param[in] stream The stream to load the EncryptionParameters from
        @throws std::exception if valid EncryptionParameters could not be read
        from stream
        */
        static EncryptionParameters Load(std::istream &stream);

        /**
        Enables access to private members of seal::EncryptionParameters for .NET
        wrapper.
        */
        struct EncryptionParametersPrivateHelper;

    private:
        /**
        Helper function to determine whether given std::uint8_t represents a valid
        value for scheme_type.
        */
        bool is_valid_scheme(std::uint8_t scheme) const noexcept
        {
            return (scheme == static_cast<std::uint8_t>(scheme_type::BFV) ||
                (scheme == static_cast<std::uint8_t>(scheme_type::CKKS)));
        }

        /**
        Returns the parms_id of the current parameters. This function is intended
        for internal use.
        */
        inline auto &parms_id() const noexcept
        {
            return parms_id_;
        }

        void compute_parms_id();

        MemoryPoolHandle pool_ = MemoryManager::GetPool();

        scheme_type scheme_;

        std::size_t poly_modulus_degree_ = 0;

        std::vector<SmallModulus> coeff_modulus_{};

        std::shared_ptr<UniformRandomGeneratorFactory> random_generator_{ nullptr };

        SmallModulus plain_modulus_{};

        parms_id_type parms_id_ = parms_id_zero;
    };
}

/**
Specializes the std::hash template for parms_id_type.
*/
namespace std
{
    template<>
    struct hash<seal::parms_id_type>
    {
        std::size_t operator()(
            const seal::parms_id_type &parms_id) const
        {
            std::uint64_t result = 17;
            result = 31 * result + parms_id[0];
            result = 31 * result + parms_id[1];
            result = 31 * result + parms_id[2];
            result = 31 * result + parms_id[3];
            return static_cast<std::size_t>(result);
        }
    };
}
