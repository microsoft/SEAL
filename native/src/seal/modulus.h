// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#pragma once

#include "seal/memorymanager.h"
#include "seal/serialization.h"
#include "seal/util/defines.h"
#include "seal/util/hestdparms.h"
#include "seal/util/uintcore.h"
#include "seal/util/ztools.h"
#include <array>
#include <cstddef>
#include <cstdint>
#include <iostream>
#include <numeric>
#include <vector>

namespace seal
{
    /**
    Represent an integer modulus of up to 61 bits. An instance of the Modulus
    class represents a non-negative integer modulus up to 61 bits. In particular,
    the encryption parameter plain_modulus, and the primes in coeff_modulus, are
    represented by instances of Modulus. The purpose of this class is to
    perform and store the pre-computation required by Barrett reduction.

    @par Thread Safety
    In general, reading from Modulus is thread-safe as long as no other thread
    is concurrently mutating it.

    @see EncryptionParameters for a description of the encryption parameters.
    */
    class Modulus
    {
    public:
        /**
        Creates a Modulus instance. The value of the Modulus is set to
        the given value, or to zero by default.

        @param[in] value The integer modulus
        @throws std::invalid_argument if value is 1 or more than 61 bits
        */
        Modulus(std::uint64_t value = 0)
        {
            set_value(value);
        }

        /**
        Creates a new Modulus by copying a given one.

        @param[in] copy The Modulus to copy from
        */
        Modulus(const Modulus &copy) = default;

        /**
        Creates a new Modulus by copying a given one.

        @param[in] source The Modulus to move from
        */
        Modulus(Modulus &&source) = default;

        /**
        Copies a given Modulus to the current one.

        @param[in] assign The Modulus to copy from
        */
        Modulus &operator=(const Modulus &assign) = default;

        /**
        Moves a given Modulus to the current one.

        @param[in] assign The Modulus to move from
        */
        Modulus &operator=(Modulus &&assign) = default;

        /**
        Sets the value of the Modulus.

        @param[in] value The new integer modulus
        @throws std::invalid_argument if value is 1 or more than 61 bits
        */
        inline Modulus &operator=(std::uint64_t value)
        {
            set_value(value);
            return *this;
        }

        /**
        Returns the significant bit count of the value of the current Modulus.
        */
        SEAL_NODISCARD inline int bit_count() const noexcept
        {
            return bit_count_;
        }

        /**
        Returns the size (in 64-bit words) of the value of the current Modulus.
        */
        SEAL_NODISCARD inline std::size_t uint64_count() const noexcept
        {
            return uint64_count_;
        }

        /**
        Returns a const pointer to the value of the current Modulus.
        */
        SEAL_NODISCARD inline const uint64_t *data() const noexcept
        {
            return &value_;
        }

        /**
        Returns the value of the current Modulus.
        */
        SEAL_NODISCARD inline std::uint64_t value() const noexcept
        {
            return value_;
        }

        /**
        Returns the Barrett ratio computed for the value of the current Modulus.
        The first two components of the Barrett ratio are the floor of 2^128/value,
        and the third component is the remainder.
        */
        SEAL_NODISCARD inline auto &const_ratio() const noexcept
        {
            return const_ratio_;
        }

        /**
        Returns whether the value of the current Modulus is zero.
        */
        SEAL_NODISCARD inline bool is_zero() const noexcept
        {
            return value_ == 0;
        }

        /**
        Returns whether the value of the current Modulus is a prime number.
        */
        SEAL_NODISCARD inline bool is_prime() const noexcept
        {
            return is_prime_;
        }

        /**
        Compares two Modulus instances.

        @param[in] compare The Modulus to compare against
        */
        SEAL_NODISCARD inline bool operator==(const Modulus &compare) const noexcept
        {
            return value_ == compare.value_;
        }

        /**
        Compares a Modulus value to an unsigned integer.

        @param[in] compare The unsigned integer to compare against
        */
        SEAL_NODISCARD inline bool operator==(std::uint64_t compare) const noexcept
        {
            return value_ == compare;
        }

        /**
        Compares two Modulus instances.

        @param[in] compare The Modulus to compare against
        */
        SEAL_NODISCARD inline bool operator!=(const Modulus &compare) const noexcept
        {
            return !(value_ == compare.value_);
        }

        /**
        Compares a Modulus value to an unsigned integer.

        @param[in] compare The unsigned integer to compare against
        */
        SEAL_NODISCARD inline bool operator!=(std::uint64_t compare) const noexcept
        {
            return value_ != compare;
        }

        /**
        Compares two Modulus instances.

        @param[in] compare The Modulus to compare against
        */
        SEAL_NODISCARD inline bool operator<(const Modulus &compare) const noexcept
        {
            return value_ < compare.value_;
        }

        /**
        Compares a Modulus value to an unsigned integer.

        @param[in] compare The unsigned integer to compare against
        */
        SEAL_NODISCARD inline bool operator<(std::uint64_t compare) const noexcept
        {
            return value_ < compare;
        }

        /**
        Compares two Modulus instances.

        @param[in] compare The Modulus to compare against
        */
        SEAL_NODISCARD inline bool operator<=(const Modulus &compare) const noexcept
        {
            return value_ <= compare.value_;
        }

        /**
        Compares a Modulus value to an unsigned integer.

        @param[in] compare The unsigned integer to compare against
        */
        SEAL_NODISCARD inline bool operator<=(std::uint64_t compare) const noexcept
        {
            return value_ <= compare;
        }

        /**
        Compares two Modulus instances.

        @param[in] compare The Modulus to compare against
        */
        SEAL_NODISCARD inline bool operator>(const Modulus &compare) const noexcept
        {
            return value_ > compare.value_;
        }

        /**
        Compares a Modulus value to an unsigned integer.

        @param[in] compare The unsigned integer to compare against
        */
        SEAL_NODISCARD inline bool operator>(std::uint64_t compare) const noexcept
        {
            return value_ > compare;
        }

        /**
        Compares two Modulus instances.

        @param[in] compare The Modulus to compare against
        */
        SEAL_NODISCARD inline bool operator>=(const Modulus &compare) const noexcept
        {
            return value_ >= compare.value_;
        }

        /**
        Compares a Modulus value to an unsigned integer.

        @param[in] compare The unsigned integer to compare against
        */
        SEAL_NODISCARD inline bool operator>=(std::uint64_t compare) const noexcept
        {
            return value_ >= compare;
        }

        /**
        Returns an upper bound on the size of the Modulus, as if it was
        written to an output stream.

        @param[in] compr_mode The compression mode
        @throws std::invalid_argument if the compression mode is not supported
        @throws std::logic_error if the size does not fit in the return type
        */
        SEAL_NODISCARD inline std::streamoff save_size(
            compr_mode_type compr_mode = Serialization::compr_mode_default) const
        {
            std::size_t members_size = Serialization::ComprSizeEstimate(util::add_safe(sizeof(value_)), compr_mode);

            return util::safe_cast<std::streamoff>(util::add_safe(sizeof(Serialization::SEALHeader), members_size));
        }

        /**
        Saves the Modulus to an output stream. The full state of the modulus is
        serialized. The output is in binary format and not human-readable. The output
        stream must have the "binary" flag set.

        @param[out] stream The stream to save the Modulus to
        @param[in] compr_mode The desired compression mode
        @throws std::invalid_argument if the compression mode is not supported
        @throws std::logic_error if the data to be saved is invalid, or if
        compression failed
        @throws std::runtime_error if I/O operations failed
        */
        inline std::streamoff save(
            std::ostream &stream, compr_mode_type compr_mode = Serialization::compr_mode_default) const
        {
            using namespace std::placeholders;
            return Serialization::Save(
                std::bind(&Modulus::save_members, this, _1), save_size(compr_mode_type::none), stream, compr_mode);
        }

        /**
        Loads a Modulus from an input stream overwriting the current
        Modulus.

        @param[in] stream The stream to load the Modulus from
        @throws std::logic_error if the data cannot be loaded by this version of
        Microsoft SEAL, if the loaded data is invalid, or if decompression failed
        @throws std::runtime_error if I/O operations failed
        */
        inline std::streamoff load(std::istream &stream)
        {
            using namespace std::placeholders;
            return Serialization::Load(std::bind(&Modulus::load_members, this, _1), stream);
        }

        /**
        Saves the Modulus to a given memory location. The full state of the
        modulus is serialized. The output is in binary format and not human-readable.

        @param[out] out The memory location to write the Modulus to
        @param[in] size The number of bytes available in the given memory location
        @param[in] compr_mode The desired compression mode
        @throws std::invalid_argument if out is null or if size is too small to
        contain a SEALHeader, or if the compression mode is not supported
        @throws std::logic_error if the data to be saved is invalid, or if
        compression failed
        @throws std::runtime_error if I/O operations failed
        */
        inline std::streamoff save(
            SEAL_BYTE *out, std::size_t size, compr_mode_type compr_mode = Serialization::compr_mode_default) const
        {
            using namespace std::placeholders;
            return Serialization::Save(
                std::bind(&Modulus::save_members, this, _1), save_size(compr_mode_type::none), out, size, compr_mode);
        }

        /**
        Loads a Modulus from a given memory location overwriting the current
        Modulus.

        @param[in] in The memory location to load the Modulus from
        @param[in] size The number of bytes available in the given memory location
        @throws std::invalid_argument if in is null or if size is too small to
        contain a SEALHeader
        @throws std::logic_error if the data cannot be loaded by this version of
        Microsoft SEAL, if the loaded data is invalid, or if decompression failed
        @throws std::runtime_error if I/O operations failed
        */
        inline std::streamoff load(const SEAL_BYTE *in, std::size_t size)
        {
            using namespace std::placeholders;
            return Serialization::Load(std::bind(&Modulus::load_members, this, _1), in, size);
        }

    private:
        void set_value(std::uint64_t value);

        void save_members(std::ostream &stream) const;

        void load_members(std::istream &stream);

        std::uint64_t value_ = 0;

        std::array<std::uint64_t, 3> const_ratio_{ { 0, 0, 0 } };

        std::size_t uint64_count_ = 0;

        int bit_count_ = 0;

        bool is_prime_ = false;
    };

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
        SEAL_NODISCARD static constexpr int MaxBitCount(
            std::size_t poly_modulus_degree, sec_level_type sec_level = sec_level_type::tc128) noexcept
        {
            switch (sec_level)
            {
            case sec_level_type::tc128:
                return util::SEAL_HE_STD_PARMS_128_TC(poly_modulus_degree);

            case sec_level_type::tc192:
                return util::SEAL_HE_STD_PARMS_192_TC(poly_modulus_degree);

            case sec_level_type::tc256:
                return util::SEAL_HE_STD_PARMS_256_TC(poly_modulus_degree);

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
        SEAL_NODISCARD static std::vector<Modulus> BFVDefault(
            std::size_t poly_modulus_degree, sec_level_type sec_level = sec_level_type::tc128);

        /**
        Returns a custom coefficient modulus suitable for use with the specified
        poly_modulus_degree. The return value will be a vector consisting of
        Modulus elements representing distinct prime numbers of bit-lengths
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
        SEAL_NODISCARD static std::vector<Modulus> Create(std::size_t poly_modulus_degree, std::vector<int> bit_sizes);
    };

    /**
    This class contains static methods for creating a plaintext modulus easily.
    */
    class PlainModulus
    {
    public:
        PlainModulus() = delete;

        /**
        Creates a prime number Modulus for use as plain_modulus encryption
        parameter that supports batching with a given poly_modulus_degree.

        @param[in] poly_modulus_degree The value of the poly_modulus_degree
        encryption parameter
        @param[in] bit_size The bit-length of the prime to be generated
        @throws std::invalid_argument if poly_modulus_degree is not a power-of-two
        or is too large
        @throws std::invalid_argument if bit_size is out of bounds
        @throws std::logic_error if a suitable prime could not be found
        */
        SEAL_NODISCARD static inline Modulus Batching(std::size_t poly_modulus_degree, int bit_size)
        {
            return CoeffModulus::Create(poly_modulus_degree, { bit_size })[0];
        }

        /**
        Creates several prime number Modulus elements that can be used as
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
        SEAL_NODISCARD static inline std::vector<Modulus> Batching(
            std::size_t poly_modulus_degree, std::vector<int> bit_sizes)
        {
            return CoeffModulus::Create(poly_modulus_degree, bit_sizes);
        }
    };
} // namespace seal
