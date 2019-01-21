// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#pragma once

#include <iostream>
#include <vector>
#include <numeric>
#include "seal/ciphertext.h"
#include "seal/memorymanager.h"
#include "seal/encryptionparams.h"

namespace seal
{
    /**
    Class to store Galois keys.

    @par Slot Rotations
    Galois keys are used together with batching (BatchEncoder). If the polynomial modulus
    is a polynomial of degree N, in batching the idea is to view a plaintext polynomial as
    a 2-by-(N/2) matrix of integers modulo plaintext modulus. Normal homomorphic computations
    operate on such encrypted matrices element (slot) wise. However, special rotation
    operations allow us to also rotate the matrix rows cyclically in either direction, and 
    rotate the columns (swap the rows). These operations require the Galois keys.

    @par Decomposition Bit Count
    Decomposition bit count (dbc) is a parameter that describes a performance trade-off in
    the rotation operation. Its function is exactly the same as in relinearization. Namely, 
    the polynomials in the ciphertexts (with large coefficients) get decomposed into a smaller
    base 2^dbc, coefficient-wise. Each of the decomposition factors corresponds to a piece of 
    data in the Galois keys, so the smaller the dbc is, the larger the Galois keys are. 
    Moreover, a smaller dbc results in less invariant noise budget being consumed in the
    rotation operation. However, using a large dbc is much faster, and often one would want 
    to optimize the dbc to be as large as possible for performance. The dbc is upper-bounded 
    by the value of 60, and lower-bounded by the value of 1.

    @par Thread Safety
    In general, reading from GaloisKeys is thread-safe as long as no other thread is 
    concurrently mutating it. This is due to the underlying data structure storing the
    Galois keys not being thread-safe.

    @see SecretKey for the class that stores the secret key.
    @see PublicKey for the class that stores the public key.
    @see RelinKeys for the class that stores the relinearization keys.
    @see KeyGenerator for the class that generates the Galois keys.
    */
    class GaloisKeys
    {
        friend class KeyGenerator;

    public:
        /**
        Creates an empty set of Galois keys.
        */
        GaloisKeys() = default;

        /**
        Creates a new GaloisKeys instance by copying a given instance.

        @param[in] copy The GaloisKeys to copy from
        */
        GaloisKeys(const GaloisKeys &copy) = default;

        /**
        Creates a new GaloisKeys instance by moving a given instance.

        @param[in] source The GaloisKeys to move from
        */
        GaloisKeys(GaloisKeys &&source) = default;

        /**
        Copies a given GaloisKeys instance to the current one.

        @param[in] assign The GaloisKeys to copy from
        */
        GaloisKeys &operator =(const GaloisKeys &assign);

        /**
        Moves a given GaloisKeys instance to the current one.

        @param[in] assign The GaloisKeys to move from
        */
        GaloisKeys &operator =(GaloisKeys &&assign) = default;

        /**
        Returns the current number of Galois keys.
        */
        inline std::size_t size() const
        {
            return std::accumulate(keys_.begin(), keys_.end(), std::size_t(0),
                [](std::size_t current_size, const std::vector<Ciphertext> &next_key)
            {
                return current_size + static_cast<std::size_t>(next_key.size() > 0);
            });
        }

        /*
        Returns the decomposition bit count.
        */
        inline int decomposition_bit_count() const noexcept
        {
            return decomposition_bit_count_;
        }

        /**
        Returns a reference to the Galois keys data.
        */
        inline auto &data() noexcept
        {
            return keys_;
        }

        /**
        Returns a const reference to the Galois keys data.
        */
        inline auto &data() const noexcept
        {
            return keys_;
        }

        /**
        Returns a const reference to a Galois key. The returned Galois key corresponds 
        to the given Galois element.

        @param[in] galois_elt The Galois element
        @throw std::invalid_argument if the key corresponding to galois_elt does not exist
        */
        inline auto &key(std::uint64_t galois_elt) const
        {            
            if (!has_key(galois_elt))
            {
                throw std::invalid_argument("requested key does not exist");
            }
            std::uint64_t index = (galois_elt - 1) >> 1;
            return keys_[index];
        }

        /**
        Returns whether a Galois key corresponding to a given Galois element exists.

        @param[in] galois_elt The Galois element
        @throw std::invalid_argument if Galois element is not valid
        */
        inline bool has_key(std::uint64_t galois_elt) const
        {
            // Verify parameters
            if (!(galois_elt & 1))
            {
                throw std::invalid_argument("galois element is not valid");
            }
            std::uint64_t index = (galois_elt - 1) >> 1;
            return (index < keys_.size()) && !keys_[index].empty();
        }

        /**
        Returns a reference to parms_id.

        @see EncryptionParameters for more information about parms_id.
        */
        inline auto &parms_id() noexcept
        {
            return parms_id_;
        }

        /**
        Returns a const reference to parms_id.

        @see EncryptionParameters for more information about parms_id.
        */
        inline auto &parms_id() const noexcept
        {
            return parms_id_;
        }

        /**
        Check whether the current GaloisKeys is valid for a given SEALContext. If 
        the given SEALContext is not set, the encryption parameters are invalid, 
        or the GaloisKeys data does not match the SEALContext, this function returns 
        false. Otherwise, returns true.

        @param[in] context The SEALContext
        */
        bool is_valid_for(std::shared_ptr<const SEALContext> context) const noexcept;

        /**
        Check whether the current GaloisKeys is valid for a given SEALContext. If 
        the given SEALContext is not set, the encryption parameters are invalid, 
        or the GaloisKeys data does not match the SEALContext, this function returns 
        false. Otherwise, returns true. This function only checks the metadata
        and not the Galois key data itself.

        @param[in] context The SEALContext
        */
        bool is_metadata_valid_for(std::shared_ptr<const SEALContext> context) const noexcept;

        /**
        Saves the GaloisKeys instance to an output stream. The output is in binary 
        format and not human-readable. The output stream must have the "binary" 
        flag set.

        @param[in] stream The stream to save the GaloisKeys to
        @throws std::exception if the GaloisKeys could not be written to stream
        */
        void save(std::ostream &stream) const;

        /**
        Loads a GaloisKeys from an input stream overwriting the current GaloisKeys.
        No checking of the validity of the GaloisKeys data against encryption
        parameters is performed. This function should not be used unless the 
        GaloisKeys comes from a fully trusted source.

        @param[in] stream The stream to load the GaloisKeys from
        @throws std::exception if a valid GaloisKeys could not be read from stream
        */
        void unsafe_load(std::istream &stream);

        /**
        Loads a GaloisKeys from an input stream overwriting the current GaloisKeys.
        The loaded GaloisKeys is verified to be valid for the given SEALContext.

        @param[in] context The SEALContext
        @param[in] stream The stream to load the GaloisKeys from
        @throws std::invalid_argument if the context is not set or encryption
        parameters are not valid
        @throws std::exception if a valid GaloisKeys could not be read from stream
        @throws std::invalid_argument if the loaded GaloisKeys is invalid for the
        context
        */
        inline void load(std::shared_ptr<SEALContext> context, std::istream &stream)
        {
            unsafe_load(stream);
            if (!is_valid_for(std::move(context)))
            {
                throw std::invalid_argument("GaloisKeys data is invalid");
            }
        }

        /**
        Returns the currently used MemoryPoolHandle.
        */
        inline MemoryPoolHandle pool() const noexcept
        {
            return pool_;
        }

        /**
        Enables access to private members of seal::GaloisKeys for .NET wrapper.
        */
        struct GaloisKeysPrivateHelper;

    private:
        MemoryPoolHandle pool_ = MemoryManager::GetPool();

        parms_id_type parms_id_ = parms_id_zero;

        /**
        The vector of Galois keys.
        */
        std::vector<std::vector<Ciphertext>> keys_{};

        int decomposition_bit_count_ = 0;
    };
}
