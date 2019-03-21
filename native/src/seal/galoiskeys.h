// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#pragma once

#include <iostream>
#include <vector>
#include <numeric>
#include "seal/ciphertext.h"
#include "seal/memorymanager.h"
#include "seal/encryptionparams.h"
#include "seal/kswitchkeys.h"

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

    @par Thread Safety
    In general, reading from GaloisKeys is thread-safe as long as no other thread is 
    concurrently mutating it. This is due to the underlying data structure storing the
    Galois keys not being thread-safe.

    @see SecretKey for the class that stores the secret key.
    @see PublicKey for the class that stores the public key.
    @see RelinKeys for the class that stores the relinearization keys.
    @see KeyGenerator for the class that generates the Galois keys.
    */
    class GaloisKeys : public KSwitchKeys
    {
    public:
        /**
        Returns a const reference to a Galois key. The returned Galois key corresponds 
        to the given Galois element.

        @param[in] galois_elt The Galois element
        @throw std::invalid_argument if the key corresponding to galois_elt does not exist
        */
        inline static std::size_t get_index(std::size_t galois_elt)
        {
            return (galois_elt - 1) >> 1;
        }
        inline auto &key(std::uint64_t galois_elt) const
        {            
            if (!has_key(galois_elt))
            {
                throw std::invalid_argument("requested key does not exist");
            }
            return keys_[get_index(galois_elt)];
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
            auto index = get_index(galois_elt);
            return index < keys_.size() && !keys_[index].empty();
        }
    };
}
