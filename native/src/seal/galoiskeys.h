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
#include "seal/util/common.h"

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
        Returns the index of a Galois key in the backing KSwitchKeys instance that
        corresponds to the given Galois element, assuming that it exists in the
        backing KSwitchKeys.

        @param[in] galois_elt The Galois element
        @throws std::invalid_argument if galois_elt is not valid
        */
        inline static std::size_t get_index(std::uint64_t galois_elt)
        {
            // Verify parameters
            if (!(galois_elt & 1))
            {
                throw std::invalid_argument("galois_elt is not valid");
            }
            return util::safe_cast<std::size_t>((galois_elt - 1) >> 1);
        }

        /**
        Returns whether a Galois key corresponding to a given Galois element exists.

        @param[in] galois_elt The Galois element
        @throws std::invalid_argument if galois_elt is not valid
        */
        inline bool has_key(std::uint64_t galois_elt) const
        {
            std::size_t index = get_index(galois_elt);
            return data().size() > index && !data()[index].empty();
        }

        /**
        Returns a const reference to a Galois key. The returned Galois key corresponds
        to the given Galois element.

        @param[in] galois_elt The Galois element
        @throws std::invalid_argument if the key corresponding to galois_elt does not exist
        */
        inline const auto &key(std::uint64_t galois_elt) const
        {
            return KSwitchKeys::data(get_index(galois_elt));
        }
    };
}
