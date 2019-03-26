// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#pragma once

#include <iostream>
#include <vector>
#include <limits>
#include "seal/ciphertext.h"
#include "seal/memorymanager.h"
#include "seal/encryptionparams.h"
#include "seal/kswitchkeys.h"

namespace seal
{
    /**
    Class to store relinearization keys.

    @par Relinearization
    Concretely, an relinearization key corresponding to a power K of the secret
    key can be used in the relinearization operation to change a ciphertext of size
    K+1 to size K. Recall that the smallest possible size for a ciphertext is 2,
    so the first relinearization key is corresponds to the square of the secret
    key. The second relinearization key corresponds to the cube of the secret key,
    and so on. For example, to relinearize a ciphertext of size 7 back to size 2,
    one would need 5 relinearization keys, although it is hard to imagine a situation
    where it makes sense to have size 7 ciphertexts, as operating on such objects
    would be very slow. Most commonly only one relinearization key is needed, and
    relinearization is performed after every multiplication.

    @par Thread Safety
    In general, reading from RelinKeys is thread-safe as long as no other thread
    is concurrently mutating it. This is due to the underlying data structure
    storing the relinearization keys not being thread-safe.

    @see SecretKey for the class that stores the secret key.
    @see PublicKey for the class that stores the public key.
    @see GaloisKeys for the class that stores the Galois keys.
    @see KeyGenerator for the class that generates the relinearization keys.
    */
    class RelinKeys : public KSwitchKeys
    {
    public:
        /**
        Returns a const reference to an relinearization key. The returned
        relinearization key corresponds to the given power of the secret key.

        @param[in] key_power The power of the secret key
        @throws std::invalid_argument if the key corresponding to key_power does
        not exist
        */
        inline static std::size_t get_index(std::size_t key_power)
        {
            return key_power - 2;
        }

        /**
        Returns a const reference to an relinearization key. The returned
        relinearization key corresponds to the given power of the secret key.

        @param[in] key_power The power of the secret key
        @throws std::invalid_argument if the key corresponding to key_power does not exist
        */
        inline auto &key(std::size_t key_power) const
        {
            if (!has_key(key_power))
            {
                throw std::invalid_argument("requested key does not exist");
            }
            return keys_[get_index(key_power)];
        }

        /**
        Returns whether an relinearization key corresponding to a given power of
        the secret key exists.

        @param[in] key_power The power of the secret key
        */
        inline bool has_key(std::size_t key_power) const noexcept
        {
            return (key_power >= 2) && (keys_.size() >= key_power - 1);
        }
    };
}
