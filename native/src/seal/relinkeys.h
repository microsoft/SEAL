// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#pragma once

#include "seal/ciphertext.h"
#include "seal/encryptionparams.h"
#include "seal/kswitchkeys.h"
#include "seal/memorymanager.h"
#include "seal/util/defines.h"
#include <iostream>
#include <limits>
#include <vector>

namespace seal
{
    /**
    Class to store relinearization keys.

    @par Relinearization
    Freshly encrypted ciphertexts have a size of 2, and multiplying ciphertexts
    of sizes K and L results in a ciphertext of size K+L-1. Unfortunately, this
    growth in size slows down further multiplications and increases noise growth.
    Relinearization is an operation that has no semantic meaning, but it reduces
    the size of ciphertexts back to 2. Microsoft SEAL can only relinearize size 3
    ciphertexts back to size 2, so if the ciphertexts grow larger than size 3,
    there is no way to reduce their size. Relinearization requires an instance of
    RelinKeys to be created by the secret key owner and to be shared with the
    evaluator. Note that plain multiplication is fundamentally different from
    normal multiplication and does not result in ciphertext size growth.

    @par When to Relinearize
    Typically, one should always relinearize after each multiplications. However,
    in some cases relinearization should be postponed as late as possible due to
    its computational cost. For example, suppose the computation involves several
    homomorphic multiplications followed by a sum of the results. In this case it
    makes sense to not relinearize each product, but instead add them first and
    only then relinearize the sum. This is particularly important when using the
    CKKS scheme, where relinearization is much more computationally costly than
    multiplications and additions.

    @par Thread Safety
    In general, reading from RelinKeys is thread-safe as long as no other thread
    is concurrently mutating it. This is due to the underlying data structure
    storing the relinearization keys not being thread-safe.

    @see GaloisKeys for the class that stores the Galois keys.
    @see KeyGenerator for the class that generates the relinearization keys.
    */
    class RelinKeys : public KSwitchKeys
    {
    public:
        /**
        Returns the index of a relinearization key in the backing KSwitchKeys
        instance that corresponds to the given secret key power, assuming that
        it exists in the backing KSwitchKeys.

        @param[in] key_power The power of the secret key
        @throws std::invalid_argument if key_power is less than 2
        */
        SEAL_NODISCARD inline static std::size_t get_index(std::size_t key_power)
        {
            if (key_power < 2)
            {
                throw std::invalid_argument("key_power cannot be less than 2");
            }
            return key_power - 2;
        }

        /**
        Returns whether a relinearization key corresponding to a given power of
        the secret key exists.

        @param[in] key_power The power of the secret key
        @throws std::invalid_argument if key_power is less than 2
        */
        SEAL_NODISCARD inline bool has_key(std::size_t key_power) const
        {
            std::size_t index = get_index(key_power);
            return data().size() > index && !data()[index].empty();
        }

        /**
        Returns a const reference to a relinearization key. The returned
        relinearization key corresponds to the given power of the secret key.

        @param[in] key_power The power of the secret key
        @throws std::invalid_argument if the key corresponding to key_power does not exist
        */
        SEAL_NODISCARD inline auto &key(std::size_t key_power) const
        {
            return KSwitchKeys::data(get_index(key_power));
        }
    };
} // namespace seal
