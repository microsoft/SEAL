// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#pragma once

#include <iostream>
#include <vector>
#include <limits>
#include "seal/publickey.h"
#include "seal/memorymanager.h"
#include "seal/encryptionparams.h"
#include "seal/valcheck.h"

namespace seal
{
    /**
    Class to store keyswitching keys. It should never be necessary for normal
    users to create an instance of KSwitchKeys. This class is used strictly as
    a base class for RelinKeys and GaloisKeys classes.

    @par Keyswitching
    Concretely, keyswitching is used to change a ciphertext encrypted with one
    key to be encrypted with another key. It is a general technique and is used
    in relinearization and Galois rotations. A keyswitching key contains a sequence
    (vector) of keys. In RelinKeys, each key is an encryption of a power of the
    secret key. In GaloisKeys, each key corresponds to a type of rotation.

    @par Thread Safety
    In general, reading from KSwitchKeys is thread-safe as long as no
    other thread is concurrently mutating it. This is due to the underlying
    data structure storing the keyswitching keys not being thread-safe.

    @see RelinKeys for the class that stores the relinearization keys.
    @see GaloisKeys for the class that stores the Galois keys.
    */
    class KSwitchKeys
    {
        friend class KeyGenerator;
        friend class RelinKeys;
        friend class GaloisKeys;

    public:
        /**
        Creates an empty KSwitchKeys.
        */
        KSwitchKeys() = default;

        /**
        Creates a new KSwitchKeys instance by copying a given instance.

        @param[in] copy The KSwitchKeys to copy from
        */
        KSwitchKeys(const KSwitchKeys &copy) = default;

        /**
        Creates a new KSwitchKeys instance by moving a given instance.

        @param[in] source The RelinKeys to move from
        */
        KSwitchKeys(KSwitchKeys &&source) = default;

        /**
        Copies a given KSwitchKeys instance to the current one.

        @param[in] assign The KSwitchKeys to copy from
        */
        KSwitchKeys &operator =(const KSwitchKeys &assign);

        /**
        Moves a given KSwitchKeys instance to the current one.

        @param[in] assign The KSwitchKeys to move from
        */
        KSwitchKeys &operator =(KSwitchKeys &&assign) = default;

        /**
        Returns the current number of keyswitching keys. Only keys that are
        non-empty are counted.
        */
        inline std::size_t size() const noexcept
        {
            return std::accumulate(keys_.cbegin(), keys_.cend(), std::size_t(0),
                [](std::size_t res, auto &next_key)
                {
                    return res + (next_key.empty() ? 0 : 1);
                });
        }

        /**
        Returns a reference to the KSwitchKeys data.
        */
        inline auto &data() noexcept
        {
            return keys_;
        }

        /**
        Returns a const reference to the KSwitchKeys data.
        */
        inline auto &data() const noexcept
        {
            return keys_;
        }

        /**
        Returns a reference to a keyswitching key at a given index.

        @param[in] index The index of the keyswitching key
        @throws std::invalid_argument if the key at the given index does not exist
        */
        inline auto &data(std::size_t index)
        {
            if (index >= keys_.size() || keys_[index].empty())
            {
                throw std::invalid_argument("keyswitching key does not exist");
            }
            return keys_[index];
        }

        /**
        Returns a const reference to a keyswitching key at a given index.

        @param[in] index The index of the keyswitching key
        @throws std::invalid_argument if the key at the given index does not exist
        */
        inline const auto &data(std::size_t index) const
        {
            if (index >= keys_.size() || keys_[index].empty())
            {
                throw std::invalid_argument("keyswitching key does not exist");
            }
            return keys_[index];
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
        Saves the KSwitchKeys instance to an output stream. The output is
        in binary format and not human-readable. The output stream must have
        the "binary" flag set.

        @param[in] stream The stream to save the KSwitchKeys to
        @throws std::exception if the KSwitchKeys could not be written to stream
        */
        void save(std::ostream &stream) const;

        /**
        Loads a KSwitchKeys from an input stream overwriting the current KSwitchKeys.
        No checking of the validity of the KSwitchKeys data against encryption
        parameters is performed. This function should not be used unless the
        KSwitchKeys comes from a fully trusted source.

        @param[in] stream The stream to load the KSwitchKeys from
        @throws std::exception if a valid KSwitchKeys could not be read from stream
        */
        void unsafe_load(std::istream &stream);

        /**
        Loads a KSwitchKeys from an input stream overwriting the current KSwitchKeys.
        The loaded KSwitchKeys is verified to be valid for the given SEALContext.

        @param[in] context The SEALContext
        @param[in] stream The stream to load the KSwitchKeys from
        @throws std::invalid_argument if the context is not set or encryption
        parameters are not valid
        @throws std::exception if a valid KSwitchKeys could not be read from stream
        @throws std::invalid_argument if the loaded KSwitchKeys is invalid for the
        context
        */
        inline void load(std::shared_ptr<SEALContext> context,
            std::istream &stream)
        {
            KSwitchKeys new_keys;
            new_keys.pool_ = pool_;
            new_keys.unsafe_load(stream);
            if (!is_valid_for(new_keys, std::move(context)))
            {
                throw std::invalid_argument("KSwitchKeys data is invalid");
            }
            std::swap(*this, new_keys);
        }

        /**
        Returns the currently used MemoryPoolHandle.
        */
        inline MemoryPoolHandle pool() const noexcept
        {
            return pool_;
        }

    private:
        MemoryPoolHandle pool_ = MemoryManager::GetPool();

        parms_id_type parms_id_ = parms_id_zero;

        /**
        The vector of keyswitching keys.
        */
        std::vector<std::vector<PublicKey>> keys_{};
    };
}