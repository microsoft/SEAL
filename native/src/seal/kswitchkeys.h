// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#pragma once

#include <iostream>
#include <vector>
#include <limits>
#include "seal/ciphertext.h"
#include "seal/memorymanager.h"
#include "seal/encryptionparams.h"

namespace seal
{
    /**
    Class to store keyswitching keys. It should never be necessary for normal
    users to create an instance of this class. It is used strictly as a base
    class for RelinKeys and GaloisKeys classes.

    @par Keyswitching
    Concretely, keyswitching is used to change a ciphertext encrypted
    with one key to be encrypted with another key. It is a general technique
    and is used in relinearization and galois rotation. A keyswitching key 
    can contain a sequence (vector) of keys. In RelinKeys, each key is an 
    encryption of a power of secret key. In GaloisKeys, each key corresponds
    to a type of rotation.

    @par Thread Safety
    In general, reading from KSwitchKeys is thread-safe as long as no
    other thread is concurrently mutating it. This is due to the underlying
    data structure storing the keyswitching keys not being thread-safe.

    @see SecretKey for the class that stores the secret key.
    @see PublicKey for the class that stores the public key.
    @see RelinKeys for the class that stores the relinearization keys.
    @see GaloisKeys for the class that stores the Galois keys.
    @see KeyGenerator for the class that generates the keyswitching keys.
    */
    class KSwitchKeys
    {
        friend class KeyGenerator;
        friend class RelinKeys;
        friend class GaloisKeys;

    public:
        /**
        Creates an empty set of keyswitching keys.
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
        Returns the current number of keyswitching keys.
        */
        inline std::size_t size() const
        {
            return keys_.size();
        }

        /**
        Returns a reference to the keyswitching keys data.
        */
        inline auto &data() noexcept
        {
            return keys_;
        }

        /**
        Returns a const reference to the keyswitching keys data.
        */
        inline auto &data() const noexcept
        {
            return keys_;
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
        Check whether the current KSwitchKeys is valid for a given
        SEALContext. If the given SEALContext is not set, the encryption
        parameters are invalid, or the KSwitchKeys data does not match the
        SEALContext, this function returns false. Otherwise, returns true.

        @param[in] context The SEALContext
        */
        bool is_valid_for(std::shared_ptr<const SEALContext> context) const noexcept;

        /**
        Check whether the current KSwitchKeys is valid for a given
        SEALContext. If the given SEALContext is not set, the encryption
        parameters are invalid, or the KSwitchKeys data does not match the
        SEALContext, this function returns false. Otherwise, returns true. This
        function only checks the metadata and not the keyswitching key data
        itself.

        @param[in] context The SEALContext
        */
        bool is_metadata_valid_for(std::shared_ptr<const SEALContext> context) const noexcept;

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
            unsafe_load(stream);
            if (!is_valid_for(std::move(context)))
            {
                throw std::invalid_argument("KSwitchKeys data is invalid");
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
        Enables access to private members of seal::KSwitchKeys for .NET wrapper.
        */
        struct KSwitchKeysPrivateHelper;

    private:
        MemoryPoolHandle pool_ = MemoryManager::GetPool();

        parms_id_type parms_id_ = parms_id_zero;

        /**
        The vector of keyswitching keys.
        */
        std::vector<std::vector<Ciphertext>> keys_{};
    };
}
