// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#pragma once

#include <iostream>
#include <memory>
#include "seal/ciphertext.h"
#include "seal/context.h"

namespace seal
{
    /**
    Class to store a public key.

    @par Thread Safety
    In general, reading from PublicKey is thread-safe as long as no other thread
    is concurrently mutating it. This is due to the underlying data structure 
    storing the public key not being thread-safe.

    @see KeyGenerator for the class that generates the public key.
    @see SecretKey for the class that stores the secret key.
    @see RelinKeys for the class that stores the relinearization keys.
    @see GaloisKeys for the class that stores the Galois keys.
    */
    class PublicKey
    {
        friend class KeyGenerator;

    public:
        /**
        Creates an empty public key.
        */
        PublicKey() = default;

        /**
        Creates a new PublicKey by copying an old one.

        @param[in] copy The PublicKey to copy from
        */
        PublicKey(const PublicKey &copy) = default;

        /**
        Creates a new PublicKey by moving an old one.

        @param[in] source The PublicKey to move from
        */
        PublicKey(PublicKey &&source) = default;

        /**
        Copies an old PublicKey to the current one.

        @param[in] assign The PublicKey to copy from
        */
        PublicKey &operator =(const PublicKey &assign) = default;

        /**
        Moves an old PublicKey to the current one.

        @param[in] assign The PublicKey to move from
        */
        PublicKey &operator =(PublicKey &&assign) = default;

        /**
        Returns a reference to the underlying data.
        */
        inline auto &data() noexcept
        {
            return pk_;
        }

        /**
        Returns a const reference to the underlying data.
        */
        inline auto &data() const noexcept
        {
            return pk_;
        }

        /**
        Check whether the current PublicKey is valid for a given SEALContext. If 
        the given SEALContext is not set, the encryption parameters are invalid, 
        or the PublicKey data does not match the SEALContext, this function returns 
        false. Otherwise, returns true.

        @param[in] context The SEALContext
        */
        inline bool is_valid_for(std::shared_ptr<SEALContext> context) const noexcept
        {
            // Verify parameters
            if (!context || !context->parameters_set())
            {
                return false;
            }
            auto parms_id = context->first_parms_id();
            return pk_.is_valid_for(std::move(context)) && 
                pk_.is_ntt_form() && pk_.parms_id() == parms_id;
        }

        /**
        Saves the PublicKey to an output stream. The output is in binary format
        and not human-readable. The output stream must have the "binary" flag set.

        @param[in] stream The stream to save the PublicKey to
        @throws std::exception if the PublicKey could not be written to stream
        */
        inline void save(std::ostream &stream) const
        {
            pk_.save(stream);
        }

        /**
        Loads a PublicKey from an input stream overwriting the current PublicKey.
        No checking of the validity of the PublicKey data against encryption
        parameters is performed. This function should not be used unless the 
        PublicKey comes from a fully trusted source.

        @param[in] stream The stream to load the PublicKey from
        @throws std::exception if a valid PublicKey could not be read from stream
        */
        inline void unsafe_load(std::istream &stream)
        {
            pk_.unsafe_load(stream);
        }

        /**
        Loads a PublicKey from an input stream overwriting the current PublicKey.
        The loaded PublicKey is verified to be valid for the given SEALContext.

        @param[in] context The SEALContext
        @param[in] stream The stream to load the PublicKey from
        @throws std::invalid_argument if the context is not set or encryption
        parameters are not valid
        @throws std::exception if a valid PublicKey could not be read from stream
        @throws std::invalid_argument if the loaded PublicKey is invalid for the
        context
        */
        inline void load(std::shared_ptr<SEALContext> context,
            std::istream &stream)
        {
            unsafe_load(stream);
            if (!is_valid_for(std::move(context)))
            {
                throw std::invalid_argument("PublicKey data is invalid");
            }
        }

        /**
        Returns a reference to parms_id.
        */
        inline auto &parms_id() noexcept
        {
            return pk_.parms_id();
        }

        /**
        Returns a const reference to parms_id.
        */
        inline auto &parms_id() const noexcept
        {
            return pk_.parms_id();
        }

        /**
        Returns the currently used MemoryPoolHandle.
        */
        inline MemoryPoolHandle pool() const noexcept
        {
            return pk_.pool();
        }

    private:
        Ciphertext pk_;
    };
}
