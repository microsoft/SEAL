// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#pragma once

#include "seal/ciphertext.h"
#include "seal/context.h"
#include "seal/valcheck.h"
#include <iostream>
#include <memory>

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
        friend class KSwitchKeys;

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
        PublicKey &operator=(const PublicKey &assign) = default;

        /**
        Moves an old PublicKey to the current one.

        @param[in] assign The PublicKey to move from
        */
        PublicKey &operator=(PublicKey &&assign) = default;

        /**
        Returns a reference to the underlying data.
        */
        SEAL_NODISCARD inline auto &data() noexcept
        {
            return pk_;
        }

        /**
        Returns a const reference to the underlying data.
        */
        SEAL_NODISCARD inline auto &data() const noexcept
        {
            return pk_;
        }

        /**
        Returns an upper bound on the size of the PublicKey, as if it was written
        to an output stream.

        @param[in] compr_mode The compression mode
        @throws std::invalid_argument if the compression mode is not supported
        @throws std::logic_error if the size does not fit in the return type
        */
        SEAL_NODISCARD inline std::streamoff save_size(
            compr_mode_type compr_mode = Serialization::compr_mode_default) const
        {
            return pk_.save_size(compr_mode);
        }

        /**
        Saves the PublicKey to an output stream. The output is in binary format
        and not human-readable. The output stream must have the "binary" flag set.

        @param[out] stream The stream to save the PublicKey to
        @param[in] compr_mode The desired compression mode
        @throws std::invalid_argument if the compression mode is not supported
        @throws std::logic_error if the data to be saved is invalid, or if
        compression failed
        @throws std::runtime_error if I/O operations failed
        */
        inline std::streamoff save(
            std::ostream &stream, compr_mode_type compr_mode = Serialization::compr_mode_default) const
        {
            return pk_.save(stream, compr_mode);
        }

        /**
        Loads a PublicKey from an input stream overwriting the current PublicKey.
        No checking of the validity of the PublicKey data against encryption
        parameters is performed. This function should not be used unless the
        PublicKey comes from a fully trusted source.

        @param[in] context The SEALContext
        @param[in] stream The stream to load the PublicKey from
        @throws std::invalid_argument if the context is not set or encryption
        parameters are not valid
        @throws std::logic_error if the data cannot be loaded by this version of
        Microsoft SEAL, if the loaded data is invalid, or if decompression failed
        @throws std::runtime_error if I/O operations failed
        */
        inline std::streamoff unsafe_load(std::shared_ptr<SEALContext> context, std::istream &stream)
        {
            Ciphertext new_pk(pk_.pool());
            auto in_size = new_pk.unsafe_load(std::move(context), stream);
            std::swap(pk_, new_pk);
            return in_size;
        }

        /**
        Loads a PublicKey from an input stream overwriting the current PublicKey.
        The loaded PublicKey is verified to be valid for the given SEALContext.

        @param[in] context The SEALContext
        @param[in] stream The stream to load the PublicKey from
        @throws std::invalid_argument if the context is not set or encryption
        parameters are not valid
        @throws std::logic_error if the data cannot be loaded by this version of
        Microsoft SEAL, if the loaded data is invalid, or if decompression failed
        @throws std::runtime_error if I/O operations failed
        */
        inline std::streamoff load(std::shared_ptr<SEALContext> context, std::istream &stream)
        {
            PublicKey new_pk(pool());
            auto in_size = new_pk.unsafe_load(context, stream);
            if (!is_valid_for(new_pk, std::move(context)))
            {
                throw std::logic_error("PublicKey data is invalid");
            }
            std::swap(*this, new_pk);
            return in_size;
        }

        /**
        Saves the PublicKey to a given memory location. The output is in binary
        format and is not human-readable.

        @param[out] out The memory location to write the PublicKey to
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
            return pk_.save(out, size, compr_mode);
        }

        /**
        Loads a PublicKey from a given memory location overwriting the current
        PublicKey. No checking of the validity of the PublicKey data against
        encryption parameters is performed. This function should not be used
        unless the PublicKey comes from a fully trusted source.

        @param[in] context The SEALContext
        @param[in] in The memory location to load the PublicKey from
        @param[in] size The number of bytes available in the given memory location
        @throws std::invalid_argument if the context is not set or encryption
        parameters are not valid
        @throws std::invalid_argument if in is null or if size is too small to
        contain a SEALHeader
        @throws std::logic_error if the data cannot be loaded by this version of
        Microsoft SEAL, if the loaded data is invalid, or if decompression failed
        @throws std::runtime_error if I/O operations failed
        */
        inline std::streamoff unsafe_load(std::shared_ptr<SEALContext> context, const SEAL_BYTE *in, std::size_t size)
        {
            Ciphertext new_pk(pk_.pool());
            auto in_size = new_pk.unsafe_load(std::move(context), in, size);
            std::swap(pk_, new_pk);
            return in_size;
        }

        /**
        Loads a PublicKey from a given memory location overwriting the current
        PublicKey. The loaded PublicKey is verified to be valid for the given
        SEALContext.

        @param[in] context The SEALContext
        @param[in] in The memory location to load the PublicKey from
        @param[in] size The number of bytes available in the given memory location
        @throws std::invalid_argument if the context is not set or encryption
        parameters are not valid
        @throws std::invalid_argument if in is null or if size is too small to
        contain a SEALHeader
        @throws std::logic_error if the data cannot be loaded by this version of
        Microsoft SEAL, if the loaded data is invalid, or if decompression failed
        @throws std::runtime_error if I/O operations failed
        */
        inline std::streamoff load(std::shared_ptr<SEALContext> context, const SEAL_BYTE *in, std::size_t size)
        {
            PublicKey new_pk(pool());
            auto in_size = new_pk.unsafe_load(context, in, size);
            if (!is_valid_for(new_pk, std::move(context)))
            {
                throw std::logic_error("PublicKey data is invalid");
            }
            std::swap(*this, new_pk);
            return in_size;
        }

        /**
        Returns a reference to parms_id.
        */
        SEAL_NODISCARD inline auto &parms_id() noexcept
        {
            return pk_.parms_id();
        }

        /**
        Returns a const reference to parms_id.
        */
        SEAL_NODISCARD inline auto &parms_id() const noexcept
        {
            return pk_.parms_id();
        }

        /**
        Returns the currently used MemoryPoolHandle.
        */
        SEAL_NODISCARD inline MemoryPoolHandle pool() const noexcept
        {
            return pk_.pool();
        }

        /**
        Enables access to private members of seal::PublicKey for SEAL_C.
        */
        struct PublicKeyPrivateHelper;

    private:
        /**
        Creates an empty public key. This is needed for loading KSwitchKeys with
        the keys residing in a single memory pool.

        @param[in] pool The MemoryPoolHandle pointing to a valid memory pool
        @throws std::invalid_argument if pool is uninitialized
        */
        PublicKey(MemoryPoolHandle pool) : pk_(std::move(pool))
        {}

        Ciphertext pk_;
    };
} // namespace seal
