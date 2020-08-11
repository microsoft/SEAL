// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#pragma once

#include "seal/memorymanager.h"
#include "seal/plaintext.h"
#include "seal/randomgen.h"
#include "seal/valcheck.h"
#include "seal/util/common.h"
#include "seal/util/defines.h"
#include <cstddef>
#include <cstdint>
#include <iostream>
#include <memory>
#include <random>

namespace seal
{
    /**
    Class to store a secret key.

    @par Thread Safety
    In general, reading from SecretKey is thread-safe as long as no other thread
    is concurrently mutating it. This is due to the underlying data structure
    storing the secret key not being thread-safe.

    @see KeyGenerator for the class that generates the secret key.
    @see PublicKey for the class that stores the public key.
    @see RelinKeys for the class that stores the relinearization keys.
    @see GaloisKeys for the class that stores the Galois keys.
    */
    class SecretKey
    {
        friend class KeyGenerator;

    public:
        /**
        Creates an empty secret key.
        */
        SecretKey() = default;

        /**
        Creates a new SecretKey by copying an old one.

        @param[in] copy The SecretKey to copy from
        */
        SecretKey(const SecretKey &copy)
        {
            // Note: sk_ is at this point initialized to use a custom (new)
            // memory pool with the `clear_on_destruction' property. Now use
            // Plaintext::operator =(const Plaintext &) to copy over the data.
            // This is very important to do right, otherwise newly created
            // SecretKey may use a normal memory pool obtained from
            // MemoryManager::GetPool() with currently active profile (MMProf).
            sk_ = copy.sk_;
        }

        /**
        Destroys the SecretKey object.
        */
        ~SecretKey() = default;

        /**
        Creates a new SecretKey by moving an old one.

        @param[in] source The SecretKey to move from
        */
        SecretKey(SecretKey &&source) = default;

        /**
        Copies an old SecretKey to the current one.

        @param[in] assign The SecretKey to copy from
        */
        SecretKey &operator=(const SecretKey &assign)
        {
            Plaintext new_sk(MemoryManager::GetPool(mm_prof_opt::FORCE_NEW, true));
            new_sk = assign.sk_;
            std::swap(sk_, new_sk);
            return *this;
        }

        /**
        Moves an old SecretKey to the current one.

        @param[in] assign The SecretKey to move from
        */
        SecretKey &operator=(SecretKey &&assign) = default;

        /**
        Returns a reference to the underlying polynomial.
        */
        SEAL_NODISCARD inline auto &data() noexcept
        {
            return sk_;
        }

        /**
        Returns a const reference to the underlying polynomial.
        */
        SEAL_NODISCARD inline auto &data() const noexcept
        {
            return sk_;
        }

        /**
        Returns an upper bound on the size of the SecretKey, as if it was written
        to an output stream.

        @param[in] compr_mode The compression mode
        @throws std::invalid_argument if the compression mode is not supported
        @throws std::logic_error if the size does not fit in the return type
        */
        SEAL_NODISCARD inline std::streamoff save_size(
            compr_mode_type compr_mode = Serialization::compr_mode_default) const
        {
            return sk_.save_size(compr_mode);
        }

        /**
        Saves the SecretKey to an output stream. The output is in binary format
        and not human-readable. The output stream must have the "binary" flag set.

        @param[out] stream The stream to save the SecretKey to
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
                std::bind(&Plaintext::save_members, &sk_, _1), sk_.save_size(compr_mode_type::none), stream, compr_mode,
                /* clear_on_destruction */ true);
        }

        /**
        Loads a SecretKey from an input stream overwriting the current SecretKey.
        No checking of the validity of the SecretKey data against encryption
        parameters is performed. This function should not be used unless the
        SecretKey comes from a fully trusted source.

        @param[in] context The SEALContext
        @param[in] stream The stream to load the SecretKey from
        @throws std::invalid_argument if the context is not set or encryption
        parameters are not valid
        @throws std::logic_error if the data cannot be loaded by this version of
        Microsoft SEAL, if the loaded data is invalid, or if decompression failed
        @throws std::runtime_error if I/O operations failed
        */
        inline std::streamoff unsafe_load(std::shared_ptr<SEALContext> context, std::istream &stream)
        {
            using namespace std::placeholders;

            // We use a fresh memory pool with `clear_on_destruction' enabled.
            Plaintext new_sk(MemoryManager::GetPool(mm_prof_opt::FORCE_NEW, true));
            auto in_size = Serialization::Load(
                std::bind(&Plaintext::load_members, &new_sk, std::move(context), _1), stream,
                /* clear_on_destruction */ true);
            std::swap(sk_, new_sk);
            return in_size;
        }

        /**
        Loads a SecretKey from an input stream overwriting the current SecretKey.
        The loaded SecretKey is verified to be valid for the given SEALContext.

        @param[in] context The SEALContext
        @param[in] stream The stream to load the SecretKey from
        @throws std::invalid_argument if the context is not set or encryption
        parameters are not valid
        @throws std::logic_error if the data cannot be loaded by this version of
        Microsoft SEAL, if the loaded data is invalid, or if decompression failed
        @throws std::runtime_error if I/O operations failed
        */
        inline std::streamoff load(std::shared_ptr<SEALContext> context, std::istream &stream)
        {
            SecretKey new_sk;
            auto in_size = new_sk.unsafe_load(context, stream);
            if (!is_valid_for(new_sk, std::move(context)))
            {
                throw std::logic_error("SecretKey data is invalid");
            }
            std::swap(*this, new_sk);
            return in_size;
        }

        /**
        Saves the SecretKey to a given memory location. The output is in binary
        format and is not human-readable.

        @param[out] out The memory location to write the SecretKey to
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
                std::bind(&Plaintext::save_members, &sk_, _1), sk_.save_size(compr_mode_type::none), out, size,
                compr_mode, /* clear_on_destruction */ true);
        }

        /**
        Loads a SecretKey from a given memory location overwriting the current
        SecretKey. No checking of the validity of the SecretKey data against
        encryption parameters is performed. This function should not be used
        unless the SecretKey comes from a fully trusted source.

        @param[in] context The SEALContext
        @param[in] in The memory location to load the SecretKey from
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
            using namespace std::placeholders;

            // We use a fresh memory pool with `clear_on_destruction' enabled.
            Plaintext new_sk(MemoryManager::GetPool(mm_prof_opt::FORCE_NEW, true));
            auto in_size = Serialization::Load(std::bind(&Plaintext::load_members, &new_sk, std::move(context), _1), in, size);
            std::swap(sk_, new_sk);
            return in_size;
        }

        /**
        Loads a SecretKey from a given memory location overwriting the current
        SecretKey. The loaded SecretKey is verified to be valid for the given
        SEALContext.

        @param[in] context The SEALContext
        @param[in] in The memory location to load the SecretKey from
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
            SecretKey new_sk;
            auto in_size = new_sk.unsafe_load(context, in, size);
            if (!is_valid_for(new_sk, std::move(context)))
            {
                throw std::logic_error("SecretKey data is invalid");
            }
            std::swap(*this, new_sk);
            return in_size;
        }

        /**
        Returns a reference to parms_id.

        @see EncryptionParameters for more information about parms_id.
        */
        SEAL_NODISCARD inline auto &parms_id() noexcept
        {
            return sk_.parms_id();
        }

        /**
        Returns a const reference to parms_id.

        @see EncryptionParameters for more information about parms_id.
        */
        SEAL_NODISCARD inline auto &parms_id() const noexcept
        {
            return sk_.parms_id();
        }

        /**
        Returns the currently used MemoryPoolHandle.
        */
        SEAL_NODISCARD inline MemoryPoolHandle pool() const noexcept
        {
            return sk_.pool();
        }

    private:
        // We use a fresh memory pool with `clear_on_destruction' enabled.
        Plaintext sk_{ MemoryManager::GetPool(mm_prof_opt::FORCE_NEW, true) };
    };
} // namespace seal
