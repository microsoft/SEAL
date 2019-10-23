// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#pragma once

#include <vector>
#include <memory>
#include "seal/util/defines.h"
#include "seal/encryptionparams.h"
#include "seal/plaintext.h"
#include "seal/ciphertext.h"
#include "seal/memorymanager.h"
#include "seal/context.h"
#include "seal/publickey.h"
#include "seal/secretkey.h"
#include "seal/util/smallntt.h"

namespace seal
{
    /**
    Encrypts Plaintext objects into Ciphertext objects. Constructing an Encryptor
    requires a SEALContext with valid encryption parameters, the public key and/or
    the secret key. If an Encrytor is given a secret key, it supports symmetric-key
    encryption. If an Encryptor is given a public key, it supports asymmetric-key
    encryption.

    @par Overloads
    For the encrypt function we provide two overloads concerning the memory pool
    used in allocations needed during the operation. In one overload the global
    memory pool is used for this purpose, and in another overload the user can
    supply a MemoryPoolHandle to to be used instead. This is to allow one single
    Encryptor to be used concurrently by several threads without running into thread
    contention in allocations taking place during operations. For example, one can
    share one single Encryptor across any number of threads, but in each thread
    call the encrypt function by giving it a thread-local MemoryPoolHandle to use.
    It is important for a developer to understand how this works to avoid unnecessary
    performance bottlenecks.

    @par NTT form
    When using the BFV scheme (scheme_type::BFV), all plaintext and ciphertexts should
    remain by default in the usual coefficient representation, i.e. not in NTT form.
    When using the CKKS scheme (scheme_type::CKKS), all plaintexts and ciphertexts
    should remain by default in NTT form. We call these scheme-specific NTT states
    the "default NTT form". Decryption requires the input ciphertexts to be in
    the default NTT form, and will throw an exception if this is not the case.
    */
    class Encryptor
    {
    public:
        /**
        Creates an Encryptor instance initialized with the specified SEALContext
        and public key.

        @param[in] context The SEALContext
        @param[in] public_key The public key
        @throws std::invalid_argument if the context is not set or encryption
        parameters are not valid
        @throws std::invalid_argument if public_key is not valid
        */
        Encryptor(std::shared_ptr<SEALContext> context, const PublicKey &public_key);

        /**
        Creates an Encryptor instance initialized with the specified SEALContext
        and secret key.

        @param[in] context The SEALContext
        @param[in] secret_key The secret key
        @throws std::invalid_argument if the context is not set or encryption
        parameters are not valid
        @throws std::invalid_argument if secret_key is not valid
        */
        Encryptor(std::shared_ptr<SEALContext> context, const SecretKey &secret_key);

        /**
        Creates an Encryptor instance initialized with the specified SEALContext,
        secret key, and public key.

        @param[in] context The SEALContext
        @param[in] public_key The public key
        @param[in] secret_key The secret key
        @throws std::invalid_argument if the context is not set or encryption
        parameters are not valid
        @throws std::invalid_argument if public_key or secret_key is not valid
        */
        Encryptor(std::shared_ptr<SEALContext> context, const PublicKey &public_key,
            const SecretKey &secret_key);

        /**
        Give a new instance of public key.

        @param[in] public_key The public key
        @throws std::invalid_argument if public_key is not valid
        */
        inline void set_public_key(const PublicKey &public_key)
        {
            if (!is_valid_for(public_key, context_))
            {
                throw std::invalid_argument("public key is not valid for encryption parameters");
            }
            public_key_ = public_key;
        }

        /**
        Give a new instance of secret key.

        @param[in] secret_key The secret key
        @throws std::invalid_argument if secret_key is not valid
        */
        inline void set_secret_key(const SecretKey &secret_key)
        {
            if (!is_valid_for(secret_key, context_))
            {
                throw std::invalid_argument("secret key is not valid for encryption parameters");
            }
            secret_key_ = secret_key;
        }

        /**
        Encrypts a plaintext with the public key and stores the result in
        destination. The encryption parameters for the resulting ciphertext
        correspond to:
        1) in BFV, the highest (data) level in the modulus switching chain,
        2) in CKKS, the encryption parameters of the plaintext.
        Dynamic memory allocations in the process are allocated from the memory
        pool pointed to by the given MemoryPoolHandle.

        @param[in] plain The plaintext to encrypt
        @param[out] destination The ciphertext to overwrite with the encrypted
        plaintext
        @param[in] pool The MemoryPoolHandle pointing to a valid memory pool
        @throws std::logic_error if a public key is not set
        @throws std::invalid_argument if plain is not valid for the encryption
        parameters
        @throws std::invalid_argument if plain is not in default NTT form
        @throws std::invalid_argument if pool is uninitialized
        */
        inline void encrypt(const Plaintext &plain, Ciphertext &destination,
            MemoryPoolHandle pool = MemoryManager::GetPool()) const
        {
            encrypt_internal(plain, true, false, destination, pool);
        }

        /**
        Encrypts a zero plaintext with the public key and stores the result in
        destination. The encryption parameters for the resulting ciphertext
        correspond to the highest (data) level in the modulus switching chain.
        Dynamic memory allocations in the process are allocated from the memory
        pool pointed to by the given MemoryPoolHandle.

        @param[out] destination The ciphertext to overwrite with the encrypted
        plaintext
        @param[in] pool The MemoryPoolHandle pointing to a valid memory pool
        @throws std::logic_error if a public key is not set
        @throws std::invalid_argument if pool is uninitialized
        */
        inline void encrypt_zero(Ciphertext &destination,
            MemoryPoolHandle pool = MemoryManager::GetPool()) const
        {
            encrypt_zero(context_->first_parms_id(), destination, pool);
        }

        /**
        Encrypts a zero plaintext with the public key and stores the result in
        destination. The encryption parameters for the resulting ciphertext
        correspond to the given parms_id. Dynamic memory allocations in the process
        are allocated from the memory pool pointed to by the given MemoryPoolHandle.

        @param[in] parms_id The parms_id for the resulting ciphertext
        @param[out] destination The ciphertext to overwrite with the encrypted
        plaintext
        @param[in] pool The MemoryPoolHandle pointing to a valid memory pool
        @throws std::logic_error if a public key is not set
        @throws std::invalid_argument if parms_id is not valid for the encryption
        parameters
        @throws std::invalid_argument if pool is uninitialized
        */
        inline void encrypt_zero(parms_id_type parms_id, Ciphertext &destination,
            MemoryPoolHandle pool = MemoryManager::GetPool()) const
        {
            encrypt_zero_internal(parms_id, true, false, destination, pool);
        }

        /**
        Encrypts a plaintext with the secret key and stores the result in
        destination. The encryption parameters for the resulting ciphertext
        correspond to:
        1) in BFV, the highest (data) level in the modulus switching chain,
        2) in CKKS, the encryption parameters of the plaintext.
        Dynamic memory allocations in the process are allocated from the memory
        pool pointed to by the given MemoryPoolHandle.

        @param[in] plain The plaintext to encrypt
        @param[out] destination The ciphertext to overwrite with the encrypted
        plaintext
        @param[in] pool The MemoryPoolHandle pointing to a valid memory pool
        @throws std::logic_error if a secret key is not set
        @throws std::invalid_argument if plain is not valid for the encryption
        parameters
        @throws std::invalid_argument if plain is not in default NTT form
        @throws std::invalid_argument if pool is uninitialized
        */
        inline void encrypt_symmetric(const Plaintext &plain,
            Ciphertext &destination,
            MemoryPoolHandle pool = MemoryManager::GetPool()) const
        {
            encrypt_internal(plain, false, false, destination, pool);
        }

        /**
        Encrypts a zero plaintext with the secret key and stores the result in
        destination. The encryption parameters for the resulting ciphertext
        correspond to the highest (data) level in the modulus switching chain.
        Dynamic memory allocations in the process are allocated from the memory
        pool pointed to by the given MemoryPoolHandle.

        @param[out] destination The ciphertext to overwrite with the encrypted
        plaintext
        @param[in] pool The MemoryPoolHandle pointing to a valid memory pool
        @throws std::logic_error if a secret key is not set
        @throws std::invalid_argument if pool is uninitialized
        */
        inline void encrypt_zero_symmetric(Ciphertext &destination,
            MemoryPoolHandle pool = MemoryManager::GetPool()) const
        {
            encrypt_zero_symmetric(
                context_->first_parms_id(),
                destination, pool);
        }

        /**
        Encrypts a zero plaintext with the secret key and stores the result in
        destination. The encryption parameters for the resulting ciphertext
        correspond to the given parms_id. Dynamic memory allocations in the process
        are allocated from the memory pool pointed to by the given MemoryPoolHandle.

        @param[in] parms_id The parms_id for the resulting ciphertext
        @param[out] destination The ciphertext to overwrite with the encrypted
        plaintext
        @param[in] pool The MemoryPoolHandle pointing to a valid memory pool
        @throws std::logic_error if a secret key is not set
        @throws std::invalid_argument if parms_id is not valid for the encryption
        parameters
        @throws std::invalid_argument if pool is uninitialized
        */
        inline void encrypt_zero_symmetric(parms_id_type parms_id,
            Ciphertext &destination,
            MemoryPoolHandle pool = MemoryManager::GetPool()) const
        {
            encrypt_zero_internal(parms_id, false, false, destination, pool);
        }

        /**
        Encrypts a plaintext with the secret key and saves result to an output
        stream. The encryption parameters for the resulting ciphertext correspond
        to:
        1) in BFV, the highest (data) level in the modulus switching chain,
        2) in CKKS, the encryption parameters of the plaintext.
        Dynamic memory allocations in the process are allocated from the memory
        pool pointed to by the given MemoryPoolHandle.

        Half of the polynomials in Galois keys are randomly generated and are
        replaced with the seed used to compress output size. The output stream
        must have the "binary" flag set. The output is in binary format and not
        human-readable.

        @param[in] plain The plaintext to encrypt
        @param[out] stream The stream to save the result to
        @param[in] compr_mode The desired compression mode
        @param[in] pool The MemoryPoolHandle pointing to a valid memory pool
        @throws std::logic_error if a secret key is not set
        @throws std::logic_error if compression mode is not supported, or if
        compression failed
        @throws std::runtime_error if I/O operations failed
        @throws std::invalid_argument if plain is not valid for the encryption
        parameters
        @throws std::invalid_argument if plain is not in default NTT form
        @throws std::invalid_argument if pool is uninitialized
        */
        inline std::streamoff encrypt_symmetric_save(
            const Plaintext &plain,
            std::ostream &stream,
            compr_mode_type compr_mode = Serialization::compr_mode_default,
            MemoryPoolHandle pool = MemoryManager::GetPool()) const
        {
            Ciphertext destination;
            encrypt_internal(plain, false, true, destination, pool);
            return destination.save(stream, compr_mode);
        }

        /**
        Encrypts a zero plaintext with the secret key and saves result to
        an output stream. The encryption parameters for the resulting ciphertext
        correspond to the highest (data) level in the modulus switching chain.
        Dynamic memory allocations in the process are allocated from the memory
        pool pointed to by the given MemoryPoolHandle.

        Half of the polynomials in Galois keys are randomly generated and are
        replaced with the seed used to compress output size. The output stream
        must have the "binary" flag set. The output is in binary format and not
        human-readable.

        @param[out] stream The stream to save the result to
        @param[in] compr_mode The desired compression mode
        @param[in] pool The MemoryPoolHandle pointing to a valid memory pool
        @throws std::logic_error if a secret key is not set
        @throws std::logic_error if compression mode is not supported, or if
        compression failed
        @throws std::runtime_error if I/O operations failed
        @throws std::invalid_argument if pool is uninitialized
        */
        inline std::streamoff encrypt_zero_symmetric_save(
            std::ostream &stream,
            compr_mode_type compr_mode = Serialization::compr_mode_default,
            MemoryPoolHandle pool = MemoryManager::GetPool()) const
        {
            return encrypt_zero_symmetric_save(
                context_->first_parms_id(), stream, compr_mode, pool);
        }

        /**
        Encrypts a zero plaintext with the secret key and saves result to
        an output stream. The encryption parameters for the resulting ciphertext
        correspond to the given parms_id. Dynamic memory allocations in the
        process are allocated from the memory pool pointed to by the given
        MemoryPoolHandle.

        Half of the polynomials in Galois keys are randomly generated and are
        replaced with the seed used to compress output size. The output stream
        must have the "binary" flag set. The output is in binary format and not
        human-readable.

        @param[in] parms_id The parms_id for the resulting ciphertext
        @param[out] stream The stream to save the result to
        @param[in] compr_mode The desired compression mode
        @param[in] pool The MemoryPoolHandle pointing to a valid memory pool
        @throws std::logic_error if a secret key is not set
        @throws std::logic_error if compression mode is not supported, or if
        compression failed
        @throws std::runtime_error if I/O operations failed
        @throws std::invalid_argument if parms_id is not valid for the encryption
        parameters
        @throws std::invalid_argument if pool is uninitialized
        */
        inline std::streamoff encrypt_zero_symmetric_save(
            parms_id_type parms_id,
            std::ostream &stream,
            compr_mode_type compr_mode = Serialization::compr_mode_default,
            MemoryPoolHandle pool = MemoryManager::GetPool()) const
        {
            Ciphertext destination;
            encrypt_zero_internal(parms_id, false, true, destination, pool);
            return destination.save(stream, compr_mode);
        }

        /**
        Encrypts a zero plaintext with the secret key and saves result to a given
        memory location. The encryption parameters for the resulting ciphertext
        correspond to:
        1) in BFV, the highest (data) level in the modulus switching chain,
        2) in CKKS, the encryption parameters of the plaintext.
        Dynamic memory allocations in the process are allocated from the memory
        pool pointed to by the given MemoryPoolHandle.

        The second polynomial in result is randomly generated and are replaced
        with the seed used to compress output size. The output is in binary format
        and not human-readable.

        @param[in] plain The plaintext to encrypt
        @param[out] out The memory location to write the ciphertext to
        @param[in] size The number of bytes available in the given memory location
        @param[in] compr_mode The desired compression mode
        @param[in] pool The MemoryPoolHandle pointing to a valid memory pool
        @throws std::logic_error if a secret key is not set
        @throws std::invalid_argument if out is null or if size is too small to
        contain a SEALHeader
        @throws std::logic_error if compression mode is not supported, or if
        compression failed
        @throws std::runtime_error if I/O operations failed
        @throws std::invalid_argument if plain is not valid for the encryption
        parameters
        @throws std::invalid_argument if plain is not in default NTT form
        @throws std::invalid_argument if pool is uninitialized
        */
        inline std::streamoff encrypt_symmetric_save(
            const Plaintext &plain,
            SEAL_BYTE *out,
            std::size_t size,
            compr_mode_type compr_mode = Serialization::compr_mode_default,
            MemoryPoolHandle pool = MemoryManager::GetPool()) const
        {
            Ciphertext destination;
            encrypt_internal(plain, false, true, destination, pool);
            return destination.save(out, size, compr_mode);
        }

        /**
        Encrypts a zero plaintext with the secret key and saves result to a given
        memory location. The encryption parameters for the resulting ciphertext
        correspond to the highest (data) level in the modulus switching chain.
        Dynamic memory allocations in the process are allocated from the memory
        pool pointed to by the given MemoryPoolHandle.

        The second polynomial in result is randomly generated and are replaced
        with the seed used to compress output size. The output is in binary format
        and not human-readable.

        @param[out] out The memory location to write the ciphertext to
        @param[in] size The number of bytes available in the given memory location
        @param[in] compr_mode The desired compression mode
        @param[in] pool The MemoryPoolHandle pointing to a valid memory pool
        @throws std::logic_error if a secret key is not set
        @throws std::invalid_argument if out is null or if size is too small to
        contain a SEALHeader
        @throws std::logic_error if compression mode is not supported, or if
        compression failed
        @throws std::runtime_error if I/O operations failed
        @throws std::invalid_argument if pool is uninitialized
        */
        inline std::streamoff encrypt_zero_symmetric_save(
            SEAL_BYTE *out,
            std::size_t size,
            compr_mode_type compr_mode = Serialization::compr_mode_default,
            MemoryPoolHandle pool = MemoryManager::GetPool()) const
        {
            return encrypt_zero_symmetric_save(
                context_->first_parms_id(), out, size, compr_mode, pool);
        }

        /**
        Encrypts a zero plaintext with the secret key and saves result to a given
        memory location. The encryption parameters for the resulting ciphertext
        correspond to the given parms_id. Dynamic memory allocations in the process
        are allocated from the memory pool pointed to by the given MemoryPoolHandle.

        The second polynomial in result is randomly generated and are replaced
        with the seed used to compress output size. The output is in binary format
        and not human-readable.

        @param[in] parms_id The parms_id for the resulting ciphertext
        @param[out] out The memory location to write the ciphertext to
        @param[in] size The number of bytes available in the given memory location
        @param[in] compr_mode The desired compression mode
        @param[in] pool The MemoryPoolHandle pointing to a valid memory pool
        @throws std::logic_error if a secret key is not set
        @throws std::invalid_argument if out is null or if size is too small to
        contain a SEALHeader
        @throws std::logic_error if the data to be saved is invalid, if compression
        mode is not supported, or if compression failed
        @throws std::runtime_error if I/O operations failed
        @throws std::invalid_argument if parms_id is not valid for the encryption
        parameters
        @throws std::invalid_argument if pool is uninitialized
        */
        inline std::streamoff encrypt_zero_symmetric_save(
            parms_id_type parms_id,
            SEAL_BYTE *out,
            std::size_t size,
            compr_mode_type compr_mode = Serialization::compr_mode_default,
            MemoryPoolHandle pool = MemoryManager::GetPool()) const
        {
            Ciphertext destination;
            encrypt_zero_internal(parms_id, false, true, destination, pool);
            return destination.save(out, size, compr_mode);
        }

        /**
        Enables access to private members of seal::Encryptor for .NET wrapper.
        */
        struct EncryptorPrivateHelper;

    private:
        Encryptor(const Encryptor &copy) = delete;

        Encryptor(Encryptor &&source) = delete;

        Encryptor &operator =(const Encryptor &assign) = delete;

        Encryptor &operator =(Encryptor &&assign) = delete;

        MemoryPoolHandle pool_ = MemoryManager::GetPool(mm_prof_opt::FORCE_NEW, true);

        void encrypt_zero_internal(
            parms_id_type parms_id,
            bool is_asymmetric, bool save_seed,
            Ciphertext &destination,
            MemoryPoolHandle pool = MemoryManager::GetPool()) const;

        void encrypt_internal(
            const Plaintext &plain,
            bool is_asymmetric, bool save_seed,
            Ciphertext &destination,
            MemoryPoolHandle pool = MemoryManager::GetPool()) const;

        std::shared_ptr<SEALContext> context_{ nullptr };

        PublicKey public_key_;

        SecretKey secret_key_;
    };
}
