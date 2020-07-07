// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#pragma once

#include "seal/ciphertext.h"
#include "seal/context.h"
#include "seal/encryptionparams.h"
#include "seal/memorymanager.h"
#include "seal/plaintext.h"
#include "seal/publickey.h"
#include "seal/secretkey.h"
#include "seal/serializable.h"
#include "seal/util/defines.h"
#include "seal/util/ntt.h"
#include <memory>
#include <vector>

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
        Encryptor(std::shared_ptr<SEALContext> context, const PublicKey &public_key, const SecretKey &secret_key);

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
        destination.

        The encryption parameters for the resulting ciphertext correspond to:
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
        inline void encrypt(
            const Plaintext &plain, Ciphertext &destination, MemoryPoolHandle pool = MemoryManager::GetPool()) const
        {
            encrypt_internal(plain, true, false, destination, pool);
        }

        /**
        Encrypts a zero plaintext with the public key and stores the result in
        destination.

        The encryption parameters for the resulting ciphertext correspond to the
        highest (data) level in the modulus switching chain. Dynamic memory
        allocations in the process are allocated from the memory pool pointed to
        by the given MemoryPoolHandle.

        @param[out] destination The ciphertext to overwrite with the encrypted
        plaintext
        @param[in] pool The MemoryPoolHandle pointing to a valid memory pool
        @throws std::logic_error if a public key is not set
        @throws std::invalid_argument if pool is uninitialized
        */
        inline void encrypt_zero(Ciphertext &destination, MemoryPoolHandle pool = MemoryManager::GetPool()) const
        {
            encrypt_zero(context_->first_parms_id(), destination, pool);
        }

        /**
        Encrypts a zero plaintext with the public key and stores the result in
        destination.

        The encryption parameters for the resulting ciphertext correspond to the
        given parms_id. Dynamic memory allocations in the process are allocated
        from the memory pool pointed to by the given MemoryPoolHandle.

        @param[in] parms_id The parms_id for the resulting ciphertext
        @param[out] destination The ciphertext to overwrite with the encrypted
        plaintext
        @param[in] pool The MemoryPoolHandle pointing to a valid memory pool
        @throws std::logic_error if a public key is not set
        @throws std::invalid_argument if parms_id is not valid for the encryption
        parameters
        @throws std::invalid_argument if pool is uninitialized
        */
        inline void encrypt_zero(
            parms_id_type parms_id, Ciphertext &destination, MemoryPoolHandle pool = MemoryManager::GetPool()) const
        {
            encrypt_zero_internal(parms_id, true, false, destination, pool);
        }

        /**
        Encrypts a plaintext with the secret key and stores the result in
        destination.

        The encryption parameters for the resulting ciphertext correspond to:
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
        inline void encrypt_symmetric(
            const Plaintext &plain, Ciphertext &destination, MemoryPoolHandle pool = MemoryManager::GetPool()) const
        {
            encrypt_internal(plain, false, false, destination, pool);
        }

        /**
        Encrypts a zero plaintext with the secret key and stores the result in
        destination.

        The encryption parameters for the resulting ciphertext correspond to the
        highest (data) level in the modulus switching chain. Dynamic memory
        allocations in the process are allocated from the memory pool pointed to
        by the given MemoryPoolHandle.

        @param[out] destination The ciphertext to overwrite with the encrypted
        plaintext
        @param[in] pool The MemoryPoolHandle pointing to a valid memory pool
        @throws std::logic_error if a secret key is not set
        @throws std::invalid_argument if pool is uninitialized
        */
        inline void encrypt_zero_symmetric(
            Ciphertext &destination, MemoryPoolHandle pool = MemoryManager::GetPool()) const
        {
            encrypt_zero_symmetric(context_->first_parms_id(), destination, pool);
        }

        /**
        Encrypts a zero plaintext with the secret key and stores the result in
        destination.

        The encryption parameters for the resulting ciphertext correspond to the
        given parms_id. Dynamic memory allocations in the process are allocated
        from the memory pool pointed to by the given MemoryPoolHandle.

        @param[in] parms_id The parms_id for the resulting ciphertext
        @param[out] destination The ciphertext to overwrite with the encrypted
        plaintext
        @param[in] pool The MemoryPoolHandle pointing to a valid memory pool
        @throws std::logic_error if a secret key is not set
        @throws std::invalid_argument if parms_id is not valid for the encryption
        parameters
        @throws std::invalid_argument if pool is uninitialized
        */
        inline void encrypt_zero_symmetric(
            parms_id_type parms_id, Ciphertext &destination, MemoryPoolHandle pool = MemoryManager::GetPool()) const
        {
            encrypt_zero_internal(parms_id, false, false, destination, pool);
        }

        /**
        Encrypts a plaintext with the secret key and returns the ciphertext as
        a serializable object.

        The encryption parameters for the resulting ciphertext correspond to:
        1) in BFV, the highest (data) level in the modulus switching chain,
        2) in CKKS, the encryption parameters of the plaintext.
        Dynamic memory allocations in the process are allocated from the memory
        pool pointed to by the given MemoryPoolHandle.

        Half of the ciphertext data is pseudo-randomly generated from a seed to
        reduce the object size. The resulting serializable object cannot be used
        directly and is meant to be serialized for the size reduction to have an
        impact.

        @param[in] plain The plaintext to encrypt
        @param[in] pool The MemoryPoolHandle pointing to a valid memory pool
        @throws std::logic_error if a secret key is not set
        @throws std::invalid_argument if plain is not valid for the encryption
        parameters
        @throws std::invalid_argument if plain is not in default NTT form
        @throws std::invalid_argument if pool is uninitialized
        */
        SEAL_NODISCARD inline Serializable<Ciphertext> encrypt_symmetric(
            const Plaintext &plain, MemoryPoolHandle pool = MemoryManager::GetPool()) const
        {
            Ciphertext destination;
            encrypt_internal(plain, false, true, destination, pool);
            return destination;
        }

        /**
        Encrypts a zero plaintext with the secret key and returns the ciphertext
        as a serializable object.

        The encryption parameters for the resulting ciphertext correspond to the
        given parms_id. Dynamic memory allocations in the process are allocated
        from the memory pool pointed to by the given MemoryPoolHandle.

        Half of the ciphertext data is pseudo-randomly generated from a seed to
        reduce the object size. The resulting serializable object cannot be used
        directly and is meant to be serialized for the size reduction to have an
        impact.

        @param[in] parms_id The parms_id for the resulting ciphertext
        @param[in] pool The MemoryPoolHandle pointing to a valid memory pool
        @throws std::logic_error if a secret key is not set
        @throws std::invalid_argument if parms_id is not valid for the encryption
        parameters
        @throws std::invalid_argument if pool is uninitialized
        */
        SEAL_NODISCARD inline Serializable<Ciphertext> encrypt_zero_symmetric(
            parms_id_type parms_id, MemoryPoolHandle pool = MemoryManager::GetPool()) const
        {
            Ciphertext destination;
            encrypt_zero_internal(parms_id, false, true, destination, pool);
            return destination;
        }

        /**
        Encrypts a zero plaintext with the secret key and returns the ciphertext
        as a serializable object.

        The encryption parameters for the resulting ciphertext correspond to the
        highest (data) level in the modulus switching chain. Dynamic memory
        allocations in the process are allocated from the memory pool pointed to
        by the given MemoryPoolHandle.

        Half of the ciphertext data is pseudo-randomly generated from a seed to
        reduce the object size. The resulting serializable object cannot be used
        directly and is meant to be serialized for the size reduction to have an
        impact.

        @param[in] pool The MemoryPoolHandle pointing to a valid memory pool
        @throws std::logic_error if a secret key is not set
        @throws std::invalid_argument if pool is uninitialized
        */
        SEAL_NODISCARD inline Serializable<Ciphertext> encrypt_zero_symmetric(
            MemoryPoolHandle pool = MemoryManager::GetPool()) const
        {
            return encrypt_zero_symmetric(context_->first_parms_id(), pool);
        }

        /**
        Enables access to private members of seal::Encryptor for SEAL_C.
        */
        struct EncryptorPrivateHelper;

    private:
        Encryptor(const Encryptor &copy) = delete;

        Encryptor(Encryptor &&source) = delete;

        Encryptor &operator=(const Encryptor &assign) = delete;

        Encryptor &operator=(Encryptor &&assign) = delete;

        MemoryPoolHandle pool_ = MemoryManager::GetPool(mm_prof_opt::FORCE_NEW, true);

        void encrypt_zero_internal(
            parms_id_type parms_id, bool is_asymmetric, bool save_seed, Ciphertext &destination,
            MemoryPoolHandle pool = MemoryManager::GetPool()) const;

        void encrypt_internal(
            const Plaintext &plain, bool is_asymmetric, bool save_seed, Ciphertext &destination,
            MemoryPoolHandle pool = MemoryManager::GetPool()) const;

        std::shared_ptr<SEALContext> context_{ nullptr };

        PublicKey public_key_;

        SecretKey secret_key_;
    };
} // namespace seal
