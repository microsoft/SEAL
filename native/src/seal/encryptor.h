// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#pragma once

#include <vector>
#include <memory>
#include "seal/encryptionparams.h"
#include "seal/plaintext.h"
#include "seal/ciphertext.h"
#include "seal/memorymanager.h"
#include "seal/context.h"
#include "seal/publickey.h"
#include "seal/util/smallntt.h"

namespace seal
{
    /**
    Encrypts Plaintext objects into Ciphertext objects. Constructing an Encryptor
    requires a SEALContext with valid encryption parameters, and the public key.

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
        Encrypts a plaintext and stores the result in the destination parameter.
        Dynamic memory allocations in the process are allocated from the memory
        pool pointed to by the given MemoryPoolHandle.

        @param[in] plain The plaintext to encrypt
        @param[out] destination The ciphertext to overwrite with the encrypted plaintext
        @param[in] pool The MemoryPoolHandle pointing to a valid memory pool
        @throws std::invalid_argument if plain is not valid for the encryption parameters
        @throws std::invalid_argument if plain is not in default NTT form
        @throws std::invalid_argument if pool is uninitialized
        */
        void encrypt(const Plaintext &plain, Ciphertext &destination,
            MemoryPoolHandle pool = MemoryManager::GetPool());

        /**
        Encrypts a zero plaintext and stores the result in the destination parameter.
        The encryption parameters for the resulting ciphertext correspond to the given
        parms_id. Dynamic memory allocations in the process are allocated from the memory
        pool pointed to by the given MemoryPoolHandle.

        @param[in] parms_id The parms_id for the resulting ciphertext
        @param[out] destination The ciphertext to overwrite with the encrypted plaintext
        @param[in] pool The MemoryPoolHandle pointing to a valid memory pool
        @throws std::invalid_argument if parms_id is not valid for the encryption parameters
        @throws std::invalid_argument if pool is uninitialized
        */
        void encrypt_zero(
            parms_id_type parms_id,
            Ciphertext &destination,
            MemoryPoolHandle pool = MemoryManager::GetPool());

        /**
        Encrypts a zero plaintext and stores the result in the destination parameter.
        The encryption parameters for the resulting ciphertext correspond to the
        highest (data) level in the modulus switching chain. Dynamic memory allocations
        in the process are allocated from the memory pool pointed to by the given
        MemoryPoolHandle.

        @param[out] destination The ciphertext to overwrite with the encrypted plaintext
        @param[in] pool The MemoryPoolHandle pointing to a valid memory pool
        @throws std::invalid_argument if pool is uninitialized
        */
        inline void encrypt_zero(Ciphertext &destination,
            MemoryPoolHandle pool = MemoryManager::GetPool())
        {
            encrypt_zero(context_->first_parms_id(), destination, pool);
        }

    private:
        Encryptor(const Encryptor &copy) = delete;

        Encryptor(Encryptor &&source) = delete;

        Encryptor &operator =(const Encryptor &assign) = delete;

        Encryptor &operator =(Encryptor &&assign) = delete;

        void preencrypt(const std::uint64_t *plain, std::size_t plain_coeff_count,
            const SEALContext::ContextData &context_data, std::uint64_t *destination);

        MemoryPoolHandle pool_ = MemoryManager::GetPool();

        std::shared_ptr<SEALContext> context_{ nullptr };

        PublicKey public_key_;
    };
}
