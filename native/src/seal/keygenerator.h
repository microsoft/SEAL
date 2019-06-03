// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#pragma once

#include <memory>
#include <random>
#include "seal/context.h"
#include "seal/util/smallntt.h"
#include "seal/memorymanager.h"
#include "seal/publickey.h"
#include "seal/secretkey.h"
#include "seal/relinkeys.h"
#include "seal/galoiskeys.h"
#include "seal/randomgen.h"

namespace seal
{
    /**
    Generates matching secret key and public key. An existing KeyGenerator can
    also at any time be used to generate relinearization keys and Galois keys.
    Constructing a KeyGenerator requires only a SEALContext.

    @see EncryptionParameters for more details on encryption parameters.
    @see SecretKey for more details on secret key.
    @see PublicKey for more details on public key.
    @see RelinKeys for more details on relinearization keys.
    @see GaloisKeys for more details on Galois keys.
    */
    class KeyGenerator
    {
    public:
        /**
        Creates a KeyGenerator initialized with the specified SEALContext.

        @param[in] context The SEALContext
        @throws std::invalid_argument if the context is not set or encryption
        parameters are not valid
        */
        KeyGenerator(std::shared_ptr<SEALContext> context);

        /**
        Creates an KeyGenerator instance initialized with the specified SEALContext
        and specified previously secret key. This can e.g. be used to increase
        the number of relinearization keys from what had earlier been generated,
        or to generate Galois keys in case they had not been generated earlier.


        @param[in] context The SEALContext
        @param[in] secret_key A previously generated secret key
        @throws std::invalid_argument if encryption parameters are not valid
        @throws std::invalid_argument if secret_key or public_key is not valid
        for encryption parameters
        */
        KeyGenerator(std::shared_ptr<SEALContext> context,
            const SecretKey &secret_key);

        /**
        Creates an KeyGenerator instance initialized with the specified SEALContext
        and specified previously secret and public keys. This can e.g. be used
        to increase the number of relinearization keys from what had earlier been
        generated, or to generate Galois keys in case they had not been generated
        earlier.

        @param[in] context The SEALContext
        @param[in] secret_key A previously generated secret key
        @param[in] public_key A previously generated public key
        @throws std::invalid_argument if encryption parameters are not valid
        @throws std::invalid_argument if secret_key or public_key is not valid
        for encryption parameters
        */
        KeyGenerator(std::shared_ptr<SEALContext> context,
            const SecretKey &secret_key, const PublicKey &public_key);

        /**
        Returns a const reference to the secret key.
        */
        const SecretKey &secret_key() const;

        /**
        Returns a const reference to the public key.
        */
        const PublicKey &public_key() const;

        /**
        Generates and returns relinearization keys.
        */
        inline RelinKeys relin_keys()
        {
            return relin_keys(1);
        }

        /**
        Generates and returns Galois keys. This function creates specific Galois
        keys that can be used to apply specific Galois automorphisms on encrypted
        data. The user needs to give as input a vector of Galois elements
        corresponding to the keys that are to be created.

        The Galois elements are odd integers in the interval [1, M-1], where
        M = 2*N, and N = degree(poly_modulus). Used with batching, a Galois element
        3^i % M corresponds to a cyclic row rotation i steps to the left, and
        a Galois element 3^(N/2-i) % M corresponds to a cyclic row rotation i
        steps to the right. The Galois element M-1 corresponds to a column rotation
        (row swap) in BFV, and complex conjugation in CKKS. In the polynomial view
        (not batching), a Galois automorphism by a Galois element p changes Enc(plain(x))
        to Enc(plain(x^p)).

        @param[in] galois_elts The Galois elements for which to generate keys
        @throws std::invalid_argument if the Galois elements are not valid
        */
        GaloisKeys galois_keys(const std::vector<std::uint64_t> &galois_elts);

        /**
        Generates and returns Galois keys. This function creates specific Galois
        keys that can be used to apply specific Galois automorphisms on encrypted
        data. The user needs to give as input a vector of desired Galois rotation
        step counts, where negative step counts correspond to rotations to the
        right and positive step counts correspond to rotations to the left.
        A step count of zero can be used to indicate a column rotation in the BFV
        scheme complex conjugation in the CKKS scheme.

        @param[in] galois_elts The rotation step counts for which to generate keys
        @throws std::logic_error if the encryption parameters do not support batching
        and scheme is scheme_type::BFV
        @throws std::invalid_argument if the step counts are not valid
        */
        GaloisKeys galois_keys(const std::vector<int> &steps);

        /**
        Generates and returns Galois keys. This function creates logarithmically
        many (in degree of the polynomial modulus) Galois keys that is sufficient
        to apply any Galois automorphism (e.g. rotations) on encrypted data. Most
        users will want to use this overload of the function.
        */
        GaloisKeys galois_keys();

    private:
        KeyGenerator(const KeyGenerator &copy) = delete;

        KeyGenerator &operator =(const KeyGenerator &assign) = delete;

        KeyGenerator(KeyGenerator &&source) = delete;

        KeyGenerator &operator =(KeyGenerator &&assign) = delete;

        void compute_secret_key_array(
            const SEALContext::ContextData &context_data,
            std::size_t max_power);

        /**
        Generates new secret key.

        @param[in] is_initialized True if the secret_key_ has already been initialized so that only the
         secret_key_array_ should be initialized (it may be the case, for instance, if the secret_key_
         was provided in the constructor
        */
        void generate_sk(bool is_initialized = false);

        /**
        Generates new public key matching to existing secret key.
        */
        void generate_pk();

        /**
        Generates new key switching keys for an array of new keys.
        */
        void generate_kswitch_keys(
            const std::uint64_t *new_keys,
            std::size_t num_keys,
            KSwitchKeys &destination);

        /**
        Generates one key switching key for a new key.
        */
        void generate_one_kswitch_key(
            const uint64_t *new_key,
            std::vector<PublicKey> &destination);

        /**
        Generates and returns the specified number of relinearization keys.

        @param[in] count The number of relinearization keys to generate
        @throws std::invalid_argument if count is zero or too large
        */
        RelinKeys relin_keys(std::size_t count);

        // We use a fresh memory pool with `clear_on_destruction' enabled.
        MemoryPoolHandle pool_ = MemoryManager::GetPool(mm_prof_opt::FORCE_NEW, true);

        std::shared_ptr<SEALContext> context_{ nullptr };

        PublicKey public_key_;

        SecretKey secret_key_;

        std::size_t secret_key_array_size_ = 0;

        util::Pointer<std::uint64_t> secret_key_array_;

        mutable util::ReaderWriterLocker secret_key_array_locker_;

        bool sk_generated_ = false;

        bool pk_generated_ = false;
    };
}
