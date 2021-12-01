// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#pragma once

#include "seal/context.h"
#include "seal/galoiskeys.h"
#include "seal/memorymanager.h"
#include "seal/publickey.h"
#include "seal/relinkeys.h"
#include "seal/secretkey.h"
#include "seal/serializable.h"
#include "seal/util/defines.h"
#include "seal/util/iterator.h"
#include <random>

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
        @throws std::invalid_argument if the encryption parameters are not valid
        */
        KeyGenerator(const SEALContext &context);

        /**
        Creates an KeyGenerator instance initialized with the specified SEALContext
        and specified previously secret key. This can e.g. be used to increase
        the number of relinearization keys from what had earlier been generated,
        or to generate Galois keys in case they had not been generated earlier.


        @param[in] context The SEALContext
        @param[in] secret_key A previously generated secret key
        @throws std::invalid_argument if encryption parameters are not valid
        @throws std::invalid_argument if secret_key is not valid for encryption
        parameters
        */
        KeyGenerator(const SEALContext &context, const SecretKey &secret_key);

        /**
        Returns a const reference to the secret key.
        */
        SEAL_NODISCARD const SecretKey &secret_key() const;

        /**
        Generates a public key and stores the result in destination. Every time
        this function is called, a new public key will be generated.

        @param[out] destination The public key to overwrite with the generated
        public key
        */
        inline void create_public_key(PublicKey &destination) const
        {
            destination = generate_pk(false);
        }

        /**
        Generates and returns a public key as a serializable object. Every time
        this function is called, a new public key will be generated.

        Half of the key data is pseudo-randomly generated from a seed to reduce
        the object size. The resulting serializable object cannot be used
        directly and is meant to be serialized for the size reduction to have an
        impact.
        */
        SEAL_NODISCARD inline Serializable<PublicKey> create_public_key() const
        {
            return generate_pk(true);
        }

        /**
        Generates relinearization keys and stores the result in destination.
        Every time this function is called, new relinearization keys will be
        generated.

        @param[out] destination The relinearization keys to overwrite with the
        generated relinearization keys
        @throws std::logic_error if the encryption parameters do not support
        keyswitching
        */
        inline void create_relin_keys(RelinKeys &destination)
        {
            destination = create_relin_keys(1, false);
        }

        /**
        Generates and returns relinearization keys as a serializable object.
        Every time this function is called, new relinearization keys will be
        generated.

        Half of the key data is pseudo-randomly generated from a seed to reduce
        the object size. The resulting serializable object cannot be used
        directly and is meant to be serialized for the size reduction to have an
        impact.

        @throws std::logic_error if the encryption parameters do not support
        keyswitching
        */
        SEAL_NODISCARD inline Serializable<RelinKeys> create_relin_keys()
        {
            return create_relin_keys(1, true);
        }

        /**
        Generates Galois keys and stores the result in destination. Every time
        this function is called, new Galois keys will be generated.

        This function creates specific Galois keys that can be used to apply
        specific Galois automorphisms on encrypted data. The user needs to give
        as input a vector of Galois elements corresponding to the keys that are
        to be created.

        The Galois elements are odd integers in the interval [1, M-1], where
        M = 2*N, and N = poly_modulus_degree. Used with batching, a Galois element
        3^i % M corresponds to a cyclic row rotation i steps to the left, and
        a Galois element 3^(N/2-i) % M corresponds to a cyclic row rotation i
        steps to the right. The Galois element M-1 corresponds to a column rotation
        (row swap) in BFV, and complex conjugation in CKKS. In the polynomial view
        (not batching), a Galois automorphism by a Galois element p changes
        Enc(plain(x)) to Enc(plain(x^p)).

        @param[in] galois_elts The Galois elements for which to generate keys
        @param[out] destination The Galois keys to overwrite with the generated
        Galois keys
        @throws std::logic_error if the encryption parameters do not support
        keyswitching
        @throws std::invalid_argument if the Galois elements are not valid
        */
        inline void create_galois_keys(const std::vector<std::uint32_t> &galois_elts, GaloisKeys &destination)
        {
            destination = create_galois_keys(galois_elts, false);
        }

        /**
        Generates and returns Galois keys as a serializable object. Every time
        this function is called, new Galois keys will be generated.

        Half of the key data is pseudo-randomly generated from a seed to reduce
        the object size. The resulting serializable object cannot be used
        directly and is meant to be serialized for the size reduction to have an
        impact.

        This function creates specific Galois keys that can be used to apply
        specific Galois automorphisms on encrypted data. The user needs to give
        as input a vector of Galois elements corresponding to the keys that are
        to be created.

        The Galois elements are odd integers in the interval [1, M-1], where
        M = 2*N, and N = poly_modulus_degree. Used with batching, a Galois element
        3^i % M corresponds to a cyclic row rotation i steps to the left, and
        a Galois element 3^(N/2-i) % M corresponds to a cyclic row rotation i
        steps to the right. The Galois element M-1 corresponds to a column rotation
        (row swap) in BFV, and complex conjugation in CKKS. In the polynomial view
        (not batching), a Galois automorphism by a Galois element p changes
        Enc(plain(x)) to Enc(plain(x^p)).

        @param[in] galois_elts The Galois elements for which to generate keys
        @throws std::logic_error if the encryption parameters do not support
        keyswitching
        @throws std::invalid_argument if the Galois elements are not valid
        */
        SEAL_NODISCARD inline Serializable<GaloisKeys> create_galois_keys(const std::vector<std::uint32_t> &galois_elts)
        {
            return create_galois_keys(galois_elts, true);
        }

        /**
        Generates Galois keys and stores the result in destination. Every time
        this function is called, new Galois keys will be generated.

        The user needs to give as input a vector of desired Galois rotation step
        counts, where negative step counts correspond to rotations to the right
        and positive step counts correspond to rotations to the left. A step
        count of zero can be used to indicate a column rotation in the BFV scheme
        and complex conjugation in the CKKS scheme.

        @param[in] steps The rotation step counts for which to generate keys
        @param[out] destination The Galois keys to overwrite with the generated
        Galois keys
        @throws std::logic_error if the encryption parameters do not support
        batching and scheme is scheme_type::BFV
        @throws std::logic_error if the encryption parameters do not support
        keyswitching
        @throws std::invalid_argument if the step counts are not valid
        */
        inline void create_galois_keys(const std::vector<int> &steps, GaloisKeys &destination)
        {
            if (!context_.key_context_data()->qualifiers().using_batching)
            {
                throw std::logic_error("encryption parameters do not support batching");
            }
            create_galois_keys(context_.key_context_data()->galois_tool()->get_elts_from_steps(steps), destination);
        }

        /**
        Generates and returns Galois keys as a serializable object. Every time
        this function is called, new Galois keys will be generated.

        Half of the key data is pseudo-randomly generated from a seed to reduce
        the object size. The resulting serializable object cannot be used
        directly and is meant to be serialized for the size reduction to have an
        impact.

        The user needs to give as input a vector of desired Galois rotation step
        counts, where negative step counts correspond to rotations to the right
        and positive step counts correspond to rotations to the left. A step
        count of zero can be used to indicate a column rotation in the BFV scheme
        and complex conjugation in the CKKS scheme.

        @param[in] steps The rotation step counts for which to generate keys
        @throws std::logic_error if the encryption parameters do not support
        batching and scheme is scheme_type::BFV
        @throws std::logic_error if the encryption parameters do not support
        keyswitching
        @throws std::invalid_argument if the step counts are not valid
        */
        SEAL_NODISCARD inline Serializable<GaloisKeys> create_galois_keys(const std::vector<int> &steps)
        {
            if (!context_.key_context_data()->qualifiers().using_batching)
            {
                throw std::logic_error("encryption parameters do not support batching");
            }
            return create_galois_keys(context_.key_context_data()->galois_tool()->get_elts_from_steps(steps));
        }

        /**
        Generates Galois keys and stores the result in destination. Every time
        this function is called, new Galois keys will be generated.

        This function creates logarithmically many (in degree of the polynomial
        modulus) Galois keys that is sufficient to apply any Galois automorphism
        (e.g., rotations) on encrypted data. Most users will want to use this
        overload of the function.

        Precisely it generates 2*log(n)-1 number of Galois keys where n is the
        degree of the polynomial modulus. When used with batching, these keys
        support direct left and right rotations of power-of-2 steps of rows in BFV
        or vectors in CKKS and rotation of columns in BFV or conjugation in CKKS.

        @param[out] destination The Galois keys to overwrite with the generated
        Galois keys
        @throws std::logic_error if the encryption parameters do not support
        keyswitching
        */
        inline void create_galois_keys(GaloisKeys &destination)
        {
            create_galois_keys(context_.key_context_data()->galois_tool()->get_elts_all(), destination);
        }

        /**
        Generates and returns Galois keys as a serializable object. Every time
        this function is called, new Galois keys will be generated.

        Half of the key data is pseudo-randomly generated from a seed to reduce
        the object size. The resulting serializable object cannot be used
        directly and is meant to be serialized for the size reduction to have an
        impact.

        This function creates logarithmically many (in degree of the polynomial
        modulus) Galois keys that is sufficient to apply any Galois automorphism
        (e.g., rotations) on encrypted data. Most users will want to use this
        overload of the function.

        Precisely it generates 2*log(n)-1 number of Galois keys where n is the
        degree of the polynomial modulus. When used with batching, these keys
        support direct left and right rotations of power-of-2 steps of rows in BFV
        or vectors in CKKS and rotation of columns in BFV or conjugation in CKKS.

        @throws std::logic_error if the encryption parameters do not support
        keyswitching
        */
        SEAL_NODISCARD inline Serializable<GaloisKeys> create_galois_keys()
        {
            return create_galois_keys(context_.key_context_data()->galois_tool()->get_elts_all());
        }

        /**
        Enables access to private members of seal::KeyGenerator for SEAL_C.
        */
        struct KeyGeneratorPrivateHelper;

    private:
        KeyGenerator(const KeyGenerator &copy) = delete;

        KeyGenerator &operator=(const KeyGenerator &assign) = delete;

        KeyGenerator(KeyGenerator &&source) = delete;

        KeyGenerator &operator=(KeyGenerator &&assign) = delete;

        void compute_secret_key_array(const SEALContext::ContextData &context_data, std::size_t max_power);

        /**
        Generates new secret key.

        @param[in] is_initialized True if the secret key has already been
        initialized so that only the secret_key_array_ should be initialized, for
        example, if the secret key was provided in the constructor
        */
        void generate_sk(bool is_initialized = false);

        /**
        Generates new public key matching to existing secret key.
        */
        PublicKey generate_pk(bool save_seed) const;

        /**
        Generates new key switching keys for an array of new keys.
        */
        void generate_kswitch_keys(
            util::ConstPolyIter new_keys, std::size_t num_keys, KSwitchKeys &destination, bool save_seed = false);

        /**
        Generates one key switching key for a new key.
        */
        void generate_one_kswitch_key(
            util::ConstRNSIter new_key, std::vector<PublicKey> &destination, bool save_seed = false);

        /**
        Generates and returns the specified number of relinearization keys.

        @param[in] count The number of relinearization keys to generate
        @param[in] save_seed If true, save seed instead of a polynomial.
        @throws std::invalid_argument if count is zero or too large
        */
        RelinKeys create_relin_keys(std::size_t count, bool save_seed);

        /**
        Generates and returns Galois keys. This function creates specific Galois
        keys that can be used to apply specific Galois automorphisms on encrypted
        data. The user needs to give as input a vector of Galois elements
        corresponding to the keys that are to be created.

        The Galois elements are odd integers in the interval [1, M-1], where
        M = 2*N, and N = poly_modulus_degree. Used with batching, a Galois element
        3^i % M corresponds to a cyclic row rotation i steps to the left, and
        a Galois element 3^(N/2-i) % M corresponds to a cyclic row rotation i
        steps to the right. The Galois element M-1 corresponds to a column rotation
        (row swap) in BFV, and complex conjugation in CKKS. In the polynomial view
        (not batching), a Galois automorphism by a Galois element p changes
        Enc(plain(x)) to Enc(plain(x^p)).

        @param[in] galois_elts The Galois elements for which to generate keys
        @param[in] save_seed If true, replace second poly in Ciphertext with seed
        @throws std::invalid_argument if the Galois elements are not valid
        */
        GaloisKeys create_galois_keys(const std::vector<std::uint32_t> &galois_elts, bool save_seed);

        // We use a fresh memory pool with `clear_on_destruction' enabled.
        MemoryPoolHandle pool_ = MemoryManager::GetPool(mm_prof_opt::mm_force_new, true);

        SEALContext context_;

        SecretKey secret_key_;

        std::size_t secret_key_array_size_ = 0;

        util::Pointer<std::uint64_t> secret_key_array_;

        mutable util::ReaderWriterLocker secret_key_array_locker_;

        bool sk_generated_ = false;
    };
} // namespace seal
