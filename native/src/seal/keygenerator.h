// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#pragma once

#include <memory>
#include <random>
#include "seal/util/defines.h"
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
        SEAL_NODISCARD const SecretKey &secret_key() const;

        /**
        Returns a const reference to the public key.
        */
        SEAL_NODISCARD const PublicKey &public_key() const;

        /**
        Generates and returns relinearization keys.

        @throws std::logic_error if the encryption parameters do not support
        keyswitching
        */
        SEAL_NODISCARD inline RelinKeys relin_keys()
        {
            return relin_keys(1, false);
        }

        /**
        Generates and saves relinearization keys to an output stream.

        Half of the polynomials in relinearization keys are randomly generated
        and are replaced with the seed used to compress output size. The output
        is in binary format and not human-readable. The output stream must have
        the "binary" flag set.

        @param[out] stream The stream to save the relinearization keys to
        @param[in] compr_mode The desired compression mode
        @throws std::logic_error if the encryption parameters do not support
        keyswitching
        @throws std::logic_error if compression mode is not supported, or if
        compression failed
        @throws std::runtime_error if I/O operations failed
        */
        inline std::streamoff relin_keys_save(
            std::ostream &stream,
            compr_mode_type compr_mode = Serialization::compr_mode_default)
        {
            return relin_keys(1, true).save(stream, compr_mode);
        }

        /**
        Generates and saves relinearization keys to a given memory location.

        Half of the polynomials in relinearization keys are randomly generated
        and are replaced with the seed used to compress output size. The output
        is in binary format and not human-readable.

        @param[out] out The memory location to write the RelinKeys to
        @param[in] size The number of bytes available in the given memory location
        @param[in] compr_mode The desired compression mode
        @throws std::logic_error if the encryption parameters do not support
        keyswitching
        @throws std::invalid_argument if out is null or if size is too small to
        contain a SEALHeader
        @throws std::logic_error if compression mode is not supported, or if
        compression failed
        @throws std::runtime_error if I/O operations failed
        */
        inline std::streamoff relin_keys_save(
            SEAL_BYTE *out,
            std::size_t size,
            compr_mode_type compr_mode = Serialization::compr_mode_default)
        {
            return relin_keys(1, true).save(out, size, compr_mode);
        }

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
        @throws std::logic_error if the encryption parameters do not support
        batching and scheme is scheme_type::BFV
        @throws std::logic_error if the encryption parameters do not support
        keyswitching
        @throws std::invalid_argument if the Galois elements are not valid
        */
        SEAL_NODISCARD inline GaloisKeys galois_keys(
            const std::vector<std::uint64_t> &galois_elts)
        {
            return galois_keys(galois_elts, false);
        }

        /**
        Generates and saves Galois keys to an output stream. This function creates
        specific Galois keys that can be used to apply specific Galois
        automorphisms on encrypted data. The user needs to give as input a vector
        of Galois elements corresponding to the keys that are to be created.

        Half of the polynomials in Galois keys are randomly generated and are
        replaced with the seed used to compress output size. The output is in
        binary format and not human-readable. The output stream must have the
        "binary" flag set.

        @param[in] galois_elts The Galois elements for which to generate keys
        @param[out] stream The stream to save the Galois keys to
        @param[in] compr_mode The desired compression mode
        @throws std::logic_error if the encryption parameters do not support
        batching and scheme is scheme_type::BFV
        @throws std::invalid_argument if the Galois elements are not valid
        @throws std::logic_error if the encryption parameters do not support
        keyswitching
        @throws std::logic_error if compression mode is not supported, or if
        compression failed
        @throws std::runtime_error if I/O operations failed
        */
        inline std::streamoff galois_keys_save(
            const std::vector<std::uint64_t> &galois_elts,
            std::ostream &stream,
            compr_mode_type compr_mode = Serialization::compr_mode_default)
        {
            return galois_keys(galois_elts, true).save(stream, compr_mode);
        }

        /**
        Generates and writes Galois keys to a given memory location. This function
        creates specific Galois keys that can be used to apply specific Galois
        automorphisms on encrypted data. The user needs to give as input a vector
        of Galois elements corresponding to the keys that are to be created.

        Half of the polynomials in Galois keys are randomly generated and are
        replaced with the seed used to compress output size. The output is in
        binary format and not human-readable.

        @param[in] galois_elts The Galois elements for which to generate keys
        @param[out] out The memory location to write the GaloisKeys to
        @param[in] size The number of bytes available in the given memory location
        @param[in] compr_mode The desired compression mode
        @throws std::logic_error if the encryption parameters do not support
        batching and scheme is scheme_type::BFV
        @throws std::logic_error if the encryption parameters do not support
        keyswitching
        @throws std::invalid_argument if out is null or if size is too small to
        contain a SEALHeader
        @throws std::logic_error if compression mode is not supported, or if
        compression failed
        @throws std::runtime_error if I/O operations failed
        @throws std::invalid_argument if the Galois elements are not valid
        */
        inline std::streamoff galois_keys_save(
            const std::vector<std::uint64_t> &galois_elts,
            SEAL_BYTE *out,
            std::size_t size,
            compr_mode_type compr_mode = Serialization::compr_mode_default)
        {
            return galois_keys(galois_elts, true).save(out, size, compr_mode);
        }

        /**
        Generates and returns Galois keys. This function creates specific Galois
        keys that can be used to apply specific Galois automorphisms on encrypted
        data. The user needs to give as input a vector of desired Galois rotation
        step counts, where negative step counts correspond to rotations to the
        right and positive step counts correspond to rotations to the left.
        A step count of zero can be used to indicate a column rotation in the BFV
        scheme complex conjugation in the CKKS scheme.

        @param[in] galois_steps The rotation step counts for which to generate keys
        @throws std::logic_error if the encryption parameters do not support
        batching and scheme is scheme_type::BFV
        @throws std::logic_error if the encryption parameters do not support
        keyswitching
        @throws std::logic_error if compression mode is not supported, or if
        compression failed
        @throws std::runtime_error if I/O operations failed
        @throws std::invalid_argument if the step counts are not valid
        */
        SEAL_NODISCARD GaloisKeys galois_keys(const std::vector<int> &steps)
        {
            return galois_keys(galois_elts_from_steps(steps));
        }

        /**
        Generates and saves Galois keys to an output stream. This function creates
        specific Galois keys that can be used to apply specific Galois automorphisms
        on encrypted data. The user needs to give as input a vector of desired
        Galois rotation step counts, where negative step counts correspond to
        rotations to the right and positive step counts correspond to rotations to
        the left. A step count of zero can be used to indicate a column rotation
        in the BFV scheme complex conjugation in the CKKS scheme.

        Half of the polynomials in Galois keys are randomly generated and are
        replaced with the seed used to compress output size. The output is in
        binary format and not human-readable. The output stream must have the
        "binary" flag set.

        @param[in] galois_steps The rotation step counts for which to generate keys
        @param[out] stream The stream to save the Galois keys to
        @param[in] compr_mode The desired compression mode
        @throws std::logic_error if the encryption parameters do not support
        batching and scheme is scheme_type::BFV
        @throws std::logic_error if the encryption parameters do not support
        keyswitching
        @throws std::logic_error if compression mode is not supported, or if
        compression failed
        @throws std::runtime_error if I/O operations failed
        @throws std::invalid_argument if the step counts are not valid
        */
        inline std::streamoff galois_keys_save(
            const std::vector<int> &steps,
            std::ostream &stream,
            compr_mode_type compr_mode = Serialization::compr_mode_default)
        {
            return galois_keys_save(
                galois_elts_from_steps(steps), stream, compr_mode);
        }

        /**
        Generates and writes Galois keys to a given memory location. This function
        creates specific Galois keys that can be used to apply specific Galois
        automorphisms on encrypted data. The user needs to give as input a vector
        of desired Galois rotation step counts, where negative step counts correspond
        to rotations to the right and positive step counts correspond to rotations to
        the left. A step count of zero can be used to indicate a column rotation
        in the BFV scheme complex conjugation in the CKKS scheme.

        Half of the polynomials in Galois keys are randomly generated and are
        replaced with the seed used to compress output size. The output is in
        binary format and not human-readable.

        @param[in] galois_steps The rotation step counts for which to generate keys
        @param[out] out The memory location to write the GaloisKeys to
        @param[in] size The number of bytes available in the given memory location
        @param[in] compr_mode The desired compression mode
        @throws std::logic_error if the encryption parameters do not support
        batching and scheme is scheme_type::BFV
        @throws std::logic_error if the encryption parameters do not support
        keyswitching
        @throws std::invalid_argument if out is null or if size is too small to
        contain a SEALHeader
        @throws std::logic_error if compression mode is not supported, or if
        compression failed
        @throws std::runtime_error if I/O operations failed
        @throws std::invalid_argument if the Galois elements are not valid
        */
        inline std::streamoff galois_keys_save(
            const std::vector<int> &steps,
            SEAL_BYTE *out,
            std::size_t size,
            compr_mode_type compr_mode = Serialization::compr_mode_default)
        {
            return galois_keys_save(
                galois_elts_from_steps(steps), out, size, compr_mode);
        }

        /**
        Generates and returns Galois keys. This function creates logarithmically
        many (in degree of the polynomial modulus) Galois keys that is sufficient
        to apply any Galois automorphism (e.g. rotations) on encrypted data. Most
        users will want to use this overload of the function.

        @throws std::logic_error if the encryption parameters do not support
        batching and scheme is scheme_type::BFV
        */
        SEAL_NODISCARD GaloisKeys galois_keys()
        {
            return galois_keys(galois_elts_all());
        }

        /**
        Generates and saves Galois keys to an output stream. This function creates
        logarithmically many (in degree of the polynomial modulus) Galois keys
        that is sufficient to apply any Galois automorphism (e.g. rotations) on
        encrypted data. Most users will want to use this overload of the function.

        Half of the polynomials in Galois keys are randomly generated and are
        replaced with the seed used to compress output size. The output is in
        binary format and not human-readable. The output stream must have the
        "binary" flag set.

        @param[out] stream The stream to save the Galois keys to
        @param[in] compr_mode The desired compression mode
        @throws std::logic_error if the encryption parameters do not support
        batching and scheme is scheme_type::BFV
        @throws std::logic_error if the encryption parameters do not support
        keyswitching
        @throws std::logic_error if compression mode is not supported, or if
        compression failed
        @throws std::runtime_error if I/O operations failed
        */
        inline std::streamoff galois_keys_save(
            std::ostream &stream,
            compr_mode_type compr_mode = Serialization::compr_mode_default)
        {
            return galois_keys_save(galois_elts_all(), stream, compr_mode);
        }

        /**
        Generates and writes Galois keys to a given memory location. This function
        creates logarithmically many (in degree of the polynomial modulus) Galois
        keys that is sufficient to apply any Galois automorphism (e.g. rotations) on
        encrypted data. Most users will want to use this overload of the function.

        Half of the polynomials in Galois keys are randomly generated and are
        replaced with the seed used to compress output size. The output is in
        binary format and not human-readable.

        @param[out] out The memory location to write the GaloisKeys to
        @param[in] size The number of bytes available in the given memory location
        @param[in] compr_mode The desired compression mode
        batching and scheme is scheme_type::BFV
        @throws std::logic_error if the encryption parameters do not support
        keyswitching
        @throws std::logic_error if the data to be saved is invalid, if compression
        mode is not supported, or if compression failed
        @throws std::runtime_error if I/O operations failed
        @throws std::logic_error if the encryption parameters do not support
        @throws std::invalid_argument if the Galois elements are not valid
        */
        inline std::streamoff galois_keys_save(
            SEAL_BYTE *out,
            std::size_t size,
            compr_mode_type compr_mode = Serialization::compr_mode_default)
        {
            return galois_keys_save(galois_elts_all(), out, size, compr_mode);
        }

        /**
        Enables access to private members of seal::KeyGenerator for .NET wrapper.
        */
        struct KeyGeneratorPrivateHelper;

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

        @param[in] is_initialized True if the secret key has already been
        initialized so that only the secret_key_array_ should be initialized, for
        example, if the secret key was provided in the constructor
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
            KSwitchKeys &destination,
            bool save_seed = false);

        /**
        Generates one key switching key for a new key.
        */
        void generate_one_kswitch_key(
            const uint64_t *new_key,
            std::vector<PublicKey> &destination,
            bool save_seed = false);

        /**
        Generates and returns the specified number of relinearization keys.

        @param[in] count The number of relinearization keys to generate
        @param[in] save_seed If true, save seed instead of a polynomial.
        @throws std::invalid_argument if count is zero or too large
        */
        RelinKeys relin_keys(std::size_t count, bool save_seed);

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
        GaloisKeys galois_keys(
            const std::vector<std::uint64_t> &galois_elts,
            bool save_seed);

        // Get a vector of galois_elts from a vector of steps.
        std::vector<std::uint64_t> galois_elts_from_steps(const std::vector<int> &steps);

        // Get a vector all necesssary galois_etls.
        std::vector<std::uint64_t> galois_elts_all();

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
