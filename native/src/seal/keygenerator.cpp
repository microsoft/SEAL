// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <algorithm>
#include "seal/keygenerator.h"
#include "seal/randomtostd.h"
#include "seal/util/common.h"
#include "seal/util/uintcore.h"
#include "seal/util/uintarith.h"
#include "seal/util/uintarithsmallmod.h"
#include "seal/util/polyarithsmallmod.h"
#include "seal/util/clipnormal.h"
#include "seal/util/polycore.h"
#include "seal/util/smallntt.h"
#include "seal/util/rlwe.h"

using namespace std;
using namespace seal::util;

namespace seal
{
    KeyGenerator::KeyGenerator(shared_ptr<SEALContext> context) :
        context_(move(context))
    {
        // Verify parameters
        if (!context_)
        {
            throw invalid_argument("invalid context");
        }
        if (!context_->parameters_set())
        {
            throw invalid_argument("encryption parameters are not set correctly");
        }

        // Secret key and public key have not been generated
        sk_generated_ = false;
        pk_generated_ = false;

        // Generate the secret and public key
        generate_sk();
        generate_pk();
    }

    KeyGenerator::KeyGenerator(shared_ptr<SEALContext> context,
        const SecretKey &secret_key) : context_(move(context))
    {
        // Verify parameters
        if (!context_)
        {
            throw invalid_argument("invalid context");
        }
        if (!context_->parameters_set())
        {
            throw invalid_argument("encryption parameters are not set correctly");
        }
        if (!is_valid_for(secret_key, context_))
        {
            throw invalid_argument("secret key is not valid for encryption parameters");
        }

        // Set the secret key
        secret_key_ = secret_key;
        sk_generated_ = true;

        // Generate the public key
        generate_sk(sk_generated_);
        generate_pk();
    }

    KeyGenerator::KeyGenerator(shared_ptr<SEALContext> context,
        const SecretKey &secret_key, const PublicKey &public_key) :
        context_(move(context))
    {
        // Verify parameters
        if (!context_)
        {
            throw invalid_argument("invalid context");
        }
        if (!context_->parameters_set())
        {
            throw invalid_argument("encryption parameters are not set correctly");
        }
        if (!is_valid_for(secret_key, context_))
        {
            throw invalid_argument("secret key is not valid for encryption parameters");
        }
        if (!is_valid_for(public_key, context_))
        {
            throw invalid_argument("public key is not valid for encryption parameters");
        }

        // Set the secret and public keys
        secret_key_ = secret_key;
        public_key_ = public_key;

        // Secret key and public key are generated
        sk_generated_ = true;
        pk_generated_ = true;

        generate_sk(sk_generated_);
    }

    void KeyGenerator::generate_sk(bool is_initialized)
    {
        // Extract encryption parameters.
        auto &context_data = *context_->key_context_data();
        auto &parms = context_data.parms();
        auto &coeff_modulus = parms.coeff_modulus();
        size_t coeff_count = parms.poly_modulus_degree();
        size_t coeff_mod_count = coeff_modulus.size();

        if (!is_initialized)
        {
            // Initialize secret key.
            secret_key_ = SecretKey();
            sk_generated_ = false;
            secret_key_.data().resize(mul_safe(coeff_count, coeff_mod_count));

            shared_ptr<UniformRandomGenerator> random(parms.random_generator()->create());

            // Generate secret key
            uint64_t *secret_key = secret_key_.data().data();
            sample_poly_ternary(secret_key, random, parms);

            auto &small_ntt_tables = context_data.small_ntt_tables();
            for (size_t i = 0; i < coeff_mod_count; i++)
            {
                // Transform the secret s into NTT representation.
                ntt_negacyclic_harvey(secret_key + (i * coeff_count), small_ntt_tables[i]);
            }

            // Set the parms_id for secret key
            secret_key_.parms_id() = context_data.parms_id();
        }

        // Set the secret_key_array to have size 1 (first power of secret)
        secret_key_array_ = allocate_poly(coeff_count, coeff_mod_count, pool_);
        set_poly_poly(secret_key_.data().data(), coeff_count, coeff_mod_count,
            secret_key_array_.get());
        secret_key_array_size_ = 1;

        // Secret key has been generated
        sk_generated_ = true;
    }

    void KeyGenerator::generate_pk()
    {
        if (!sk_generated_)
        {
            throw logic_error("cannot generate public key for unspecified secret key");
        }

        // Extract encryption parameters.
        auto &context_data = *context_->key_context_data();
        auto &parms = context_data.parms();
        auto &coeff_modulus = parms.coeff_modulus();
        size_t coeff_count = parms.poly_modulus_degree();
        size_t coeff_mod_count = coeff_modulus.size();

        // Size check
        if (!product_fits_in(coeff_count, coeff_mod_count))
        {
            throw logic_error("invalid parameters");
        }

        // Initialize public key.
        // PublicKey data allocated from pool given by MemoryManager::GetPool.
        public_key_ = PublicKey();
        pk_generated_ = false;

        shared_ptr<UniformRandomGenerator> random(
            parms.random_generator()->create());
        encrypt_zero_symmetric(secret_key_, context_, context_data.parms_id(),
            random, true, public_key_.data(), pool_);

        // Set the parms_id for public key
        public_key_.parms_id() = context_data.parms_id();

        // Public key has been generated
        pk_generated_ = true;
    }

    RelinKeys KeyGenerator::relin_keys(size_t count)
    {
        // Check to see if secret key and public key have been generated
        if (!sk_generated_)
        {
            throw logic_error("cannot generate relinearization keys for unspecified secret key");
        }
        if (!count || count > SEAL_CIPHERTEXT_SIZE_MAX - 2)
        {
            throw invalid_argument("invalid count");
        }

        // Extract encryption parameters.
        auto &context_data = *context_->key_context_data();
        auto &parms = context_data.parms();
        size_t coeff_count = parms.poly_modulus_degree();
        size_t coeff_mod_count = parms.coeff_modulus().size();

        // Size check
        if (!product_fits_in(coeff_count, coeff_mod_count))
        {
            throw logic_error("invalid parameters");
        }

        shared_ptr<UniformRandomGenerator> random(parms.random_generator()->create());

        // Make sure we have enough secret keys computed
        compute_secret_key_array(context_data, count + 1);

        // Create the RelinKeys object to return
        RelinKeys relin_keys;

        // Assume the secret key is already transformed into NTT form.
        generate_kswitch_keys(
            secret_key_array_.get() + coeff_mod_count * coeff_count,
            count,
            static_cast<KSwitchKeys &>(relin_keys));

        // Set the parms_id
        relin_keys.parms_id() = context_data.parms_id();

        return relin_keys;
    }

    GaloisKeys KeyGenerator::galois_keys(const vector<uint64_t> &galois_elts)
    {
        // Check to see if secret key and public key have been generated
        if (!sk_generated_)
        {
            throw logic_error("cannot generate Galois keys for unspecified secret key");
        }

        // Extract encryption parameters.
        auto &context_data = *context_->key_context_data();
        auto &parms = context_data.parms();
        auto &coeff_modulus = parms.coeff_modulus();
        size_t coeff_count = parms.poly_modulus_degree();
        size_t coeff_mod_count = coeff_modulus.size();
        int coeff_count_power = get_power_of_two(coeff_count);

        // Size check
        if (!product_fits_in(coeff_count, coeff_mod_count, size_t(2)))
        {
            throw logic_error("invalid parameters");
        }

        // Create the GaloisKeys object to return
        GaloisKeys galois_keys;

        // The max number of keys is equal to number of coefficients
        galois_keys.data().resize(coeff_count);

        for (uint64_t galois_elt : galois_elts)
        {
            // Verify coprime conditions.
            if (!(galois_elt & 1) || (galois_elt >= 2 * coeff_count))
            {
                throw invalid_argument("Galois element is not valid");
            }

            // Do we already have the key?
            if (galois_keys.has_key(galois_elt))
            {
                continue;
            }

            // Rotate secret key for each coeff_modulus
            auto rotated_secret_key(
                allocate_poly(coeff_count, coeff_mod_count, pool_));
            for (size_t i = 0; i < coeff_mod_count; i++)
            {
                apply_galois_ntt(
                    secret_key_.data().data() + i * coeff_count,
                    coeff_count_power,
                    galois_elt,
                    rotated_secret_key.get() + i * coeff_count);
            }

            // Initialize Galois key
            // This is the location in the galois_keys vector
            uint64_t index = GaloisKeys::get_index(galois_elt);
            shared_ptr<UniformRandomGenerator> random(parms.random_generator()->create());

            // Create Galois keys.
            generate_one_kswitch_key(
                rotated_secret_key.get(),
                galois_keys.data()[index]);
        }

        // Set the parms_id
        galois_keys.parms_id_ = context_data.parms_id();

        return galois_keys;
    }

    GaloisKeys KeyGenerator::galois_keys(const vector<int> &steps)
    {
        // Check to see if secret key and public key have been generated
        if (!sk_generated_)
        {
            throw logic_error("cannot generate Galois keys for unspecified secret key");
        }

        // Extract encryption parameters.
        auto &context_data = *context_->key_context_data();
        if (!context_data.qualifiers().using_batching)
        {
            throw logic_error("encryption parameters do not support batching");
        }

        auto &parms = context_data.parms();
        size_t coeff_count = parms.poly_modulus_degree();

        vector<uint64_t> galois_elts;
        transform(steps.begin(), steps.end(), back_inserter(galois_elts),
            [&](auto s) { return steps_to_galois_elt(s, coeff_count); });

        return galois_keys(galois_elts);
    }

    GaloisKeys KeyGenerator::galois_keys()
    {
        // Check to see if secret key and public key have been generated
        if (!sk_generated_)
        {
            throw logic_error("cannot generate Galois keys for unspecified secret key");
        }

        size_t coeff_count = context_->key_context_data()->parms().poly_modulus_degree();
        uint64_t m = coeff_count << 1;
        int logn = get_power_of_two(static_cast<uint64_t>(coeff_count));

        vector<uint64_t> logn_galois_keys{};

        // Generate Galois keys for m - 1 (X -> X^{m-1})
        logn_galois_keys.push_back(m - 1);

        // Generate Galois key for power of 3 mod m (X -> X^{3^k}) and
        // for negative power of 3 mod m (X -> X^{-3^k})
        uint64_t two_power_of_three = 3;
        uint64_t neg_two_power_of_three = 0;
        try_mod_inverse(3, m, neg_two_power_of_three);
        for (int i = 0; i < logn - 1; i++)
        {
            logn_galois_keys.push_back(two_power_of_three);
            two_power_of_three *= two_power_of_three;
            two_power_of_three &= (m - 1);

            logn_galois_keys.push_back(neg_two_power_of_three);
            neg_two_power_of_three *= neg_two_power_of_three;
            neg_two_power_of_three &= (m - 1);
        }

        return galois_keys(logn_galois_keys);
    }

    const SecretKey &KeyGenerator::secret_key() const
    {
        if (!sk_generated_)
        {
            throw logic_error("secret key has not been generated");
        }
        return secret_key_;
    }

    const PublicKey &KeyGenerator::public_key() const
    {
        if (!pk_generated_)
        {
            throw logic_error("public key has not been generated");
        }
        return public_key_;
    }

    void KeyGenerator::compute_secret_key_array(
        const SEALContext::ContextData &context_data, size_t max_power)
    {
#ifdef SEAL_DEBUG
        if (max_power < 1)
        {
            throw invalid_argument("max_power must be at least 1");
        }
        if (!secret_key_array_size_ || !secret_key_array_)
        {
            throw logic_error("secret_key_array_ is uninitialized");
        }
#endif
        // Extract encryption parameters.
        auto &parms = context_data.parms();
        auto &coeff_modulus = parms.coeff_modulus();
        size_t coeff_count = parms.poly_modulus_degree();
        size_t coeff_mod_count = coeff_modulus.size();

        // Size check
        if (!product_fits_in(coeff_count, coeff_mod_count, max_power))
        {
            throw logic_error("invalid parameters");
        }

        ReaderLock reader_lock(secret_key_array_locker_.acquire_read());

        size_t old_size = secret_key_array_size_;
        size_t new_size = max(max_power, old_size);

        if (old_size == new_size)
        {
            return;
        }

        reader_lock.unlock();

        // Need to extend the array
        // Compute powers of secret key until max_power
        auto new_secret_key_array(allocate_poly(
            new_size * coeff_count, coeff_mod_count, pool_));
        set_poly_poly(secret_key_array_.get(), old_size * coeff_count,
            coeff_mod_count, new_secret_key_array.get());

        size_t poly_ptr_increment = coeff_count * coeff_mod_count;
        uint64_t *prev_poly_ptr = new_secret_key_array.get() +
            (old_size - 1) * poly_ptr_increment;
        uint64_t *next_poly_ptr = prev_poly_ptr + poly_ptr_increment;

        // Since all of the key powers in secret_key_array_ are already
        // NTT transformed, to get the next one we simply need to compute
        // a dyadic product of the last one with the first one
        // [which is equal to NTT(secret_key_)].
        for (size_t i = old_size; i < new_size; i++)
        {
            for (size_t j = 0; j < coeff_mod_count; j++)
            {
                dyadic_product_coeffmod(
                    prev_poly_ptr + (j * coeff_count),
                    new_secret_key_array.get() + (j * coeff_count),
                    coeff_count, coeff_modulus[j],
                    next_poly_ptr + (j * coeff_count));
            }
            prev_poly_ptr = next_poly_ptr;
            next_poly_ptr += poly_ptr_increment;
        }

        // Take writer lock to update array
        WriterLock writer_lock(secret_key_array_locker_.acquire_write());

        // Do we still need to update size?
        old_size = secret_key_array_size_;
        new_size = max(max_power, secret_key_array_size_);

        if (old_size == new_size)
        {
            return;
        }

        // Acquire new array
        secret_key_array_size_ = new_size;
        secret_key_array_.acquire(new_secret_key_array);
    }

    void KeyGenerator::generate_one_kswitch_key(
        const uint64_t *new_key,
        std::vector<PublicKey> &destination)
    {
        size_t coeff_count = context_->key_context_data()->parms().poly_modulus_degree();
        size_t decomp_mod_count = context_->first_context_data()->parms().coeff_modulus().size();
        auto &key_context_data = *context_->key_context_data();
        auto &key_parms = key_context_data.parms();
        auto &key_modulus = key_parms.coeff_modulus();
        shared_ptr<UniformRandomGenerator> random(key_parms.random_generator()->create());

        // Size check
        if (!product_fits_in(coeff_count, decomp_mod_count))
        {
            throw logic_error("invalid parameters");
        }

        // KSwitchKeys data allocated from pool given by MemoryManager::GetPool.
        destination.resize(decomp_mod_count);

        auto temp(allocate_uint(coeff_count, pool_));
        uint64_t factor = 0;
        for (size_t j = 0; j < decomp_mod_count; j++)
        {
            encrypt_zero_symmetric(secret_key_, context_,
                key_context_data.parms_id(), random, true,
                destination[j].data(), pool_);

            factor = key_modulus.back().value() % key_modulus[j].value();
            multiply_poly_scalar_coeffmod(
                new_key + j * coeff_count,
                coeff_count,
                factor,
                key_modulus[j],
                temp.get());
            add_poly_poly_coeffmod(
                destination[j].data().data() + j * coeff_count,
                temp.get(),
                coeff_count,
                key_modulus[j],
                destination[j].data().data() + j * coeff_count);
        }
    }

    void KeyGenerator::generate_kswitch_keys(
        const uint64_t *new_keys,
        size_t num_keys,
        KSwitchKeys &destination)
    {
        size_t coeff_count = context_->key_context_data()->parms().poly_modulus_degree();
        auto &key_context_data = *context_->key_context_data();
        auto &key_parms = key_context_data.parms();
        size_t coeff_mod_count = key_parms.coeff_modulus().size();
        shared_ptr<UniformRandomGenerator> random(key_parms.random_generator()->create());

        // Size check
        if (!product_fits_in(coeff_count, coeff_mod_count, num_keys))
        {
            throw logic_error("invalid parameters");
        }

        destination.data().resize(num_keys);
        auto temp(allocate_uint(coeff_count, pool_));
        for (size_t l = 0; l < num_keys; l++)
        {
            const uint64_t *new_key_ptr = new_keys + l * coeff_mod_count * coeff_count;
            generate_one_kswitch_key(new_key_ptr, destination.data()[l]);
        }
    }
}