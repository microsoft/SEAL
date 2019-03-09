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
        if (!secret_key.is_valid_for(context_) ||
            secret_key.parms_id() != context_->first_parms_id())
        {
            throw invalid_argument("secret_key is not valid for encryption parameters");
        }

        // Set the secret key
        secret_key_ = secret_key;
        sk_generated_ = true;

        // Generate the public key
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
        if (!secret_key.is_valid_for(context_) ||
            secret_key.parms_id() != context_->first_parms_id())
        {
            throw invalid_argument("secret_key is not valid for encryption parameters");
        }
        if (!public_key.is_valid_for(context_) ||
            public_key.parms_id() != context_->first_parms_id())
        {
            throw invalid_argument("public_key is not valid for encryption parameters");
        }

        // Extract encryption parameters.
        auto &context_data = *context_->context_data();
        auto &parms = context_data.parms();
        auto &coeff_modulus = parms.coeff_modulus();
        size_t coeff_count = parms.poly_modulus_degree();
        size_t coeff_mod_count = coeff_modulus.size();

        // Set the secret and public keys
        public_key_ = public_key;
        secret_key_ = secret_key;

        // Set the secret_key_array to have size 1 (first power of secret) 
        secret_key_array_ = allocate_poly(coeff_count, coeff_mod_count, pool_);
        set_poly_poly(secret_key_.data().data(), coeff_count, coeff_mod_count,
            secret_key_array_.get());
        secret_key_array_size_ = 1;

        // Secret key and public key are generated
        sk_generated_ = true;
        pk_generated_ = true;
    }

    void KeyGenerator::generate_sk()
    {
        // Extract encryption parameters.
        auto &context_data = *context_->context_data();
        auto &parms = context_data.parms();
        auto &coeff_modulus = parms.coeff_modulus();
        size_t coeff_count = parms.poly_modulus_degree();
        size_t coeff_mod_count = coeff_modulus.size();

        // Initialize secret key.
        secret_key_ = SecretKey();
        sk_generated_ = false;
        secret_key_.data().resize(mul_safe(coeff_count, coeff_mod_count));

        shared_ptr<UniformRandomGenerator> random(parms.random_generator()->create());

        // Generate secret key
        uint64_t *secret_key = secret_key_.data().data();
        set_poly_coeffs_zero_one_negone(context_data, secret_key, random);

        auto &small_ntt_tables = context_data.small_ntt_tables();
        for (size_t i = 0; i < coeff_mod_count; i++)
        {
            // Transform the secret s into NTT representation. 
            ntt_negacyclic_harvey(secret_key + (i * coeff_count), small_ntt_tables[i]);
        }

        // Set the secret_key_array to have size 1 (first power of secret) 
        secret_key_array_ = allocate_poly(coeff_count, coeff_mod_count, pool_);
        set_poly_poly(secret_key_.data().data(), coeff_count, coeff_mod_count,
            secret_key_array_.get());
        secret_key_array_size_ = 1;

        // Set the parms_id for secret key
        secret_key_.parms_id() = parms.parms_id();

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
        auto &context_data = *context_->context_data();
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
        public_key_ = PublicKey();
        pk_generated_ = false;
        public_key_.data().resize(context_, parms.parms_id(), 2);

        // The public key is in NTT form
        public_key_.data().is_ntt_form() = true;

        shared_ptr<UniformRandomGenerator> random(parms.random_generator()->create());

        // Generate public key: (pk[0],pk[1]) = ([-(as+e)]_q, a)
        uint64_t *secret_key = secret_key_.data().data();

        // Sample a uniformly at random
        // Set pk[1] = a (we sample the NTT form directly)
        uint64_t *public_key_1 = public_key_.data().data(1);
        set_poly_coeffs_uniform(context_data, public_key_1, random);

        // calculate a*s + e (mod q) and store in pk[0]
        auto &small_ntt_tables = context_data.small_ntt_tables();

        auto noise(allocate_poly(coeff_count, coeff_mod_count, pool_));
        set_poly_coeffs_normal(context_data, noise.get(), random);
        for (size_t i = 0; i < coeff_mod_count; i++)
        {
            // Transform the noise e into NTT representation.
            ntt_negacyclic_harvey(
                noise.get() + (i * coeff_count), small_ntt_tables[i]);

            // The inputs are not reduced but that's OK. We are only at most at 
            // 122 bits and barrett_reduce_128 can deal with that.
            dyadic_product_coeffmod(
                secret_key + (i * coeff_count), 
                public_key_1 + (i * coeff_count), coeff_count, 
                coeff_modulus[i],
                public_key_.data().data(0) + (i * coeff_count));
            add_poly_poly_coeffmod(
                noise.get() + (i * coeff_count), 
                public_key_.data().data(0) + (i * coeff_count),
                coeff_count, coeff_modulus[i],
                public_key_.data().data(0) + (i * coeff_count));
        }

        // Negate and set this value to pk[0]
        // pk[0] is now -(as+e) mod q
        for (size_t i = 0; i < coeff_mod_count; i++)
        {
            negate_poly_coeffmod(
                public_key_.data().data(0) + (i * coeff_count), coeff_count, 
                coeff_modulus[i], public_key_.data().data(0) + (i * coeff_count));
        }

        // Set the parms_id for public key
        public_key_.parms_id() = parms.parms_id();
        
        // Public key has been generated
        pk_generated_ = true;
    }

    RelinKeys KeyGenerator::relin_keys(int decomposition_bit_count, size_t count)
    {
        // Check to see if secret key and public key have been generated
        if (!sk_generated_)
        {
            throw logic_error("cannot generate relinearization keys for unspecified secret key");
        }

        // Check that count is in correct interval
        if (count < SEAL_RELIN_KEY_COUNT_MIN || 
            count > SEAL_RELIN_KEY_COUNT_MAX)
        {
            throw invalid_argument("count out of bounds");
        }

        // Check that decomposition_bit_count is in correct interval
        if (decomposition_bit_count < SEAL_DBC_MIN || 
            decomposition_bit_count > SEAL_DBC_MAX)
        {
            throw invalid_argument("decomposition_bit_count is not in the valid range");
        }

        // Extract encryption parameters.
        auto &context_data = *context_->context_data();
        auto &parms = context_data.parms();
        auto &coeff_modulus = parms.coeff_modulus();
        size_t coeff_count = parms.poly_modulus_degree();
        size_t coeff_mod_count = coeff_modulus.size();
        auto &small_ntt_tables = context_data.small_ntt_tables();

        // Size check
        if (!product_fits_in(coeff_count, coeff_mod_count))
        {
            throw logic_error("invalid parameters");
        }

        // Create the RelinKeys object to return
        RelinKeys relin_keys;

        // Initialize decomposition_factors
        vector<vector<uint64_t>> decomposition_factors;
        populate_decomposition_factors(context_data, decomposition_bit_count,
            decomposition_factors);

        // Initialize the relinearization keys
        relin_keys.data().resize(count);
        for (size_t i = 0; i < count; i++)
        {
            relin_keys.data()[i].reserve(coeff_mod_count);

            for (size_t j = 0; j < coeff_mod_count; j++)
            {
                relin_keys.data()[i].emplace_back(
                    context_, parms.parms_id(),
                    2 * decomposition_factors[j].size(),
                    relin_keys.pool());

                // Resize to right size too (above only allocated)
                // This is slightly odd use of Ciphertext as a container
                relin_keys.data()[i].back().resize(
                    2 * decomposition_factors[j].size());

                // The keys are in NTT form
                relin_keys.data()[i].back().is_ntt_form() = true;
            }
        }

        shared_ptr<UniformRandomGenerator> random(parms.random_generator()->create());

        // Create relinearization keys.
        auto noise(allocate_poly(coeff_count, coeff_mod_count, pool_));
        auto temp(allocate_uint(coeff_count, pool_));

        // Make sure we have enough secret keys computed
        compute_secret_key_array(context_data, count + 1);

        // assume the secret key is already transformed into NTT form. 
        for (size_t k = 0; k < count; k++)
        {
            for (size_t l = 0; l < coeff_mod_count; l++)
            {
                // populate evaluate_keys_[k]
                for (size_t i = 0; i < decomposition_factors[l].size(); i++)
                {
                    // generate NTT(a_i) and store in relin_keys_[k][l].second[i]
                    uint64_t *eval_keys_first = relin_keys.data()[k][l].data(2 * i);
                    uint64_t *eval_keys_second = relin_keys.data()[k][l].data(2 * i + 1);

                    // We sample a_i directly in NTT form
                    set_poly_coeffs_uniform(context_data, eval_keys_second, random);

                    for (size_t j = 0; j < coeff_mod_count; j++)
                    {
                        // calculate a_i*s and store in relin_keys_[k].first[i]
                        dyadic_product_coeffmod(eval_keys_second + (j * coeff_count), 
                            secret_key_.data().data() + (j * coeff_count), 
                            coeff_count, coeff_modulus[j], eval_keys_first + (j * coeff_count));
                    }

                    // generate NTT(e_i) 
                    set_poly_coeffs_normal(context_data, noise.get(), random);
                    for (size_t j = 0; j < coeff_mod_count; j++)
                    {
                        ntt_negacyclic_harvey(noise.get() + (j * coeff_count), small_ntt_tables[j]);

                        // add e_i into relin_keys_[k].first[i]
                        add_poly_poly_coeffmod(
                            noise.get() + (j * coeff_count), eval_keys_first + (j * coeff_count), 
                            coeff_count, coeff_modulus[j], eval_keys_first + (j * coeff_count));

                        // negate value in relin_keys_[k].first[i]
                        negate_poly_coeffmod(
                            eval_keys_first + (j * coeff_count), coeff_count, coeff_modulus[j],
                            eval_keys_first + (j * coeff_count));

                        // multiply w^i * s^(k+2)
                        uint64_t decomposition_factor_mod = decomposition_factors[l][i] & 
                            static_cast<uint64_t>(-static_cast<int64_t>(l == j));
                        multiply_poly_scalar_coeffmod(
                            secret_key_array_.get() + (k + 1) * coeff_count * coeff_mod_count + (j * coeff_count), 
                            coeff_count, decomposition_factor_mod, coeff_modulus[j], temp.get());

                        // add w^i . s^(k+2) into relin_keys_[k].first[i]
                        add_poly_poly_coeffmod(eval_keys_first + (j * coeff_count), temp.get(), coeff_count, 
                            coeff_modulus[j], eval_keys_first + (j * coeff_count));
                    }
                }
            }
        }

        // Set decomposition_bit_count
        relin_keys.decomposition_bit_count_ = decomposition_bit_count;

        // Set the parms_id
        relin_keys.parms_id() = parms.parms_id();

        return relin_keys;
    }

    GaloisKeys KeyGenerator::galois_keys(int decomposition_bit_count, 
        const vector<uint64_t> &galois_elts)
    {
        // Check to see if secret key and public key have been generated
        if (!sk_generated_)
        {
            throw logic_error("cannot generate galois keys for unspecified secret key");
        }

        // Check that decomposition_bit_count is in correct interval
        if (decomposition_bit_count < SEAL_DBC_MIN || 
            decomposition_bit_count > SEAL_DBC_MAX)
        {
            throw invalid_argument("decomposition_bit_count is not on the valid range");
        }

        // Extract encryption parameters.
        auto &context_data = *context_->context_data();
        auto &parms = context_data.parms();
        auto &coeff_modulus = parms.coeff_modulus();
        size_t coeff_count = parms.poly_modulus_degree();
        size_t coeff_mod_count = coeff_modulus.size();
        int coeff_count_power = get_power_of_two(coeff_count);
        auto &small_ntt_tables = context_data.small_ntt_tables();

        // Size check
        if (!product_fits_in(coeff_count, coeff_mod_count, size_t(2)))
        {
            throw logic_error("invalid parameters");
        }

        // Create the GaloisKeys object to return
        GaloisKeys galois_keys;

        // The max number of keys is equal to number of coefficients
        galois_keys.data().resize(coeff_count);

        // Initialize decomposition_factors
        vector<vector<uint64_t>> decomposition_factors;
        populate_decomposition_factors(context_data, decomposition_bit_count,
            decomposition_factors);

        for (uint64_t galois_elt : galois_elts)
        {
            // Verify coprime conditions.
            if (!(galois_elt & 1) || (galois_elt >= 2 * coeff_count))
            {
                throw invalid_argument("galois element is not valid");
            }

            // Do we already have the key?
            if (galois_keys.has_key(galois_elt))
            {
                continue;
            }

            // Rotate secret key for each coeff_modulus
            auto rotated_secret_key(allocate_poly(coeff_count, coeff_mod_count, pool_));
            for (size_t i = 0; i < coeff_mod_count; i++)
            {
                apply_galois_ntt(secret_key_.data().data() + (i * coeff_count),
                    coeff_count_power, galois_elt,
                    rotated_secret_key.get() + (i * coeff_count));
            }

            // Initialize galois key
            // This is the location in the galois_keys vector
            uint64_t index = (galois_elt - 1) >> 1;
            galois_keys.data()[index].reserve(coeff_mod_count);

            for (size_t i = 0; i < coeff_mod_count; i++)
            {
                galois_keys.data()[index].emplace_back(
                    context_, parms.parms_id(),
                    2 * decomposition_factors[i].size(),
                    galois_keys.pool());

                // Resize to right size too (above only allocated)
                // This is slightly odd use of Ciphertext as a container
                galois_keys.data()[index].back().resize(
                    2 * decomposition_factors[i].size());

                // The Galois keys are in NTT form
                galois_keys.data()[index].back().is_ntt_form() = true;
            }

            shared_ptr<UniformRandomGenerator> random(parms.random_generator()->create());

            // Create Galois keys.
            auto noise(allocate_poly(coeff_count, coeff_mod_count, pool_));
            auto temp(allocate_uint(coeff_count, pool_));

            for (size_t l = 0; l < coeff_mod_count; l++)
            {
                // populate galois_keys_[k]
                for (size_t i = 0; i < decomposition_factors[l].size(); i++)
                {
                    // generate NTT(a_i) and store in galois_keys_[k][l].second[i]
                    uint64_t *eval_keys_first = galois_keys.data()[index][l].data(2 * i);
                    uint64_t *eval_keys_second = galois_keys.data()[index][l].data(2 * i + 1);

                    // We sample a_i in NTT form directly
                    set_poly_coeffs_uniform(context_data, eval_keys_second, random);
                    for (size_t j = 0; j < coeff_mod_count; j++)
                    {
                        // calculate a_i*s and store in galois_keys_[k].first[i]
                        dyadic_product_coeffmod(eval_keys_second + (j * coeff_count), 
                            secret_key_.data().data() + (j * coeff_count), 
                            coeff_count, coeff_modulus[j], 
                            eval_keys_first + (j * coeff_count));
                    }

                    // generate NTT(e_i) 
                    set_poly_coeffs_normal(context_data, noise.get(), random);
                    for (size_t j = 0; j < coeff_mod_count; j++)
                    {
                        ntt_negacyclic_harvey(
                            noise.get() + (j * coeff_count), small_ntt_tables[j]);

                        // add NTT(e_i) into galois_keys_[k].first[i]
                        add_poly_poly_coeffmod(noise.get() + (j * coeff_count), 
                            eval_keys_first + (j * coeff_count), 
                            coeff_count, coeff_modulus[j],
                            eval_keys_first + (j * coeff_count));

                        // negate value in galois_keys_[k].first[i]
                        negate_poly_coeffmod(
                            eval_keys_first + (j * coeff_count), coeff_count, 
                            coeff_modulus[j], eval_keys_first + (j * coeff_count));

                        // multiply w^i * rotated_secret_key
                        uint64_t decomposition_factor_mod = decomposition_factors[l][i] & 
                            static_cast<uint64_t>(-static_cast<int64_t>(l == j));
                        multiply_poly_scalar_coeffmod(rotated_secret_key.get() + (j * coeff_count), 
                            coeff_count, decomposition_factor_mod, 
                            coeff_modulus[j], temp.get());

                        // add w^i * rotated_secret_key into galois_keys_[k].first[i]
                        add_poly_poly_coeffmod(eval_keys_first + (j * coeff_count), temp.get(), 
                            coeff_count, coeff_modulus[j], eval_keys_first + (j * coeff_count));
                    }
                }
            }
        }

        // Set decomposition_bit_count
        galois_keys.decomposition_bit_count_ = decomposition_bit_count;

        // Set the parms_id
        galois_keys.parms_id_ = parms.parms_id();

        return galois_keys;
    }

    GaloisKeys KeyGenerator::galois_keys(int decomposition_bit_count, 
        const vector<int> &steps)
    {
        // Check to see if secret key and public key have been generated
        if (!sk_generated_)
        {
            throw logic_error("cannot generate galois keys for unspecified secret key");
        }

        // Check that decomposition_bit_count is in correct interval
        if (decomposition_bit_count < SEAL_DBC_MIN || 
            decomposition_bit_count > SEAL_DBC_MAX)
        {
            throw invalid_argument("decomposition_bit_count is not on the valid range");
        }

        // Extract encryption parameters.
        auto &context_data = *context_->context_data();
        if (!context_data.qualifiers().using_batching)
        {
            throw logic_error("encryption parameters do not support batching");
        }

        auto &parms = context_data.parms();
        size_t coeff_count = parms.poly_modulus_degree();

        vector<uint64_t> galois_elts;
        transform(steps.begin(), steps.end(), back_inserter(galois_elts),
            [&](auto s) { return steps_to_galois_elt(s, coeff_count); });

        return galois_keys(decomposition_bit_count, galois_elts);
    }

    GaloisKeys KeyGenerator::galois_keys(int decomposition_bit_count)
    {
        // Check to see if secret key and public key have been generated
        if (!sk_generated_)
        {
            throw logic_error("cannot generate galois keys for unspecified secret key");
        }

        // Check that decomposition_bit_count is in correct interval
        if (decomposition_bit_count < SEAL_DBC_MIN || 
            decomposition_bit_count > SEAL_DBC_MAX)
        {
            throw invalid_argument("decomposition_bit_count is not in the valid range");
        }

        size_t coeff_count = context_->context_data()->parms().poly_modulus_degree();
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

        return galois_keys(decomposition_bit_count, logn_galois_keys);
    }

    void KeyGenerator::set_poly_coeffs_zero_one_negone(
        const SEALContext::ContextData &context_data, 
        uint64_t *poly, shared_ptr<UniformRandomGenerator> random) const
    {
        // Extract encryption parameters.
        auto &parms = context_data.parms();
        auto &coeff_modulus = parms.coeff_modulus();
        size_t coeff_count = parms.poly_modulus_degree();
        size_t coeff_mod_count = coeff_modulus.size();

        RandomToStandardAdapter engine(random);
        uniform_int_distribution<int> dist(-1, 1);

        for (size_t i = 0; i < coeff_count; i++)
        {
            int rand_index = dist(engine);
            if (rand_index == 1)
            {
                for (size_t j = 0; j < coeff_mod_count; j++)
                {
                    poly[i + (j * coeff_count)] = 1;
                }
            }
            else if (rand_index == -1)
            {
                for (size_t j = 0; j < coeff_mod_count; j++)
                {
                    poly[i + (j * coeff_count)] = coeff_modulus[j].value() - 1;
                }
            }
            else
            {
                for (size_t j = 0; j < coeff_mod_count; j++)
                {
                    poly[i + (j * coeff_count)] = 0;
                }
            }
        }
    }

    void KeyGenerator::set_poly_coeffs_normal(
        const SEALContext::ContextData &context_data, uint64_t *poly, 
        shared_ptr<UniformRandomGenerator> random) const
    {
        // Extract encryption parameters.
        auto &parms = context_data.parms();
        auto &coeff_modulus = parms.coeff_modulus();
        size_t coeff_count = parms.poly_modulus_degree();
        size_t coeff_mod_count = coeff_modulus.size();

        if (parms.noise_standard_deviation() == 0 || 
            parms.noise_max_deviation() == 0)
        {
            set_zero_poly(coeff_count, coeff_mod_count, poly);
            return;
        }
        RandomToStandardAdapter engine(random);
        ClippedNormalDistribution dist(0, parms.noise_standard_deviation(), 
            parms.noise_max_deviation());
        for (size_t i = 0; i < coeff_count; i++)
        {
            int64_t noise = static_cast<int64_t>(dist(engine));
            if (noise > 0)
            {
                for (size_t j = 0; j < coeff_mod_count; j++)
                {
                    poly[i + (j * coeff_count)] = static_cast<uint64_t>(noise);
                }
            }
            else if (noise < 0)
            {
                noise = -noise;
                for (size_t j = 0; j < coeff_mod_count; j++)
                {
                    poly[i + (j * coeff_count)] = 
                        coeff_modulus[j].value() - static_cast<uint64_t>(noise);
                }
            }
            else
            {
                for (size_t j = 0; j < coeff_mod_count; j++)
                {
                    poly[i + (j * coeff_count)] = 0;
                }
            }
        }
    }

    void KeyGenerator::set_poly_coeffs_uniform(
        const SEALContext::ContextData &context_data,
        uint64_t *poly, shared_ptr<UniformRandomGenerator> random) const
    {
        // Extract encryption parameters.
        auto &parms = context_data.parms();
        auto &coeff_modulus = parms.coeff_modulus();
        size_t coeff_count = parms.poly_modulus_degree();
        size_t coeff_mod_count = coeff_modulus.size();

        // Set up source of randomness which produces random things of size 32 bit
        RandomToStandardAdapter engine(random);

        for (size_t j = 0; j < coeff_mod_count; j++)
        {
            uint64_t current_modulus = coeff_modulus[j].value();
            for (size_t i = 0; i < coeff_count; i++, poly++)
            {
                uint64_t new_coeff = (static_cast<uint64_t>(engine()) << 32) + 
                    static_cast<uint64_t>(engine());
                *poly = new_coeff % current_modulus; 
            }
        }
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

    // decomposition_factors[i][j] = 2^(w*j) * hat-q_i * hat-q_i^(-1) mod q_i
    // This is HPS improvement to Bajard's RNS key switching 
    void KeyGenerator::populate_decomposition_factors(
        const SEALContext::ContextData &context_data, 
        int decomposition_bit_count,
        vector<vector<uint64_t>> &decomposition_factors) const
    {
        // Extract encryption parameters.
        auto &parms = context_data.parms();
        auto &coeff_modulus = parms.coeff_modulus();
        size_t coeff_mod_count = coeff_modulus.size();

        decomposition_factors.clear();

        // Initialize decomposition_factors
        decomposition_factors.resize(coeff_mod_count);
        uint64_t power_of_w = uint64_t(1) << decomposition_bit_count;

        for (size_t i = 0; i < coeff_mod_count; i++)
        {
            // We use HPS improvement to Bajard's RNS key switching 
            uint64_t current_decomposition_factor = 1;

            uint64_t current_smallmod = coeff_modulus[i].value();
            while (current_smallmod != 0)
            {
                decomposition_factors[i].emplace_back(current_decomposition_factor);

                //multiply 2^w mod q_i
                current_decomposition_factor = multiply_uint_uint_mod(
                    current_decomposition_factor, power_of_w, coeff_modulus[i]);
                current_smallmod >>= decomposition_bit_count;
            }
        }

        // We need to ensure that the total number of decomposition factors does not 
        // exceed 63 for lazy reduction in relinearization to work
        size_t total_ev_factor_count = 0;
        for (size_t i = 0; i < coeff_mod_count; i++)
        {
            total_ev_factor_count = 
                add_safe(total_ev_factor_count, decomposition_factors[i].size());
        }
        if (total_ev_factor_count > 63)
        {
            throw invalid_argument("decomposition_bit_count is too small");
        }
    }
}
