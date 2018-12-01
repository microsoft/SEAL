// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <algorithm>
#include <stdexcept>
#include "seal/encryptor.h"
#include "seal/util/common.h"
#include "seal/util/uintarith.h"
#include "seal/util/polyarithsmallmod.h"
#include "seal/util/clipnormal.h"
#include "seal/util/randomtostd.h"
#include "seal/util/smallntt.h"
#include "seal/smallmodulus.h"

using namespace std;
using namespace seal::util;

namespace seal
{
    Encryptor::Encryptor(shared_ptr<SEALContext> context, 
        const PublicKey &public_key) : context_(move(context))
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
        if (public_key.parms_id() != context_->first_parms_id())
        {
            throw invalid_argument("public key is not valid for encryption parameters");
        }

        auto &parms = context_->context_data()->parms();
        auto &coeff_modulus = parms.coeff_modulus();
        size_t coeff_count = parms.poly_modulus_degree();
        size_t coeff_mod_count = coeff_modulus.size();

        // Quick sanity check
        if (!product_fits_in(coeff_count, coeff_mod_count, size_t(2)))
        {
            throw logic_error("invalid parameters");
        }
        
        // Allocate space and copy over key
        public_key_ = allocate_poly(2 * coeff_count, coeff_mod_count, pool_);
        set_poly_poly(public_key.data().data(0), 2 * coeff_count, coeff_mod_count, 
            public_key_.get());
    }

    void Encryptor::encrypt(const Plaintext &plain, 
        Ciphertext &destination, MemoryPoolHandle pool)
    {
        // Verify parameters.
        if (!pool)
        {
            throw invalid_argument("pool is uninitialized");
        }

        auto &context_data = *context_->context_data();
        auto &parms = context_data.parms();

        switch (parms.scheme())
        {
        case scheme_type::BFV:
            bfv_encrypt(plain, destination, move(pool));
            return;

        case scheme_type::CKKS:
            ckks_encrypt(plain, destination, move(pool));
            return;

        default:
            throw invalid_argument("unsupported scheme");
        }
    }

    void Encryptor::bfv_encrypt(const Plaintext &plain, 
        Ciphertext &destination, MemoryPoolHandle pool)
    {
        if (plain.is_ntt_form())
        {
            throw invalid_argument("plain cannot be in NTT form");
        }

        auto &context_data = *context_->context_data();
        auto &parms = context_data.parms();
        auto &coeff_modulus = parms.coeff_modulus();
        size_t coeff_count = parms.poly_modulus_degree();
        size_t first_coeff_mod_count = 
            context_->context_data()->parms().coeff_modulus().size();
        size_t coeff_mod_count = coeff_modulus.size();

        // Verify more parameters.
        if (plain.coeff_count() > coeff_count)
        {
            throw invalid_argument("plain is not valid for encryption parameters");
        }

        auto &small_ntt_tables = context_data.small_ntt_tables();
#ifdef SEAL_DEBUG
        if (!are_poly_coefficients_less_than(plain.data(), 
            plain.coeff_count(), parms.plain_modulus().value()))
        {
            throw invalid_argument("plain is not valid for encryption parameters");
        }
#endif
        // Make destination have right size and parms_id
        destination.resize(context_, parms.parms_id(), 2);
        destination.is_ntt_form() = false;

        /*
        Ciphertext (c_0,c_1)
        c_0 = Delta * m + public_key_[0] * u + e_1 where u sampled from R_2 and e_1 sampled from chi.
        c_1 = public_key_[1] * u + e_2 where e_2 sampled from chi.
        */

        // Generate u 
        auto u(allocate_poly(coeff_count, coeff_mod_count, pool));
        shared_ptr<UniformRandomGenerator> random(parms.random_generator()->create());
        
        set_poly_coeffs_zero_one_negone(u.get(), random, context_data);

        // Multiply both u * public_key_[0] and u * public_key_[1] using the same FFT
        for (size_t i = 0; i < coeff_mod_count; i++)
        {
            ntt_negacyclic_harvey_lazy(u.get() + (i * coeff_count), small_ntt_tables[i]);

            dyadic_product_coeffmod(u.get() + (i * coeff_count), 
                public_key_.get() + (i * coeff_count), coeff_count, 
                coeff_modulus[i], destination.data() + (i * coeff_count));
            inverse_ntt_negacyclic_harvey(destination.data() + (i * coeff_count), 
                small_ntt_tables[i]);

            dyadic_product_coeffmod(u.get() + (i * coeff_count), 
                public_key_.get() + (coeff_count * first_coeff_mod_count) + (i * coeff_count), 
                coeff_count, coeff_modulus[i], destination.data(1) + (i * coeff_count));
            inverse_ntt_negacyclic_harvey(destination.data(1) + (i * coeff_count), 
                small_ntt_tables[i]);
        }

        // Multiply plain by scalar coeff_div_plaintext and reposition if in upper-half.
        // Result gets added into the c_0 term of ciphertext (c_0,c_1).
        preencrypt(plain.data(), plain.coeff_count(), context_data, destination.data());

        // Generate e_0, add this value into destination[0].
        set_poly_coeffs_normal(u.get(), random, context_data);
        for (size_t i = 0; i < coeff_mod_count; i++)
        {
            add_poly_poly_coeffmod(u.get() + (i * coeff_count), 
                destination.data() + (i * coeff_count), coeff_count, 
                coeff_modulus[i], destination.data() + (i * coeff_count));
        }
        // Generate e_1, add this value into destination[1].
        set_poly_coeffs_normal(u.get(), random, context_data);
        for (size_t i = 0; i < coeff_mod_count; i++)
        {
            add_poly_poly_coeffmod(u.get() + (i * coeff_count), 
                destination.data(1) + (i * coeff_count), coeff_count, 
                coeff_modulus[i], destination.data(1) + (i * coeff_count));
        }
    }

    void Encryptor::ckks_encrypt(const Plaintext &plain, 
        Ciphertext &destination, MemoryPoolHandle pool)
    {
        if (!plain.is_ntt_form())
        {
            throw invalid_argument("plain must be in NTT form");
        }

        auto context_data_ptr = context_->context_data(plain.parms_id());
        if (!context_data_ptr)
        {
            throw invalid_argument("plain is not valid for encryption parameters");
        }

        auto &context_data = *context_data_ptr;
        auto &parms = context_data.parms();
        auto &coeff_modulus = parms.coeff_modulus();
        size_t coeff_count = parms.poly_modulus_degree();
        size_t first_coeff_mod_count = 
            context_->context_data()->parms().coeff_modulus().size();
        size_t coeff_mod_count = coeff_modulus.size();

        auto &small_ntt_tables = context_data.small_ntt_tables();
#ifdef SEAL_DEBUG
        // Check that the plaintext doesn't have more coefficients than allowed
        if (unsigned_gt(plain.coeff_count(), mul_safe(coeff_count, coeff_mod_count)))
        {
            throw invalid_argument("plain is not valid for encryption parameters");
        }
#endif
        // Make destination have right size and hash block
        destination.resize(context_, parms.parms_id(), 2);
        destination.is_ntt_form() = true;
        destination.scale() = plain.scale();

        /*
            Ciphertext (c_0,c_1)
            c_0 = m + public_key_[0] * u + e_1 where u sampled from R_2 and e_1 sampled from chi.
            c_1 = public_key_[1] * u + e_2 where e_2 sampled from chi.
        */

        // Generate u 
        auto u(allocate_poly(coeff_count, coeff_mod_count, pool));
        shared_ptr<UniformRandomGenerator> random(parms.random_generator()->create());

        set_poly_coeffs_zero_one_negone(u.get(), random, context_data);
        
        // Multiply both u * public_key_[0] and u * public_key_[1] using the same FFT
        for (size_t i = 0; i < coeff_mod_count; i++)
        {
            ntt_negacyclic_harvey(u.get() + (i * coeff_count), small_ntt_tables[i]);
            dyadic_product_coeffmod(
                u.get() + (i * coeff_count), 
                public_key_.get() + (i * coeff_count), 
                coeff_count,
                coeff_modulus[i], 
                destination.data() + (i * coeff_count));
            dyadic_product_coeffmod(
                u.get() + (i * coeff_count), 
                public_key_.get() + (coeff_count * first_coeff_mod_count) + (i * coeff_count),
                coeff_count,
                coeff_modulus[i], 
                destination.data(1) + (i * coeff_count));
        }

        auto tmp(allocate_uint(coeff_count, pool));
        // The plaintext gets added into the c_0 term of ciphertext (c_0,c_1).
        for (size_t i = 0; i < coeff_mod_count; i++)
        {
            add_poly_poly_coeffmod(destination.data() + (i * coeff_count),
                plain.data() + (i * coeff_count), coeff_count,
                coeff_modulus[i], destination.data() + (i * coeff_count));
        }
        
        // Generate e_0, add this value into destination[0].
        set_poly_coeffs_normal(u.get(), random, context_data);

        for (size_t i = 0; i < coeff_mod_count; i++)
        {
            ntt_negacyclic_harvey(u.get() + (i * coeff_count), small_ntt_tables[i]);
            add_poly_poly_coeffmod(u.get() + (i * coeff_count),
                destination.data() + (i * coeff_count), coeff_count,
                coeff_modulus[i], destination.data() + (i * coeff_count));
        }
        // Generate e_1, add this value into destination[1].
        set_poly_coeffs_normal(u.get(), random, context_data);

        for (size_t i = 0; i < coeff_mod_count; i++)
        {
            ntt_negacyclic_harvey(u.get() + (i * coeff_count), small_ntt_tables[i]);
            add_poly_poly_coeffmod(u.get() + (i * coeff_count),
                destination.data(1) + (i * coeff_count), coeff_count,
                coeff_modulus[i], destination.data(1) + (i * coeff_count));
        }
    }

    void Encryptor::preencrypt(const uint64_t *plain, size_t plain_coeff_count, 
        const SEALContext::ContextData &context_data, uint64_t *destination)
    {
        auto &parms = context_data.parms();
        auto &coeff_modulus = parms.coeff_modulus();
        size_t coeff_count = parms.poly_modulus_degree();
        size_t coeff_mod_count = coeff_modulus.size();

        auto coeff_div_plain_modulus = context_data.coeff_div_plain_modulus();
        auto plain_upper_half_threshold = context_data.plain_upper_half_threshold();
        auto upper_half_increment = context_data.upper_half_increment();

        // Multiply plain by scalar coeff_div_plain_modulus_ and reposition if in upper-half.
        for (size_t i = 0; i < plain_coeff_count; i++)
        {
            if (plain[i] >= plain_upper_half_threshold)
            {
                // Loop over primes
                for (size_t j = 0; j < coeff_mod_count; j++)
                {
                    unsigned long long temp[2]{ 0, 0 };
                    multiply_uint64(coeff_div_plain_modulus[j], plain[i], temp);
                    temp[1] += add_uint64(temp[0], upper_half_increment[j], 0, temp);
                    uint64_t scaled_plain_coeff = barrett_reduce_128(temp, coeff_modulus[j]);
                    destination[j * coeff_count] = add_uint_uint_mod(
                        destination[j * coeff_count], scaled_plain_coeff, coeff_modulus[j]);
                }
            }
            else
            {
                for (size_t j = 0; j < coeff_mod_count; j++)
                {
                    uint64_t scaled_plain_coeff = multiply_uint_uint_mod(
                        coeff_div_plain_modulus[j], plain[i], coeff_modulus[j]);
                    destination[j * coeff_count] = add_uint_uint_mod(
                        destination[j * coeff_count], scaled_plain_coeff, coeff_modulus[j]);
                }
            }
            destination++;
        }
    }

    void Encryptor::set_poly_coeffs_zero_one_negone(uint64_t *poly, 
        std::shared_ptr<UniformRandomGenerator> random, 
        const SEALContext::ContextData &context_data) const
    {
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

    void Encryptor::set_poly_coeffs_zero_one(uint64_t *poly,
        std::shared_ptr<UniformRandomGenerator> random, 
        const SEALContext::ContextData &context_data) const
    {
        auto &parms = context_data.parms();
        auto &coeff_modulus = parms.coeff_modulus();
        size_t coeff_count = parms.poly_modulus_degree();
        size_t coeff_mod_count = coeff_modulus.size();

        RandomToStandardAdapter engine(random);
        uniform_int_distribution<int> dist(0, 1);

        set_zero_poly(coeff_count, coeff_mod_count, poly);
        for (size_t i = 0; i < coeff_count; i++)
        {
            int rand_index = dist(engine);
            for (size_t j = 0; j < coeff_mod_count; j++)
            {
                poly[i + (j * coeff_count)] = static_cast<uint64_t>(rand_index);
            }
        }
    }

    void Encryptor::set_poly_coeffs_normal(uint64_t *poly, 
        std::shared_ptr<UniformRandomGenerator> random,
        const SEALContext::ContextData &context_data) const
    {
        auto &parms = context_data.parms();
        auto &coeff_modulus = parms.coeff_modulus();
        size_t coeff_count = parms.poly_modulus_degree();
        size_t coeff_mod_count = coeff_modulus.size();

        if ((parms.noise_standard_deviation() == 0.0) || 
            (parms.noise_max_deviation() == 0.0))
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
}
