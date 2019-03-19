// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <algorithm>
#include <stdexcept>
#include "seal/encryptor.h"
#include "seal/randomgen.h"
#include "seal/randomtostd.h"
#include "seal/smallmodulus.h"
#include "seal/util/common.h"
#include "seal/util/uintarith.h"
#include "seal/util/polyarithsmallmod.h"
#include "seal/util/clipnormal.h"
#include "seal/util/smallntt.h"
#include "seal/util/polyrandom.h"

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
        if (!context_->key_context_data()->qualifiers().parameters_set)
        {
            throw invalid_argument("encryption parameters are not set correctly");
        }
        if (public_key.parms_id() != context_->key_parms_id())
        {
            throw invalid_argument("public key is not valid for encryption parameters");
        }

        auto &parms = context_->key_context_data()->parms();
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

    void Encryptor::encrypt_zero_internal(Ciphertext &destination,
            parms_id_type parms_id,
            MemoryPoolHandle pool)
    {
        // Verify parameters.
        if (!pool)
        {
            throw invalid_argument("pool is uninitialized");
        }

        auto &context_data = *context_->context_data(parms_id);
        auto &parms = context_data.parms();
        if (parms.scheme() != scheme_type::BFV &&
            parms.scheme() != scheme_type::CKKS)
        {
            throw invalid_argument("unsupported scheme");
        }

        auto &coeff_modulus = parms.coeff_modulus();
        size_t coeff_mod_count = coeff_modulus.size();
        size_t key_rns_mod_count = context_->key_context_data()->parms().coeff_modulus().size();
        size_t coeff_count = parms.poly_modulus_degree();
        auto &small_ntt_tables = context_data.small_ntt_tables();
        shared_ptr<UniformRandomGenerator> random(parms.random_generator()->create());

        // Make destination have right size and parms_id
        destination.resize(context_, parms_id, 2);

        // Multiply both u * public_key_[0] and u * public_key_[1]
        uint64_t *public_key[2] = {
                public_key_.get(),
                public_key_.get() + coeff_count * key_rns_mod_count };

        // Ciphertext (c_0,c_1)
        // c_0 = public_key_[0] * u + e_0 where e_0 <-- chi, u <-- R_3.
        // c_1 = public_key_[1] * u + e_1 where e_1 <-- chi.

        // Generate u <-- R_3
        auto u(allocate_poly(coeff_count, coeff_mod_count, pool));
        sample_poly_ternary(u.get(), random, parms);
        // c_0 = public_key[0] * u
        // c_1 = public_key[1] * u
        for (size_t i = 0; i < coeff_mod_count; i++)
        {
            ntt_negacyclic_harvey(
                    u.get() + i * coeff_count,
                    small_ntt_tables[i]);
            for (size_t j = 0; j < 2; j ++)
            {
                dyadic_product_coeffmod(
                        u.get() + i * coeff_count,
                        public_key[j] + i * coeff_count,
                        coeff_count,
                        coeff_modulus[i],
                        destination.data(j) + i * coeff_count);
                // For BFV, addition with e_0, e_1 is in non-NTT form.
                if (parms.scheme() == scheme_type::BFV)
                {
                    inverse_ntt_negacyclic_harvey(
                            destination.data(j) + i * coeff_count,
                            small_ntt_tables[i]);
                }
            }
        }

        // Generate e_0, e_1 <-- chi.
        // c_0 = public_key[0] * u + e_0
        // c_1 = public_key[1] * u + e_1
        for (size_t j = 0; j < 2; j ++)
        {
            sample_poly_normal(u.get(), random, parms);
            for (size_t i = 0; i < coeff_mod_count; i++)
            {
                // For CKKS, addition with e_0, e_1 is in NTT form.
                if (parms.scheme() == scheme_type::CKKS)
                {
                    ntt_negacyclic_harvey(
                            u.get() + i * coeff_count,
                            small_ntt_tables[i]);
                }
                add_poly_poly_coeffmod(
                        u.get() + i * coeff_count, 
                        destination.data(j) + i * coeff_count,
                        coeff_count,
                        coeff_modulus[i],
                        destination.data(j) + i * coeff_count);
            }
        }

        if (parms.scheme() == scheme_type::BFV)
        {
            destination.is_ntt_form() = false;
        }
        else if (parms.scheme() == scheme_type::CKKS)
        {
            destination.is_ntt_form() = true;
        }
    }

    void Encryptor::encrypt_zero(Ciphertext &destination,
            parms_id_type parms_id,
            MemoryPoolHandle pool)
    {
        auto &context_data = *context_->context_data(parms_id);
        auto &parms = context_data.parms();
        size_t coeff_mod_count = parms.coeff_modulus().size();

        size_t coeff_count = parms.poly_modulus_degree();
        // resize destination and save results
        destination.resize(context_, parms_id, 2);

        auto prev_context_data_ptr = context_data.prev_context_data();
        auto &prev_context_data = *prev_context_data_ptr;
        if (prev_context_data_ptr)
        {
            auto &prev_parms_id = prev_context_data.parms().parms_id();
            auto &base_converter = prev_context_data.base_converter();
            // zero encryption without modulus switching
            Ciphertext temp;
            encrypt_zero_internal(temp, prev_parms_id);

            // modulus switching
            for (size_t j = 0; j < 2; j ++)
            {
                if (temp.is_ntt_form())
                {
                    base_converter->floor_last_coeff_modulus_ntt_inplace(
                            temp.data(j),
                            prev_context_data.small_ntt_tables(),
                            pool);
                }
                else
                {
                    base_converter->floor_last_coeff_modulus_inplace(
                            temp.data(j),
                            pool);
                }
                set_poly_poly(
                        temp.data(j),
                        coeff_count,
                        coeff_mod_count,
                        destination.data(j));
            }
            destination.is_ntt_form() = temp.is_ntt_form();
            return;
        }
        else
        {
            encrypt_zero_internal(destination, parms_id);
            return;
        }
    }

    void Encryptor::encrypt(const Plaintext &plain, 
            Ciphertext &destination,
            MemoryPoolHandle pool)
    {
        // Verify parameters.
        if (!pool)
        {
            throw invalid_argument("pool is uninitialized");
        }
        // Verify that plain is valid.
        if (!plain.is_valid_for(context_))
        {
            throw invalid_argument("plain is not valid for encryption parameters");
        }

        auto scheme = context_->data_context_data_head()->parms().scheme();

        if (scheme == scheme_type::BFV)
        {
            if (plain.is_ntt_form())
            {
                throw invalid_argument("plain cannot be in NTT form");
            }
            
            encrypt_zero(destination, context_->data_parms_id_head());
            // Multiply plain by scalar coeff_div_plaintext and reposition if in upper-half.
            // Result gets added into the c_0 term of ciphertext (c_0,c_1).
            preencrypt(plain.data(),
                    plain.coeff_count(),
                    *context_->data_context_data_head(),
                    destination.data());
        }
        else if (scheme == scheme_type::CKKS)
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
            auto &context_data = *context_->context_data(plain.parms_id());
            auto &parms = context_data.parms();
            auto &coeff_modulus = parms.coeff_modulus();
            size_t coeff_mod_count = coeff_modulus.size();
            size_t coeff_count = parms.poly_modulus_degree();
            
            encrypt_zero(destination, parms.parms_id());
            // The plaintext gets added into the c_0 term of ciphertext (c_0,c_1).
            for (size_t i = 0; i < coeff_mod_count; i++)
            {
                add_poly_poly_coeffmod(
                        destination.data() + (i * coeff_count),
                        plain.data() + (i * coeff_count),
                        coeff_count,
                        coeff_modulus[i],
                        destination.data() + (i * coeff_count));
            }
            destination.scale() = plain.scale();
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
        for (size_t i = 0; i < plain_coeff_count; i++, destination++)
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
        }
    }

}
