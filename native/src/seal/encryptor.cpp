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
#include "seal/util/rlwe.h"

using namespace std;
using namespace seal::util;

namespace seal
{
    Encryptor::Encryptor(shared_ptr<SEALContext> context,
        const PublicKey &public_key) : context_(move(context)),
        public_key_(public_key)
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
    }

    void Encryptor::encrypt_zero(parms_id_type parms_id,
        Ciphertext &destination,
        MemoryPoolHandle pool)
    {
        // Verify parameters.
        auto context_data_ptr = context_->get_context_data(parms_id);
        if (!context_data_ptr)
        {
            throw invalid_argument("parms_id is not valid for encryption parameters");
        }

        auto &context_data = *context_->get_context_data(parms_id);
        auto &parms = context_data.parms();
        size_t coeff_mod_count = parms.coeff_modulus().size();
        size_t coeff_count = parms.poly_modulus_degree();

        bool is_ntt_form = false;
        if (parms.scheme() == scheme_type::CKKS)
        {
            is_ntt_form = true;
        }
        else if (parms.scheme() != scheme_type::BFV)
        {
            throw invalid_argument("unsupported scheme");
        }

        shared_ptr<UniformRandomGenerator> random(
            parms.random_generator()->create());

        // Resize destination and save results
        destination.resize(context_, parms_id, 2);

        auto prev_context_data_ptr = context_data.prev_context_data();
        auto &prev_context_data = *prev_context_data_ptr;
        if (prev_context_data_ptr)
        {
            auto &prev_parms_id = prev_context_data.parms_id();
            auto &base_converter = prev_context_data.base_converter();

            // Zero encryption without modulus switching
            Ciphertext temp(pool);
            encrypt_zero_asymmetric(public_key_, context_, prev_parms_id,
                random, is_ntt_form, temp, pool);
            if (temp.is_ntt_form() != is_ntt_form)
            {
                throw invalid_argument("NTT form mismatch");
            }

            // Modulus switching
            for (size_t j = 0; j < 2; j++)
            {
                if (is_ntt_form)
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

            destination.is_ntt_form() = is_ntt_form;

            // Need to set the scale here since encrypt_zero_asymmetric only sets
            // it for temp
            destination.scale() = temp.scale();
        }
        else
        {
            encrypt_zero_asymmetric(public_key_, context_,
                parms_id, random, is_ntt_form, destination, pool);
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
        if (!is_valid_for(plain, context_))
        {
            throw invalid_argument("plain is not valid for encryption parameters");
        }

        auto scheme = context_->key_context_data()->parms().scheme();
        if (scheme == scheme_type::BFV)
        {
            if (plain.is_ntt_form())
            {
                throw invalid_argument("plain cannot be in NTT form");
            }

            encrypt_zero(context_->first_parms_id(), destination);

            // Multiply plain by scalar coeff_div_plaintext and reposition if in upper-half.
            // Result gets added into the c_0 term of ciphertext (c_0,c_1).
            preencrypt(plain.data(),
                plain.coeff_count(),
                *context_->first_context_data(),
                destination.data());
        }
        else if (scheme == scheme_type::CKKS)
        {
            if (!plain.is_ntt_form())
            {
                throw invalid_argument("plain must be in NTT form");
            }
            auto context_data_ptr = context_->get_context_data(plain.parms_id());
            if (!context_data_ptr)
            {
                throw invalid_argument("plain is not valid for encryption parameters");
            }
            auto &context_data = *context_->get_context_data(plain.parms_id());
            auto &parms = context_data.parms();
            auto &coeff_modulus = parms.coeff_modulus();
            size_t coeff_mod_count = coeff_modulus.size();
            size_t coeff_count = parms.poly_modulus_degree();

            encrypt_zero(context_data.parms_id(), destination);

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
        else
        {
            throw invalid_argument("unsupported scheme");
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
