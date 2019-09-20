// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include "seal/randomtostd.h"
#include "seal/util/rlwe.h"
#include "seal/util/common.h"
#include "seal/util/clipnormal.h"
#include "seal/util/polycore.h"
#include "seal/util/smallntt.h"
#include "seal/util/polyarithsmallmod.h"
#include "seal/util/globals.h"

using namespace std;

namespace seal
{
    namespace util
    {
        void sample_poly_ternary(
            uint64_t *poly,
            shared_ptr<UniformRandomGenerator> random,
            const EncryptionParameters &parms)
        {
            auto coeff_modulus = parms.coeff_modulus();
            size_t coeff_mod_count = coeff_modulus.size();
            size_t coeff_count = parms.poly_modulus_degree();
            RandomToStandardAdapter engine(random);
            uniform_int_distribution<int> dist(-1, 1);

            for (size_t i = 0; i < coeff_count; i++)
            {
                int rand_index = dist(engine);
                if (rand_index == 1)
                {
                    for (size_t j = 0; j < coeff_mod_count; j++)
                    {
                        poly[i + j * coeff_count] = 1;
                    }
                }
                else if (rand_index == -1)
                {
                    for (size_t j = 0; j < coeff_mod_count; j++)
                    {
                        poly[i + j * coeff_count] = coeff_modulus[j].value() - 1;
                    }
                }
                else
                {
                    for (size_t j = 0; j < coeff_mod_count; j++)
                    {
                        poly[i + j * coeff_count] = 0;
                    }
                }
            }
        }

        void sample_poly_normal(
            uint64_t *poly,
            shared_ptr<UniformRandomGenerator> random,
            const EncryptionParameters &parms)
        {
            auto coeff_modulus = parms.coeff_modulus();
            size_t coeff_mod_count = coeff_modulus.size();
            size_t coeff_count = parms.poly_modulus_degree();

            if (are_close(global_variables::noise_max_deviation, 0.0))
            {
                set_zero_poly(coeff_count, coeff_mod_count, poly);
                return;
            }

            RandomToStandardAdapter engine(random);
            ClippedNormalDistribution dist(
                0, global_variables::noise_standard_deviation,
                global_variables::noise_max_deviation);
            for (size_t i = 0; i < coeff_count; i++)
            {
                int64_t noise = static_cast<int64_t>(dist(engine));
                if (noise > 0)
                {
                    for (size_t j = 0; j < coeff_mod_count; j++)
                    {
                        poly[i + j * coeff_count] = static_cast<uint64_t>(noise);
                    }
                }
                else if (noise < 0)
                {
                    noise = -noise;
                    for (size_t j = 0; j < coeff_mod_count; j++)
                    {
                        poly[i + j * coeff_count] = coeff_modulus[j].value() -
                            static_cast<uint64_t>(noise);
                    }
                }
                else
                {
                    for (size_t j = 0; j < coeff_mod_count; j++)
                    {
                        poly[i + j * coeff_count] = 0;
                    }
                }
            }
        }

        void sample_poly_uniform(
            uint64_t *poly,
            shared_ptr<UniformRandomGenerator> random,
            const EncryptionParameters &parms)
        {
            // Extract encryption parameters.
            auto coeff_modulus = parms.coeff_modulus();
            size_t coeff_mod_count = coeff_modulus.size();
            size_t coeff_count = parms.poly_modulus_degree();

            // Set up source of randomness that produces 32 bit random things.
            RandomToStandardAdapter engine(random);

            // We sample numbers up to 2^63-1 to use barrett_reduce_63
            constexpr uint64_t max_random =
                numeric_limits<uint64_t>::max() & uint64_t(0x7FFFFFFFFFFFFFFF);
            for (size_t j = 0; j < coeff_mod_count; j++)
            {
                auto &modulus = coeff_modulus[j];
                uint64_t max_multiple = max_random - max_random % modulus.value();
                for (size_t i = 0; i < coeff_count; i++)
                {
                    // This ensures uniform distribution.
                    uint64_t rand;
                    do
                    {
                        rand = (static_cast<uint64_t>(engine()) << 31) |
                            (static_cast<uint64_t>(engine() >> 1));
                    }
                    while (rand >= max_multiple);
                    poly[i + j * coeff_count] = barrett_reduce_63(rand, modulus);
                }
            }
        }

        void encrypt_zero_asymmetric(
            const PublicKey &public_key,
            shared_ptr<SEALContext> context,
            parms_id_type parms_id,
            shared_ptr<UniformRandomGenerator> random,
            bool is_ntt_form,
            Ciphertext &destination,
            MemoryPoolHandle pool)
        {
            if (!pool)
            {
                throw invalid_argument("pool is uninitialized");
            }
            if (public_key.parms_id() != context->key_parms_id())
            {
                throw invalid_argument("key_parms_id mismatch");
            }

            auto &context_data = *context->get_context_data(parms_id);
            auto &parms = context_data.parms();
            auto &coeff_modulus = parms.coeff_modulus();
            size_t coeff_mod_count = coeff_modulus.size();
            size_t coeff_count = parms.poly_modulus_degree();
            auto &small_ntt_tables = context_data.small_ntt_tables();
            size_t encrypted_size = public_key.data().size();

            if (encrypted_size < 2)
            {
                throw invalid_argument("public_key has less than 2 parts");
            }

            // Make destination have right size and parms_id
            // Ciphertext (c_0,c_1, ...)
            destination.resize(context, parms_id, encrypted_size);
            destination.is_ntt_form() = is_ntt_form;
            destination.scale() = 1.0;

            // c[j] = public_key[j] * u + e[j] where e[j] <-- chi, u <-- R_3.

            // Generate u <-- R_3
            auto u(allocate_poly(coeff_count, coeff_mod_count, pool));
            sample_poly_ternary(u.get(), random, parms);

            // c[j] = u * public_key[j]
            for (size_t i = 0; i < coeff_mod_count; i++)
            {
                ntt_negacyclic_harvey(
                    u.get() + i * coeff_count,
                    small_ntt_tables[i]);
                for (size_t j = 0; j < encrypted_size; j++)
                {
                    dyadic_product_coeffmod(
                        u.get() + i * coeff_count,
                        public_key.data().data(j) + i * coeff_count,
                        coeff_count,
                        coeff_modulus[i],
                        destination.data(j) + i * coeff_count);

                    // addition with e_0, e_1 is in non-NTT form.
                    if (!is_ntt_form)
                    {
                        inverse_ntt_negacyclic_harvey(
                            destination.data(j) + i * coeff_count,
                            small_ntt_tables[i]);
                    }
                }
            }

            // Generate e_j <-- chi.
            // c[j] = public_key[j] * u + e[j]
            for (size_t j = 0; j < encrypted_size; j++)
            {
                sample_poly_normal(u.get(), random, parms);
                for (size_t i = 0; i < coeff_mod_count; i++)
                {
                    // addition with e_0, e_1 is in NTT form.
                    if (is_ntt_form)
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
        }

        void encrypt_zero_symmetric(
            const SecretKey &secret_key,
            shared_ptr<SEALContext> context,
            parms_id_type parms_id,
            shared_ptr<UniformRandomGenerator> random,
            bool is_ntt_form,
            Ciphertext &destination,
            MemoryPoolHandle pool)
        {
            if (!pool)
            {
                throw invalid_argument("pool is uninitialized");
            }
            if (secret_key.parms_id() != context->key_parms_id())
            {
                throw invalid_argument("key_parms_id mismatch");
            }
            auto &context_data = *context->get_context_data(parms_id);
            auto &parms = context_data.parms();
            auto &coeff_modulus = parms.coeff_modulus();
            size_t coeff_mod_count = coeff_modulus.size();
            size_t coeff_count = parms.poly_modulus_degree();
            auto &small_ntt_tables = context_data.small_ntt_tables();
            size_t encrypted_size = 2;

            destination.resize(context, parms_id, encrypted_size);
            destination.is_ntt_form() = is_ntt_form;
            destination.scale() = 1.0;

            // Generate ciphertext: (c[0], c[1]) = ([-(as+e)]_q, a)

            // Sample a uniformly at random
            // Set c[1] = a (we sample the NTT form directly)
            sample_poly_uniform(destination.data(1), random, parms);

            // Sample e <-- chi
            auto noise(allocate_poly(coeff_count, coeff_mod_count, pool));
            sample_poly_normal(noise.get(), random, parms);

            // calculate -(a*s + e) (mod q) and store in c[0]
            for (size_t i = 0; i < coeff_mod_count; i++)
            {
                dyadic_product_coeffmod(
                    secret_key.data().data() + i * coeff_count,
                    destination.data(1) + i * coeff_count,
                    coeff_count,
                    coeff_modulus[i],
                    destination.data() + i * coeff_count);
                if (is_ntt_form) {
                    // Transform the noise e into NTT representation.
                    ntt_negacyclic_harvey(
                        noise.get() + i * coeff_count,
                        small_ntt_tables[i]);
                }
                else {
                    inverse_ntt_negacyclic_harvey(
                        destination.data() + i * coeff_count,
                        small_ntt_tables[i]);
                }
                add_poly_poly_coeffmod(
                    noise.get() + i * coeff_count,
                    destination.data() + i * coeff_count,
                    coeff_count,
                    coeff_modulus[i],
                    destination.data() + i * coeff_count);
                negate_poly_coeffmod(
                    destination.data() + i * coeff_count,
                    coeff_count,
                    coeff_modulus[i],
                    destination.data() + i * coeff_count);
            }
        }

        void multiply_plain_with_scaling_variant(
            const uint64_t *plain, size_t plain_coeff_count,
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

        void divide_plain_by_scaling_variant(std::uint64_t *plain,
            const SEALContext::ContextData &context_data, std::uint64_t *destination,
            MemoryPoolHandle pool)
        {
            auto &parms = context_data.parms();
            auto &coeff_modulus = parms.coeff_modulus();
            size_t coeff_count = parms.poly_modulus_degree();
            size_t coeff_mod_count = coeff_modulus.size();

            auto &base_converter = context_data.base_converter();
            auto &plain_gamma_product = base_converter->get_plain_gamma_product();
            auto &plain_gamma_array = base_converter->get_plain_gamma_array();
            auto &neg_inv_coeff = base_converter->get_neg_inv_coeff();
            auto inv_gamma = base_converter->get_inv_gamma();

            // The number of uint64 count for plain_modulus and gamma together
            size_t plain_gamma_uint64_count = 2;

            // Compute |gamma * plain|qi * ct(s)
            for (size_t i = 0; i < coeff_mod_count; i++)
            {
                multiply_poly_scalar_coeffmod(plain + (i * coeff_count), coeff_count,
                    plain_gamma_product[i], coeff_modulus[i], plain + (i * coeff_count));
            }

            // Make another temp destination to get the poly in mod {gamma U plain_modulus}
            auto tmp_dest_plain_gamma(allocate_poly(coeff_count, plain_gamma_uint64_count, pool));

            // Compute FastBConvert from q to {gamma, plain_modulus}
            base_converter->fastbconv_plain_gamma(plain, tmp_dest_plain_gamma.get(), pool);

            // Compute result multiply by coeff_modulus inverse in mod {gamma U plain_modulus}
            for (size_t i = 0; i < plain_gamma_uint64_count; i++)
            {
                multiply_poly_scalar_coeffmod(tmp_dest_plain_gamma.get() + (i * coeff_count),
                    coeff_count, neg_inv_coeff[i], plain_gamma_array[i],
                    tmp_dest_plain_gamma.get() + (i * coeff_count));
            }

            // First correct the values which are larger than floor(gamma/2)
            uint64_t gamma_div_2 = plain_gamma_array[1].value() >> 1;

            // Now compute the subtraction to remove error and perform final multiplication by
            // gamma inverse mod plain_modulus
            for (size_t i = 0; i < coeff_count; i++)
            {
                // Need correction beacuse of center mod
                if (tmp_dest_plain_gamma[i + coeff_count] > gamma_div_2)
                {
                    // Compute -(gamma - a) instead of (a - gamma)
                    tmp_dest_plain_gamma[i + coeff_count] = plain_gamma_array[1].value() -
                        tmp_dest_plain_gamma[i + coeff_count];
                    tmp_dest_plain_gamma[i + coeff_count] %= plain_gamma_array[0].value();
                    destination[i] = add_uint_uint_mod(tmp_dest_plain_gamma[i],
                        tmp_dest_plain_gamma[i + coeff_count], plain_gamma_array[0]);
                }
                // No correction needed
                else
                {
                    tmp_dest_plain_gamma[i + coeff_count] %= plain_gamma_array[0].value();
                    destination[i] = sub_uint_uint_mod(tmp_dest_plain_gamma[i],
                        tmp_dest_plain_gamma[i + coeff_count], plain_gamma_array[0]);
                }
            }
        }
    }
}
