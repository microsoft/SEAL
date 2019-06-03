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

            uint64_t max_uint64 = numeric_limits<uint64_t>::max();
            uint64_t modulus = 0;
            uint64_t max_multiple = 0;

            for (size_t j = 0; j < coeff_mod_count; j++)
            {
                modulus = coeff_modulus[j].value();
                max_multiple = max_uint64 - max_uint64 % modulus;
                for (size_t i = 0; i < coeff_count; i++)
                {
                    // This ensures uniform distribution.
                    uint64_t rand;
                    do
                    {
                        rand = (static_cast<uint64_t>(engine()) << 32) +
                            static_cast<uint64_t>(engine());
                    }
                    while (rand >= max_multiple);
                    poly[i + j * coeff_count] = rand % modulus;
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
            for (size_t j = 0; j < 2; j++)
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
                // Transform the noise e into NTT representation.
                ntt_negacyclic_harvey(
                    noise.get() + i * coeff_count,
                    small_ntt_tables[i]);
                dyadic_product_coeffmod(
                    secret_key.data().data() + i * coeff_count,
                    destination.data(1) + i * coeff_count,
                    coeff_count,
                    coeff_modulus[i],
                    destination.data() + i * coeff_count);
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
    }
}