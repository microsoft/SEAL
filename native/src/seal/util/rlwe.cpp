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
#include "seal/randomgen.h"

using namespace std;

namespace seal
{
    namespace util
    {
        void sample_poly_ternary(
            shared_ptr<UniformRandomGenerator> rng,
            const EncryptionParameters &parms,
            uint64_t *destination)
        {
            auto coeff_modulus = parms.coeff_modulus();
            size_t coeff_mod_count = coeff_modulus.size();
            size_t coeff_count = parms.poly_modulus_degree();
            RandomToStandardAdapter engine(rng);
            uniform_int_distribution<int> dist(-1, 1);

            for (size_t i = 0; i < coeff_count; i++)
            {
                int rand_index = dist(engine);
                if (rand_index == 1)
                {
                    for (size_t j = 0; j < coeff_mod_count; j++)
                    {
                        destination[i + j * coeff_count] = 1;
                    }
                }
                else if (rand_index == -1)
                {
                    for (size_t j = 0; j < coeff_mod_count; j++)
                    {
                        destination[i + j * coeff_count] = coeff_modulus[j].value() - 1;
                    }
                }
                else
                {
                    for (size_t j = 0; j < coeff_mod_count; j++)
                    {
                        destination[i + j * coeff_count] = 0;
                    }
                }
            }
        }

        void sample_poly_normal(
            shared_ptr<UniformRandomGenerator> rng,
            const EncryptionParameters &parms,
            uint64_t *destination)
        {
            auto coeff_modulus = parms.coeff_modulus();
            size_t coeff_mod_count = coeff_modulus.size();
            size_t coeff_count = parms.poly_modulus_degree();

            if (are_close(global_variables::noise_max_deviation, 0.0))
            {
                set_zero_poly(coeff_count, coeff_mod_count, destination);
                return;
            }

            RandomToStandardAdapter engine(rng);
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
                        destination[i + j * coeff_count] = static_cast<uint64_t>(noise);
                    }
                }
                else if (noise < 0)
                {
                    noise = -noise;
                    for (size_t j = 0; j < coeff_mod_count; j++)
                    {
                        destination[i + j * coeff_count] = coeff_modulus[j].value() -
                            static_cast<uint64_t>(noise);
                    }
                }
                else
                {
                    for (size_t j = 0; j < coeff_mod_count; j++)
                    {
                        destination[i + j * coeff_count] = 0;
                    }
                }
            }
        }

        void sample_poly_uniform(
            shared_ptr<UniformRandomGenerator> rng,
            const EncryptionParameters &parms,
            uint64_t *destination)
        {
            // Extract encryption parameters.
            auto coeff_modulus = parms.coeff_modulus();
            size_t coeff_mod_count = coeff_modulus.size();
            size_t coeff_count = parms.poly_modulus_degree();

            // Set up source of randomness that produces 32 bit random things.
            RandomToStandardAdapter engine(rng);

            // We sample numbers up to 2^63-1 to use barrett_reduce_63
            constexpr uint64_t max_random = static_cast<uint64_t>(0x7FFFFFFFFFFFFFFFULL);
            for (size_t j = 0; j < coeff_mod_count; j++)
            {
                auto &modulus = coeff_modulus[j];
                uint64_t max_multiple = max_random - barrett_reduce_63(max_random, modulus);
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
                    destination[i + j * coeff_count] = barrett_reduce_63(rand, modulus);
                }
            }
        }

        void encrypt_zero_asymmetric(
            const PublicKey &public_key,
            shared_ptr<SEALContext> context,
            parms_id_type parms_id,
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

            // Create RNG, u and error share one RNG.
            auto rng = parms.random_generator()->create();

            // Generate u <-- R_3
            auto u(allocate_poly(coeff_count, coeff_mod_count, pool));
            sample_poly_ternary(rng, parms, u.get());

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
                sample_poly_normal(rng, parms, u.get());
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

            // Create RNG, c[1] = a and error share one RNG.
            auto rng = parms.random_generator()->create();

            // Generate ciphertext: (c[0], c[1]) = ([-(as+e)]_q, a)

            // Sample a uniformly at random
            // Set c[1] = a (we sample the NTT form directly)
            sample_poly_uniform(rng, parms, destination.data(1));

            // Sample e <-- chi
            auto noise(allocate_poly(coeff_count, coeff_mod_count, pool));
            sample_poly_normal(rng, parms, noise.get());

            // calculate -(a*s + e) (mod q) and store in c[0]
            for (size_t i = 0; i < coeff_mod_count; i++)
            {
                dyadic_product_coeffmod(
                    secret_key.data().data() + i * coeff_count,
                    destination.data(1) + i * coeff_count,
                    coeff_count,
                    coeff_modulus[i],
                    destination.data() + i * coeff_count);
                if (is_ntt_form)
                {
                    // Transform the noise e into NTT representation.
                    ntt_negacyclic_harvey(
                        noise.get() + i * coeff_count,
                        small_ntt_tables[i]);
                }
                else
                {
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

        void encrypt_zero_symmetric_save_seed(
            const SecretKey &secret_key,
            shared_ptr<SEALContext> context,
            parms_id_type parms_id,
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

            // Create RNG, c[1] = a and error must not share an RNG.
            auto rng_ciphertext = BlakePRNGFactory().create();
            random_seed_type seed = rng_ciphertext->seed();
            auto rng_error = parms.random_generator()->create();

            // Generate ciphertext: (c[0], c[1]) = ([-(as+e)]_q, a)

            uint64_t *c0 = destination.data();
            uint64_t *c1 = destination.data(1);

            // Sample a uniformly at random
            // Set c[1] = a (we sample the NTT form directly)
            sample_poly_uniform(rng_ciphertext, parms, c1);

            // Sample e <-- chi
            auto noise(allocate_poly(coeff_count, coeff_mod_count, pool));
            sample_poly_normal(rng_error, parms, noise.get());

            // calculate -(a*s + e) (mod q) and store in c[0]
            for (size_t i = 0; i < coeff_mod_count; i++)
            {
                dyadic_product_coeffmod(
                    secret_key.data().data() + i * coeff_count,
                    c1 + i * coeff_count,
                    coeff_count,
                    coeff_modulus[i],
                    c0 + i * coeff_count);
                if (is_ntt_form)
                {
                    // Transform the noise e into NTT representation.
                    ntt_negacyclic_harvey(
                        noise.get() + i * coeff_count,
                        small_ntt_tables[i]);
                }
                else
                {
                    inverse_ntt_negacyclic_harvey(
                        c0 + i * coeff_count,
                        small_ntt_tables[i]);
                }
                add_poly_poly_coeffmod(
                    noise.get() + i * coeff_count,
                    c0 + i * coeff_count,
                    coeff_count,
                    coeff_modulus[i],
                    c0 + i * coeff_count);
                negate_poly_coeffmod(
                    c0 + i * coeff_count,
                    coeff_count,
                    coeff_modulus[i],
                    c0 + i * coeff_count);
            }

            // Write random seed to destination.data(1).
            c1[0] = static_cast<uint64_t>(0xffffffffffffffffULL);
            for (size_t i = 0; i < seed.size(); i++)
            {
                c1[i + 1] = seed[i];
            }
        }
    }
}
