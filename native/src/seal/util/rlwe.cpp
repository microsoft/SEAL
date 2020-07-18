// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include "seal/ciphertext.h"
#include "seal/randomgen.h"
#include "seal/randomtostd.h"
#include "seal/util/clipnormal.h"
#include "seal/util/common.h"
#include "seal/util/globals.h"
#include "seal/util/ntt.h"
#include "seal/util/polyarithsmallmod.h"
#include "seal/util/polycore.h"
#include "seal/util/rlwe.h"

using namespace std;

namespace seal
{
    namespace util
    {
        void sample_poly_ternary(
            shared_ptr<UniformRandomGenerator> rng, const EncryptionParameters &parms, uint64_t *destination)
        {
            auto coeff_modulus = parms.coeff_modulus();
            size_t coeff_modulus_size = coeff_modulus.size();
            size_t coeff_count = parms.poly_modulus_degree();
            RandomToStandardAdapter engine(rng);
            uniform_int_distribution<int> dist(-1, 1);

            for (size_t i = 0; i < coeff_count; i++)
            {
                int rand_index = dist(engine);
                if (rand_index == 1)
                {
                    for (size_t j = 0; j < coeff_modulus_size; j++)
                    {
                        destination[i + j * coeff_count] = 1;
                    }
                }
                else if (rand_index == -1)
                {
                    for (size_t j = 0; j < coeff_modulus_size; j++)
                    {
                        destination[i + j * coeff_count] = coeff_modulus[j].value() - 1;
                    }
                }
                else
                {
                    for (size_t j = 0; j < coeff_modulus_size; j++)
                    {
                        destination[i + j * coeff_count] = 0;
                    }
                }
            }
        }

        void sample_poly_normal(
            shared_ptr<UniformRandomGenerator> rng, const EncryptionParameters &parms, uint64_t *destination)
        {
            auto coeff_modulus = parms.coeff_modulus();
            size_t coeff_modulus_size = coeff_modulus.size();
            size_t coeff_count = parms.poly_modulus_degree();

            if (are_close(global_variables::noise_max_deviation, 0.0))
            {
                set_zero_poly(coeff_count, coeff_modulus_size, destination);
                return;
            }

            RandomToStandardAdapter engine(rng);
            ClippedNormalDistribution dist(
                0, global_variables::noise_standard_deviation, global_variables::noise_max_deviation);
            for (size_t i = 0; i < coeff_count; i++)
            {
                int64_t noise = static_cast<int64_t>(dist(engine));
                if (noise > 0)
                {
                    for (size_t j = 0; j < coeff_modulus_size; j++)
                    {
                        destination[i + j * coeff_count] = static_cast<uint64_t>(noise);
                    }
                }
                else if (noise < 0)
                {
                    noise = -noise;
                    for (size_t j = 0; j < coeff_modulus_size; j++)
                    {
                        destination[i + j * coeff_count] = coeff_modulus[j].value() - static_cast<uint64_t>(noise);
                    }
                }
                else
                {
                    for (size_t j = 0; j < coeff_modulus_size; j++)
                    {
                        destination[i + j * coeff_count] = 0;
                    }
                }
            }
        }

        void sample_poly_uniform(
            shared_ptr<UniformRandomGenerator> rng, const EncryptionParameters &parms, uint64_t *destination)
        {
            // Extract encryption parameters.
            auto coeff_modulus = parms.coeff_modulus();
            size_t coeff_modulus_size = coeff_modulus.size();
            size_t coeff_count = parms.poly_modulus_degree();

            // Set up source of randomness that produces 32 bit random things.
            RandomToStandardAdapter engine(rng);

            constexpr uint64_t max_random = static_cast<uint64_t>(0xFFFFFFFFFFFFFFFFULL);
            for (size_t j = 0; j < coeff_modulus_size; j++)
            {
                auto &modulus = coeff_modulus[j];
                uint64_t max_multiple = max_random - barrett_reduce_64(max_random, modulus) - 1;
                for (size_t i = 0; i < coeff_count; i++)
                {
                    // This ensures uniform distribution.
                    uint64_t rand;
                    do
                    {
                        rand = (static_cast<uint64_t>(engine()) << 32) | static_cast<uint64_t>(engine());
                    } while (rand >= max_multiple);
                    destination[i + j * coeff_count] = barrett_reduce_64(rand, modulus);
                }
            }
        }

        void encrypt_zero_asymmetric(
            const PublicKey &public_key, shared_ptr<SEALContext> context, parms_id_type parms_id, bool is_ntt_form,
            Ciphertext &destination)
        {
#ifdef SEAL_DEBUG
            if (!is_valid_for(public_key, context))
            {
                throw invalid_argument("public key is not valid for the encryption parameters");
            }
#endif
            // We use a fresh memory pool with `clear_on_destruction' enabled.
            MemoryPoolHandle pool = MemoryManager::GetPool(mm_prof_opt::FORCE_NEW, true);

            auto &context_data = *context->get_context_data(parms_id);
            auto &parms = context_data.parms();
            auto &coeff_modulus = parms.coeff_modulus();
            size_t coeff_modulus_size = coeff_modulus.size();
            size_t coeff_count = parms.poly_modulus_degree();
            auto ntt_tables = context_data.small_ntt_tables();
            size_t encrypted_size = public_key.data().size();

            // Make destination have right size and parms_id
            // Ciphertext (c_0,c_1, ...)
            destination.resize(context, parms_id, encrypted_size);
            destination.is_ntt_form() = is_ntt_form;
            destination.scale() = 1.0;

            // c[j] = public_key[j] * u + e[j] where e[j] <-- chi, u <-- R_3.

            // Create RNG, u and error share one RNG.
            auto rng = parms.random_generator()->create();

            // Generate u <-- R_3
            auto u(allocate_poly(coeff_count, coeff_modulus_size, pool));
            sample_poly_ternary(rng, parms, u.get());

            // c[j] = u * public_key[j]
            for (size_t i = 0; i < coeff_modulus_size; i++)
            {
                ntt_negacyclic_harvey(u.get() + i * coeff_count, ntt_tables[i]);
                for (size_t j = 0; j < encrypted_size; j++)
                {
                    dyadic_product_coeffmod(
                        u.get() + i * coeff_count, public_key.data().data(j) + i * coeff_count, coeff_count,
                        coeff_modulus[i], destination.data(j) + i * coeff_count);

                    // Addition with e_0, e_1 is in non-NTT form.
                    if (!is_ntt_form)
                    {
                        inverse_ntt_negacyclic_harvey(destination.data(j) + i * coeff_count, ntt_tables[i]);
                    }
                }
            }

            // Generate e_j <-- chi.
            // c[j] = public_key[j] * u + e[j]
            for (size_t j = 0; j < encrypted_size; j++)
            {
                sample_poly_normal(rng, parms, u.get());
                for (size_t i = 0; i < coeff_modulus_size; i++)
                {
                    // Addition with e_0, e_1 is in NTT form.
                    if (is_ntt_form)
                    {
                        ntt_negacyclic_harvey(u.get() + i * coeff_count, ntt_tables[i]);
                    }
                    add_poly_coeffmod(
                        u.get() + i * coeff_count, destination.data(j) + i * coeff_count, coeff_count, coeff_modulus[i],
                        destination.data(j) + i * coeff_count);
                }
            }
        }

        void encrypt_zero_symmetric(
            const SecretKey &secret_key, shared_ptr<SEALContext> context, parms_id_type parms_id, bool is_ntt_form,
            bool save_seed, Ciphertext &destination)
        {
#ifdef SEAL_DEBUG
            if (!is_valid_for(secret_key, context))
            {
                throw invalid_argument("secret key is not valid for the encryption parameters");
            }
#endif
            // We use a fresh memory pool with `clear_on_destruction' enabled.
            MemoryPoolHandle pool = MemoryManager::GetPool(mm_prof_opt::FORCE_NEW, true);

            auto &context_data = *context->get_context_data(parms_id);
            auto &parms = context_data.parms();
            auto &coeff_modulus = parms.coeff_modulus();
            size_t coeff_modulus_size = coeff_modulus.size();
            size_t coeff_count = parms.poly_modulus_degree();
            auto ntt_tables = context_data.small_ntt_tables();
            size_t encrypted_size = 2;

            // If a polynomial is too small to store a seed, disable save_seed.
            auto poly_uint64_count = mul_safe(coeff_count, coeff_modulus_size);
            if (save_seed && static_cast<uint64_t>(poly_uint64_count) < (random_seed_type().size() + 1))
            {
                save_seed = false;
            }

            destination.resize(context, parms_id, encrypted_size);
            destination.is_ntt_form() = is_ntt_form;
            destination.scale() = 1.0;

            // Create an instance of a random number generator. We use this for sampling a seed for a second BlakePRNG
            // used for sampling u (the seed can be public information. This RNG is also used for sampling the error.
            auto bootstrap_rng = parms.random_generator()->create();

            // Sample a seed for generating uniform randomness for the ciphertext; this seed is public information
            random_seed_type public_rng_seed;
            bootstrap_rng->generate(sizeof(random_seed_type), reinterpret_cast<SEAL_BYTE *>(public_rng_seed.data()));

            // Create a BlakePRNG for sampling u
            auto ciphertext_rng = BlakePRNGFactory(public_rng_seed).create();

            // Generate ciphertext: (c[0], c[1]) = ([-(as+e)]_q, a)
            uint64_t *c0 = destination.data();
            uint64_t *c1 = destination.data(1);

            // Sample a uniformly at random
            if (is_ntt_form || !save_seed)
            {
                // Sample the NTT form directly
                sample_poly_uniform(ciphertext_rng, parms, c1);
            }
            else if (save_seed)
            {
                // Sample non-NTT form and store the seed
                sample_poly_uniform(ciphertext_rng, parms, c1);
                for (size_t i = 0; i < coeff_modulus_size; i++)
                {
                    // Transform the c1 into NTT representation.
                    ntt_negacyclic_harvey(c1 + i * coeff_count, ntt_tables[i]);
                }
            }

            // Sample e <-- chi
            auto noise(allocate_poly(coeff_count, coeff_modulus_size, pool));
            sample_poly_normal(bootstrap_rng, parms, noise.get());

            // Calculate -(a*s + e) (mod q) and store in c[0]
            for (size_t i = 0; i < coeff_modulus_size; i++)
            {
                dyadic_product_coeffmod(
                    secret_key.data().data() + i * coeff_count, c1 + i * coeff_count, coeff_count, coeff_modulus[i],
                    c0 + i * coeff_count);
                if (is_ntt_form)
                {
                    // Transform the noise e into NTT representation.
                    ntt_negacyclic_harvey(noise.get() + i * coeff_count, ntt_tables[i]);
                }
                else
                {
                    inverse_ntt_negacyclic_harvey(c0 + i * coeff_count, ntt_tables[i]);
                }
                add_poly_coeffmod(
                    noise.get() + i * coeff_count, c0 + i * coeff_count, coeff_count, coeff_modulus[i],
                    c0 + i * coeff_count);
                negate_poly_coeffmod(c0 + i * coeff_count, coeff_count, coeff_modulus[i], c0 + i * coeff_count);
            }

            if (!is_ntt_form && !save_seed)
            {
                for (size_t i = 0; i < coeff_modulus_size; i++)
                {
                    // Transform the c1 into non-NTT representation.
                    inverse_ntt_negacyclic_harvey(c1 + i * coeff_count, ntt_tables[i]);
                }
            }

            if (save_seed)
            {
                // Write random seed to destination.data(1).
                c1[0] = static_cast<uint64_t>(0xFFFFFFFFFFFFFFFFULL);
                copy_n(public_rng_seed.cbegin(), public_rng_seed.size(), c1 + 1);
            }
        }
    } // namespace util
} // namespace seal
