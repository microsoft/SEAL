// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include "seal/util/random.h"
#include "seal/randomtostd.h"
#include "seal/util/clipnormal.h"
#include "seal/util/polycore.h"

using namespace std;

namespace seal
{
    namespace util
    {
        void sample_poly_ternary(
            uint64_t *poly,
            std::shared_ptr<UniformRandomGenerator> random,
            const EncryptionParameters &parms)
        {
            auto coeff_modulus = parms.coeff_modulus();
            size_t coeff_mod_count = coeff_modulus.size();
            size_t coeff_count = parms.poly_modulus_degree();
            RandomToStandardAdapter engine(random);
            std::uniform_int_distribution<int> dist(-1, 1);
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
                        poly[i + j * coeff_count] =
                                coeff_modulus[j].value() - 1;
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
                std::shared_ptr<UniformRandomGenerator> random,
                const EncryptionParameters &parms)
        {
            auto coeff_modulus = parms.coeff_modulus();
            size_t coeff_mod_count = coeff_modulus.size();
            size_t coeff_count = parms.poly_modulus_degree();

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
                        poly[i + j * coeff_count] = 
                                static_cast<uint64_t>(noise);
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

            uint64_t max_uint64 = std::numeric_limits<uint64_t>::max();
            uint64_t modulus = 0;
            uint64_t max_multiple = 0;
            uint64_t rand;
            for (size_t j = 0; j < coeff_mod_count; j++)
            {
                modulus = coeff_modulus[j].value();
                max_multiple = max_uint64 - max_uint64 % modulus;
                for (size_t i = 0; i < coeff_count; i++)
                {
                    // This ensures uniform distribution.
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
    }
}