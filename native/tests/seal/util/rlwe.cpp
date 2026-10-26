// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include "seal/encryptionparams.h"
#include "seal/modulus.h"
#include "seal/randomgen.h"
#include "seal/util/globals.h"
#include "seal/util/rlwe.h"
#include <cmath>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <vector>
#include "gtest/gtest.h"

using namespace seal;
using namespace seal::util;
using namespace std;

namespace sealtest
{
    namespace util
    {
        TEST(RLWETest, SamplePolyNormalRounding)
        {
            EncryptionParameters parms(scheme_type::bfv);
            parms.set_poly_modulus_degree(4096);
            parms.set_coeff_modulus(CoeffModulus::Create(4096, { 40 }));
            uint64_t q = parms.coeff_modulus()[0].value();

            // Sample 16 * 4096 noise coefficients from a fixed seed and compute their standard deviation.
            auto prng = make_shared<Shake256PRNG>(prng_seed_type{});
            vector<uint64_t> poly(4096);
            double sum_of_squares = 0;
            for (int i = 0; i < 16; i++)
            {
                sample_poly_normal(prng, parms, poly.data());
                for (auto coeff : poly)
                {
                    double noise = coeff > q / 2 ? -static_cast<double>(q - coeff) : static_cast<double>(coeff);
                    sum_of_squares += noise * noise;
                }
            }

            // Rounding to the nearest integer keeps the standard deviation close to noise_standard_deviation;
            // truncating toward zero would lower it to about 2.83.
            double standard_deviation = sqrt(sum_of_squares / (16 * 4096));
            ASSERT_NEAR(global_variables::noise_standard_deviation, standard_deviation, 0.1);
        }
    } // namespace util
} // namespace sealtest
