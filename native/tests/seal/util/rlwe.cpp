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
#include <limits>
#include <memory>
#include <utility>
#include <vector>
#include "gtest/gtest.h"

using namespace seal;
using namespace seal::util;
using namespace std;

namespace sealtest
{
    namespace util
    {
        namespace
        {
            // Serves a fixed sequence of 64-bit words, followed by zeros
            class ScriptedRandomGenerator : public UniformRandomGenerator
            {
            public:
                ScriptedRandomGenerator(vector<uint64_t> words) : UniformRandomGenerator({}), words_(std::move(words))
                {}

            protected:
                void refill_buffer() override
                {
                    auto out = reinterpret_cast<uint64_t *>(buffer_begin_);
                    for (size_t i = 0; i < buffer_size_ / sizeof(uint64_t); i++)
                    {
                        out[i] = next_ < words_.size() ? words_[next_++] : 0;
                    }
                }

                SEAL_NODISCARD prng_type type() const noexcept override
                {
                    return prng_type::unknown;
                }

            private:
                vector<uint64_t> words_;

                size_t next_ = 0;
            };
        } // namespace

        TEST(RLWETest, SamplePolyUniformRejectionThreshold)
        {
            EncryptionParameters parms(scheme_type::bfv);
            parms.set_poly_modulus_degree(64);
            parms.set_coeff_modulus(CoeffModulus::Create(64, { 60 }));
            uint64_t q = parms.coeff_modulus()[0].value();

            // Compute the largest multiple of q that fits in 64 bits. We want sampling to reject anything >=
            // this threshold and accept anything below it.
            uint64_t max_multiple = (numeric_limits<uint64_t>::max() / q) * q;

            // sample_poly_uniform will draw words[0..63] and apply rejection sampling;
            // rejected words are replaced from words[64] onwards.
            vector<uint64_t> words(128, 1);
            words[0] = max_multiple - 1;
            words[1] = max_multiple;
            words[64] = 12345;

            // words[0] should be accepted; words[1] should be rejected and replaced with the value in words[64].
            vector<uint64_t> poly(64);
            sample_poly_uniform(make_shared<ScriptedRandomGenerator>(words), parms, poly.data());
            ASSERT_EQ(q - 1, poly[0]);
            ASSERT_EQ(12345ULL, poly[1]);
        }

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

            // Confirm the sampled standard deviation matches global_variables::noise_standard_deviation
            double standard_deviation = sqrt(sum_of_squares / (16 * 4096));
            ASSERT_NEAR(global_variables::noise_standard_deviation, standard_deviation, 0.1);
        }
    } // namespace util
} // namespace sealtest
