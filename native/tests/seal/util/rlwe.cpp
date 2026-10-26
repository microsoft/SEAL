// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include "seal/encryptionparams.h"
#include "seal/modulus.h"
#include "seal/randomgen.h"
#include "seal/util/rlwe.h"
#include "seal/util/uintarithsmallmod.h"
#include <cstddef>
#include <cstdint>
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
            const Modulus &modulus = parms.coeff_modulus()[0];

            // Largest multiple of the modulus that fits in 64 bits; [0, threshold) holds only complete
            // residue classes, so every value below it must be accepted and every value from it rejected
            uint64_t max_random = static_cast<uint64_t>(0xFFFFFFFFFFFFFFFFULL);
            uint64_t threshold = max_random - barrett_reduce_64(max_random, modulus);

            // The first 64 words are the bulk draw; rejected words are replaced from word 64 onwards
            vector<uint64_t> words(128, 1);
            words[0] = threshold - 1;
            words[1] = threshold;
            words[64] = 12345;

            vector<uint64_t> poly(64);
            sample_poly_uniform(make_shared<ScriptedRandomGenerator>(words), parms, poly.data());
            ASSERT_EQ(modulus.value() - 1, poly[0]);
            ASSERT_EQ(12345ULL, poly[1]);
        }
    } // namespace util
} // namespace sealtest
