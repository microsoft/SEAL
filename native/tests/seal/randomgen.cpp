// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include "gtest/gtest.h"
#include "seal/randomgen.h"
#include "seal/keygenerator.h"
#include <random>
#include <cstdint>
#include <memory>

using namespace seal;
using namespace std;

namespace SEALTest
{
    namespace
    {
        class CustomRandomEngine : public UniformRandomGenerator
        {
        public:
            CustomRandomEngine()
            {
            }

            uint32_t generate() override
            {
                count_++;
                return static_cast<uint32_t>(engine_());
            }

            static int count()
            {
                return count_;
            }

        private:
            default_random_engine engine_;

            static int count_;
        };

        class CustomRandomEngineFactory : public UniformRandomGeneratorFactory
        {
        public:
            shared_ptr<UniformRandomGenerator> create() override
            {
                return shared_ptr<UniformRandomGenerator>(new CustomRandomEngine());
            }
        };

        int CustomRandomEngine::count_ = 0;
    }

    TEST(RandomGenerator, UniformRandomCreateDefault)
    {
        shared_ptr<UniformRandomGenerator> generator(UniformRandomGeneratorFactory::default_factory()->create());
        bool lower_half = false;
        bool upper_half = false;
        bool even = false;
        bool odd = false;
        for (int i = 0; i < 10; ++i)
        {
            uint32_t value = generator->generate();
            if (value < UINT32_MAX / 2)
            {
                lower_half = true;
            }
            else
            {
                upper_half = true;
            }
            if ((value % 2) == 0)
            {
                even = true;
            }
            else
            {
                odd = true;
            }
        }
        ASSERT_TRUE(lower_half);
        ASSERT_TRUE(upper_half);
        ASSERT_TRUE(even);
        ASSERT_TRUE(odd);
    }

    TEST(RandomGenerator, StandardRandomAdapterGenerate)
    {
        StandardRandomAdapter<default_random_engine> generator;
        bool lower_half = false;
        bool upper_half = false;
        bool even = false;
        bool odd = false;
        for (int i = 0; i < 10; ++i)
        {
            uint32_t value = generator.generate();
            if (value < UINT32_MAX / 2)
            {
                lower_half = true;
            }
            else
            {
                upper_half = true;
            }
            if ((value % 2) == 0)
            {
                even = true;
            }
            else
            {
                odd = true;
            }
        }
        ASSERT_TRUE(lower_half);
        ASSERT_TRUE(upper_half);
        ASSERT_TRUE(even);
        ASSERT_TRUE(odd);
    }

    TEST(RandomGenerator, CustomRandomGenerator)
    {
        shared_ptr<CustomRandomEngineFactory> factory(new CustomRandomEngineFactory);

        EncryptionParameters parms(scheme_type::BFV);
        uint64_t coeff_modulus;
        SmallModulus plain_modulus;
        coeff_modulus = 0xFFFFFFFFC001;
        plain_modulus = 1 << 6;
        parms.set_poly_modulus_degree(64);
        parms.set_plain_modulus(plain_modulus);
        parms.set_coeff_modulus({ coeff_modulus });
        parms.set_random_generator(factory);
        auto context = SEALContext::Create(parms, false, sec_level_type::none);

        ASSERT_EQ(0, CustomRandomEngine::count());

        KeyGenerator keygen(context);

        ASSERT_NE(0, CustomRandomEngine::count());
    }
}
