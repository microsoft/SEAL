// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include "gtest/gtest.h"
#include "seal/context.h"

using namespace seal;
using namespace std;

namespace SEALTest
{
    TEST(ContextTest, ContextConstructor)
    {
        // Nothing set
        auto scheme = scheme_type::BFV;
        EncryptionParameters parms(scheme);
        {
            auto context = SEALContext::Create(parms);
            auto qualifiers = context->context_data()->qualifiers();
            ASSERT_FALSE(qualifiers.parameters_set);
            ASSERT_FALSE(qualifiers.using_fft);
            ASSERT_FALSE(qualifiers.using_ntt);
            ASSERT_FALSE(qualifiers.using_batching);
            ASSERT_FALSE(qualifiers.using_fast_plain_lift);
        }

        // Not relatively prime coeff moduli
        parms.set_poly_modulus_degree(4);
        parms.set_coeff_modulus({ 2, 30 });
        parms.set_plain_modulus(2);
        parms.set_noise_standard_deviation(3.20);
        parms.set_random_generator(UniformRandomGeneratorFactory::default_factory());
        {
            auto context = SEALContext::Create(parms);
            auto qualifiers = context->context_data()->qualifiers();
            ASSERT_FALSE(qualifiers.parameters_set);
            ASSERT_FALSE(qualifiers.using_fft);
            ASSERT_FALSE(qualifiers.using_ntt);
            ASSERT_FALSE(qualifiers.using_batching);
            ASSERT_FALSE(qualifiers.using_fast_plain_lift);
        }

        // Plain modulus not relatively prime to coeff moduli
        parms.set_poly_modulus_degree(4);
        parms.set_coeff_modulus({ 17, 41 });
        parms.set_plain_modulus(34);
        parms.set_noise_standard_deviation(3.20);
        parms.set_random_generator(UniformRandomGeneratorFactory::default_factory());
        {
            auto context = SEALContext::Create(parms);
            auto qualifiers = context->context_data()->qualifiers();
            ASSERT_FALSE(qualifiers.parameters_set);
            ASSERT_TRUE(qualifiers.using_fft);
            ASSERT_TRUE(qualifiers.using_ntt);
            ASSERT_FALSE(qualifiers.using_batching);
            ASSERT_FALSE(qualifiers.using_fast_plain_lift);
        }

        // Plain modulus not smaller than product of coeff moduli
        parms.set_poly_modulus_degree(4);
        parms.set_coeff_modulus({ 2 });
        parms.set_plain_modulus(3);
        parms.set_noise_standard_deviation(3.20);
        parms.set_random_generator(UniformRandomGeneratorFactory::default_factory());
        {
            auto context = SEALContext::Create(parms);
            ASSERT_EQ(2ULL, *context->context_data()->total_coeff_modulus());
            auto qualifiers = context->context_data()->qualifiers();
            ASSERT_FALSE(qualifiers.parameters_set);
            ASSERT_TRUE(qualifiers.using_fft);
            ASSERT_FALSE(qualifiers.using_ntt);
            ASSERT_FALSE(qualifiers.using_batching);
            ASSERT_FALSE(qualifiers.using_fast_plain_lift);
        }

        // FFT poly but not NTT modulus
        parms.set_poly_modulus_degree(4);
        parms.set_coeff_modulus({ 3 });
        parms.set_plain_modulus(2);
        parms.set_noise_standard_deviation(3.20);
        parms.set_random_generator(UniformRandomGeneratorFactory::default_factory());
        {
            auto context = SEALContext::Create(parms);
            ASSERT_EQ(3ULL, *context->context_data()->total_coeff_modulus());
            auto qualifiers = context->context_data()->qualifiers();
            ASSERT_FALSE(qualifiers.parameters_set);
            ASSERT_TRUE(qualifiers.using_fft);
            ASSERT_FALSE(qualifiers.using_ntt);
            ASSERT_FALSE(qualifiers.using_batching);
            ASSERT_FALSE(qualifiers.using_fast_plain_lift);
        }

        // Parameters OK; no fast plain lift
        parms.set_poly_modulus_degree(4);
        parms.set_coeff_modulus({ 17, 41 });
        parms.set_plain_modulus(18);
        parms.set_noise_standard_deviation(3.20);
        parms.set_random_generator(UniformRandomGeneratorFactory::default_factory());
        {
            auto context = SEALContext::Create(parms);
            ASSERT_EQ(697ULL, *context->context_data()->total_coeff_modulus());
            auto qualifiers = context->context_data()->qualifiers();
            ASSERT_TRUE(qualifiers.parameters_set);
            ASSERT_TRUE(qualifiers.using_fft);
            ASSERT_TRUE(qualifiers.using_ntt);
            ASSERT_FALSE(qualifiers.using_batching);
            ASSERT_FALSE(qualifiers.using_fast_plain_lift);
        }

        // Parameters OK; fast plain lift
        parms.set_poly_modulus_degree(4);
        parms.set_coeff_modulus({ 17, 41 });
        parms.set_plain_modulus(16);
        parms.set_noise_standard_deviation(3.20);
        parms.set_random_generator(UniformRandomGeneratorFactory::default_factory());
        {
            auto context = SEALContext::Create(parms);
            ASSERT_EQ(697ULL, *context->context_data()->total_coeff_modulus());
            auto qualifiers = context->context_data()->qualifiers();
            ASSERT_TRUE(qualifiers.parameters_set);
            ASSERT_TRUE(qualifiers.using_fft);
            ASSERT_TRUE(qualifiers.using_ntt);
            ASSERT_FALSE(qualifiers.using_batching);
            ASSERT_TRUE(qualifiers.using_fast_plain_lift);
        }

        // Parameters OK; no batching due to non-prime plain modulus
        parms.set_poly_modulus_degree(4);
        parms.set_coeff_modulus({ 17, 41 });
        parms.set_plain_modulus(49);
        parms.set_noise_standard_deviation(3.20);
        parms.set_random_generator(UniformRandomGeneratorFactory::default_factory());
        {
            auto context = SEALContext::Create(parms);
            ASSERT_EQ(697ULL, *context->context_data()->total_coeff_modulus());
            auto qualifiers = context->context_data()->qualifiers();
            ASSERT_TRUE(qualifiers.parameters_set);
            ASSERT_TRUE(qualifiers.using_fft);
            ASSERT_TRUE(qualifiers.using_ntt);
            ASSERT_FALSE(qualifiers.using_batching);
            ASSERT_FALSE(qualifiers.using_fast_plain_lift);
        }

        // Parameters OK; batching enabled
        parms.set_poly_modulus_degree(4);
        parms.set_coeff_modulus({ 17, 41 });
        parms.set_plain_modulus(73);
        parms.set_noise_standard_deviation(3.20);
        parms.set_random_generator(UniformRandomGeneratorFactory::default_factory());
        {
            auto context = SEALContext::Create(parms);
            ASSERT_EQ(697ULL, *context->context_data()->total_coeff_modulus());
            auto qualifiers = context->context_data()->qualifiers();
            ASSERT_TRUE(qualifiers.parameters_set);
            ASSERT_TRUE(qualifiers.using_fft);
            ASSERT_TRUE(qualifiers.using_ntt);
            ASSERT_TRUE(qualifiers.using_batching);
            ASSERT_FALSE(qualifiers.using_fast_plain_lift);
        }

        // Parameters OK; batching and fast plain lift enabled
        parms.set_poly_modulus_degree(4);
        parms.set_coeff_modulus({ 137, 193 });
        parms.set_plain_modulus(73);
        parms.set_noise_standard_deviation(3.20);
        parms.set_random_generator(UniformRandomGeneratorFactory::default_factory());
        {
            auto context = SEALContext::Create(parms);
            ASSERT_EQ(26441ULL, *context->context_data()->total_coeff_modulus());
            auto qualifiers = context->context_data()->qualifiers();
            ASSERT_TRUE(qualifiers.parameters_set);
            ASSERT_TRUE(qualifiers.using_fft);
            ASSERT_TRUE(qualifiers.using_ntt);
            ASSERT_TRUE(qualifiers.using_batching);
            ASSERT_TRUE(qualifiers.using_fast_plain_lift);
        }

        // Parameters OK; batching and fast plain lift enabled; nullptr RNG
        parms.set_poly_modulus_degree(4);
        parms.set_coeff_modulus({ 137, 193 });
        parms.set_plain_modulus(73);
        parms.set_noise_standard_deviation(3.20);
        parms.set_random_generator(nullptr);
        {
            auto context = SEALContext::Create(parms);
            ASSERT_EQ(26441ULL, *context->context_data()->total_coeff_modulus());
            auto qualifiers = context->context_data()->qualifiers();
            ASSERT_TRUE(qualifiers.parameters_set);
            ASSERT_TRUE(qualifiers.using_fft);
            ASSERT_TRUE(qualifiers.using_ntt);
            ASSERT_TRUE(qualifiers.using_batching);
            ASSERT_TRUE(qualifiers.using_fast_plain_lift);
        }
    }

    TEST(ContextTest, ModulusChainExpansion)
    {
        {
            EncryptionParameters parms(scheme_type::BFV);
            parms.set_poly_modulus_degree(4);
            parms.set_coeff_modulus({ 41, 137, 193, 65537 });
            parms.set_plain_modulus(73);
            auto context = SEALContext::Create(parms, true);
            ASSERT_EQ(size_t(2), context->context_data()->chain_index());
            ASSERT_EQ(71047416497ULL, *context->context_data()->total_coeff_modulus());
            ASSERT_TRUE(!!context->context_data()->next_context_data());

            context = SEALContext::Create(parms, false);
            ASSERT_EQ(size_t(0), context->context_data()->chain_index());
            ASSERT_EQ(71047416497ULL, *context->context_data()->total_coeff_modulus());
            ASSERT_FALSE(!!context->context_data()->next_context_data());
        }
        {
            EncryptionParameters parms(scheme_type::CKKS);
            parms.set_poly_modulus_degree(4);
            parms.set_coeff_modulus({ 41, 137, 193, 65537 });
            auto context = SEALContext::Create(parms, true);
            ASSERT_EQ(size_t(3), context->context_data()->chain_index());
            ASSERT_EQ(71047416497ULL, *context->context_data()->total_coeff_modulus());
            ASSERT_TRUE(!!context->context_data()->next_context_data());

            context = SEALContext::Create(parms, false);
            ASSERT_EQ(size_t(0), context->context_data()->chain_index());
            ASSERT_EQ(71047416497ULL, *context->context_data()->total_coeff_modulus());
            ASSERT_FALSE(!!context->context_data()->next_context_data());
        }
    }
}
