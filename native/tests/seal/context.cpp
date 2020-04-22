// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include "seal/context.h"
#include "seal/modulus.h"
#include "gtest/gtest.h"

using namespace seal;
using namespace std;

using error_type = EncryptionParameterQualifiers::error_type;

namespace sealtest
{
    TEST(ContextTest, ContextConstructor)
    {
        // Nothing set
        auto scheme = scheme_type::BFV;
        EncryptionParameters parms(scheme);
        {
            auto context = SEALContext::Create(parms, false, sec_level_type::none);
            auto qualifiers = context->first_context_data()->qualifiers();
            ASSERT_FALSE(qualifiers.parameters_set());
            ASSERT_EQ(qualifiers.parameter_error, error_type::invalid_coeff_modulus_size);
            ASSERT_FALSE(qualifiers.using_fft);
            ASSERT_FALSE(qualifiers.using_ntt);
            ASSERT_FALSE(qualifiers.using_batching);
            ASSERT_FALSE(qualifiers.using_fast_plain_lift);
            ASSERT_FALSE(qualifiers.using_descending_modulus_chain);
            ASSERT_EQ(sec_level_type::none, qualifiers.sec_level);
            ASSERT_FALSE(context->using_keyswitching());
        }

        // Not relatively prime coeff moduli
        parms.set_poly_modulus_degree(4);
        parms.set_coeff_modulus({ 2, 30 });
        parms.set_plain_modulus(2);
        parms.set_random_generator(UniformRandomGeneratorFactory::DefaultFactory());
        {
            auto context = SEALContext::Create(parms, false, sec_level_type::none);
            auto qualifiers = context->first_context_data()->qualifiers();
            ASSERT_FALSE(qualifiers.parameters_set());
            ASSERT_EQ(qualifiers.parameter_error, error_type::failed_creating_rns_base);
            ASSERT_TRUE(qualifiers.using_fft);
            ASSERT_FALSE(qualifiers.using_ntt);
            ASSERT_FALSE(qualifiers.using_batching);
            ASSERT_FALSE(qualifiers.using_fast_plain_lift);
            ASSERT_FALSE(qualifiers.using_descending_modulus_chain);
            ASSERT_EQ(sec_level_type::none, qualifiers.sec_level);
            ASSERT_FALSE(context->using_keyswitching());
        }

        // Plain modulus not relatively prime to coeff moduli
        parms.set_poly_modulus_degree(4);
        parms.set_coeff_modulus({ 17, 41 });
        parms.set_plain_modulus(34);
        parms.set_random_generator(UniformRandomGeneratorFactory::DefaultFactory());
        {
            auto context = SEALContext::Create(parms, false, sec_level_type::none);
            auto qualifiers = context->first_context_data()->qualifiers();
            ASSERT_FALSE(qualifiers.parameters_set());
            ASSERT_EQ(qualifiers.parameter_error, error_type::invalid_plain_modulus_coprimality);
            ASSERT_TRUE(qualifiers.using_fft);
            ASSERT_TRUE(qualifiers.using_ntt);
            ASSERT_FALSE(qualifiers.using_batching);
            ASSERT_FALSE(qualifiers.using_fast_plain_lift);
            ASSERT_FALSE(qualifiers.using_descending_modulus_chain);
            ASSERT_EQ(sec_level_type::none, qualifiers.sec_level);
            ASSERT_FALSE(context->using_keyswitching());
        }

        // Plain modulus not smaller than product of coeff moduli
        parms.set_poly_modulus_degree(4);
        parms.set_coeff_modulus({ 17 });
        parms.set_plain_modulus(41);
        parms.set_random_generator(UniformRandomGeneratorFactory::DefaultFactory());
        {
            auto context = SEALContext::Create(parms, false, sec_level_type::none);
            ASSERT_EQ(17ULL, *context->first_context_data()->total_coeff_modulus());
            auto qualifiers = context->first_context_data()->qualifiers();
            ASSERT_FALSE(qualifiers.parameters_set());
            ASSERT_EQ(qualifiers.parameter_error, error_type::invalid_plain_modulus_too_large);
            ASSERT_TRUE(qualifiers.using_fft);
            ASSERT_TRUE(qualifiers.using_ntt);
            ASSERT_FALSE(qualifiers.using_batching);
            ASSERT_FALSE(qualifiers.using_fast_plain_lift);
            ASSERT_FALSE(qualifiers.using_descending_modulus_chain);
            ASSERT_EQ(sec_level_type::none, qualifiers.sec_level);
            ASSERT_FALSE(context->using_keyswitching());
        }

        // FFT poly but not NTT modulus
        parms.set_poly_modulus_degree(4);
        parms.set_coeff_modulus({ 3 });
        parms.set_plain_modulus(2);
        parms.set_random_generator(UniformRandomGeneratorFactory::DefaultFactory());
        {
            auto context = SEALContext::Create(parms, false, sec_level_type::none);
            ASSERT_EQ(3ULL, *context->first_context_data()->total_coeff_modulus());
            auto qualifiers = context->first_context_data()->qualifiers();
            ASSERT_FALSE(qualifiers.parameters_set());
            ASSERT_EQ(qualifiers.parameter_error, error_type::invalid_coeff_modulus_no_ntt);
            ASSERT_TRUE(qualifiers.using_fft);
            ASSERT_FALSE(qualifiers.using_ntt);
            ASSERT_FALSE(qualifiers.using_batching);
            ASSERT_FALSE(qualifiers.using_fast_plain_lift);
            ASSERT_FALSE(qualifiers.using_descending_modulus_chain);
            ASSERT_EQ(sec_level_type::none, qualifiers.sec_level);
            ASSERT_FALSE(context->using_keyswitching());
        }

        // Parameters OK; no fast plain lift
        parms.set_poly_modulus_degree(4);
        parms.set_coeff_modulus({ 17, 41 });
        parms.set_plain_modulus(18);
        parms.set_random_generator(UniformRandomGeneratorFactory::DefaultFactory());
        {
            auto context = SEALContext::Create(parms, false, sec_level_type::none);
            ASSERT_EQ(697ULL, *context->first_context_data()->total_coeff_modulus());
            auto qualifiers = context->first_context_data()->qualifiers();
            ASSERT_TRUE(qualifiers.parameters_set());
            ASSERT_TRUE(qualifiers.using_fft);
            ASSERT_TRUE(qualifiers.using_ntt);
            ASSERT_FALSE(qualifiers.using_batching);
            ASSERT_FALSE(qualifiers.using_fast_plain_lift);
            ASSERT_FALSE(qualifiers.using_descending_modulus_chain);
            ASSERT_EQ(sec_level_type::none, qualifiers.sec_level);
            ASSERT_FALSE(context->using_keyswitching());
        }

        // Parameters OK; fast plain lift
        parms.set_poly_modulus_degree(4);
        parms.set_coeff_modulus({ 17, 41 });
        parms.set_plain_modulus(16);
        parms.set_random_generator(UniformRandomGeneratorFactory::DefaultFactory());
        {
            auto context = SEALContext::Create(parms, false, sec_level_type::none);
            ASSERT_EQ(17ULL, *context->first_context_data()->total_coeff_modulus());
            ASSERT_EQ(697ULL, *context->key_context_data()->total_coeff_modulus());
            auto qualifiers = context->first_context_data()->qualifiers();
            auto key_qualifiers = context->key_context_data()->qualifiers();
            ASSERT_TRUE(qualifiers.parameters_set());
            ASSERT_TRUE(qualifiers.using_fft);
            ASSERT_TRUE(qualifiers.using_ntt);
            ASSERT_FALSE(qualifiers.using_batching);
            ASSERT_TRUE(qualifiers.using_fast_plain_lift);
            ASSERT_FALSE(key_qualifiers.using_descending_modulus_chain);
            ASSERT_EQ(sec_level_type::none, qualifiers.sec_level);
            ASSERT_TRUE(context->using_keyswitching());
        }

        // Parameters OK; no batching due to non-prime plain modulus
        parms.set_poly_modulus_degree(4);
        parms.set_coeff_modulus({ 17, 41 });
        parms.set_plain_modulus(49);
        parms.set_random_generator(UniformRandomGeneratorFactory::DefaultFactory());
        {
            auto context = SEALContext::Create(parms, false, sec_level_type::none);
            ASSERT_EQ(697ULL, *context->first_context_data()->total_coeff_modulus());
            auto qualifiers = context->first_context_data()->qualifiers();
            ASSERT_TRUE(qualifiers.parameters_set());
            ASSERT_TRUE(qualifiers.using_fft);
            ASSERT_TRUE(qualifiers.using_ntt);
            ASSERT_FALSE(qualifiers.using_batching);
            ASSERT_FALSE(qualifiers.using_fast_plain_lift);
            ASSERT_FALSE(qualifiers.using_descending_modulus_chain);
            ASSERT_EQ(sec_level_type::none, qualifiers.sec_level);
            ASSERT_FALSE(context->using_keyswitching());
        }

        // Parameters OK; batching enabled
        parms.set_poly_modulus_degree(4);
        parms.set_coeff_modulus({ 17, 41 });
        parms.set_plain_modulus(73);
        parms.set_random_generator(UniformRandomGeneratorFactory::DefaultFactory());
        {
            auto context = SEALContext::Create(parms, false, sec_level_type::none);
            ASSERT_EQ(697ULL, *context->first_context_data()->total_coeff_modulus());
            auto qualifiers = context->first_context_data()->qualifiers();
            ASSERT_TRUE(qualifiers.parameters_set());
            ASSERT_TRUE(qualifiers.using_fft);
            ASSERT_TRUE(qualifiers.using_ntt);
            ASSERT_TRUE(qualifiers.using_batching);
            ASSERT_FALSE(qualifiers.using_fast_plain_lift);
            ASSERT_FALSE(qualifiers.using_descending_modulus_chain);
            ASSERT_EQ(sec_level_type::none, qualifiers.sec_level);
            ASSERT_FALSE(context->using_keyswitching());
        }

        // Parameters OK; batching and fast plain lift enabled
        parms.set_poly_modulus_degree(4);
        parms.set_coeff_modulus({ 137, 193 });
        parms.set_plain_modulus(73);
        parms.set_random_generator(UniformRandomGeneratorFactory::DefaultFactory());
        {
            auto context = SEALContext::Create(parms, false, sec_level_type::none);
            ASSERT_EQ(137ULL, *context->first_context_data()->total_coeff_modulus());
            ASSERT_EQ(26441ULL, *context->key_context_data()->total_coeff_modulus());
            auto qualifiers = context->first_context_data()->qualifiers();
            auto key_qualifiers = context->key_context_data()->qualifiers();
            ASSERT_TRUE(qualifiers.parameters_set());
            ASSERT_TRUE(qualifiers.using_fft);
            ASSERT_TRUE(qualifiers.using_ntt);
            ASSERT_TRUE(qualifiers.using_batching);
            ASSERT_TRUE(qualifiers.using_fast_plain_lift);
            ASSERT_FALSE(key_qualifiers.using_descending_modulus_chain);
            ASSERT_EQ(sec_level_type::none, qualifiers.sec_level);
            ASSERT_TRUE(context->using_keyswitching());
        }

        // Parameters OK; batching and fast plain lift enabled; nullptr RNG
        parms.set_poly_modulus_degree(4);
        parms.set_coeff_modulus({ 137, 193 });
        parms.set_plain_modulus(73);
        parms.set_random_generator(nullptr);
        {
            auto context = SEALContext::Create(parms, false, sec_level_type::none);
            ASSERT_EQ(137ULL, *context->first_context_data()->total_coeff_modulus());
            ASSERT_EQ(26441ULL, *context->key_context_data()->total_coeff_modulus());
            auto qualifiers = context->first_context_data()->qualifiers();
            auto key_qualifiers = context->key_context_data()->qualifiers();
            ASSERT_TRUE(qualifiers.parameters_set());
            ASSERT_TRUE(qualifiers.using_fft);
            ASSERT_TRUE(qualifiers.using_ntt);
            ASSERT_TRUE(qualifiers.using_batching);
            ASSERT_TRUE(qualifiers.using_fast_plain_lift);
            ASSERT_FALSE(key_qualifiers.using_descending_modulus_chain);
            ASSERT_EQ(sec_level_type::none, qualifiers.sec_level);
            ASSERT_TRUE(context->using_keyswitching());
        }

        // Parameters not OK due to too small poly_modulus_degree and enforce_hes
        parms.set_poly_modulus_degree(4);
        parms.set_coeff_modulus({ 137, 193 });
        parms.set_plain_modulus(73);
        parms.set_random_generator(nullptr);
        {
            auto context = SEALContext::Create(parms, false, sec_level_type::tc128);
            auto qualifiers = context->first_context_data()->qualifiers();
            ASSERT_FALSE(qualifiers.parameters_set());
            ASSERT_EQ(qualifiers.parameter_error, error_type::invalid_parameters_insecure);
            ASSERT_EQ(sec_level_type::none, qualifiers.sec_level);
            ASSERT_FALSE(context->using_keyswitching());
        }

        // Parameters not OK due to too large coeff_modulus and enforce_hes
        parms.set_poly_modulus_degree(2048);
        parms.set_coeff_modulus(CoeffModulus::BFVDefault(4096, sec_level_type::tc128));
        parms.set_plain_modulus(73);
        parms.set_random_generator(nullptr);
        {
            auto context = SEALContext::Create(parms, false, sec_level_type::tc128);
            auto qualifiers = context->first_context_data()->qualifiers();
            ASSERT_FALSE(qualifiers.parameters_set());
            ASSERT_EQ(qualifiers.parameter_error, error_type::invalid_parameters_insecure);
            ASSERT_EQ(sec_level_type::none, qualifiers.sec_level);
            ASSERT_FALSE(context->using_keyswitching());
        }

        // Parameters OK; descending modulus chain
        parms.set_poly_modulus_degree(4096);
        parms.set_coeff_modulus({ 0xffffee001, 0xffffc4001 });
        parms.set_plain_modulus(73);
        {
            auto context = SEALContext::Create(parms, false, sec_level_type::tc128);
            auto qualifiers = context->first_context_data()->qualifiers();
            ASSERT_TRUE(qualifiers.parameters_set());
            ASSERT_TRUE(qualifiers.using_fft);
            ASSERT_TRUE(qualifiers.using_ntt);
            ASSERT_FALSE(qualifiers.using_batching);
            ASSERT_TRUE(qualifiers.using_fast_plain_lift);
            ASSERT_TRUE(qualifiers.using_descending_modulus_chain);
            ASSERT_EQ(sec_level_type::tc128, qualifiers.sec_level);
            ASSERT_TRUE(context->using_keyswitching());
        }

        // Parameters OK; no standard security
        parms.set_poly_modulus_degree(2048);
        parms.set_coeff_modulus({ 0x1ffffe0001, 0xffffee001, 0xffffc4001 });
        parms.set_plain_modulus(73);
        {
            auto context = SEALContext::Create(parms, false, sec_level_type::none);
            auto qualifiers = context->first_context_data()->qualifiers();
            auto key_qualifiers = context->key_context_data()->qualifiers();
            ASSERT_TRUE(qualifiers.parameters_set());
            ASSERT_TRUE(qualifiers.using_fft);
            ASSERT_TRUE(qualifiers.using_ntt);
            ASSERT_FALSE(qualifiers.using_batching);
            ASSERT_TRUE(qualifiers.using_fast_plain_lift);
            ASSERT_TRUE(key_qualifiers.using_descending_modulus_chain);
            ASSERT_EQ(sec_level_type::none, qualifiers.sec_level);
            ASSERT_TRUE(context->using_keyswitching());
        }

        // Parameters OK; using batching; no keyswitching
        parms.set_poly_modulus_degree(2048);
        parms.set_coeff_modulus(CoeffModulus::Create(2048, { 40 }));
        parms.set_plain_modulus(65537);
        {
            auto context = SEALContext::Create(parms, false, sec_level_type::none);
            auto qualifiers = context->first_context_data()->qualifiers();
            ASSERT_TRUE(qualifiers.parameters_set());
            ASSERT_TRUE(qualifiers.using_fft);
            ASSERT_TRUE(qualifiers.using_ntt);
            ASSERT_TRUE(qualifiers.using_batching);
            ASSERT_TRUE(qualifiers.using_fast_plain_lift);
            ASSERT_TRUE(qualifiers.using_descending_modulus_chain);
            ASSERT_EQ(sec_level_type::none, qualifiers.sec_level);
            ASSERT_FALSE(context->using_keyswitching());
        }
    }

    TEST(ContextTest, ModulusChainExpansion)
    {
        {
            EncryptionParameters parms(scheme_type::BFV);
            parms.set_poly_modulus_degree(4);
            parms.set_coeff_modulus({ 41, 137, 193, 65537 });
            parms.set_plain_modulus(73);
            auto context = SEALContext::Create(parms, true, sec_level_type::none);
            auto context_data = context->key_context_data();
            ASSERT_EQ(size_t(2), context_data->chain_index());
            ASSERT_EQ(71047416497ULL, *context_data->total_coeff_modulus());
            ASSERT_FALSE(!!context_data->prev_context_data());
            ASSERT_EQ(context_data->parms_id(), context->key_parms_id());
            auto prev_context_data = context_data;
            context_data = context_data->next_context_data();
            ASSERT_EQ(size_t(1), context_data->chain_index());
            ASSERT_EQ(1084081ULL, *context_data->total_coeff_modulus());
            ASSERT_EQ(context_data->prev_context_data()->parms_id(), prev_context_data->parms_id());
            prev_context_data = context_data;
            context_data = context_data->next_context_data();
            ASSERT_EQ(size_t(0), context_data->chain_index());
            ASSERT_EQ(5617ULL, *context_data->total_coeff_modulus());
            ASSERT_EQ(context_data->prev_context_data()->parms_id(), prev_context_data->parms_id());
            ASSERT_FALSE(!!context_data->next_context_data());
            ASSERT_EQ(context_data->parms_id(), context->last_parms_id());

            context = SEALContext::Create(parms, false, sec_level_type::none);
            ASSERT_EQ(size_t(1), context->key_context_data()->chain_index());
            ASSERT_EQ(size_t(0), context->first_context_data()->chain_index());
            ASSERT_EQ(71047416497ULL, *context->key_context_data()->total_coeff_modulus());
            ASSERT_EQ(1084081ULL, *context->first_context_data()->total_coeff_modulus());
            ASSERT_FALSE(!!context->first_context_data()->next_context_data());
            ASSERT_TRUE(!!context->first_context_data()->prev_context_data());
        }
        {
            EncryptionParameters parms(scheme_type::CKKS);
            parms.set_poly_modulus_degree(4);
            parms.set_coeff_modulus({ 41, 137, 193, 65537 });
            auto context = SEALContext::Create(parms, true, sec_level_type::none);
            auto context_data = context->key_context_data();
            ASSERT_EQ(size_t(3), context_data->chain_index());
            ASSERT_EQ(71047416497ULL, *context_data->total_coeff_modulus());
            ASSERT_FALSE(!!context_data->prev_context_data());
            ASSERT_EQ(context_data->parms_id(), context->key_parms_id());
            auto prev_context_data = context_data;
            context_data = context_data->next_context_data();
            ASSERT_EQ(size_t(2), context_data->chain_index());
            ASSERT_EQ(1084081ULL, *context_data->total_coeff_modulus());
            ASSERT_EQ(context_data->prev_context_data()->parms_id(), prev_context_data->parms_id());
            prev_context_data = context_data;
            context_data = context_data->next_context_data();
            ASSERT_EQ(size_t(1), context_data->chain_index());
            ASSERT_EQ(5617ULL, *context_data->total_coeff_modulus());
            ASSERT_EQ(context_data->prev_context_data()->parms_id(), prev_context_data->parms_id());
            prev_context_data = context_data;
            context_data = context_data->next_context_data();
            ASSERT_EQ(size_t(0), context_data->chain_index());
            ASSERT_EQ(41ULL, *context_data->total_coeff_modulus());
            ASSERT_EQ(context_data->prev_context_data()->parms_id(), prev_context_data->parms_id());
            ASSERT_FALSE(!!context_data->next_context_data());
            ASSERT_EQ(context_data->parms_id(), context->last_parms_id());

            context = SEALContext::Create(parms, false, sec_level_type::none);
            ASSERT_EQ(size_t(1), context->key_context_data()->chain_index());
            ASSERT_EQ(size_t(0), context->first_context_data()->chain_index());
            ASSERT_EQ(71047416497ULL, *context->key_context_data()->total_coeff_modulus());
            ASSERT_EQ(1084081ULL, *context->first_context_data()->total_coeff_modulus());
            ASSERT_FALSE(!!context->first_context_data()->next_context_data());
            ASSERT_TRUE(!!context->first_context_data()->prev_context_data());
        }
    }

    TEST(EncryptionParameterQualifiersTest, ParameterError)
    {
        auto scheme = scheme_type::BFV;
        EncryptionParameters parms(scheme);
        auto context = SEALContext::Create(parms, false, sec_level_type::none);
        auto qualifiers = context->first_context_data()->qualifiers();

        qualifiers.parameter_error = error_type::none;
        ASSERT_STREQ(qualifiers.parameter_error_name(), "none");
        ASSERT_STREQ(qualifiers.parameter_error_message(), "constructed but not yet validated");

        qualifiers.parameter_error = error_type::success;
        ASSERT_STREQ(qualifiers.parameter_error_name(), "success");
        ASSERT_STREQ(qualifiers.parameter_error_message(), "valid");

        qualifiers.parameter_error = error_type::invalid_coeff_modulus_bit_count;
        ASSERT_STREQ(qualifiers.parameter_error_name(), "invalid_coeff_modulus_bit_count");
        ASSERT_STREQ(
            qualifiers.parameter_error_message(),
            "coeff_modulus's primes' bit counts are not bounded by SEAL_USER_MOD_BIT_COUNT_MIN(MAX)");

        parms.set_poly_modulus_degree(127);
        parms.set_coeff_modulus({ 17, 73 });
        parms.set_plain_modulus(41);
        parms.set_random_generator(UniformRandomGeneratorFactory::DefaultFactory());
        context = SEALContext::Create(parms, false, sec_level_type::none);
        ASSERT_FALSE(context->parameters_set());
        ASSERT_STREQ(context->parameter_error_name(), "invalid_poly_modulus_degree_non_power_of_two");
        ASSERT_STREQ(context->parameter_error_message(), "poly_modulus_degree is not a power of two");
    }
} // namespace sealtest
