// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include "seal/batchencoder.h"
#include "seal/context.h"
#include "seal/keygenerator.h"
#include "seal/modulus.h"
#include <ctime>
#include <vector>
#include "gtest/gtest.h"

using namespace seal;
using namespace seal::util;
using namespace std;

namespace sealtest
{
    TEST(BatchEncoderTest, BatchUnbatchUIntVector)
    {
        EncryptionParameters parms(scheme_type::BFV);
        parms.set_poly_modulus_degree(64);
        parms.set_coeff_modulus(CoeffModulus::Create(64, { 60 }));
        parms.set_plain_modulus(257);

        auto context = SEALContext::Create(parms, false, sec_level_type::none);
        ASSERT_TRUE(context->first_context_data()->qualifiers().using_batching);

        BatchEncoder batch_encoder(context);
        ASSERT_EQ(64ULL, batch_encoder.slot_count());
        vector<uint64_t> plain_vec;
        for (size_t i = 0; i < batch_encoder.slot_count(); i++)
        {
            plain_vec.push_back(i);
        }

        Plaintext plain;
        batch_encoder.encode(plain_vec, plain);
        vector<uint64_t> plain_vec2;
        batch_encoder.decode(plain, plain_vec2);
        ASSERT_TRUE(plain_vec == plain_vec2);

        for (size_t i = 0; i < batch_encoder.slot_count(); i++)
        {
            plain_vec[i] = 5;
        }
        batch_encoder.encode(plain_vec, plain);
        ASSERT_TRUE(plain.to_string() == "5");
        batch_encoder.decode(plain, plain_vec2);
        ASSERT_TRUE(plain_vec == plain_vec2);

        vector<uint64_t> short_plain_vec;
        for (size_t i = 0; i < 20; i++)
        {
            short_plain_vec.push_back(i);
        }
        batch_encoder.encode(short_plain_vec, plain);
        vector<uint64_t> short_plain_vec2;
        batch_encoder.decode(plain, short_plain_vec2);
        ASSERT_EQ(20ULL, short_plain_vec.size());
        ASSERT_EQ(64ULL, short_plain_vec2.size());
        for (size_t i = 0; i < 20; i++)
        {
            ASSERT_EQ(short_plain_vec[i], short_plain_vec2[i]);
        }
        for (size_t i = 20; i < batch_encoder.slot_count(); i++)
        {
            ASSERT_EQ(0ULL, short_plain_vec2[i]);
        }
    }

    TEST(BatchEncoderTest, BatchUnbatchIntVector)
    {
        EncryptionParameters parms(scheme_type::BFV);
        parms.set_poly_modulus_degree(64);
        parms.set_coeff_modulus(CoeffModulus::Create(64, { 60 }));
        parms.set_plain_modulus(257);

        auto context = SEALContext::Create(parms, false, sec_level_type::none);
        ASSERT_TRUE(context->first_context_data()->qualifiers().using_batching);

        BatchEncoder batch_encoder(context);
        ASSERT_EQ(64ULL, batch_encoder.slot_count());
        vector<int64_t> plain_vec;
        for (uint64_t i = 0; i < static_cast<uint64_t>(batch_encoder.slot_count()); i++)
        {
            plain_vec.push_back(static_cast<int64_t>(i * (1 - (i & 1) * 2)));
        }

        Plaintext plain;
        batch_encoder.encode(plain_vec, plain);
        vector<int64_t> plain_vec2;
        batch_encoder.decode(plain, plain_vec2);
        ASSERT_TRUE(plain_vec == plain_vec2);

        for (size_t i = 0; i < batch_encoder.slot_count(); i++)
        {
            plain_vec[i] = -5;
        }
        batch_encoder.encode(plain_vec, plain);
        ASSERT_TRUE(plain.to_string() == "FC");
        batch_encoder.decode(plain, plain_vec2);
        ASSERT_TRUE(plain_vec == plain_vec2);

        vector<int64_t> short_plain_vec;
        for (int64_t i = 0; i < 20; i++)
        {
            short_plain_vec.push_back(i * (int64_t(1) - (i & 1) * 2));
        }
        batch_encoder.encode(short_plain_vec, plain);
        vector<int64_t> short_plain_vec2;
        batch_encoder.decode(plain, short_plain_vec2);
        ASSERT_EQ(20ULL, short_plain_vec.size());
        ASSERT_EQ(64ULL, short_plain_vec2.size());
        for (size_t i = 0; i < 20; i++)
        {
            ASSERT_EQ(short_plain_vec[i], short_plain_vec2[i]);
        }
        for (size_t i = 20; i < batch_encoder.slot_count(); i++)
        {
            ASSERT_EQ(0ULL, short_plain_vec2[i]);
        }
    }

    TEST(BatchEncoderTest, BatchUnbatchPlaintext)
    {
        EncryptionParameters parms(scheme_type::BFV);
        parms.set_poly_modulus_degree(64);
        parms.set_coeff_modulus(CoeffModulus::Create(64, { 60 }));
        parms.set_plain_modulus(257);

        auto context = SEALContext::Create(parms, false, sec_level_type::none);
        ASSERT_TRUE(context->first_context_data()->qualifiers().using_batching);

        BatchEncoder batch_encoder(context);
        ASSERT_EQ(64ULL, batch_encoder.slot_count());
        Plaintext plain(batch_encoder.slot_count());
        for (size_t i = 0; i < batch_encoder.slot_count(); i++)
        {
            plain[i] = i;
        }

        batch_encoder.encode(plain);
        batch_encoder.decode(plain);
        for (size_t i = 0; i < batch_encoder.slot_count(); i++)
        {
            ASSERT_TRUE(plain[i] == i);
        }

        for (size_t i = 0; i < batch_encoder.slot_count(); i++)
        {
            plain[i] = 5;
        }
        batch_encoder.encode(plain);
        ASSERT_TRUE(plain.to_string() == "5");
        batch_encoder.decode(plain);
        for (size_t i = 0; i < batch_encoder.slot_count(); i++)
        {
            ASSERT_EQ(5ULL, plain[i]);
        }

        Plaintext short_plain(20);
        for (size_t i = 0; i < 20; i++)
        {
            short_plain[i] = i;
        }
        batch_encoder.encode(short_plain);
        batch_encoder.decode(short_plain);
        for (size_t i = 0; i < 20; i++)
        {
            ASSERT_TRUE(short_plain[i] == i);
        }
        for (size_t i = 20; i < batch_encoder.slot_count(); i++)
        {
            ASSERT_TRUE(short_plain[i] == 0);
        }
    }
} // namespace sealtest
