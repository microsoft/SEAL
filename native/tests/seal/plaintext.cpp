// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include "seal/ckks.h"
#include "seal/context.h"
#include "seal/evaluator.h"
#include "seal/memorymanager.h"
#include "seal/modulus.h"
#include "seal/plaintext.h"
#include <vector>
#include "gtest/gtest.h"
#ifdef SEAL_USE_MSGSL
#include "gsl/span"
#endif

using namespace seal;
using namespace seal::util;
using namespace std;

namespace sealtest
{
    TEST(PlaintextTest, PlaintextBasics)
    {
        Plaintext plain(2);
        ASSERT_EQ(2ULL, plain.capacity());
        ASSERT_EQ(2ULL, plain.coeff_count());
        ASSERT_EQ(0ULL, plain.significant_coeff_count());
        ASSERT_EQ(0ULL, plain.nonzero_coeff_count());
        ASSERT_FALSE(plain.is_ntt_form());

        plain[0] = 1;
        plain[1] = 2;

        plain.reserve(10);
        ASSERT_EQ(10ULL, plain.capacity());
        ASSERT_EQ(2ULL, plain.coeff_count());
        ASSERT_EQ(2ULL, plain.significant_coeff_count());
        ASSERT_EQ(2ULL, plain.nonzero_coeff_count());
        ASSERT_EQ(1ULL, plain[0]);
        ASSERT_EQ(2ULL, plain[1]);
        ASSERT_FALSE(plain.is_ntt_form());

        plain.resize(5);
        ASSERT_EQ(10ULL, plain.capacity());
        ASSERT_EQ(5ULL, plain.coeff_count());
        ASSERT_EQ(2ULL, plain.significant_coeff_count());
        ASSERT_EQ(2ULL, plain.nonzero_coeff_count());
        ASSERT_EQ(1ULL, plain[0]);
        ASSERT_EQ(2ULL, plain[1]);
        ASSERT_EQ(0ULL, plain[2]);
        ASSERT_EQ(0ULL, plain[3]);
        ASSERT_EQ(0ULL, plain[4]);
        ASSERT_FALSE(plain.is_ntt_form());

        Plaintext plain2;
        plain2.resize(15);
        ASSERT_EQ(15ULL, plain2.capacity());
        ASSERT_EQ(15ULL, plain2.coeff_count());
        ASSERT_EQ(0ULL, plain2.significant_coeff_count());
        ASSERT_EQ(0ULL, plain2.nonzero_coeff_count());
        ASSERT_FALSE(plain.is_ntt_form());

        plain2 = plain;
        ASSERT_EQ(15ULL, plain2.capacity());
        ASSERT_EQ(5ULL, plain2.coeff_count());
        ASSERT_EQ(2ULL, plain2.significant_coeff_count());
        ASSERT_EQ(2ULL, plain2.nonzero_coeff_count());
        ASSERT_EQ(1ULL, plain2[0]);
        ASSERT_EQ(2ULL, plain2[1]);
        ASSERT_EQ(0ULL, plain2[2]);
        ASSERT_EQ(0ULL, plain2[3]);
        ASSERT_EQ(0ULL, plain2[4]);
        ASSERT_FALSE(plain.is_ntt_form());

        plain.parms_id() = { 1ULL, 2ULL, 3ULL, 4ULL };
        ASSERT_TRUE(plain.is_ntt_form());
        plain2 = plain;
        ASSERT_TRUE(plain == plain2);
        plain2.parms_id() = parms_id_zero;
        ASSERT_FALSE(plain2.is_ntt_form());
        ASSERT_FALSE(plain == plain2);
        plain2.parms_id() = { 1ULL, 2ULL, 3ULL, 5ULL };
        ASSERT_FALSE(plain == plain2);
    }
#ifdef SEAL_USE_MSGSL
    TEST(PlaintextTest, FromSpan)
    {
        // Constructors
        vector<uint64_t> coeffs{};
        Plaintext plain(coeffs);
        ASSERT_TRUE(plain.is_zero());

        coeffs = { 0 };
        plain = Plaintext(coeffs);
        ASSERT_EQ(1ULL, plain.coeff_count());
        ASSERT_EQ(1ULL, plain.capacity());
        ASSERT_TRUE(equal(coeffs.begin(), coeffs.end(), plain.data()));

        plain = Plaintext(coeffs, 2);
        ASSERT_EQ(1ULL, plain.coeff_count());
        ASSERT_EQ(2ULL, plain.capacity());
        ASSERT_TRUE(equal(coeffs.begin(), coeffs.end(), plain.data()));

        coeffs = { 1, 2 };
        plain = Plaintext(coeffs);
        ASSERT_EQ(2ULL, plain.coeff_count());
        ASSERT_EQ(2ULL, plain.capacity());
        ASSERT_TRUE(equal(coeffs.begin(), coeffs.end(), plain.data()));

        plain = Plaintext(coeffs, 3);
        ASSERT_EQ(2ULL, plain.coeff_count());
        ASSERT_EQ(3ULL, plain.capacity());
        ASSERT_TRUE(equal(coeffs.begin(), coeffs.end(), plain.data()));

        // Setter
        coeffs = {};
        plain = coeffs;
        ASSERT_EQ(0ULL, plain.coeff_count());
        ASSERT_EQ(3ULL, plain.capacity());

        coeffs = { 5, 4, 3, 2, 1 };
        plain = coeffs;
        ASSERT_EQ(5ULL, plain.coeff_count());
        ASSERT_EQ(5ULL, plain.capacity());
        ASSERT_TRUE(equal(coeffs.begin(), coeffs.end(), plain.data()));
    }
#endif
    TEST(PlaintextTest, SaveLoadPlaintext)
    {
        stringstream stream;
        Plaintext plain;
        Plaintext plain2;

        {
            EncryptionParameters parms(scheme_type::ckks);
            parms.set_poly_modulus_degree(4);
            parms.set_coeff_modulus(CoeffModulus::Create(4, { 20 }));

            SEALContext context(parms, false, sec_level_type::none);

            plain.save(stream);
            plain2.unsafe_load(context, stream);
            ASSERT_TRUE(plain.data() == plain2.data());
            ASSERT_TRUE(plain2.data() == nullptr);
            ASSERT_EQ(0ULL, plain2.capacity());
            ASSERT_EQ(0ULL, plain2.coeff_count());
            ASSERT_FALSE(plain2.is_ntt_form());

            plain.reserve(20);
            plain.resize(4);
            plain[0] = 1;
            plain[1] = 2;
            plain[2] = 3;
            plain.save(stream);
            plain2.unsafe_load(context, stream);
            ASSERT_TRUE(plain.data() != plain2.data());
            ASSERT_EQ(4ULL, plain2.capacity());
            ASSERT_EQ(4ULL, plain2.coeff_count());
            ASSERT_EQ(1ULL, plain2[0]);
            ASSERT_EQ(2ULL, plain2[1]);
            ASSERT_EQ(3ULL, plain2[2]);
            ASSERT_EQ(0ULL, plain2[3]);
            ASSERT_FALSE(plain2.is_ntt_form());

            plain.parms_id() = context.first_parms_id();
            plain.save(stream);
            plain2.unsafe_load(context, stream);
            ASSERT_TRUE(plain2.is_ntt_form());
            ASSERT_TRUE(plain2.parms_id() == plain.parms_id());
        }
        {
            EncryptionParameters parms(scheme_type::bfv);
            parms.set_poly_modulus_degree(64);
            parms.set_coeff_modulus(CoeffModulus::Create(64, { 30, 30 }));
            parms.set_plain_modulus(65537);

            SEALContext context(parms, false, sec_level_type::none);

            plain.parms_id() = parms_id_zero;
            plain = "1x^63 + 2x^62 + Fx^32 + Ax^9 + 1x^1 + 1";
            plain.save(stream);
            plain2.load(context, stream);
            ASSERT_TRUE(plain.data() != plain2.data());
            ASSERT_FALSE(plain2.is_ntt_form());

            Evaluator evaluator(context);
            evaluator.transform_to_ntt_inplace(plain, context.first_parms_id());
            plain.save(stream);
            plain2.load(context, stream);
            ASSERT_TRUE(plain.data() != plain2.data());
            ASSERT_TRUE(plain2.is_ntt_form());
        }
        {
            EncryptionParameters parms(scheme_type::bgv);
            parms.set_poly_modulus_degree(64);
            parms.set_coeff_modulus(CoeffModulus::Create(64, { 30, 30 }));
            parms.set_plain_modulus(65537);

            SEALContext context(parms, false, sec_level_type::none);

            plain.parms_id() = parms_id_zero;
            plain = "1x^63 + 2x^62 + Fx^32 + Ax^9 + 1x^1 + 1";
            plain.save(stream);
            plain2.load(context, stream);
            ASSERT_TRUE(plain.data() != plain2.data());
            ASSERT_FALSE(plain2.is_ntt_form());

            Evaluator evaluator(context);
            evaluator.transform_to_ntt_inplace(plain, context.first_parms_id());
            plain.save(stream);
            plain2.load(context, stream);
            ASSERT_TRUE(plain.data() != plain2.data());
            ASSERT_TRUE(plain2.is_ntt_form());
        }
        {
            EncryptionParameters parms(scheme_type::ckks);
            parms.set_poly_modulus_degree(64);
            parms.set_coeff_modulus(CoeffModulus::Create(64, { 30, 30 }));

            SEALContext context(parms, false, sec_level_type::none);
            CKKSEncoder encoder(context);

            encoder.encode(vector<double>{ 0.1, 2.3, 34.4 }, pow(2.0, 20), plain);
            ASSERT_TRUE(plain.is_ntt_form());
            plain.save(stream);
            plain2.load(context, stream);
            ASSERT_TRUE(plain.data() != plain2.data());
            ASSERT_TRUE(plain2.is_ntt_form());
        }
    }
} // namespace sealtest
