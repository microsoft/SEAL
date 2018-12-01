// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include "gtest/gtest.h"
#include "seal/ciphertext.h"
#include "seal/context.h"
#include "seal/keygenerator.h"
#include "seal/encryptor.h"
#include "seal/memorymanager.h"
#include "seal/defaultparams.h"

using namespace seal;
using namespace seal::util;
using namespace std;

namespace SEALTest
{
    TEST(CiphertextTest, CiphertextBasics)
    {
        EncryptionParameters parms(scheme_type::BFV);

        parms.set_poly_modulus_degree(2);
        parms.set_coeff_modulus({ small_mods_30bit(0) });
        parms.set_plain_modulus(2);
        parms.set_noise_standard_deviation(1.0);
        auto context = SEALContext::Create(parms);

        Ciphertext ctxt(context);
        ctxt.reserve(10);
        ASSERT_EQ(0ULL, ctxt.size());
        ASSERT_EQ(0ULL, ctxt.uint64_count());
        ASSERT_EQ(10ULL * 2 * 1, ctxt.uint64_count_capacity());
        ASSERT_EQ(2ULL, ctxt.poly_modulus_degree());
        ASSERT_TRUE(ctxt.parms_id() == parms.parms_id());
        ASSERT_FALSE(ctxt.is_ntt_form());
        const uint64_t *ptr = ctxt.data();

        ctxt.reserve(5);
        ASSERT_EQ(0ULL, ctxt.size());
        ASSERT_EQ(0ULL, ctxt.uint64_count());
        ASSERT_EQ(5ULL * 2 * 1, ctxt.uint64_count_capacity());
        ASSERT_EQ(2ULL, ctxt.poly_modulus_degree());
        ASSERT_TRUE(ptr != ctxt.data());
        ASSERT_TRUE(ctxt.parms_id() == parms.parms_id());
        ptr = ctxt.data();

        ctxt.reserve(10);
        ASSERT_EQ(0ULL, ctxt.size());
        ASSERT_EQ(0ULL, ctxt.uint64_count());
        ASSERT_EQ(10ULL * 2 * 1, ctxt.uint64_count_capacity());
        ASSERT_EQ(2ULL, ctxt.poly_modulus_degree());
        ASSERT_TRUE(ptr != ctxt.data());
        ASSERT_TRUE(ctxt.parms_id() == parms.parms_id());
        ASSERT_FALSE(ctxt.is_ntt_form());
        ptr = ctxt.data();

        ctxt.reserve(2);
        ASSERT_EQ(0ULL, ctxt.size());
        ASSERT_EQ(2ULL * 2 * 1, ctxt.uint64_count_capacity());
        ASSERT_EQ(0ULL, ctxt.uint64_count());
        ASSERT_EQ(2ULL, ctxt.poly_modulus_degree());
        ASSERT_TRUE(ptr != ctxt.data());
        ASSERT_TRUE(ctxt.parms_id() == parms.parms_id());
        ASSERT_FALSE(ctxt.is_ntt_form());
        ptr = ctxt.data();

        ctxt.reserve(5);
        ASSERT_EQ(0ULL, ctxt.size());
        ASSERT_EQ(5ULL * 2 * 1, ctxt.uint64_count_capacity());
        ASSERT_EQ(0ULL, ctxt.uint64_count());
        ASSERT_EQ(2ULL, ctxt.poly_modulus_degree());
        ASSERT_TRUE(ptr != ctxt.data());
        ASSERT_TRUE(ctxt.parms_id() == parms.parms_id());
        ASSERT_FALSE(ctxt.is_ntt_form());

        Ciphertext ctxt2{ ctxt };
        ASSERT_EQ(ctxt.coeff_mod_count(), ctxt2.coeff_mod_count());
        ASSERT_EQ(ctxt.is_ntt_form(), ctxt2.is_ntt_form());
        ASSERT_EQ(ctxt.poly_modulus_degree(), ctxt2.poly_modulus_degree());
        ASSERT_TRUE(ctxt.parms_id() == ctxt2.parms_id());
        ASSERT_EQ(ctxt.poly_modulus_degree(), ctxt2.poly_modulus_degree());
        ASSERT_EQ(ctxt.size(), ctxt2.size());

        Ciphertext ctxt3;
        ctxt3 = ctxt;
        ASSERT_EQ(ctxt.coeff_mod_count(), ctxt3.coeff_mod_count());
        ASSERT_EQ(ctxt.poly_modulus_degree(), ctxt3.poly_modulus_degree());
        ASSERT_EQ(ctxt.is_ntt_form(), ctxt3.is_ntt_form());
        ASSERT_TRUE(ctxt.parms_id() == ctxt3.parms_id());
        ASSERT_EQ(ctxt.poly_modulus_degree(), ctxt3.poly_modulus_degree());
        ASSERT_EQ(ctxt.size(), ctxt3.size());
    }

    TEST(CiphertextTest, SaveLoadCiphertext)
    {
        stringstream stream;
        EncryptionParameters parms(scheme_type::BFV);
        parms.set_poly_modulus_degree(2);
        parms.set_coeff_modulus({ small_mods_30bit(0) });
        parms.set_plain_modulus(2);
        parms.set_noise_standard_deviation(1.0);

        auto context = SEALContext::Create(parms);

        Ciphertext ctxt(context);
        Ciphertext ctxt2;
        ctxt.save(stream);
        ctxt2.load(context, stream);
        ASSERT_TRUE(ctxt.parms_id() == ctxt2.parms_id());
        ASSERT_FALSE(ctxt.is_ntt_form());
        ASSERT_FALSE(ctxt2.is_ntt_form());

        parms.set_poly_modulus_degree(1024);
        parms.set_coeff_modulus(coeff_modulus_128(1024));
        parms.set_plain_modulus(0xF0F0);
        parms.set_noise_standard_deviation(3.14159);
        context = SEALContext::Create(parms);
        KeyGenerator keygen(context);
        Encryptor encryptor(context, keygen.public_key());
        encryptor.encrypt(Plaintext("Ax^10 + 9x^9 + 8x^8 + 7x^7 + 6x^6 + 5x^5 + 4x^4 + 3x^3 + 2x^2 + 1"), ctxt);
        ctxt.save(stream);
        ctxt2.load(context, stream);
        ASSERT_TRUE(ctxt.parms_id() == ctxt2.parms_id());
        ASSERT_FALSE(ctxt.is_ntt_form());
        ASSERT_FALSE(ctxt2.is_ntt_form());
        ASSERT_TRUE(is_equal_uint_uint(ctxt.data(), ctxt2.data(),
            parms.poly_modulus_degree() * parms.coeff_modulus().size() * 2));
        ASSERT_TRUE(ctxt.data() != ctxt2.data());
    }
}
