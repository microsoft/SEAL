// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include "seal/context.h"
#include "seal/decryptor.h"
#include "seal/encryptor.h"
#include "seal/evaluator.h"
#include "seal/keygenerator.h"
#include "seal/valcheck.h"
#include "seal/util/polycore.h"
#include "gtest/gtest.h"

using namespace seal;
using namespace seal::util;
using namespace std;

namespace sealtest
{
    TEST(KeyGeneratorTest, BFVKeyGeneration)
    {
        EncryptionParameters parms(scheme_type::BFV);
        {
            parms.set_poly_modulus_degree(64);
            parms.set_plain_modulus(65537);
            parms.set_coeff_modulus(CoeffModulus::Create(64, { 60 }));
            auto context = SEALContext::Create(parms, false, sec_level_type::none);
            KeyGenerator keygen(context);

            ASSERT_THROW(RelinKeys evk = keygen.relin_keys_local(), logic_error);
            ASSERT_THROW(GaloisKeys galk = keygen.galois_keys_local(), logic_error);
        }
        {
            parms.set_poly_modulus_degree(64);
            parms.set_plain_modulus(65537);
            parms.set_coeff_modulus(CoeffModulus::Create(64, { 60, 60 }));
            auto context = SEALContext::Create(parms, false, sec_level_type::none);
            KeyGenerator keygen(context);

            RelinKeys evk = keygen.relin_keys_local();
            ASSERT_TRUE(evk.parms_id() == context->key_parms_id());
            ASSERT_EQ(1ULL, evk.key(2).size());
            for (auto &a : evk.data())
            {
                for (auto &b : a)
                {
                    ASSERT_FALSE(b.data().is_transparent());
                }
            }
            ASSERT_TRUE(is_valid_for(evk, context));

            GaloisKeys galks = keygen.galois_keys_local();
            for (auto &a : galks.data())
            {
                for (auto &b : a)
                {
                    ASSERT_FALSE(b.data().is_transparent());
                }
            }
            ASSERT_TRUE(is_valid_for(galks, context));

            ASSERT_TRUE(galks.parms_id() == context->key_parms_id());
            ASSERT_EQ(1ULL, galks.key(3).size());
            ASSERT_EQ(10ULL, galks.size());

            galks = keygen.galois_keys_local(vector<uint32_t>{ 1, 3, 5, 7 });
            ASSERT_TRUE(galks.parms_id() == context->key_parms_id());
            ASSERT_TRUE(galks.has_key(1));
            ASSERT_TRUE(galks.has_key(3));
            ASSERT_TRUE(galks.has_key(5));
            ASSERT_TRUE(galks.has_key(7));
            ASSERT_FALSE(galks.has_key(9));
            ASSERT_FALSE(galks.has_key(127));
            ASSERT_EQ(1ULL, galks.key(1).size());
            ASSERT_EQ(1ULL, galks.key(3).size());
            ASSERT_EQ(1ULL, galks.key(5).size());
            ASSERT_EQ(1ULL, galks.key(7).size());
            ASSERT_EQ(4ULL, galks.size());

            galks = keygen.galois_keys_local(vector<uint32_t>{ 1 });
            ASSERT_TRUE(galks.parms_id() == context->key_parms_id());
            ASSERT_TRUE(galks.has_key(1));
            ASSERT_FALSE(galks.has_key(3));
            ASSERT_FALSE(galks.has_key(127));
            ASSERT_EQ(1ULL, galks.key(1).size());
            ASSERT_EQ(1ULL, galks.size());

            galks = keygen.galois_keys_local(vector<uint32_t>{ 127 });
            ASSERT_TRUE(galks.parms_id() == context->key_parms_id());
            ASSERT_FALSE(galks.has_key(1));
            ASSERT_TRUE(galks.has_key(127));
            ASSERT_EQ(1ULL, galks.key(127).size());
            ASSERT_EQ(1ULL, galks.size());
        }
        {
            parms.set_poly_modulus_degree(256);
            parms.set_plain_modulus(65537);
            parms.set_coeff_modulus(CoeffModulus::Create(256, { 60, 30, 30 }));

            auto context = SEALContext::Create(parms, false, sec_level_type::none);
            KeyGenerator keygen(context);

            RelinKeys evk = keygen.relin_keys_local();
            ASSERT_TRUE(evk.parms_id() == context->key_parms_id());
            ASSERT_EQ(2ULL, evk.key(2).size());

            for (auto &a : evk.data())
            {
                for (auto &b : a)
                {
                    ASSERT_FALSE(b.data().is_transparent());
                }
            }
            ASSERT_TRUE(is_valid_for(evk, context));

            GaloisKeys galks = keygen.galois_keys_local();
            for (auto &a : galks.data())
            {
                for (auto &b : a)
                {
                    ASSERT_FALSE(b.data().is_transparent());
                }
            }
            ASSERT_TRUE(is_valid_for(galks, context));

            ASSERT_TRUE(galks.parms_id() == context->key_parms_id());
            ASSERT_EQ(2ULL, galks.key(3).size());
            ASSERT_EQ(14ULL, galks.size());

            galks = keygen.galois_keys_local(vector<uint32_t>{ 1, 3, 5, 7 });
            ASSERT_TRUE(galks.parms_id() == context->key_parms_id());
            ASSERT_TRUE(galks.has_key(1));
            ASSERT_TRUE(galks.has_key(3));
            ASSERT_TRUE(galks.has_key(5));
            ASSERT_TRUE(galks.has_key(7));
            ASSERT_FALSE(galks.has_key(9));
            ASSERT_FALSE(galks.has_key(511));
            ASSERT_EQ(2ULL, galks.key(1).size());
            ASSERT_EQ(2ULL, galks.key(3).size());
            ASSERT_EQ(2ULL, galks.key(5).size());
            ASSERT_EQ(2ULL, galks.key(7).size());
            ASSERT_EQ(4ULL, galks.size());

            galks = keygen.galois_keys_local(vector<uint32_t>{ 1 });
            ASSERT_TRUE(galks.parms_id() == context->key_parms_id());
            ASSERT_TRUE(galks.has_key(1));
            ASSERT_FALSE(galks.has_key(3));
            ASSERT_FALSE(galks.has_key(511));
            ASSERT_EQ(2ULL, galks.key(1).size());
            ASSERT_EQ(1ULL, galks.size());

            galks = keygen.galois_keys_local(vector<uint32_t>{ 511 });
            ASSERT_TRUE(galks.parms_id() == context->key_parms_id());
            ASSERT_FALSE(galks.has_key(1));
            ASSERT_TRUE(galks.has_key(511));
            ASSERT_EQ(2ULL, galks.key(511).size());
            ASSERT_EQ(1ULL, galks.size());
        }
    }

    TEST(KeyGeneratorTest, CKKSKeyGeneration)
    {
        EncryptionParameters parms(scheme_type::CKKS);
        {
            parms.set_poly_modulus_degree(64);
            parms.set_coeff_modulus(CoeffModulus::Create(64, { 60 }));
            auto context = SEALContext::Create(parms, false, sec_level_type::none);
            KeyGenerator keygen(context);

            ASSERT_THROW(RelinKeys evk = keygen.relin_keys_local(), logic_error);
            ASSERT_THROW(GaloisKeys galk = keygen.galois_keys_local(), logic_error);
        }
        {
            parms.set_poly_modulus_degree(64);
            parms.set_coeff_modulus(CoeffModulus::Create(64, { 60, 60 }));

            auto context = SEALContext::Create(parms, false, sec_level_type::none);
            KeyGenerator keygen(context);

            RelinKeys evk = keygen.relin_keys_local();
            ASSERT_TRUE(evk.parms_id() == context->key_parms_id());
            ASSERT_EQ(1ULL, evk.key(2).size());
            for (auto &a : evk.data())
            {
                for (auto &b : a)
                {
                    ASSERT_FALSE(b.data().is_transparent());
                }
            }
            ASSERT_TRUE(is_valid_for(evk, context));

            GaloisKeys galks = keygen.galois_keys_local();
            for (auto &a : galks.data())
            {
                for (auto &b : a)
                {
                    ASSERT_FALSE(b.data().is_transparent());
                }
            }
            ASSERT_TRUE(is_valid_for(galks, context));

            ASSERT_TRUE(galks.parms_id() == context->key_parms_id());
            ASSERT_EQ(1ULL, galks.key(3).size());
            ASSERT_EQ(10ULL, galks.size());

            galks = keygen.galois_keys_local(vector<uint32_t>{ 1, 3, 5, 7 });
            ASSERT_TRUE(galks.parms_id() == context->key_parms_id());
            ASSERT_TRUE(galks.has_key(1));
            ASSERT_TRUE(galks.has_key(3));
            ASSERT_TRUE(galks.has_key(5));
            ASSERT_TRUE(galks.has_key(7));
            ASSERT_FALSE(galks.has_key(9));
            ASSERT_FALSE(galks.has_key(127));
            ASSERT_EQ(1ULL, galks.key(1).size());
            ASSERT_EQ(1ULL, galks.key(3).size());
            ASSERT_EQ(1ULL, galks.key(5).size());
            ASSERT_EQ(1ULL, galks.key(7).size());
            ASSERT_EQ(4ULL, galks.size());

            galks = keygen.galois_keys_local(vector<uint32_t>{ 1 });
            ASSERT_TRUE(galks.parms_id() == context->key_parms_id());
            ASSERT_TRUE(galks.has_key(1));
            ASSERT_FALSE(galks.has_key(3));
            ASSERT_FALSE(galks.has_key(127));
            ASSERT_EQ(1ULL, galks.key(1).size());
            ASSERT_EQ(1ULL, galks.size());

            galks = keygen.galois_keys_local(vector<uint32_t>{ 127 });
            ASSERT_TRUE(galks.parms_id() == context->key_parms_id());
            ASSERT_FALSE(galks.has_key(1));
            ASSERT_TRUE(galks.has_key(127));
            ASSERT_EQ(1ULL, galks.key(127).size());
            ASSERT_EQ(1ULL, galks.size());
        }
        {
            parms.set_poly_modulus_degree(256);
            parms.set_coeff_modulus(CoeffModulus::Create(256, { 60, 30, 30 }));

            auto context = SEALContext::Create(parms, false, sec_level_type::none);
            KeyGenerator keygen(context);

            RelinKeys evk = keygen.relin_keys_local();
            ASSERT_TRUE(evk.parms_id() == context->key_parms_id());
            ASSERT_EQ(2ULL, evk.key(2).size());
            for (auto &a : evk.data())
            {
                for (auto &b : a)
                {
                    ASSERT_FALSE(b.data().is_transparent());
                }
            }
            ASSERT_TRUE(is_valid_for(evk, context));

            GaloisKeys galks = keygen.galois_keys_local();
            for (auto &a : galks.data())
            {
                for (auto &b : a)
                {
                    ASSERT_FALSE(b.data().is_transparent());
                }
            }
            ASSERT_TRUE(is_valid_for(galks, context));

            ASSERT_TRUE(galks.parms_id() == context->key_parms_id());
            ASSERT_EQ(2ULL, galks.key(3).size());
            ASSERT_EQ(14ULL, galks.size());

            galks = keygen.galois_keys_local(vector<uint32_t>{ 1, 3, 5, 7 });
            ASSERT_TRUE(galks.parms_id() == context->key_parms_id());
            ASSERT_TRUE(galks.has_key(1));
            ASSERT_TRUE(galks.has_key(3));
            ASSERT_TRUE(galks.has_key(5));
            ASSERT_TRUE(galks.has_key(7));
            ASSERT_FALSE(galks.has_key(9));
            ASSERT_FALSE(galks.has_key(511));
            ASSERT_EQ(2ULL, galks.key(1).size());
            ASSERT_EQ(2ULL, galks.key(3).size());
            ASSERT_EQ(2ULL, galks.key(5).size());
            ASSERT_EQ(2ULL, galks.key(7).size());
            ASSERT_EQ(4ULL, galks.size());

            galks = keygen.galois_keys_local(vector<uint32_t>{ 1 });
            ASSERT_TRUE(galks.parms_id() == context->key_parms_id());
            ASSERT_TRUE(galks.has_key(1));
            ASSERT_FALSE(galks.has_key(3));
            ASSERT_FALSE(galks.has_key(511));
            ASSERT_EQ(2ULL, galks.key(1).size());
            ASSERT_EQ(1ULL, galks.size());

            galks = keygen.galois_keys_local(vector<uint32_t>{ 511 });
            ASSERT_TRUE(galks.parms_id() == context->key_parms_id());
            ASSERT_FALSE(galks.has_key(1));
            ASSERT_TRUE(galks.has_key(511));
            ASSERT_EQ(2ULL, galks.key(511).size());
            ASSERT_EQ(1ULL, galks.size());
        }
    }

    TEST(KeyGeneratorTest, Constructors)
    {
        EncryptionParameters parms(scheme_type::BFV);
        parms.set_poly_modulus_degree(128);
        parms.set_plain_modulus(65537);
        parms.set_coeff_modulus(CoeffModulus::Create(128, { 60, 50, 40 }));
        auto context = SEALContext::Create(parms, false, sec_level_type::none);
        Evaluator evaluator(context);

        KeyGenerator keygen(context);
        auto pk = keygen.public_key();
        auto sk = keygen.secret_key();
        RelinKeys rlk = keygen.relin_keys_local();
        GaloisKeys galk = keygen.galois_keys_local();

        ASSERT_TRUE(is_valid_for(rlk, context));
        ASSERT_TRUE(is_valid_for(galk, context));

        Encryptor encryptor(context, pk);
        Decryptor decryptor(context, sk);
        Plaintext pt("1x^2 + 2"), ptres;
        Ciphertext ct;
        encryptor.encrypt(pt, ct);
        evaluator.square_inplace(ct);
        evaluator.relinearize_inplace(ct, rlk);
        decryptor.decrypt(ct, ptres);
        ASSERT_EQ("1x^4 + 4x^2 + 4", ptres.to_string());

        KeyGenerator keygen2(context, sk);
        auto sk2 = keygen.secret_key();
        auto pk2 = keygen2.public_key();
        ASSERT_EQ(sk2.data(), sk.data());

        RelinKeys rlk2 = keygen2.relin_keys_local();
        GaloisKeys galk2 = keygen2.galois_keys_local();

        ASSERT_TRUE(is_valid_for(rlk2, context));
        ASSERT_TRUE(is_valid_for(galk2, context));

        Encryptor encryptor2(context, pk2);
        Decryptor decryptor2(context, sk2);
        pt = "1x^2 + 2";
        ptres.set_zero();
        encryptor.encrypt(pt, ct);
        evaluator.square_inplace(ct);
        evaluator.relinearize_inplace(ct, rlk2);
        decryptor.decrypt(ct, ptres);
        ASSERT_EQ("1x^4 + 4x^2 + 4", ptres.to_string());

        auto pk3 = keygen2.public_key();

        // There is a small random chance for this to fail
        for (size_t i = 0; i < pk3.data().int_array().size(); i++)
        {
            ASSERT_NE(pk3.data().data()[i], pk2.data().data()[i]);
        }
    }
} // namespace sealtest
