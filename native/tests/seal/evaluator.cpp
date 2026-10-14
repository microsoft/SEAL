// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include "seal/batchencoder.h"
#include "seal/ckks.h"
#include "seal/context.h"
#include "seal/decryptor.h"
#include "seal/encryptor.h"
#include "seal/evaluator.h"
#include "seal/keygenerator.h"
#include "seal/memorymanager.h"
#include "seal/modulus.h"
#include "seal/valcheck.h"
#include "seal/util/ntt.h"
#include "seal/util/rlwe.h"
#include "seal/util/rns.h"
#include "seal/util/uintarith.h"
#include "seal/util/uintarithsmallmod.h"
#include "seal/util/uintcore.h"
#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <memory>
#include <random>
#include <string>
#include <utility>
#include <vector>
#include "gtest/gtest.h"
#include "testseed.h"

using namespace seal;
using namespace std;

namespace sealtest
{
    TEST(EvaluatorTest, BFVEncryptNegateDecrypt)
    {
        EncryptionParameters parms(scheme_type::bfv);
        Modulus plain_modulus(1 << 6);
        parms.set_poly_modulus_degree(64);
        parms.set_plain_modulus(plain_modulus);
        parms.set_coeff_modulus(CoeffModulus::Create(64, { 40 }));

        SEALContext context(parms, false, sec_level_type::none);
        KeyGenerator keygen(context);
        PublicKey pk;
        keygen.create_public_key(pk);

        Encryptor encryptor(context, pk);
        Evaluator evaluator(context);
        Decryptor decryptor(context, keygen.secret_key());

        Ciphertext encrypted;
        Plaintext plain;

        plain = "1x^28 + 1x^25 + 1x^21 + 1x^20 + 1x^18 + 1x^14 + 1x^12 + 1x^10 + 1x^9 + 1x^6 + 1x^5 + 1x^4 + 1x^3";
        encryptor.encrypt(plain, encrypted);
        evaluator.negate_inplace(encrypted);
        decryptor.decrypt(encrypted, plain);
        ASSERT_EQ(
            plain.to_string(), "3Fx^28 + 3Fx^25 + 3Fx^21 + 3Fx^20 + 3Fx^18 + 3Fx^14 + 3Fx^12 + 3Fx^10 + 3Fx^9 + 3Fx^6 "
                               "+ 3Fx^5 + 3Fx^4 + 3Fx^3");
        ASSERT_TRUE(encrypted.parms_id() == context.first_parms_id());

        plain = "0";
        encryptor.encrypt(plain, encrypted);
        evaluator.negate_inplace(encrypted);
        decryptor.decrypt(encrypted, plain);
        ASSERT_EQ(plain.to_string(), "0");
        ASSERT_TRUE(encrypted.parms_id() == context.first_parms_id());

        plain = "1";
        encryptor.encrypt(plain, encrypted);
        evaluator.negate_inplace(encrypted);
        decryptor.decrypt(encrypted, plain);
        ASSERT_EQ(plain.to_string(), "3F");
        ASSERT_TRUE(encrypted.parms_id() == context.first_parms_id());

        plain = "3F";
        encryptor.encrypt(plain, encrypted);
        evaluator.negate_inplace(encrypted);
        decryptor.decrypt(encrypted, plain);
        ASSERT_EQ(plain.to_string(), "1");
        ASSERT_TRUE(encrypted.parms_id() == context.first_parms_id());

        plain = "1x^1";
        encryptor.encrypt(plain, encrypted);
        evaluator.negate_inplace(encrypted);
        decryptor.decrypt(encrypted, plain);
        ASSERT_EQ(plain.to_string(), "3Fx^1");
        ASSERT_TRUE(encrypted.parms_id() == context.first_parms_id());

        plain = "3Fx^2 + 3F";
        encryptor.encrypt(plain, encrypted);
        evaluator.negate_inplace(encrypted);
        decryptor.decrypt(encrypted, plain);
        ASSERT_EQ(plain.to_string(), "1x^2 + 1");
        ASSERT_TRUE(encrypted.parms_id() == context.first_parms_id());
    }

    TEST(EvaluatorTest, BFVEncryptAddDecrypt)
    {
        EncryptionParameters parms(scheme_type::bfv);
        Modulus plain_modulus(1 << 6);
        parms.set_poly_modulus_degree(64);
        parms.set_plain_modulus(plain_modulus);
        parms.set_coeff_modulus(CoeffModulus::Create(64, { 40 }));

        SEALContext context(parms, false, sec_level_type::none);
        KeyGenerator keygen(context);
        PublicKey pk;
        keygen.create_public_key(pk);

        Encryptor encryptor(context, pk);
        Evaluator evaluator(context);
        Decryptor decryptor(context, keygen.secret_key());

        Ciphertext encrypted1;
        Ciphertext encrypted2;
        Plaintext plain, plain1, plain2;

        plain1 = "1x^28 + 1x^25 + 1x^21 + 1x^20 + 1x^18 + 1x^14 + 1x^12 + 1x^10 + 1x^9 + 1x^6 + 1x^5 + 1x^4 + 1x^3";
        plain2 = "1x^18 + 1x^16 + 1x^14 + 1x^9 + 1x^8 + 1x^5 + 1";
        encryptor.encrypt(plain1, encrypted1);
        encryptor.encrypt(plain2, encrypted2);
        evaluator.add_inplace(encrypted1, encrypted2);
        decryptor.decrypt(encrypted1, plain);
        ASSERT_EQ(
            plain.to_string(), "1x^28 + 1x^25 + 1x^21 + 1x^20 + 2x^18 + 1x^16 + 2x^14 + 1x^12 + 1x^10 + 2x^9 + 1x^8 + "
                               "1x^6 + 2x^5 + 1x^4 + 1x^3 + 1");
        ASSERT_TRUE(encrypted2.parms_id() == encrypted1.parms_id());
        ASSERT_TRUE(encrypted1.parms_id() == context.first_parms_id());

        plain1 = "0";
        plain2 = "0";
        encryptor.encrypt(plain1, encrypted1);
        encryptor.encrypt(plain2, encrypted2);
        evaluator.add_inplace(encrypted1, encrypted2);
        decryptor.decrypt(encrypted1, plain);
        ASSERT_EQ("0", plain.to_string());
        ASSERT_TRUE(encrypted2.parms_id() == encrypted1.parms_id());
        ASSERT_TRUE(encrypted1.parms_id() == context.first_parms_id());

        plain1 = "0";
        plain2 = "1x^2 + 1";
        encryptor.encrypt(plain1, encrypted1);
        encryptor.encrypt(plain2, encrypted2);
        evaluator.add_inplace(encrypted1, encrypted2);
        decryptor.decrypt(encrypted1, plain);
        ASSERT_EQ(plain.to_string(), "1x^2 + 1");
        ASSERT_TRUE(encrypted2.parms_id() == encrypted1.parms_id());
        ASSERT_TRUE(encrypted1.parms_id() == context.first_parms_id());

        plain1 = "1x^2 + 1";
        plain2 = "3Fx^1 + 3F";
        encryptor.encrypt(plain1, encrypted1);
        encryptor.encrypt(plain2, encrypted2);
        evaluator.add_inplace(encrypted1, encrypted2);
        decryptor.decrypt(encrypted1, plain);
        ASSERT_EQ(plain.to_string(), "1x^2 + 3Fx^1");
        ASSERT_TRUE(encrypted2.parms_id() == encrypted1.parms_id());
        ASSERT_TRUE(encrypted1.parms_id() == context.first_parms_id());

        plain1 = "3Fx^2 + 3Fx^1 + 3F";
        plain2 = "1x^1";
        encryptor.encrypt(plain1, encrypted1);
        encryptor.encrypt(plain2, encrypted2);
        evaluator.add_inplace(encrypted1, encrypted2);
        decryptor.decrypt(encrypted1, plain);
        ASSERT_EQ(plain.to_string(), "3Fx^2 + 3F");
        ASSERT_TRUE(encrypted2.parms_id() == encrypted1.parms_id());
        ASSERT_TRUE(encrypted1.parms_id() == context.first_parms_id());

        plain1 = "2x^2 + 1x^1 + 3";
        plain2 = "3x^3 + 4x^2 + 5x^1 + 6";
        encryptor.encrypt(plain1, encrypted1);
        encryptor.encrypt(plain2, encrypted2);
        evaluator.add_inplace(encrypted1, encrypted2);
        decryptor.decrypt(encrypted1, plain);
        ASSERT_TRUE(plain.to_string() == "3x^3 + 6x^2 + 6x^1 + 9");
        ASSERT_TRUE(encrypted2.parms_id() == encrypted1.parms_id());
        ASSERT_TRUE(encrypted1.parms_id() == context.first_parms_id());

        plain1 = "3x^5 + 1x^4 + 4x^3 + 1";
        plain2 = "5x^2 + 9x^1 + 2";
        encryptor.encrypt(plain1, encrypted1);
        encryptor.encrypt(plain2, encrypted2);
        evaluator.add_inplace(encrypted1, encrypted2);
        decryptor.decrypt(encrypted1, plain);
        ASSERT_TRUE(plain.to_string() == "3x^5 + 1x^4 + 4x^3 + 5x^2 + 9x^1 + 3");
        ASSERT_TRUE(encrypted2.parms_id() == encrypted1.parms_id());
        ASSERT_TRUE(encrypted1.parms_id() == context.first_parms_id());
    }

    TEST(EvaluatorTest, BGVEncryptNegateDecrypt)
    {
        EncryptionParameters parms(scheme_type::bgv);
        Modulus plain_modulus(65);
        parms.set_poly_modulus_degree(64);
        parms.set_plain_modulus(plain_modulus);
        parms.set_coeff_modulus(CoeffModulus::Create(64, { 40 }));

        SEALContext context(parms, false, sec_level_type::none);
        KeyGenerator keygen(context);
        PublicKey pk;
        keygen.create_public_key(pk);

        Encryptor encryptor(context, pk);
        Evaluator evaluator(context);
        Decryptor decryptor(context, keygen.secret_key());

        Ciphertext encrypted;
        Plaintext plain;

        plain = "1x^28 + 1x^25 + 1x^21 + 1x^20 + 1x^18 + 1x^14 + 1x^12 + 1x^10 + 1x^9 + 1x^6 + 1x^5 + 1x^4 + 1x^3";
        encryptor.encrypt(plain, encrypted);
        evaluator.negate_inplace(encrypted);
        decryptor.decrypt(encrypted, plain);
        ASSERT_EQ(
            plain.to_string(), "40x^28 + 40x^25 + 40x^21 + 40x^20 + 40x^18 + 40x^14 + 40x^12 + 40x^10 + 40x^9 + 40x^6 "
                               "+ 40x^5 + 40x^4 + 40x^3");
        ASSERT_TRUE(encrypted.parms_id() == context.first_parms_id());

        plain = "0";
        encryptor.encrypt(plain, encrypted);
        evaluator.negate_inplace(encrypted);
        decryptor.decrypt(encrypted, plain);
        ASSERT_EQ(plain.to_string(), "0");
        ASSERT_TRUE(encrypted.parms_id() == context.first_parms_id());

        plain = "1";
        encryptor.encrypt(plain, encrypted);
        evaluator.negate_inplace(encrypted);
        decryptor.decrypt(encrypted, plain);
        ASSERT_EQ(plain.to_string(), "40");
        ASSERT_TRUE(encrypted.parms_id() == context.first_parms_id());

        plain = "40";
        encryptor.encrypt(plain, encrypted);
        evaluator.negate_inplace(encrypted);
        decryptor.decrypt(encrypted, plain);
        ASSERT_EQ(plain.to_string(), "1");
        ASSERT_TRUE(encrypted.parms_id() == context.first_parms_id());

        plain = "1x^1";
        encryptor.encrypt(plain, encrypted);
        evaluator.negate_inplace(encrypted);
        decryptor.decrypt(encrypted, plain);
        ASSERT_EQ(plain.to_string(), "40x^1");
        ASSERT_TRUE(encrypted.parms_id() == context.first_parms_id());

        plain = "40x^2 + 40";
        encryptor.encrypt(plain, encrypted);
        evaluator.negate_inplace(encrypted);
        decryptor.decrypt(encrypted, plain);
        ASSERT_EQ(plain.to_string(), "1x^2 + 1");
        ASSERT_TRUE(encrypted.parms_id() == context.first_parms_id());
    }

    TEST(EvaluatorTest, BGVEncryptAddDecrypt)
    {
        EncryptionParameters parms(scheme_type::bgv);
        Modulus plain_modulus(65);
        parms.set_poly_modulus_degree(64);
        parms.set_plain_modulus(plain_modulus);
        parms.set_coeff_modulus(CoeffModulus::Create(64, { 40 }));

        SEALContext context(parms, false, sec_level_type::none);
        KeyGenerator keygen(context);
        PublicKey pk;
        keygen.create_public_key(pk);

        Encryptor encryptor(context, pk);
        Evaluator evaluator(context);
        Decryptor decryptor(context, keygen.secret_key());

        Ciphertext encrypted1;
        Ciphertext encrypted2;
        Plaintext plain, plain1, plain2;

        plain1 = "1x^28 + 1x^25 + 1x^21 + 1x^20 + 1x^18 + 1x^14 + 1x^12 + 1x^10 + 1x^9 + 1x^6 + 1x^5 + 1x^4 + 1x^3";
        plain2 = "1x^18 + 1x^16 + 1x^14 + 1x^9 + 1x^8 + 1x^5 + 1";
        encryptor.encrypt(plain1, encrypted1);
        encryptor.encrypt(plain2, encrypted2);
        evaluator.add_inplace(encrypted1, encrypted2);
        decryptor.decrypt(encrypted1, plain);
        ASSERT_EQ(
            plain.to_string(), "1x^28 + 1x^25 + 1x^21 + 1x^20 + 2x^18 + 1x^16 + 2x^14 + 1x^12 + 1x^10 + 2x^9 + 1x^8 + "
                               "1x^6 + 2x^5 + 1x^4 + 1x^3 + 1");
        ASSERT_TRUE(encrypted2.parms_id() == encrypted1.parms_id());
        ASSERT_TRUE(encrypted1.parms_id() == context.first_parms_id());

        // Test correction factor
        plain1 = "2x^28 + 2x^25 + 2x^21 + 2x^20 + 2x^18 + 2x^14 + 2x^12 + 2x^10 + 2x^9 + 2x^6 + 2x^5 + 2x^4 + 2x^3";
        plain2 = "40x^18 + 40x^16 + 40x^14 + 40x^9 + 40x^8 + 40x^5 + 40";
        encryptor.encrypt(plain1, encrypted1);
        encrypted1.correction_factor() = 2;
        encryptor.encrypt(plain2, encrypted2);
        encrypted2.correction_factor() = 64;
        evaluator.add_inplace(encrypted1, encrypted2);
        decryptor.decrypt(encrypted1, plain);
        ASSERT_EQ(
            plain.to_string(), "1x^28 + 1x^25 + 1x^21 + 1x^20 + 2x^18 + 1x^16 + 2x^14 + 1x^12 + 1x^10 + 2x^9 + 1x^8 + "
                               "1x^6 + 2x^5 + 1x^4 + 1x^3 + 1");
        ASSERT_TRUE(encrypted2.parms_id() == encrypted1.parms_id());
        ASSERT_TRUE(encrypted1.parms_id() == context.first_parms_id());

        plain1 = "0";
        plain2 = "0";
        encryptor.encrypt(plain1, encrypted1);
        encryptor.encrypt(plain2, encrypted2);
        evaluator.add_inplace(encrypted1, encrypted2);
        decryptor.decrypt(encrypted1, plain);
        ASSERT_EQ("0", plain.to_string());
        ASSERT_TRUE(encrypted2.parms_id() == encrypted1.parms_id());
        ASSERT_TRUE(encrypted1.parms_id() == context.first_parms_id());

        plain1 = "0";
        plain2 = "1x^2 + 1";
        encryptor.encrypt(plain1, encrypted1);
        encryptor.encrypt(plain2, encrypted2);
        evaluator.add_inplace(encrypted1, encrypted2);
        decryptor.decrypt(encrypted1, plain);
        ASSERT_EQ(plain.to_string(), "1x^2 + 1");
        ASSERT_TRUE(encrypted2.parms_id() == encrypted1.parms_id());
        ASSERT_TRUE(encrypted1.parms_id() == context.first_parms_id());

        plain1 = "1x^2 + 1";
        plain2 = "40x^1 + 40";
        encryptor.encrypt(plain1, encrypted1);
        encryptor.encrypt(plain2, encrypted2);
        evaluator.add_inplace(encrypted1, encrypted2);
        decryptor.decrypt(encrypted1, plain);
        ASSERT_EQ(plain.to_string(), "1x^2 + 40x^1");
        ASSERT_TRUE(encrypted2.parms_id() == encrypted1.parms_id());
        ASSERT_TRUE(encrypted1.parms_id() == context.first_parms_id());

        plain1 = "40x^2 + 40x^1 + 40";
        plain2 = "1x^1";
        encryptor.encrypt(plain1, encrypted1);
        encryptor.encrypt(plain2, encrypted2);
        evaluator.add_inplace(encrypted1, encrypted2);
        decryptor.decrypt(encrypted1, plain);
        ASSERT_EQ(plain.to_string(), "40x^2 + 40");
        ASSERT_TRUE(encrypted2.parms_id() == encrypted1.parms_id());
        ASSERT_TRUE(encrypted1.parms_id() == context.first_parms_id());

        plain1 = "2x^2 + 1x^1 + 3";
        plain2 = "3x^3 + 4x^2 + 5x^1 + 6";
        encryptor.encrypt(plain1, encrypted1);
        encryptor.encrypt(plain2, encrypted2);
        evaluator.add_inplace(encrypted1, encrypted2);
        decryptor.decrypt(encrypted1, plain);
        ASSERT_TRUE(plain.to_string() == "3x^3 + 6x^2 + 6x^1 + 9");
        ASSERT_TRUE(encrypted2.parms_id() == encrypted1.parms_id());
        ASSERT_TRUE(encrypted1.parms_id() == context.first_parms_id());

        plain1 = "3x^5 + 1x^4 + 4x^3 + 1";
        plain2 = "5x^2 + 9x^1 + 2";
        encryptor.encrypt(plain1, encrypted1);
        encryptor.encrypt(plain2, encrypted2);
        evaluator.add_inplace(encrypted1, encrypted2);
        decryptor.decrypt(encrypted1, plain);
        ASSERT_TRUE(plain.to_string() == "3x^5 + 1x^4 + 4x^3 + 5x^2 + 9x^1 + 3");
        ASSERT_TRUE(encrypted2.parms_id() == encrypted1.parms_id());
        ASSERT_TRUE(encrypted1.parms_id() == context.first_parms_id());
    }

    TEST(EvaluatorTest, CKKSEncryptAddDecrypt)
    {
        EncryptionParameters parms(scheme_type::ckks);
        {
            // Adding two zero vectors
            size_t slot_size = 32;
            parms.set_poly_modulus_degree(slot_size * 2);
            parms.set_coeff_modulus(CoeffModulus::Create(slot_size * 2, { 30, 30, 30, 30, 30 }));

            SEALContext context(parms, false, sec_level_type::none);
            KeyGenerator keygen(context);
            PublicKey pk;
            keygen.create_public_key(pk);

            CKKSEncoder encoder(context);
            Encryptor encryptor(context, pk);
            Decryptor decryptor(context, keygen.secret_key());
            Evaluator evaluator(context);

            Ciphertext encrypted;
            Plaintext plain;
            Plaintext plainRes;

            vector<complex<double>> input(slot_size, 0.0);
            vector<complex<double>> output(slot_size);
            const double delta = static_cast<double>(1 << 16);
            encoder.encode(input, context.first_parms_id(), delta, plain);

            encryptor.encrypt(plain, encrypted);
            evaluator.add_inplace(encrypted, encrypted);

            // Check correctness of encryption
            ASSERT_TRUE(encrypted.parms_id() == context.first_parms_id());

            decryptor.decrypt(encrypted, plainRes);
            encoder.decode(plainRes, output);
            for (size_t i = 0; i < slot_size; i++)
            {
                auto tmp = abs(input[i].real() - output[i].real());
                ASSERT_TRUE(tmp < 0.5);
            }
        }
        {
            // Adding two random vectors 100 times
            size_t slot_size = 32;
            parms.set_poly_modulus_degree(slot_size * 2);
            parms.set_coeff_modulus(CoeffModulus::Create(slot_size * 2, { 60, 60, 60 }));

            SEALContext context(parms, false, sec_level_type::none);
            KeyGenerator keygen(context);
            PublicKey pk;
            keygen.create_public_key(pk);

            CKKSEncoder encoder(context);
            Encryptor encryptor(context, pk);
            Decryptor decryptor(context, keygen.secret_key());
            Evaluator evaluator(context);

            Ciphertext encrypted1;
            Ciphertext encrypted2;
            Plaintext plain1;
            Plaintext plain2;
            Plaintext plainRes;

            vector<complex<double>> input1(slot_size, 0.0);
            vector<complex<double>> input2(slot_size, 0.0);
            vector<complex<double>> expected(slot_size, 0.0);
            vector<complex<double>> output(slot_size);

            int data_bound = (1 << 30);
            const double delta = static_cast<double>(1 << 16);

            srand(seal_test_seed);

            for (int expCount = 0; expCount < 100; expCount++)
            {
                for (size_t i = 0; i < slot_size; i++)
                {
                    input1[i] = static_cast<double>(rand() % data_bound);
                    input2[i] = static_cast<double>(rand() % data_bound);
                    expected[i] = input1[i] + input2[i];
                }

                encoder.encode(input1, context.first_parms_id(), delta, plain1);
                encoder.encode(input2, context.first_parms_id(), delta, plain2);

                encryptor.encrypt(plain1, encrypted1);
                encryptor.encrypt(plain2, encrypted2);
                evaluator.add_inplace(encrypted1, encrypted2);

                // Check correctness of encryption
                ASSERT_TRUE(encrypted1.parms_id() == context.first_parms_id());

                decryptor.decrypt(encrypted1, plainRes);
                encoder.decode(plainRes, output);
                for (size_t i = 0; i < slot_size; i++)
                {
                    auto tmp = abs(expected[i].real() - output[i].real());
                    ASSERT_TRUE(tmp < 0.5);
                }
            }
        }
        {
            // Adding two random vectors 100 times
            size_t slot_size = 8;
            parms.set_poly_modulus_degree(64);
            parms.set_coeff_modulus(CoeffModulus::Create(64, { 60, 60, 60 }));

            SEALContext context(parms, false, sec_level_type::none);
            KeyGenerator keygen(context);
            PublicKey pk;
            keygen.create_public_key(pk);

            CKKSEncoder encoder(context);
            Encryptor encryptor(context, pk);
            Decryptor decryptor(context, keygen.secret_key());
            Evaluator evaluator(context);

            Ciphertext encrypted1;
            Ciphertext encrypted2;
            Plaintext plain1;
            Plaintext plain2;
            Plaintext plainRes;

            vector<complex<double>> input1(slot_size, 0.0);
            vector<complex<double>> input2(slot_size, 0.0);
            vector<complex<double>> expected(slot_size, 0.0);
            vector<complex<double>> output(slot_size);

            int data_bound = (1 << 30);
            const double delta = static_cast<double>(1 << 16);

            srand(seal_test_seed);

            for (int expCount = 0; expCount < 100; expCount++)
            {
                for (size_t i = 0; i < slot_size; i++)
                {
                    input1[i] = static_cast<double>(rand() % data_bound);
                    input2[i] = static_cast<double>(rand() % data_bound);
                    expected[i] = input1[i] + input2[i];
                }

                encoder.encode(input1, context.first_parms_id(), delta, plain1);
                encoder.encode(input2, context.first_parms_id(), delta, plain2);

                encryptor.encrypt(plain1, encrypted1);
                encryptor.encrypt(plain2, encrypted2);
                evaluator.add_inplace(encrypted1, encrypted2);

                // Check correctness of encryption
                ASSERT_TRUE(encrypted1.parms_id() == context.first_parms_id());

                decryptor.decrypt(encrypted1, plainRes);
                encoder.decode(plainRes, output);
                for (size_t i = 0; i < slot_size; i++)
                {
                    auto tmp = abs(expected[i].real() - output[i].real());
                    ASSERT_TRUE(tmp < 0.5);
                }
            }
        }
    }

    TEST(EvaluatorTest, CKKSEncryptAddPlainDecrypt)
    {
        EncryptionParameters parms(scheme_type::ckks);
        {
            // Adding two zero vectors
            size_t slot_size = 32;
            parms.set_poly_modulus_degree(slot_size * 2);
            parms.set_coeff_modulus(CoeffModulus::Create(slot_size * 2, { 30, 30, 30, 30, 30 }));

            SEALContext context(parms, false, sec_level_type::none);
            KeyGenerator keygen(context);
            PublicKey pk;
            keygen.create_public_key(pk);

            CKKSEncoder encoder(context);
            Encryptor encryptor(context, pk);
            Decryptor decryptor(context, keygen.secret_key());
            Evaluator evaluator(context);

            Ciphertext encrypted;
            Plaintext plain;
            Plaintext plainRes;

            vector<complex<double>> input(slot_size, 0.0);
            vector<complex<double>> output(slot_size);
            const double delta = static_cast<double>(1 << 16);
            encoder.encode(input, context.first_parms_id(), delta, plain);

            encryptor.encrypt(plain, encrypted);
            evaluator.add_plain_inplace(encrypted, plain);

            // Check correctness of encryption
            ASSERT_TRUE(encrypted.parms_id() == context.first_parms_id());

            decryptor.decrypt(encrypted, plainRes);
            encoder.decode(plainRes, output);
            for (size_t i = 0; i < slot_size; i++)
            {
                auto tmp = abs(input[i].real() - output[i].real());
                ASSERT_TRUE(tmp < 0.5);
            }
        }
        {
            // Adding two random vectors 50 times
            size_t slot_size = 32;
            parms.set_poly_modulus_degree(slot_size * 2);
            parms.set_coeff_modulus(CoeffModulus::Create(slot_size * 2, { 60, 60, 60 }));

            SEALContext context(parms, false, sec_level_type::none);
            KeyGenerator keygen(context);
            PublicKey pk;
            keygen.create_public_key(pk);

            CKKSEncoder encoder(context);
            Encryptor encryptor(context, pk);
            Decryptor decryptor(context, keygen.secret_key());
            Evaluator evaluator(context);

            Ciphertext encrypted1;
            Plaintext plain1;
            Plaintext plain2;
            Plaintext plainRes;

            vector<complex<double>> input1(slot_size, 0.0);
            vector<complex<double>> input2(slot_size, 0.0);
            vector<complex<double>> expected(slot_size, 0.0);
            vector<complex<double>> output(slot_size);

            int data_bound = (1 << 8);
            const double delta = static_cast<double>(1ULL << 16);

            srand(seal_test_seed);

            for (int expCount = 0; expCount < 50; expCount++)
            {
                for (size_t i = 0; i < slot_size; i++)
                {
                    input1[i] = static_cast<double>(rand() % data_bound);
                    input2[i] = static_cast<double>(rand() % data_bound);
                    expected[i] = input1[i] + input2[i];
                }

                encoder.encode(input1, context.first_parms_id(), delta, plain1);
                encoder.encode(input2, context.first_parms_id(), delta, plain2);

                encryptor.encrypt(plain1, encrypted1);
                evaluator.add_plain_inplace(encrypted1, plain2);

                // Check correctness of encryption
                ASSERT_TRUE(encrypted1.parms_id() == context.first_parms_id());

                decryptor.decrypt(encrypted1, plainRes);
                encoder.decode(plainRes, output);
                for (size_t i = 0; i < slot_size; i++)
                {
                    auto tmp = abs(expected[i].real() - output[i].real());
                    ASSERT_TRUE(tmp < 0.5);
                }
            }
        }
        {
            // Adding two random vectors 50 times
            size_t slot_size = 32;
            parms.set_poly_modulus_degree(slot_size * 2);
            parms.set_coeff_modulus(CoeffModulus::Create(slot_size * 2, { 60, 60, 60 }));

            SEALContext context(parms, false, sec_level_type::none);
            KeyGenerator keygen(context);
            PublicKey pk;
            keygen.create_public_key(pk);

            CKKSEncoder encoder(context);
            Encryptor encryptor(context, pk);
            Decryptor decryptor(context, keygen.secret_key());
            Evaluator evaluator(context);

            Ciphertext encrypted1;
            Plaintext plain1;
            Plaintext plain2;
            Plaintext plainRes;

            vector<complex<double>> input1(slot_size, 0.0);
            double input2;
            vector<complex<double>> expected(slot_size, 0.0);
            vector<complex<double>> output(slot_size);

            int data_bound = (1 << 8);
            const double delta = static_cast<double>(1ULL << 16);

            srand(seal_test_seed);

            for (int expCount = 0; expCount < 50; expCount++)
            {
                input2 = static_cast<double>(rand() % (data_bound * data_bound)) / data_bound;
                for (size_t i = 0; i < slot_size; i++)
                {
                    input1[i] = static_cast<double>(rand() % data_bound);
                    expected[i] = input1[i] + input2;
                }

                encoder.encode(input1, context.first_parms_id(), delta, plain1);
                encoder.encode(input2, context.first_parms_id(), delta, plain2);

                encryptor.encrypt(plain1, encrypted1);
                evaluator.add_plain_inplace(encrypted1, plain2);

                // Check correctness of encryption
                ASSERT_TRUE(encrypted1.parms_id() == context.first_parms_id());

                decryptor.decrypt(encrypted1, plainRes);
                encoder.decode(plainRes, output);
                for (size_t i = 0; i < slot_size; i++)
                {
                    auto tmp = abs(expected[i].real() - output[i].real());
                    ASSERT_TRUE(tmp < 0.5);
                }
            }
        }
        {
            // Adding two random vectors 50 times
            size_t slot_size = 8;
            parms.set_poly_modulus_degree(64);
            parms.set_coeff_modulus(CoeffModulus::Create(64, { 60, 60, 60 }));

            SEALContext context(parms, false, sec_level_type::none);
            KeyGenerator keygen(context);
            PublicKey pk;
            keygen.create_public_key(pk);

            CKKSEncoder encoder(context);
            Encryptor encryptor(context, pk);
            Decryptor decryptor(context, keygen.secret_key());
            Evaluator evaluator(context);

            Ciphertext encrypted1;
            Plaintext plain1;
            Plaintext plain2;
            Plaintext plainRes;

            vector<complex<double>> input1(slot_size, 0.0);
            double input2;
            vector<complex<double>> expected(slot_size, 0.0);
            vector<complex<double>> output(slot_size);

            int data_bound = (1 << 8);
            const double delta = static_cast<double>(1ULL << 16);

            srand(seal_test_seed);

            for (int expCount = 0; expCount < 50; expCount++)
            {
                input2 = static_cast<double>(rand() % (data_bound * data_bound)) / data_bound;
                for (size_t i = 0; i < slot_size; i++)
                {
                    input1[i] = static_cast<double>(rand() % data_bound);
                    expected[i] = input1[i] + input2;
                }

                encoder.encode(input1, context.first_parms_id(), delta, plain1);
                encoder.encode(input2, context.first_parms_id(), delta, plain2);

                encryptor.encrypt(plain1, encrypted1);
                evaluator.add_plain_inplace(encrypted1, plain2);

                // Check correctness of encryption
                ASSERT_TRUE(encrypted1.parms_id() == context.first_parms_id());

                decryptor.decrypt(encrypted1, plainRes);
                encoder.decode(plainRes, output);
                for (size_t i = 0; i < slot_size; i++)
                {
                    auto tmp = abs(expected[i].real() - output[i].real());
                    ASSERT_TRUE(tmp < 0.5);
                }
            }
        }
    }

    TEST(EvaluatorTest, CKKSEncryptSubPlainDecrypt)
    {
        EncryptionParameters parms(scheme_type::ckks);
        {
            // Subtracting two zero vectors
            size_t slot_size = 32;
            parms.set_poly_modulus_degree(slot_size * 2);
            parms.set_coeff_modulus(CoeffModulus::Create(slot_size * 2, { 30, 30, 30, 30, 30 }));

            SEALContext context(parms, false, sec_level_type::none);
            KeyGenerator keygen(context);
            PublicKey pk;
            keygen.create_public_key(pk);

            CKKSEncoder encoder(context);
            Encryptor encryptor(context, pk);
            Decryptor decryptor(context, keygen.secret_key());
            Evaluator evaluator(context);

            Ciphertext encrypted;
            Plaintext plain;
            Plaintext plainRes;

            vector<complex<double>> input(slot_size, 0.0);
            vector<complex<double>> output(slot_size);
            const double delta = static_cast<double>(1 << 16);
            encoder.encode(input, context.first_parms_id(), delta, plain);

            encryptor.encrypt(plain, encrypted);
            evaluator.add_plain_inplace(encrypted, plain);

            // Check correctness of encryption
            ASSERT_TRUE(encrypted.parms_id() == context.first_parms_id());

            decryptor.decrypt(encrypted, plainRes);
            encoder.decode(plainRes, output);
            for (size_t i = 0; i < slot_size; i++)
            {
                auto tmp = abs(input[i].real() - output[i].real());
                ASSERT_TRUE(tmp < 0.5);
            }
        }
        {
            // Subtracting two random vectors 100 times
            size_t slot_size = 32;
            parms.set_poly_modulus_degree(slot_size * 2);
            parms.set_coeff_modulus(CoeffModulus::Create(slot_size * 2, { 60, 60, 60 }));

            SEALContext context(parms, false, sec_level_type::none);
            KeyGenerator keygen(context);
            PublicKey pk;
            keygen.create_public_key(pk);

            CKKSEncoder encoder(context);
            Encryptor encryptor(context, pk);
            Decryptor decryptor(context, keygen.secret_key());
            Evaluator evaluator(context);

            Ciphertext encrypted1;
            Plaintext plain1;
            Plaintext plain2;
            Plaintext plainRes;

            vector<complex<double>> input1(slot_size, 0.0);
            vector<complex<double>> input2(slot_size, 0.0);
            vector<complex<double>> expected(slot_size, 0.0);
            vector<complex<double>> output(slot_size);

            int data_bound = (1 << 8);
            const double delta = static_cast<double>(1ULL << 16);

            srand(seal_test_seed);

            for (int expCount = 0; expCount < 100; expCount++)
            {
                for (size_t i = 0; i < slot_size; i++)
                {
                    input1[i] = static_cast<double>(rand() % data_bound);
                    input2[i] = static_cast<double>(rand() % data_bound);
                    expected[i] = input1[i] - input2[i];
                }

                encoder.encode(input1, context.first_parms_id(), delta, plain1);
                encoder.encode(input2, context.first_parms_id(), delta, plain2);

                encryptor.encrypt(plain1, encrypted1);
                evaluator.sub_plain_inplace(encrypted1, plain2);

                // Check correctness of encryption
                ASSERT_TRUE(encrypted1.parms_id() == context.first_parms_id());

                decryptor.decrypt(encrypted1, plainRes);
                encoder.decode(plainRes, output);
                for (size_t i = 0; i < slot_size; i++)
                {
                    auto tmp = abs(expected[i].real() - output[i].real());
                    ASSERT_TRUE(tmp < 0.5);
                }
            }
        }
        {
            // Subtracting two random vectors 100 times
            size_t slot_size = 8;
            parms.set_poly_modulus_degree(64);
            parms.set_coeff_modulus(CoeffModulus::Create(64, { 60, 60, 60 }));

            SEALContext context(parms, false, sec_level_type::none);
            KeyGenerator keygen(context);
            PublicKey pk;
            keygen.create_public_key(pk);

            CKKSEncoder encoder(context);
            Encryptor encryptor(context, pk);
            Decryptor decryptor(context, keygen.secret_key());
            Evaluator evaluator(context);

            Ciphertext encrypted1;
            Plaintext plain1;
            Plaintext plain2;
            Plaintext plainRes;

            vector<complex<double>> input1(slot_size, 0.0);
            vector<complex<double>> input2(slot_size, 0.0);
            vector<complex<double>> expected(slot_size, 0.0);
            vector<complex<double>> output(slot_size);

            int data_bound = (1 << 8);
            const double delta = static_cast<double>(1ULL << 16);

            srand(seal_test_seed);

            for (int expCount = 0; expCount < 100; expCount++)
            {
                for (size_t i = 0; i < slot_size; i++)
                {
                    input1[i] = static_cast<double>(rand() % data_bound);
                    input2[i] = static_cast<double>(rand() % data_bound);
                    expected[i] = input1[i] - input2[i];
                }

                encoder.encode(input1, context.first_parms_id(), delta, plain1);
                encoder.encode(input2, context.first_parms_id(), delta, plain2);

                encryptor.encrypt(plain1, encrypted1);
                evaluator.sub_plain_inplace(encrypted1, plain2);

                // Check correctness of encryption
                ASSERT_TRUE(encrypted1.parms_id() == context.first_parms_id());

                decryptor.decrypt(encrypted1, plainRes);
                encoder.decode(plainRes, output);
                for (size_t i = 0; i < slot_size; i++)
                {
                    auto tmp = abs(expected[i].real() - output[i].real());
                    ASSERT_TRUE(tmp < 0.5);
                }
            }
        }
    }

    TEST(EvaluatorTest, BFVEncryptSubDecrypt)
    {
        EncryptionParameters parms(scheme_type::bfv);
        Modulus plain_modulus(1 << 6);
        parms.set_poly_modulus_degree(64);
        parms.set_plain_modulus(plain_modulus);
        parms.set_coeff_modulus(CoeffModulus::Create(64, { 40 }));

        SEALContext context(parms, false, sec_level_type::none);
        KeyGenerator keygen(context);
        PublicKey pk;
        keygen.create_public_key(pk);

        Encryptor encryptor(context, pk);
        Evaluator evaluator(context);
        Decryptor decryptor(context, keygen.secret_key());

        Ciphertext encrypted1;
        Ciphertext encrypted2;
        Plaintext plain, plain1, plain2;

        plain1 = "1x^28 + 1x^25 + 1x^21 + 1x^20 + 1x^18 + 1x^14 + 1x^12 + 1x^10 + 1x^9 + 1x^6 + 1x^5 + 1x^4 + 1x^3";
        plain2 = "1x^18 + 1x^16 + 1x^14 + 1x^9 + 1x^8 + 1x^5 + 1";
        encryptor.encrypt(plain1, encrypted1);
        encryptor.encrypt(plain2, encrypted2);
        evaluator.sub_inplace(encrypted1, encrypted2);
        decryptor.decrypt(encrypted1, plain);
        ASSERT_EQ(
            plain.to_string(),
            "1x^28 + 1x^25 + 1x^21 + 1x^20 + 3Fx^16 + 1x^12 + 1x^10 + 3Fx^8 + 1x^6 + 1x^4 + 1x^3 + 3F");
        ASSERT_TRUE(encrypted2.parms_id() == encrypted1.parms_id());
        ASSERT_TRUE(encrypted1.parms_id() == context.first_parms_id());

        plain1 = "0";
        plain2 = "0";
        encryptor.encrypt(plain1, encrypted1);
        encryptor.encrypt(plain2, encrypted2);
        evaluator.sub_inplace(encrypted1, encrypted2);
        decryptor.decrypt(encrypted1, plain);
        ASSERT_EQ(plain.to_string(), "0");
        ASSERT_TRUE(encrypted2.parms_id() == encrypted1.parms_id());
        ASSERT_TRUE(encrypted1.parms_id() == context.first_parms_id());

        plain1 = "0";
        plain2 = "1x^2 + 1";
        encryptor.encrypt(plain1, encrypted1);
        encryptor.encrypt(plain2, encrypted2);
        evaluator.sub_inplace(encrypted1, encrypted2);
        decryptor.decrypt(encrypted1, plain);
        ASSERT_EQ(plain.to_string(), "3Fx^2 + 3F");
        ASSERT_TRUE(encrypted2.parms_id() == encrypted1.parms_id());
        ASSERT_TRUE(encrypted1.parms_id() == context.first_parms_id());

        plain1 = "1x^2 + 1";
        plain2 = "3Fx^1 + 3F";
        encryptor.encrypt(plain1, encrypted1);
        encryptor.encrypt(plain2, encrypted2);
        evaluator.sub_inplace(encrypted1, encrypted2);
        decryptor.decrypt(encrypted1, plain);
        ASSERT_EQ(plain.to_string(), "1x^2 + 1x^1 + 2");
        ASSERT_TRUE(encrypted2.parms_id() == encrypted1.parms_id());
        ASSERT_TRUE(encrypted1.parms_id() == context.first_parms_id());

        plain1 = "3Fx^2 + 3Fx^1 + 3F";
        plain2 = "1x^1";
        encryptor.encrypt(plain1, encrypted1);
        encryptor.encrypt(plain2, encrypted2);
        evaluator.sub_inplace(encrypted1, encrypted2);
        decryptor.decrypt(encrypted1, plain);
        ASSERT_EQ(plain.to_string(), "3Fx^2 + 3Ex^1 + 3F");
        ASSERT_TRUE(encrypted2.parms_id() == encrypted1.parms_id());
        ASSERT_TRUE(encrypted1.parms_id() == context.first_parms_id());
    }

    TEST(EvaluatorTest, BFVEncryptAddPlainDecrypt)
    {
        EncryptionParameters parms(scheme_type::bfv);
        Modulus plain_modulus(1 << 6);
        parms.set_poly_modulus_degree(64);
        parms.set_plain_modulus(plain_modulus);
        parms.set_coeff_modulus(CoeffModulus::Create(64, { 40 }));

        SEALContext context(parms, false, sec_level_type::none);
        KeyGenerator keygen(context);
        PublicKey pk;
        keygen.create_public_key(pk);

        Encryptor encryptor(context, pk);
        Evaluator evaluator(context);
        Decryptor decryptor(context, keygen.secret_key());

        Ciphertext encrypted1;
        Ciphertext encrypted2;
        Plaintext plain, plain1, plain2;

        plain1 = "1x^28 + 1x^25 + 1x^21 + 1x^20 + 1x^18 + 1x^14 + 1x^12 + 1x^10 + 1x^9 + 1x^6 + 1x^5 + 1x^4 + 1x^3";
        plain2 = "1x^18 + 1x^16 + 1x^14 + 1x^9 + 1x^8 + 1x^5 + 1";
        encryptor.encrypt(plain1, encrypted1);
        evaluator.add_plain_inplace(encrypted1, plain2);
        decryptor.decrypt(encrypted1, plain);
        ASSERT_EQ(
            plain.to_string(), "1x^28 + 1x^25 + 1x^21 + 1x^20 + 2x^18 + 1x^16 + 2x^14 + 1x^12 + 1x^10 + 2x^9 + 1x^8 + "
                               "1x^6 + 2x^5 + 1x^4 + 1x^3 + 1");
        ASSERT_TRUE(encrypted1.parms_id() == context.first_parms_id());

        plain1 = "0";
        plain2 = "0";
        encryptor.encrypt(plain1, encrypted1);
        evaluator.add_plain_inplace(encrypted1, plain2);
        decryptor.decrypt(encrypted1, plain);
        ASSERT_EQ(plain.to_string(), "0");
        ASSERT_TRUE(encrypted1.parms_id() == context.first_parms_id());

        plain1 = "0";
        plain2 = "1x^2 + 1";
        encryptor.encrypt(plain1, encrypted1);
        evaluator.add_plain_inplace(encrypted1, plain2);
        decryptor.decrypt(encrypted1, plain);
        ASSERT_EQ(plain.to_string(), "1x^2 + 1");
        ASSERT_TRUE(encrypted1.parms_id() == context.first_parms_id());

        plain1 = "1x^2 + 1";
        plain2 = "3Fx^1 + 3F";
        encryptor.encrypt(plain1, encrypted1);
        evaluator.add_plain_inplace(encrypted1, plain2);
        decryptor.decrypt(encrypted1, plain);
        ASSERT_EQ(plain.to_string(), "1x^2 + 3Fx^1");
        ASSERT_TRUE(encrypted1.parms_id() == context.first_parms_id());

        plain1 = "3Fx^2 + 3Fx^1 + 3F";
        plain2 = "1x^2 + 1x^1 + 1";
        encryptor.encrypt(plain1, encrypted1);
        evaluator.add_plain_inplace(encrypted1, plain2);
        decryptor.decrypt(encrypted1, plain);
        ASSERT_EQ(plain.to_string(), "0");
        ASSERT_TRUE(encrypted1.parms_id() == context.first_parms_id());
    }

    TEST(EvaluatorTest, BFVEncryptSubPlainDecrypt)
    {
        EncryptionParameters parms(scheme_type::bfv);
        Modulus plain_modulus(1 << 6);
        parms.set_poly_modulus_degree(64);
        parms.set_plain_modulus(plain_modulus);
        parms.set_coeff_modulus(CoeffModulus::Create(64, { 40 }));

        SEALContext context(parms, false, sec_level_type::none);
        KeyGenerator keygen(context);
        PublicKey pk;
        keygen.create_public_key(pk);

        Encryptor encryptor(context, pk);
        Evaluator evaluator(context);
        Decryptor decryptor(context, keygen.secret_key());

        Ciphertext encrypted1;
        Plaintext plain, plain1, plain2;

        plain1 = "1x^28 + 1x^25 + 1x^21 + 1x^20 + 1x^18 + 1x^14 + 1x^12 + 1x^10 + 1x^9 + 1x^6 + 1x^5 + 1x^4 + 1x^3";
        plain2 = "1x^18 + 1x^16 + 1x^14 + 1x^9 + 1x^8 + 1x^5 + 1";
        encryptor.encrypt(plain1, encrypted1);
        evaluator.sub_plain_inplace(encrypted1, plain2);
        decryptor.decrypt(encrypted1, plain);
        ASSERT_EQ(
            plain.to_string(),
            "1x^28 + 1x^25 + 1x^21 + 1x^20 + 3Fx^16 + 1x^12 + 1x^10 + 3Fx^8 + 1x^6 + 1x^4 + 1x^3 + 3F");
        ASSERT_TRUE(encrypted1.parms_id() == context.first_parms_id());

        plain1 = "0";
        plain2 = "0";
        encryptor.encrypt(plain1, encrypted1);
        evaluator.sub_plain_inplace(encrypted1, plain2);
        decryptor.decrypt(encrypted1, plain);
        ASSERT_EQ(plain.to_string(), "0");
        ASSERT_TRUE(encrypted1.parms_id() == context.first_parms_id());

        plain1 = "0";
        plain2 = "1x^2 + 1";
        encryptor.encrypt(plain1, encrypted1);
        evaluator.sub_plain_inplace(encrypted1, plain2);
        decryptor.decrypt(encrypted1, plain);
        ASSERT_EQ(plain.to_string(), "3Fx^2 + 3F");
        ASSERT_TRUE(encrypted1.parms_id() == context.first_parms_id());

        plain1 = "1x^2 + 1";
        plain2 = "3Fx^1 + 3F";
        encryptor.encrypt(plain1, encrypted1);
        evaluator.sub_plain_inplace(encrypted1, plain2);
        decryptor.decrypt(encrypted1, plain);
        ASSERT_EQ(plain.to_string(), "1x^2 + 1x^1 + 2");
        ASSERT_TRUE(encrypted1.parms_id() == context.first_parms_id());

        plain1 = "3Fx^2 + 3Fx^1 + 3F";
        plain2 = "1x^1";
        encryptor.encrypt(plain1, encrypted1);
        evaluator.sub_plain_inplace(encrypted1, plain2);
        decryptor.decrypt(encrypted1, plain);
        ASSERT_EQ(plain.to_string(), "3Fx^2 + 3Ex^1 + 3F");
        ASSERT_TRUE(encrypted1.parms_id() == context.first_parms_id());
    }

    TEST(EvaluatorTest, BFVEncryptMultiplyPlainDecrypt)
    {
        {
            EncryptionParameters parms(scheme_type::bfv);
            Modulus plain_modulus(1 << 6);
            parms.set_poly_modulus_degree(64);
            parms.set_plain_modulus(plain_modulus);
            parms.set_coeff_modulus(CoeffModulus::Create(64, { 40 }));

            SEALContext context(parms, false, sec_level_type::none);
            KeyGenerator keygen(context);
            PublicKey pk;
            keygen.create_public_key(pk);

            Encryptor encryptor(context, pk);
            Evaluator evaluator(context);
            Decryptor decryptor(context, keygen.secret_key());

            Ciphertext encrypted;
            Plaintext plain, plain1, plain2;

            plain1 = "1x^28 + 1x^25 + 1x^21 + 1x^20 + 1x^18 + 1x^14 + 1x^12 + 1x^10 + 1x^9 + 1x^6 + 1x^5 + 1x^4 + 1x^3";
            plain2 = "1x^18 + 1x^16 + 1x^14 + 1x^9 + 1x^8 + 1x^5 + 1";
            encryptor.encrypt(plain1, encrypted);
            evaluator.multiply_plain_inplace(encrypted, plain2);
            decryptor.decrypt(encrypted, plain);
            ASSERT_EQ(
                plain.to_string(), "1x^46 + 1x^44 + 1x^43 + 1x^42 + 1x^41 + 2x^39 + 1x^38 + 2x^37 + 3x^36 + 1x^35 + "
                                   "3x^34 + 2x^33 + 2x^32 + 4x^30 + 2x^29 + 5x^28 + 2x^27 + 4x^26 + 3x^25 + 2x^24 + "
                                   "4x^23 + 3x^22 + 4x^21 + 4x^20 + 4x^19 + 4x^18 + 3x^17 + 2x^15 + 4x^14 + 2x^13 + "
                                   "3x^12 + 2x^11 + 2x^10 + 2x^9 + 1x^8 + 1x^6 + 1x^5 + 1x^4 + 1x^3");
            ASSERT_TRUE(encrypted.parms_id() == context.first_parms_id());

            plain1 = "0";
            plain2 = "1x^2 + 1";
            encryptor.encrypt(plain1, encrypted);
            evaluator.multiply_plain_inplace(encrypted, plain2);
            decryptor.decrypt(encrypted, plain);
            ASSERT_EQ(plain.to_string(), "0");
            ASSERT_TRUE(encrypted.parms_id() == context.first_parms_id());

            plain1 = "1x^2 + 1x^1 + 1";
            plain2 = "1x^2";
            encryptor.encrypt(plain1, encrypted);
            evaluator.multiply_plain_inplace(encrypted, plain2);
            decryptor.decrypt(encrypted, plain);
            ASSERT_EQ(plain.to_string(), "1x^4 + 1x^3 + 1x^2");
            ASSERT_TRUE(encrypted.parms_id() == context.first_parms_id());

            plain1 = "1x^2 + 1x^1 + 1";
            plain2 = "1x^1";
            encryptor.encrypt(plain1, encrypted);
            evaluator.multiply_plain_inplace(encrypted, plain2);
            decryptor.decrypt(encrypted, plain);
            ASSERT_EQ(plain.to_string(), "1x^3 + 1x^2 + 1x^1");
            ASSERT_TRUE(encrypted.parms_id() == context.first_parms_id());

            plain1 = "1x^2 + 1x^1 + 1";
            plain2 = "1";
            encryptor.encrypt(plain1, encrypted);
            evaluator.multiply_plain_inplace(encrypted, plain2);
            decryptor.decrypt(encrypted, plain);
            ASSERT_EQ(plain.to_string(), "1x^2 + 1x^1 + 1");
            ASSERT_TRUE(encrypted.parms_id() == context.first_parms_id());

            plain1 = "1x^2 + 1";
            plain2 = "3Fx^1 + 3F";
            encryptor.encrypt(plain1, encrypted);
            evaluator.multiply_plain_inplace(encrypted, plain2);
            decryptor.decrypt(encrypted, plain);
            ASSERT_EQ(plain.to_string(), "3Fx^3 + 3Fx^2 + 3Fx^1 + 3F");
            ASSERT_TRUE(encrypted.parms_id() == context.first_parms_id());

            plain1 = "3Fx^2 + 3Fx^1 + 3F";
            plain2 = "1x^1";
            encryptor.encrypt(plain1, encrypted);
            evaluator.multiply_plain_inplace(encrypted, plain2);
            decryptor.decrypt(encrypted, plain);
            ASSERT_EQ(plain.to_string(), "3Fx^3 + 3Fx^2 + 3Fx^1");
            ASSERT_TRUE(encrypted.parms_id() == context.first_parms_id());
        }
        {
            EncryptionParameters parms(scheme_type::bfv);
            Modulus plain_modulus((1ULL << 20) - 1);
            parms.set_poly_modulus_degree(64);
            parms.set_plain_modulus(plain_modulus);
            parms.set_coeff_modulus(CoeffModulus::Create(64, { 30, 60, 60 }));

            SEALContext context(parms, false, sec_level_type::none);
            KeyGenerator keygen(context);
            PublicKey pk;
            keygen.create_public_key(pk);

            Encryptor encryptor(context, pk);
            Evaluator evaluator(context);
            Decryptor decryptor(context, keygen.secret_key());

            Ciphertext encrypted;
            Plaintext plain, plain1, plain2;

            plain1 = "1x^28 + 1x^25 + 1x^21 + 1x^20 + 1x^18 + 1x^14 + 1x^12 + 1x^10 + 1x^9 + 1x^6 + 1x^5 + 1x^4 + 1x^3";
            plain2 = "1";
            encryptor.encrypt(plain1, encrypted);
            evaluator.multiply_plain_inplace(encrypted, plain2);
            decryptor.decrypt(encrypted, plain);
            ASSERT_EQ(
                plain.to_string(),
                "1x^28 + 1x^25 + 1x^21 + 1x^20 + 1x^18 + 1x^14 + 1x^12 + 1x^10 + 1x^9 + 1x^6 + 1x^5 + 1x^4 + 1x^3");
            ASSERT_TRUE(encrypted.parms_id() == context.first_parms_id());

            plain2 = "5";
            evaluator.multiply_plain_inplace(encrypted, plain2);
            decryptor.decrypt(encrypted, plain);
            ASSERT_EQ(
                plain.to_string(),
                "5x^28 + 5x^25 + 5x^21 + 5x^20 + 5x^18 + 5x^14 + 5x^12 + 5x^10 + 5x^9 + 5x^6 + 5x^5 + 5x^4 + 5x^3");
            ASSERT_TRUE(encrypted.parms_id() == context.first_parms_id());
        }
        {
            EncryptionParameters parms(scheme_type::bfv);
            Modulus plain_modulus((1ULL << 40) - 1);
            parms.set_poly_modulus_degree(64);
            parms.set_plain_modulus(plain_modulus);
            parms.set_coeff_modulus(CoeffModulus::Create(64, { 30, 60, 60 }));

            SEALContext context(parms, false, sec_level_type::none);
            KeyGenerator keygen(context);
            PublicKey pk;
            keygen.create_public_key(pk);

            Encryptor encryptor(context, pk);
            Evaluator evaluator(context);
            Decryptor decryptor(context, keygen.secret_key());

            Ciphertext encrypted;
            Plaintext plain, plain1, plain2;

            plain1 = "1x^28 + 1x^25 + 1x^21 + 1x^20 + 1x^18 + 1x^14 + 1x^12 + 1x^10 + 1x^9 + 1x^6 + 1x^5 + 1x^4 + 1x^3";
            plain2 = "1";
            encryptor.encrypt(plain1, encrypted);
            evaluator.multiply_plain_inplace(encrypted, plain2);
            decryptor.decrypt(encrypted, plain);
            ASSERT_EQ(
                plain.to_string(),
                "1x^28 + 1x^25 + 1x^21 + 1x^20 + 1x^18 + 1x^14 + 1x^12 + 1x^10 + 1x^9 + 1x^6 + 1x^5 + 1x^4 + 1x^3");
            ASSERT_TRUE(encrypted.parms_id() == context.first_parms_id());

            plain2 = "5";
            evaluator.multiply_plain_inplace(encrypted, plain2);
            decryptor.decrypt(encrypted, plain);
            ASSERT_EQ(
                plain.to_string(),
                "5x^28 + 5x^25 + 5x^21 + 5x^20 + 5x^18 + 5x^14 + 5x^12 + 5x^10 + 5x^9 + 5x^6 + 5x^5 + 5x^4 + 5x^3");
            ASSERT_TRUE(encrypted.parms_id() == context.first_parms_id());
        }
        {
            EncryptionParameters parms(scheme_type::bfv);
            Modulus plain_modulus(PlainModulus::Batching(64, 20));
            parms.set_poly_modulus_degree(64);
            parms.set_plain_modulus(plain_modulus);
            parms.set_coeff_modulus(CoeffModulus::Create(64, { 30, 30, 30 }));

            SEALContext context(parms, false, sec_level_type::none);
            KeyGenerator keygen(context);
            PublicKey pk;
            keygen.create_public_key(pk);

            BatchEncoder batch_encoder(context);
            Encryptor encryptor(context, pk);
            Evaluator evaluator(context);
            Decryptor decryptor(context, keygen.secret_key());

            Ciphertext encrypted;
            Plaintext plain;
            vector<int64_t> result;

            batch_encoder.encode(vector<int64_t>(batch_encoder.slot_count(), 7), plain);
            encryptor.encrypt(plain, encrypted);
            evaluator.multiply_plain_inplace(encrypted, plain);
            decryptor.decrypt(encrypted, plain);
            batch_encoder.decode(plain, result);
            ASSERT_TRUE(vector<int64_t>(batch_encoder.slot_count(), 49) == result);
            ASSERT_TRUE(encrypted.parms_id() == context.first_parms_id());

            batch_encoder.encode(vector<int64_t>(batch_encoder.slot_count(), -7), plain);
            encryptor.encrypt(plain, encrypted);
            evaluator.multiply_plain_inplace(encrypted, plain);
            decryptor.decrypt(encrypted, plain);
            batch_encoder.decode(plain, result);
            ASSERT_TRUE(vector<int64_t>(batch_encoder.slot_count(), 49) == result);
            ASSERT_TRUE(encrypted.parms_id() == context.first_parms_id());
        }
        {
            EncryptionParameters parms(scheme_type::bfv);
            Modulus plain_modulus(PlainModulus::Batching(64, 40));
            parms.set_poly_modulus_degree(64);
            parms.set_plain_modulus(plain_modulus);
            parms.set_coeff_modulus(CoeffModulus::Create(64, { 30, 30, 30, 30, 30 }));

            SEALContext context(parms, false, sec_level_type::none);
            KeyGenerator keygen(context);
            PublicKey pk;
            keygen.create_public_key(pk);

            BatchEncoder batch_encoder(context);
            Encryptor encryptor(context, pk);
            Evaluator evaluator(context);
            Decryptor decryptor(context, keygen.secret_key());

            Ciphertext encrypted;
            Plaintext plain;
            vector<int64_t> result;

            // First test with constant plaintext
            batch_encoder.encode(vector<int64_t>(batch_encoder.slot_count(), 7), plain);
            encryptor.encrypt(plain, encrypted);
            evaluator.multiply_plain_inplace(encrypted, plain);
            decryptor.decrypt(encrypted, plain);
            batch_encoder.decode(plain, result);
            ASSERT_TRUE(vector<int64_t>(batch_encoder.slot_count(), 49) == result);
            ASSERT_TRUE(encrypted.parms_id() == context.first_parms_id());

            batch_encoder.encode(vector<int64_t>(batch_encoder.slot_count(), -7), plain);
            encryptor.encrypt(plain, encrypted);
            evaluator.multiply_plain_inplace(encrypted, plain);
            decryptor.decrypt(encrypted, plain);
            batch_encoder.decode(plain, result);
            ASSERT_TRUE(vector<int64_t>(batch_encoder.slot_count(), 49) == result);
            ASSERT_TRUE(encrypted.parms_id() == context.first_parms_id());

            // Now test a non-constant plaintext
            vector<int64_t> input(batch_encoder.slot_count() - 1, 7);
            input.push_back(1);
            vector<int64_t> true_result(batch_encoder.slot_count() - 1, 49);
            true_result.push_back(1);
            batch_encoder.encode(input, plain);
            encryptor.encrypt(plain, encrypted);
            evaluator.multiply_plain_inplace(encrypted, plain);
            decryptor.decrypt(encrypted, plain);
            batch_encoder.decode(plain, result);
            ASSERT_TRUE(true_result == result);
            ASSERT_TRUE(encrypted.parms_id() == context.first_parms_id());

            input = vector<int64_t>(batch_encoder.slot_count() - 1, -7);
            input.push_back(1);
            batch_encoder.encode(input, plain);
            encryptor.encrypt(plain, encrypted);
            evaluator.multiply_plain_inplace(encrypted, plain);
            decryptor.decrypt(encrypted, plain);
            batch_encoder.decode(plain, result);
            ASSERT_TRUE(true_result == result);
            ASSERT_TRUE(encrypted.parms_id() == context.first_parms_id());
        }
    }

    TEST(EvaluatorTest, BFVEncryptMultiplyDecrypt)
    {
        {
            EncryptionParameters parms(scheme_type::bfv);
            Modulus plain_modulus(1 << 6);
            parms.set_poly_modulus_degree(64);
            parms.set_plain_modulus(plain_modulus);
            parms.set_coeff_modulus(CoeffModulus::Create(64, { 40 }));

            SEALContext context(parms, false, sec_level_type::none);
            KeyGenerator keygen(context);
            PublicKey pk;
            keygen.create_public_key(pk);

            Encryptor encryptor(context, pk);
            Evaluator evaluator(context);
            Decryptor decryptor(context, keygen.secret_key());

            Ciphertext encrypted1;
            Ciphertext encrypted2;
            Plaintext plain, plain1, plain2;

            plain1 = "1x^28 + 1x^25 + 1x^21 + 1x^20 + 1x^18 + 1x^14 + 1x^12 + 1x^10 + 1x^9 + 1x^6 + 1x^5 + 1x^4 + 1x^3";
            plain2 = "1x^18 + 1x^16 + 1x^14 + 1x^9 + 1x^8 + 1x^5 + 1";
            encryptor.encrypt(plain1, encrypted1);
            encryptor.encrypt(plain2, encrypted2);
            evaluator.multiply_inplace(encrypted1, encrypted2);
            decryptor.decrypt(encrypted1, plain);
            ASSERT_EQ(
                plain.to_string(), "1x^46 + 1x^44 + 1x^43 + 1x^42 + 1x^41 + 2x^39 + 1x^38 + 2x^37 + 3x^36 + 1x^35 + "
                                   "3x^34 + 2x^33 + 2x^32 + 4x^30 + 2x^29 + 5x^28 + 2x^27 + 4x^26 + 3x^25 + 2x^24 + "
                                   "4x^23 + 3x^22 + 4x^21 + 4x^20 + 4x^19 + 4x^18 + 3x^17 + 2x^15 + 4x^14 + 2x^13 + "
                                   "3x^12 + 2x^11 + 2x^10 + 2x^9 + 1x^8 + 1x^6 + 1x^5 + 1x^4 + 1x^3");
            ASSERT_TRUE(encrypted2.parms_id() == encrypted1.parms_id());
            ASSERT_TRUE(encrypted1.parms_id() == context.first_parms_id());

            plain1 = "0";
            plain2 = "0";
            encryptor.encrypt(plain1, encrypted1);
            encryptor.encrypt(plain2, encrypted2);
            evaluator.multiply_inplace(encrypted1, encrypted2);
            decryptor.decrypt(encrypted1, plain);
            ASSERT_EQ(plain.to_string(), "0");
            ASSERT_TRUE(encrypted2.parms_id() == encrypted1.parms_id());
            ASSERT_TRUE(encrypted1.parms_id() == context.first_parms_id());

            plain1 = "0";
            plain2 = "1x^2 + 1";
            encryptor.encrypt(plain1, encrypted1);
            encryptor.encrypt(plain2, encrypted2);
            evaluator.multiply_inplace(encrypted1, encrypted2);
            decryptor.decrypt(encrypted1, plain);
            ASSERT_EQ(plain.to_string(), "0");
            ASSERT_TRUE(encrypted2.parms_id() == encrypted1.parms_id());
            ASSERT_TRUE(encrypted1.parms_id() == context.first_parms_id());

            plain1 = "1x^2 + 1x^1 + 1";
            plain2 = "1";
            encryptor.encrypt(plain1, encrypted1);
            encryptor.encrypt(plain2, encrypted2);
            evaluator.multiply_inplace(encrypted1, encrypted2);
            decryptor.decrypt(encrypted1, plain);
            ASSERT_EQ(plain.to_string(), "1x^2 + 1x^1 + 1");
            ASSERT_TRUE(encrypted2.parms_id() == encrypted1.parms_id());
            ASSERT_TRUE(encrypted1.parms_id() == context.first_parms_id());

            plain1 = "1x^2 + 1";
            plain2 = "3Fx^1 + 3F";
            encryptor.encrypt(plain1, encrypted1);
            encryptor.encrypt(plain2, encrypted2);
            evaluator.multiply_inplace(encrypted1, encrypted2);
            decryptor.decrypt(encrypted1, plain);
            ASSERT_EQ(plain.to_string(), "3Fx^3 + 3Fx^2 + 3Fx^1 + 3F");
            ASSERT_TRUE(encrypted2.parms_id() == encrypted1.parms_id());
            ASSERT_TRUE(encrypted1.parms_id() == context.first_parms_id());

            plain1 = "1x^16";
            plain2 = "1x^8";
            encryptor.encrypt(plain1, encrypted1);
            encryptor.encrypt(plain2, encrypted2);
            evaluator.multiply_inplace(encrypted1, encrypted2);
            decryptor.decrypt(encrypted1, plain);
            ASSERT_EQ(plain.to_string(), "1x^24");
            ASSERT_TRUE(encrypted2.parms_id() == encrypted1.parms_id());
            ASSERT_TRUE(encrypted1.parms_id() == context.first_parms_id());
        }
        {
            EncryptionParameters parms(scheme_type::bfv);
            Modulus plain_modulus((1ULL << 60) - 1);
            parms.set_poly_modulus_degree(64);
            parms.set_plain_modulus(plain_modulus);
            parms.set_coeff_modulus(CoeffModulus::Create(64, { 60, 60, 60, 60 }));

            SEALContext context(parms, false, sec_level_type::none);
            KeyGenerator keygen(context);
            PublicKey pk;
            keygen.create_public_key(pk);

            Encryptor encryptor(context, pk);
            Evaluator evaluator(context);
            Decryptor decryptor(context, keygen.secret_key());

            Ciphertext encrypted1;
            Ciphertext encrypted2;
            Plaintext plain, plain1, plain2;

            plain1 = "1x^28 + 1x^25 + 1x^21 + 1x^20 + 1x^18 + 1x^14 + 1x^12 + 1x^10 + 1x^9 + 1x^6 + 1x^5 + 1x^4 + 1x^3";
            plain2 = "1x^18 + 1x^16 + 1x^14 + 1x^9 + 1x^8 + 1x^5 + 1";
            encryptor.encrypt(plain1, encrypted1);
            encryptor.encrypt(plain2, encrypted2);
            evaluator.multiply_inplace(encrypted1, encrypted2);
            decryptor.decrypt(encrypted1, plain);
            ASSERT_EQ(
                plain.to_string(), "1x^46 + 1x^44 + 1x^43 + 1x^42 + 1x^41 + 2x^39 + 1x^38 + 2x^37 + 3x^36 + 1x^35 + "
                                   "3x^34 + 2x^33 + 2x^32 + 4x^30 + 2x^29 + 5x^28 + 2x^27 + 4x^26 + 3x^25 + 2x^24 + "
                                   "4x^23 + 3x^22 + 4x^21 + 4x^20 + 4x^19 + 4x^18 + 3x^17 + 2x^15 + 4x^14 + 2x^13 + "
                                   "3x^12 + 2x^11 + 2x^10 + 2x^9 + 1x^8 + 1x^6 + 1x^5 + 1x^4 + 1x^3");
            ASSERT_TRUE(encrypted2.parms_id() == encrypted1.parms_id());
            ASSERT_TRUE(encrypted1.parms_id() == context.first_parms_id());

            plain1 = "0";
            plain2 = "0";
            encryptor.encrypt(plain1, encrypted1);
            encryptor.encrypt(plain2, encrypted2);
            evaluator.multiply_inplace(encrypted1, encrypted2);
            decryptor.decrypt(encrypted1, plain);
            ASSERT_EQ(plain.to_string(), "0");
            ASSERT_TRUE(encrypted2.parms_id() == encrypted1.parms_id());
            ASSERT_TRUE(encrypted1.parms_id() == context.first_parms_id());

            plain1 = "0";
            plain2 = "1x^2 + 1";
            encryptor.encrypt(plain1, encrypted1);
            encryptor.encrypt(plain2, encrypted2);
            evaluator.multiply_inplace(encrypted1, encrypted2);
            decryptor.decrypt(encrypted1, plain);
            ASSERT_EQ(plain.to_string(), "0");
            ASSERT_TRUE(encrypted2.parms_id() == encrypted1.parms_id());
            ASSERT_TRUE(encrypted1.parms_id() == context.first_parms_id());

            plain1 = "1x^2 + 1x^1 + 1";
            plain2 = "1";
            encryptor.encrypt(plain1, encrypted1);
            encryptor.encrypt(plain2, encrypted2);
            evaluator.multiply_inplace(encrypted1, encrypted2);
            decryptor.decrypt(encrypted1, plain);
            ASSERT_EQ(plain.to_string(), "1x^2 + 1x^1 + 1");
            ASSERT_TRUE(encrypted2.parms_id() == encrypted1.parms_id());
            ASSERT_TRUE(encrypted1.parms_id() == context.first_parms_id());

            plain1 = "1x^2 + 1";
            plain2 = "FFFFFFFFFFFFFFEx^1 + FFFFFFFFFFFFFFE";
            encryptor.encrypt(plain1, encrypted1);
            encryptor.encrypt(plain2, encrypted2);
            evaluator.multiply_inplace(encrypted1, encrypted2);
            decryptor.decrypt(encrypted1, plain);
            ASSERT_EQ(
                plain.to_string(), "FFFFFFFFFFFFFFEx^3 + FFFFFFFFFFFFFFEx^2 + FFFFFFFFFFFFFFEx^1 + FFFFFFFFFFFFFFE");
            ASSERT_TRUE(encrypted2.parms_id() == encrypted1.parms_id());
            ASSERT_TRUE(encrypted1.parms_id() == context.first_parms_id());

            plain1 = "1x^16";
            plain2 = "1x^8";
            encryptor.encrypt(plain1, encrypted1);
            encryptor.encrypt(plain2, encrypted2);
            evaluator.multiply_inplace(encrypted1, encrypted2);
            decryptor.decrypt(encrypted1, plain);
            ASSERT_EQ(plain.to_string(), "1x^24");
            ASSERT_TRUE(encrypted2.parms_id() == encrypted1.parms_id());
            ASSERT_TRUE(encrypted1.parms_id() == context.first_parms_id());
        }
        {
            EncryptionParameters parms(scheme_type::bfv);
            Modulus plain_modulus(1 << 6);
            parms.set_poly_modulus_degree(128);
            parms.set_plain_modulus(plain_modulus);
            parms.set_coeff_modulus(CoeffModulus::Create(128, { 40, 40 }));

            SEALContext context(parms, false, sec_level_type::none);
            KeyGenerator keygen(context);
            PublicKey pk;
            keygen.create_public_key(pk);

            Encryptor encryptor(context, pk);
            Evaluator evaluator(context);
            Decryptor decryptor(context, keygen.secret_key());

            Ciphertext encrypted1;
            Ciphertext encrypted2;
            Plaintext plain, plain1, plain2;

            plain1 = "1x^28 + 1x^25 + 1x^21 + 1x^20 + 1x^18 + 1x^14 + 1x^12 + 1x^10 + 1x^9 + 1x^6 + 1x^5 + 1x^4 + 1x^3";
            plain2 = "1x^18 + 1x^16 + 1x^14 + 1x^9 + 1x^8 + 1x^5 + 1";
            encryptor.encrypt(plain1, encrypted1);
            encryptor.encrypt(plain2, encrypted2);
            evaluator.multiply_inplace(encrypted1, encrypted2);
            decryptor.decrypt(encrypted1, plain);
            ASSERT_EQ(
                plain.to_string(), "1x^46 + 1x^44 + 1x^43 + 1x^42 + 1x^41 + 2x^39 + 1x^38 + 2x^37 + 3x^36 + 1x^35 + "
                                   "3x^34 + 2x^33 + 2x^32 + 4x^30 + 2x^29 + 5x^28 + 2x^27 + 4x^26 + 3x^25 + 2x^24 + "
                                   "4x^23 + 3x^22 + 4x^21 + 4x^20 + 4x^19 + 4x^18 + 3x^17 + 2x^15 + 4x^14 + 2x^13 + "
                                   "3x^12 + 2x^11 + 2x^10 + 2x^9 + 1x^8 + 1x^6 + 1x^5 + 1x^4 + 1x^3");
            ASSERT_TRUE(encrypted2.parms_id() == encrypted1.parms_id());
            ASSERT_TRUE(encrypted1.parms_id() == context.first_parms_id());

            plain1 = "0";
            plain2 = "0";
            encryptor.encrypt(plain1, encrypted1);
            encryptor.encrypt(plain2, encrypted2);
            evaluator.multiply_inplace(encrypted1, encrypted2);
            decryptor.decrypt(encrypted1, plain);
            ASSERT_EQ(plain.to_string(), "0");
            ASSERT_TRUE(encrypted2.parms_id() == encrypted1.parms_id());
            ASSERT_TRUE(encrypted1.parms_id() == context.first_parms_id());

            plain1 = "0";
            plain2 = "1x^2 + 1";
            encryptor.encrypt(plain1, encrypted1);
            encryptor.encrypt(plain2, encrypted2);
            evaluator.multiply_inplace(encrypted1, encrypted2);
            decryptor.decrypt(encrypted1, plain);
            ASSERT_EQ(plain.to_string(), "0");
            ASSERT_TRUE(encrypted2.parms_id() == encrypted1.parms_id());
            ASSERT_TRUE(encrypted1.parms_id() == context.first_parms_id());

            plain1 = "1x^2 + 1x^1 + 1";
            plain2 = "1";
            encryptor.encrypt(plain1, encrypted1);
            encryptor.encrypt(plain2, encrypted2);
            evaluator.multiply_inplace(encrypted1, encrypted2);
            decryptor.decrypt(encrypted1, plain);
            ASSERT_EQ(plain.to_string(), "1x^2 + 1x^1 + 1");
            ASSERT_TRUE(encrypted2.parms_id() == encrypted1.parms_id());
            ASSERT_TRUE(encrypted1.parms_id() == context.first_parms_id());

            plain1 = "1x^2 + 1";
            plain2 = "3Fx^1 + 3F";
            encryptor.encrypt(plain1, encrypted1);
            encryptor.encrypt(plain2, encrypted2);
            evaluator.multiply_inplace(encrypted1, encrypted2);
            decryptor.decrypt(encrypted1, plain);
            ASSERT_EQ(plain.to_string(), "3Fx^3 + 3Fx^2 + 3Fx^1 + 3F");
            ASSERT_TRUE(encrypted2.parms_id() == encrypted1.parms_id());
            ASSERT_TRUE(encrypted1.parms_id() == context.first_parms_id());

            plain1 = "1x^16";
            plain2 = "1x^8";
            encryptor.encrypt(plain1, encrypted1);
            encryptor.encrypt(plain2, encrypted2);
            evaluator.multiply_inplace(encrypted1, encrypted2);
            decryptor.decrypt(encrypted1, plain);
            ASSERT_EQ(plain.to_string(), "1x^24");
            ASSERT_TRUE(encrypted2.parms_id() == encrypted1.parms_id());
            ASSERT_TRUE(encrypted1.parms_id() == context.first_parms_id());
        }
        {
            EncryptionParameters parms(scheme_type::bfv);
            Modulus plain_modulus(1 << 8);
            parms.set_poly_modulus_degree(128);
            parms.set_plain_modulus(plain_modulus);
            parms.set_coeff_modulus(CoeffModulus::Create(128, { 40, 40, 40 }));

            SEALContext context(parms, false, sec_level_type::none);
            KeyGenerator keygen(context);
            PublicKey pk;
            keygen.create_public_key(pk);

            Encryptor encryptor(context, pk);
            Evaluator evaluator(context);
            Decryptor decryptor(context, keygen.secret_key());

            Ciphertext encrypted1;
            Plaintext plain, plain1;

            plain1 = "1x^6 + 1x^5 + 1x^4 + 1x^3 + 1x^1 + 1";
            encryptor.encrypt(plain1, encrypted1);
            evaluator.multiply(encrypted1, encrypted1, encrypted1);
            evaluator.multiply(encrypted1, encrypted1, encrypted1);
            decryptor.decrypt(encrypted1, plain);
            ASSERT_EQ(
                plain.to_string(), "1x^24 + 4x^23 + Ax^22 + 14x^21 + 1Fx^20 + 2Cx^19 + 3Cx^18 + 4Cx^17 + 5Fx^16 + "
                                   "6Cx^15 + 70x^14 + 74x^13 + 71x^12 + 6Cx^11 + 64x^10 + 50x^9 + 40x^8 + 34x^7 + "
                                   "26x^6 + 1Cx^5 + 11x^4 + 8x^3 + 6x^2 + 4x^1 + 1");
            ASSERT_TRUE(encrypted1.parms_id() == context.first_parms_id());
        }
    }

    TEST(EvaluatorTest, BGVEncryptSubDecrypt)
    {
        EncryptionParameters parms(scheme_type::bgv);
        Modulus plain_modulus(65);
        parms.set_poly_modulus_degree(64);
        parms.set_plain_modulus(plain_modulus);
        parms.set_coeff_modulus(CoeffModulus::Create(64, { 40 }));

        SEALContext context(parms, false, sec_level_type::none);
        KeyGenerator keygen(context);
        PublicKey pk;
        keygen.create_public_key(pk);

        Encryptor encryptor(context, pk);
        Evaluator evaluator(context);
        Decryptor decryptor(context, keygen.secret_key());

        Ciphertext encrypted1;
        Ciphertext encrypted2;
        Plaintext plain, plain1, plain2;

        plain1 = "1x^28 + 1x^25 + 1x^21 + 1x^20 + 1x^18 + 1x^14 + 1x^12 + 1x^10 + 1x^9 + 1x^6 + 1x^5 + 1x^4 + 1x^3";
        plain2 = "1x^18 + 1x^16 + 1x^14 + 1x^9 + 1x^8 + 1x^5 + 1";
        encryptor.encrypt(plain1, encrypted1);
        encryptor.encrypt(plain2, encrypted2);
        evaluator.sub_inplace(encrypted1, encrypted2);
        decryptor.decrypt(encrypted1, plain);
        ASSERT_EQ(
            plain.to_string(),
            "1x^28 + 1x^25 + 1x^21 + 1x^20 + 40x^16 + 1x^12 + 1x^10 + 40x^8 + 1x^6 + 1x^4 + 1x^3 + 40");
        ASSERT_TRUE(encrypted2.parms_id() == encrypted1.parms_id());
        ASSERT_TRUE(encrypted1.parms_id() == context.first_parms_id());

        // Test correction factor
        plain1 = "2x^28 + 2x^25 + 2x^21 + 2x^20 + 2x^18 + 2x^14 + 2x^12 + 2x^10 + 2x^9 + 2x^6 + 2x^5 + 2x^4 + 2x^3";
        plain2 = "40x^18 + 40x^16 + 40x^14 + 40x^9 + 40x^8 + 40x^5 + 40";
        encryptor.encrypt(plain1, encrypted1);
        encrypted1.correction_factor() = 2;
        encryptor.encrypt(plain2, encrypted2);
        encrypted2.correction_factor() = 64;
        evaluator.sub_inplace(encrypted1, encrypted2);
        decryptor.decrypt(encrypted1, plain);
        ASSERT_EQ(
            plain.to_string(),
            "1x^28 + 1x^25 + 1x^21 + 1x^20 + 40x^16 + 1x^12 + 1x^10 + 40x^8 + 1x^6 + 1x^4 + 1x^3 + 40");
        ASSERT_TRUE(encrypted2.parms_id() == encrypted1.parms_id());
        ASSERT_TRUE(encrypted1.parms_id() == context.first_parms_id());

        plain1 = "0";
        plain2 = "0";
        encryptor.encrypt(plain1, encrypted1);
        encryptor.encrypt(plain2, encrypted2);
        evaluator.sub_inplace(encrypted1, encrypted2);
        decryptor.decrypt(encrypted1, plain);
        ASSERT_EQ(plain.to_string(), "0");
        ASSERT_TRUE(encrypted2.parms_id() == encrypted1.parms_id());
        ASSERT_TRUE(encrypted1.parms_id() == context.first_parms_id());

        plain1 = "0";
        plain2 = "1x^2 + 1";
        encryptor.encrypt(plain1, encrypted1);
        encryptor.encrypt(plain2, encrypted2);
        evaluator.sub_inplace(encrypted1, encrypted2);
        decryptor.decrypt(encrypted1, plain);
        ASSERT_EQ(plain.to_string(), "40x^2 + 40");
        ASSERT_TRUE(encrypted2.parms_id() == encrypted1.parms_id());
        ASSERT_TRUE(encrypted1.parms_id() == context.first_parms_id());

        plain1 = "1x^2 + 1";
        plain2 = "40x^1 + 40";
        encryptor.encrypt(plain1, encrypted1);
        encryptor.encrypt(plain2, encrypted2);
        evaluator.sub_inplace(encrypted1, encrypted2);
        decryptor.decrypt(encrypted1, plain);
        ASSERT_EQ(plain.to_string(), "1x^2 + 1x^1 + 2");
        ASSERT_TRUE(encrypted2.parms_id() == encrypted1.parms_id());
        ASSERT_TRUE(encrypted1.parms_id() == context.first_parms_id());

        plain1 = "3Fx^2 + 3Fx^1 + 3F";
        plain2 = "1x^1";
        encryptor.encrypt(plain1, encrypted1);
        encryptor.encrypt(plain2, encrypted2);
        evaluator.sub_inplace(encrypted1, encrypted2);
        decryptor.decrypt(encrypted1, plain);
        ASSERT_EQ(plain.to_string(), "3Fx^2 + 3Ex^1 + 3F");
        ASSERT_TRUE(encrypted2.parms_id() == encrypted1.parms_id());
        ASSERT_TRUE(encrypted1.parms_id() == context.first_parms_id());
    }

    TEST(EvaluatorTest, BGVEncryptAddPlainDecrypt)
    {
        {
            EncryptionParameters parms(scheme_type::bgv);
            Modulus plain_modulus(65);
            parms.set_poly_modulus_degree(64);
            parms.set_plain_modulus(plain_modulus);
            parms.set_coeff_modulus(CoeffModulus::Create(64, { 40 }));

            SEALContext context(parms, false, sec_level_type::none);
            KeyGenerator keygen(context);
            PublicKey pk;
            keygen.create_public_key(pk);

            Encryptor encryptor(context, pk);
            Evaluator evaluator(context);
            Decryptor decryptor(context, keygen.secret_key());

            Ciphertext encrypted1;
            Ciphertext encrypted2;
            Plaintext plain, plain1, plain2;

            plain1 = "1x^28 + 1x^25 + 1x^21 + 1x^20 + 1x^18 + 1x^14 + 1x^12 + 1x^10 + 1x^9 + 1x^6 + 1x^5 + 1x^4 + 1x^3";
            plain2 = "1x^18 + 1x^16 + 1x^14 + 1x^9 + 1x^8 + 1x^5 + 1";
            encryptor.encrypt(plain1, encrypted1);
            evaluator.add_plain_inplace(encrypted1, plain2);
            decryptor.decrypt(encrypted1, plain);
            ASSERT_EQ(
                plain.to_string(),
                "1x^28 + 1x^25 + 1x^21 + 1x^20 + 2x^18 + 1x^16 + 2x^14 + 1x^12 + 1x^10 + 2x^9 + 1x^8 + "
                "1x^6 + 2x^5 + 1x^4 + 1x^3 + 1");
            ASSERT_TRUE(encrypted1.parms_id() == context.first_parms_id());

            // Test correction factor
            plain1 = "2x^28 + 2x^25 + 2x^21 + 2x^20 + 2x^18 + 2x^14 + 2x^12 + 2x^10 + 2x^9 + 2x^6 + 2x^5 + 2x^4 + 2x^3";
            plain2 = "1x^18 + 1x^16 + 1x^14 + 1x^9 + 1x^8 + 1x^5 + 1";
            encryptor.encrypt(plain1, encrypted1);
            encrypted1.correction_factor() = 2;
            evaluator.add_plain_inplace(encrypted1, plain2);
            decryptor.decrypt(encrypted1, plain);
            ASSERT_EQ(
                plain.to_string(),
                "1x^28 + 1x^25 + 1x^21 + 1x^20 + 2x^18 + 1x^16 + 2x^14 + 1x^12 + 1x^10 + 2x^9 + 1x^8 + "
                "1x^6 + 2x^5 + 1x^4 + 1x^3 + 1");
            ASSERT_TRUE(encrypted1.parms_id() == context.first_parms_id());

            plain1 = "0";
            plain2 = "0";
            encryptor.encrypt(plain1, encrypted1);
            evaluator.add_plain_inplace(encrypted1, plain2);
            decryptor.decrypt(encrypted1, plain);
            ASSERT_EQ(plain.to_string(), "0");
            ASSERT_TRUE(encrypted1.parms_id() == context.first_parms_id());

            plain1 = "0";
            plain2 = "1x^2 + 1";
            encryptor.encrypt(plain1, encrypted1);
            evaluator.add_plain_inplace(encrypted1, plain2);
            decryptor.decrypt(encrypted1, plain);
            ASSERT_EQ(plain.to_string(), "1x^2 + 1");
            ASSERT_TRUE(encrypted1.parms_id() == context.first_parms_id());

            plain1 = "1x^2 + 1";
            plain2 = "40x^1 + 40";
            encryptor.encrypt(plain1, encrypted1);
            evaluator.add_plain_inplace(encrypted1, plain2);
            decryptor.decrypt(encrypted1, plain);
            ASSERT_EQ(plain.to_string(), "1x^2 + 40x^1");
            ASSERT_TRUE(encrypted1.parms_id() == context.first_parms_id());

            plain1 = "40x^2 + 40x^1 + 40";
            plain2 = "1x^2 + 1x^1 + 1";
            encryptor.encrypt(plain1, encrypted1);
            evaluator.add_plain_inplace(encrypted1, plain2);
            decryptor.decrypt(encrypted1, plain);
            ASSERT_EQ(plain.to_string(), "0");
            ASSERT_TRUE(encrypted1.parms_id() == context.first_parms_id());
        }
    }

    TEST(EvaluatorTest, BGVEncryptSubPlainDecrypt)
    {
        EncryptionParameters parms(scheme_type::bgv);
        Modulus plain_modulus(65);
        parms.set_poly_modulus_degree(64);
        parms.set_plain_modulus(plain_modulus);
        parms.set_coeff_modulus(CoeffModulus::Create(64, { 40 }));

        SEALContext context(parms, false, sec_level_type::none);
        KeyGenerator keygen(context);
        PublicKey pk;
        keygen.create_public_key(pk);

        Encryptor encryptor(context, pk);
        Evaluator evaluator(context);
        Decryptor decryptor(context, keygen.secret_key());

        Ciphertext encrypted1;
        Plaintext plain, plain1, plain2;

        plain1 = "1x^28 + 1x^25 + 1x^21 + 1x^20 + 1x^18 + 1x^14 + 1x^12 + 1x^10 + 1x^9 + 1x^6 + 1x^5 + 1x^4 + 1x^3";
        plain2 = "1x^18 + 1x^16 + 1x^14 + 1x^9 + 1x^8 + 1x^5 + 1";
        encryptor.encrypt(plain1, encrypted1);
        evaluator.sub_plain_inplace(encrypted1, plain2);
        decryptor.decrypt(encrypted1, plain);
        ASSERT_EQ(
            plain.to_string(),
            "1x^28 + 1x^25 + 1x^21 + 1x^20 + 40x^16 + 1x^12 + 1x^10 + 40x^8 + 1x^6 + 1x^4 + 1x^3 + 40");
        ASSERT_TRUE(encrypted1.parms_id() == context.first_parms_id());

        // Test correction factor
        plain1 = "2x^28 + 2x^25 + 2x^21 + 2x^20 + 2x^18 + 2x^14 + 2x^12 + 2x^10 + 2x^9 + 2x^6 + 2x^5 + 2x^4 + 2x^3";
        plain2 = "1x^18 + 1x^16 + 1x^14 + 1x^9 + 1x^8 + 1x^5 + 1";
        encryptor.encrypt(plain1, encrypted1);
        encrypted1.correction_factor() = 2;
        evaluator.sub_plain_inplace(encrypted1, plain2);
        decryptor.decrypt(encrypted1, plain);
        ASSERT_EQ(
            plain.to_string(),
            "1x^28 + 1x^25 + 1x^21 + 1x^20 + 40x^16 + 1x^12 + 1x^10 + 40x^8 + 1x^6 + 1x^4 + 1x^3 + 40");
        ASSERT_TRUE(encrypted1.parms_id() == context.first_parms_id());

        plain1 = "0";
        plain2 = "0";
        encryptor.encrypt(plain1, encrypted1);
        evaluator.sub_plain_inplace(encrypted1, plain2);
        decryptor.decrypt(encrypted1, plain);
        ASSERT_EQ(plain.to_string(), "0");
        ASSERT_TRUE(encrypted1.parms_id() == context.first_parms_id());

        plain1 = "0";
        plain2 = "1x^2 + 1";
        encryptor.encrypt(plain1, encrypted1);
        evaluator.sub_plain_inplace(encrypted1, plain2);
        decryptor.decrypt(encrypted1, plain);
        ASSERT_EQ(plain.to_string(), "40x^2 + 40");
        ASSERT_TRUE(encrypted1.parms_id() == context.first_parms_id());

        plain1 = "1x^2 + 1";
        plain2 = "40x^1 + 40";
        encryptor.encrypt(plain1, encrypted1);
        evaluator.sub_plain_inplace(encrypted1, plain2);
        decryptor.decrypt(encrypted1, plain);
        ASSERT_EQ(plain.to_string(), "1x^2 + 1x^1 + 2");
        ASSERT_TRUE(encrypted1.parms_id() == context.first_parms_id());

        plain1 = "3Fx^2 + 3Fx^1 + 3F";
        plain2 = "1x^1";
        encryptor.encrypt(plain1, encrypted1);
        evaluator.sub_plain_inplace(encrypted1, plain2);
        decryptor.decrypt(encrypted1, plain);
        ASSERT_EQ(plain.to_string(), "3Fx^2 + 3Ex^1 + 3F");
        ASSERT_TRUE(encrypted1.parms_id() == context.first_parms_id());
    }

    TEST(EvaluatorTest, BGVEncryptMultiplyPlainDecrypt)
    {
        {
            EncryptionParameters parms(scheme_type::bgv);
            Modulus plain_modulus(65);
            parms.set_poly_modulus_degree(64);
            parms.set_plain_modulus(plain_modulus);
            parms.set_coeff_modulus(CoeffModulus::Create(64, { 40 }));

            SEALContext context(parms, false, sec_level_type::none);
            KeyGenerator keygen(context);
            PublicKey pk;
            keygen.create_public_key(pk);

            Encryptor encryptor(context, pk);
            Evaluator evaluator(context);
            Decryptor decryptor(context, keygen.secret_key());

            Ciphertext encrypted;
            Plaintext plain, plain1, plain2;

            plain1 = "1x^28 + 1x^25 + 1x^21 + 1x^20 + 1x^18 + 1x^14 + 1x^12 + 1x^10 + 1x^9 + 1x^6 + 1x^5 + 1x^4 + 1x^3";
            plain2 = "1x^18 + 1x^16 + 1x^14 + 1x^9 + 1x^8 + 1x^5 + 1";
            encryptor.encrypt(plain1, encrypted);
            evaluator.multiply_plain_inplace(encrypted, plain2);
            decryptor.decrypt(encrypted, plain);
            ASSERT_EQ(
                plain.to_string(), "1x^46 + 1x^44 + 1x^43 + 1x^42 + 1x^41 + 2x^39 + 1x^38 + 2x^37 + 3x^36 + 1x^35 + "
                                   "3x^34 + 2x^33 + 2x^32 + 4x^30 + 2x^29 + 5x^28 + 2x^27 + 4x^26 + 3x^25 + 2x^24 + "
                                   "4x^23 + 3x^22 + 4x^21 + 4x^20 + 4x^19 + 4x^18 + 3x^17 + 2x^15 + 4x^14 + 2x^13 + "
                                   "3x^12 + 2x^11 + 2x^10 + 2x^9 + 1x^8 + 1x^6 + 1x^5 + 1x^4 + 1x^3");
            ASSERT_TRUE(encrypted.parms_id() == context.first_parms_id());

            plain1 = "0";
            plain2 = "1x^2 + 1";
            encryptor.encrypt(plain1, encrypted);
            evaluator.multiply_plain_inplace(encrypted, plain2);
            decryptor.decrypt(encrypted, plain);
            ASSERT_EQ(plain.to_string(), "0");
            ASSERT_TRUE(encrypted.parms_id() == context.first_parms_id());

            plain1 = "1x^2 + 1x^1 + 1";
            plain2 = "1x^2";
            encryptor.encrypt(plain1, encrypted);
            evaluator.multiply_plain_inplace(encrypted, plain2);
            decryptor.decrypt(encrypted, plain);
            ASSERT_EQ(plain.to_string(), "1x^4 + 1x^3 + 1x^2");
            ASSERT_TRUE(encrypted.parms_id() == context.first_parms_id());

            plain1 = "1x^2 + 1x^1 + 1";
            plain2 = "1x^1";
            encryptor.encrypt(plain1, encrypted);
            evaluator.multiply_plain_inplace(encrypted, plain2);
            decryptor.decrypt(encrypted, plain);
            ASSERT_EQ(plain.to_string(), "1x^3 + 1x^2 + 1x^1");
            ASSERT_TRUE(encrypted.parms_id() == context.first_parms_id());

            plain1 = "1x^2 + 1x^1 + 1";
            plain2 = "1";
            encryptor.encrypt(plain1, encrypted);
            evaluator.multiply_plain_inplace(encrypted, plain2);
            decryptor.decrypt(encrypted, plain);
            ASSERT_EQ(plain.to_string(), "1x^2 + 1x^1 + 1");
            ASSERT_TRUE(encrypted.parms_id() == context.first_parms_id());

            plain1 = "1x^2 + 1";
            plain2 = "3Fx^1 + 3F";
            encryptor.encrypt(plain1, encrypted);
            evaluator.multiply_plain_inplace(encrypted, plain2);
            decryptor.decrypt(encrypted, plain);
            ASSERT_EQ(plain.to_string(), "3Fx^3 + 3Fx^2 + 3Fx^1 + 3F");
            ASSERT_TRUE(encrypted.parms_id() == context.first_parms_id());

            plain1 = "3Fx^2 + 3Fx^1 + 3F";
            plain2 = "1x^1";
            encryptor.encrypt(plain1, encrypted);
            evaluator.multiply_plain_inplace(encrypted, plain2);
            decryptor.decrypt(encrypted, plain);
            ASSERT_EQ(plain.to_string(), "3Fx^3 + 3Fx^2 + 3Fx^1");
            ASSERT_TRUE(encrypted.parms_id() == context.first_parms_id());
        }
        {
            EncryptionParameters parms(scheme_type::bgv);
            Modulus plain_modulus((1ULL << 20) - 1);
            parms.set_poly_modulus_degree(64);
            parms.set_plain_modulus(plain_modulus);
            parms.set_coeff_modulus(CoeffModulus::Create(64, { 30, 60, 60 }));

            SEALContext context(parms, false, sec_level_type::none);
            KeyGenerator keygen(context);
            PublicKey pk;
            keygen.create_public_key(pk);

            Encryptor encryptor(context, pk);
            Evaluator evaluator(context);
            Decryptor decryptor(context, keygen.secret_key());

            Ciphertext encrypted;
            Plaintext plain, plain1, plain2;

            plain1 = "1x^28 + 1x^25 + 1x^21 + 1x^20 + 1x^18 + 1x^14 + 1x^12 + 1x^10 + 1x^9 + 1x^6 + 1x^5 + 1x^4 + 1x^3";
            plain2 = "1";
            encryptor.encrypt(plain1, encrypted);
            evaluator.multiply_plain_inplace(encrypted, plain2);
            decryptor.decrypt(encrypted, plain);
            ASSERT_EQ(
                plain.to_string(),
                "1x^28 + 1x^25 + 1x^21 + 1x^20 + 1x^18 + 1x^14 + 1x^12 + 1x^10 + 1x^9 + 1x^6 + 1x^5 + 1x^4 + 1x^3");
            ASSERT_TRUE(encrypted.parms_id() == context.first_parms_id());

            plain2 = "5";
            evaluator.multiply_plain_inplace(encrypted, plain2);
            decryptor.decrypt(encrypted, plain);
            ASSERT_EQ(
                plain.to_string(),
                "5x^28 + 5x^25 + 5x^21 + 5x^20 + 5x^18 + 5x^14 + 5x^12 + 5x^10 + 5x^9 + 5x^6 + 5x^5 + 5x^4 + 5x^3");
            ASSERT_TRUE(encrypted.parms_id() == context.first_parms_id());
        }
        {
            EncryptionParameters parms(scheme_type::bgv);
            Modulus plain_modulus((1ULL << 40) - 1);
            parms.set_poly_modulus_degree(64);
            parms.set_plain_modulus(plain_modulus);
            parms.set_coeff_modulus(CoeffModulus::Create(64, { 30, 60, 60 }));

            SEALContext context(parms, false, sec_level_type::none);
            KeyGenerator keygen(context);
            PublicKey pk;
            keygen.create_public_key(pk);

            Encryptor encryptor(context, pk);
            Evaluator evaluator(context);
            Decryptor decryptor(context, keygen.secret_key());

            Ciphertext encrypted;
            Plaintext plain, plain1, plain2;

            plain1 = "1x^28 + 1x^25 + 1x^21 + 1x^20 + 1x^18 + 1x^14 + 1x^12 + 1x^10 + 1x^9 + 1x^6 + 1x^5 + 1x^4 + 1x^3";
            plain2 = "1";
            encryptor.encrypt(plain1, encrypted);
            evaluator.multiply_plain_inplace(encrypted, plain2);
            decryptor.decrypt(encrypted, plain);
            ASSERT_EQ(
                plain.to_string(),
                "1x^28 + 1x^25 + 1x^21 + 1x^20 + 1x^18 + 1x^14 + 1x^12 + 1x^10 + 1x^9 + 1x^6 + 1x^5 + 1x^4 + 1x^3");
            ASSERT_TRUE(encrypted.parms_id() == context.first_parms_id());

            plain2 = "5";
            evaluator.multiply_plain_inplace(encrypted, plain2);
            decryptor.decrypt(encrypted, plain);
            ASSERT_EQ(
                plain.to_string(),
                "5x^28 + 5x^25 + 5x^21 + 5x^20 + 5x^18 + 5x^14 + 5x^12 + 5x^10 + 5x^9 + 5x^6 + 5x^5 + 5x^4 + 5x^3");
            ASSERT_TRUE(encrypted.parms_id() == context.first_parms_id());
        }
        {
            EncryptionParameters parms(scheme_type::bgv);
            Modulus plain_modulus(PlainModulus::Batching(64, 20));
            parms.set_poly_modulus_degree(64);
            parms.set_plain_modulus(plain_modulus);
            parms.set_coeff_modulus(CoeffModulus::Create(64, { 30, 30, 30 }));

            SEALContext context(parms, false, sec_level_type::none);
            KeyGenerator keygen(context);
            PublicKey pk;
            keygen.create_public_key(pk);

            BatchEncoder batch_encoder(context);
            Encryptor encryptor(context, pk);
            Evaluator evaluator(context);
            Decryptor decryptor(context, keygen.secret_key());

            Ciphertext encrypted;
            Plaintext plain;
            vector<int64_t> result;

            batch_encoder.encode(vector<int64_t>(batch_encoder.slot_count(), 7), plain);
            encryptor.encrypt(plain, encrypted);
            evaluator.multiply_plain_inplace(encrypted, plain);
            decryptor.decrypt(encrypted, plain);
            batch_encoder.decode(plain, result);
            ASSERT_TRUE(vector<int64_t>(batch_encoder.slot_count(), 49) == result);
            ASSERT_TRUE(encrypted.parms_id() == context.first_parms_id());

            batch_encoder.encode(vector<int64_t>(batch_encoder.slot_count(), -7), plain);
            encryptor.encrypt(plain, encrypted);
            evaluator.multiply_plain_inplace(encrypted, plain);
            decryptor.decrypt(encrypted, plain);
            batch_encoder.decode(plain, result);
            ASSERT_TRUE(vector<int64_t>(batch_encoder.slot_count(), 49) == result);
            ASSERT_TRUE(encrypted.parms_id() == context.first_parms_id());
        }
        {
            EncryptionParameters parms(scheme_type::bgv);
            Modulus plain_modulus(PlainModulus::Batching(64, 40));
            parms.set_poly_modulus_degree(64);
            parms.set_plain_modulus(plain_modulus);
            parms.set_coeff_modulus(CoeffModulus::Create(64, { 30, 30, 30, 30, 30 }));

            SEALContext context(parms, false, sec_level_type::none);
            KeyGenerator keygen(context);
            PublicKey pk;
            keygen.create_public_key(pk);

            BatchEncoder batch_encoder(context);
            Encryptor encryptor(context, pk);
            Evaluator evaluator(context);
            Decryptor decryptor(context, keygen.secret_key());

            Ciphertext encrypted;
            Plaintext plain;
            vector<int64_t> result;

            // First test with constant plaintext
            batch_encoder.encode(vector<int64_t>(batch_encoder.slot_count(), 7), plain);
            encryptor.encrypt(plain, encrypted);
            evaluator.multiply_plain_inplace(encrypted, plain);
            decryptor.decrypt(encrypted, plain);
            batch_encoder.decode(plain, result);
            ASSERT_TRUE(vector<int64_t>(batch_encoder.slot_count(), 49) == result);
            ASSERT_TRUE(encrypted.parms_id() == context.first_parms_id());

            batch_encoder.encode(vector<int64_t>(batch_encoder.slot_count(), -7), plain);
            encryptor.encrypt(plain, encrypted);
            evaluator.multiply_plain_inplace(encrypted, plain);
            decryptor.decrypt(encrypted, plain);
            batch_encoder.decode(plain, result);
            ASSERT_TRUE(vector<int64_t>(batch_encoder.slot_count(), 49) == result);
            ASSERT_TRUE(encrypted.parms_id() == context.first_parms_id());

            // Now test a non-constant plaintext
            vector<int64_t> input(batch_encoder.slot_count() - 1, 7);
            input.push_back(1);
            vector<int64_t> true_result(batch_encoder.slot_count() - 1, 49);
            true_result.push_back(1);
            batch_encoder.encode(input, plain);
            encryptor.encrypt(plain, encrypted);
            evaluator.multiply_plain_inplace(encrypted, plain);
            decryptor.decrypt(encrypted, plain);
            batch_encoder.decode(plain, result);
            ASSERT_TRUE(true_result == result);
            ASSERT_TRUE(encrypted.parms_id() == context.first_parms_id());

            input = vector<int64_t>(batch_encoder.slot_count() - 1, -7);
            input.push_back(1);
            batch_encoder.encode(input, plain);
            encryptor.encrypt(plain, encrypted);
            evaluator.multiply_plain_inplace(encrypted, plain);
            decryptor.decrypt(encrypted, plain);
            batch_encoder.decode(plain, result);
            ASSERT_TRUE(true_result == result);
            ASSERT_TRUE(encrypted.parms_id() == context.first_parms_id());
        }
    }

    TEST(EvaluatorTest, BGVEncryptMultiplyDecrypt)
    {
        {
            EncryptionParameters parms(scheme_type::bgv);
            Modulus plain_modulus(65);
            parms.set_poly_modulus_degree(64);
            parms.set_plain_modulus(plain_modulus);
            parms.set_coeff_modulus(CoeffModulus::Create(64, { 40 }));

            SEALContext context(parms, false, sec_level_type::none);
            KeyGenerator keygen(context);
            PublicKey pk;
            keygen.create_public_key(pk);

            Encryptor encryptor(context, pk);
            Evaluator evaluator(context);
            Decryptor decryptor(context, keygen.secret_key());

            Ciphertext encrypted1;
            Ciphertext encrypted2;
            Plaintext plain, plain1, plain2;

            plain1 = "1x^28 + 1x^25 + 1x^21 + 1x^20 + 1x^18 + 1x^14 + 1x^12 + 1x^10 + 1x^9 + 1x^6 + 1x^5 + 1x^4 + 1x^3";
            plain2 = "1x^18 + 1x^16 + 1x^14 + 1x^9 + 1x^8 + 1x^5 + 1";
            encryptor.encrypt(plain1, encrypted1);
            encryptor.encrypt(plain2, encrypted2);
            evaluator.multiply_inplace(encrypted1, encrypted2);
            decryptor.decrypt(encrypted1, plain);
            ASSERT_EQ(
                plain.to_string(), "1x^46 + 1x^44 + 1x^43 + 1x^42 + 1x^41 + 2x^39 + 1x^38 + 2x^37 + 3x^36 + 1x^35 + "
                                   "3x^34 + 2x^33 + 2x^32 + 4x^30 + 2x^29 + 5x^28 + 2x^27 + 4x^26 + 3x^25 + 2x^24 + "
                                   "4x^23 + 3x^22 + 4x^21 + 4x^20 + 4x^19 + 4x^18 + 3x^17 + 2x^15 + 4x^14 + 2x^13 + "
                                   "3x^12 + 2x^11 + 2x^10 + 2x^9 + 1x^8 + 1x^6 + 1x^5 + 1x^4 + 1x^3");
            ASSERT_TRUE(encrypted2.parms_id() == encrypted1.parms_id());
            ASSERT_TRUE(encrypted1.parms_id() == context.first_parms_id());

            plain1 = "0";
            plain2 = "0";
            encryptor.encrypt(plain1, encrypted1);
            encryptor.encrypt(plain2, encrypted2);
            evaluator.multiply_inplace(encrypted1, encrypted2);
            decryptor.decrypt(encrypted1, plain);
            ASSERT_EQ(plain.to_string(), "0");
            ASSERT_TRUE(encrypted2.parms_id() == encrypted1.parms_id());
            ASSERT_TRUE(encrypted1.parms_id() == context.first_parms_id());

            plain1 = "0";
            plain2 = "1x^2 + 1";
            encryptor.encrypt(plain1, encrypted1);
            encryptor.encrypt(plain2, encrypted2);
            evaluator.multiply_inplace(encrypted1, encrypted2);
            decryptor.decrypt(encrypted1, plain);
            ASSERT_EQ(plain.to_string(), "0");
            ASSERT_TRUE(encrypted2.parms_id() == encrypted1.parms_id());
            ASSERT_TRUE(encrypted1.parms_id() == context.first_parms_id());

            plain1 = "1x^2 + 1x^1 + 1";
            plain2 = "1";
            encryptor.encrypt(plain1, encrypted1);
            encryptor.encrypt(plain2, encrypted2);
            evaluator.multiply_inplace(encrypted1, encrypted2);
            decryptor.decrypt(encrypted1, plain);
            ASSERT_EQ(plain.to_string(), "1x^2 + 1x^1 + 1");
            ASSERT_TRUE(encrypted2.parms_id() == encrypted1.parms_id());
            ASSERT_TRUE(encrypted1.parms_id() == context.first_parms_id());

            plain1 = "1x^2 + 1";
            plain2 = "3Fx^1 + 3F";
            encryptor.encrypt(plain1, encrypted1);
            encryptor.encrypt(plain2, encrypted2);
            evaluator.multiply_inplace(encrypted1, encrypted2);
            decryptor.decrypt(encrypted1, plain);
            ASSERT_EQ(plain.to_string(), "3Fx^3 + 3Fx^2 + 3Fx^1 + 3F");
            ASSERT_TRUE(encrypted2.parms_id() == encrypted1.parms_id());
            ASSERT_TRUE(encrypted1.parms_id() == context.first_parms_id());

            plain1 = "1x^16";
            plain2 = "1x^8";
            encryptor.encrypt(plain1, encrypted1);
            encryptor.encrypt(plain2, encrypted2);
            evaluator.multiply_inplace(encrypted1, encrypted2);
            decryptor.decrypt(encrypted1, plain);
            ASSERT_EQ(plain.to_string(), "1x^24");
            ASSERT_TRUE(encrypted2.parms_id() == encrypted1.parms_id());
            ASSERT_TRUE(encrypted1.parms_id() == context.first_parms_id());
        }
        {
            EncryptionParameters parms(scheme_type::bgv);
            Modulus plain_modulus((1ULL << 60) - 1);
            parms.set_poly_modulus_degree(64);
            parms.set_plain_modulus(plain_modulus);
            parms.set_coeff_modulus(CoeffModulus::Create(64, { 60, 60, 60, 60 }));

            SEALContext context(parms, false, sec_level_type::none);
            KeyGenerator keygen(context);
            PublicKey pk;
            keygen.create_public_key(pk);

            Encryptor encryptor(context, pk);
            Evaluator evaluator(context);
            Decryptor decryptor(context, keygen.secret_key());

            Ciphertext encrypted1;
            Ciphertext encrypted2;
            Plaintext plain, plain1, plain2;

            plain1 = "1x^28 + 1x^25 + 1x^21 + 1x^20 + 1x^18 + 1x^14 + 1x^12 + 1x^10 + 1x^9 + 1x^6 + 1x^5 + 1x^4 + 1x^3";
            plain2 = "1x^18 + 1x^16 + 1x^14 + 1x^9 + 1x^8 + 1x^5 + 1";
            encryptor.encrypt(plain1, encrypted1);
            encryptor.encrypt(plain2, encrypted2);
            evaluator.multiply_inplace(encrypted1, encrypted2);
            decryptor.decrypt(encrypted1, plain);
            ASSERT_EQ(
                plain.to_string(), "1x^46 + 1x^44 + 1x^43 + 1x^42 + 1x^41 + 2x^39 + 1x^38 + 2x^37 + 3x^36 + 1x^35 + "
                                   "3x^34 + 2x^33 + 2x^32 + 4x^30 + 2x^29 + 5x^28 + 2x^27 + 4x^26 + 3x^25 + 2x^24 + "
                                   "4x^23 + 3x^22 + 4x^21 + 4x^20 + 4x^19 + 4x^18 + 3x^17 + 2x^15 + 4x^14 + 2x^13 + "
                                   "3x^12 + 2x^11 + 2x^10 + 2x^9 + 1x^8 + 1x^6 + 1x^5 + 1x^4 + 1x^3");
            ASSERT_TRUE(encrypted2.parms_id() == encrypted1.parms_id());
            ASSERT_TRUE(encrypted1.parms_id() == context.first_parms_id());

            plain1 = "0";
            plain2 = "0";
            encryptor.encrypt(plain1, encrypted1);
            encryptor.encrypt(plain2, encrypted2);
            evaluator.multiply_inplace(encrypted1, encrypted2);
            decryptor.decrypt(encrypted1, plain);
            ASSERT_EQ(plain.to_string(), "0");
            ASSERT_TRUE(encrypted2.parms_id() == encrypted1.parms_id());
            ASSERT_TRUE(encrypted1.parms_id() == context.first_parms_id());

            plain1 = "0";
            plain2 = "1x^2 + 1";
            encryptor.encrypt(plain1, encrypted1);
            encryptor.encrypt(plain2, encrypted2);
            evaluator.multiply_inplace(encrypted1, encrypted2);
            decryptor.decrypt(encrypted1, plain);
            ASSERT_EQ(plain.to_string(), "0");
            ASSERT_TRUE(encrypted2.parms_id() == encrypted1.parms_id());
            ASSERT_TRUE(encrypted1.parms_id() == context.first_parms_id());

            plain1 = "1x^2 + 1x^1 + 1";
            plain2 = "1";
            encryptor.encrypt(plain1, encrypted1);
            encryptor.encrypt(plain2, encrypted2);
            evaluator.multiply_inplace(encrypted1, encrypted2);
            decryptor.decrypt(encrypted1, plain);
            ASSERT_EQ(plain.to_string(), "1x^2 + 1x^1 + 1");
            ASSERT_TRUE(encrypted2.parms_id() == encrypted1.parms_id());
            ASSERT_TRUE(encrypted1.parms_id() == context.first_parms_id());

            plain1 = "1x^2 + 1";
            plain2 = "FFFFFFFFFFFFFFEx^1 + FFFFFFFFFFFFFFE";
            encryptor.encrypt(plain1, encrypted1);
            encryptor.encrypt(plain2, encrypted2);
            evaluator.multiply_inplace(encrypted1, encrypted2);
            decryptor.decrypt(encrypted1, plain);
            ASSERT_EQ(
                plain.to_string(), "FFFFFFFFFFFFFFEx^3 + FFFFFFFFFFFFFFEx^2 + FFFFFFFFFFFFFFEx^1 + FFFFFFFFFFFFFFE");
            ASSERT_TRUE(encrypted2.parms_id() == encrypted1.parms_id());
            ASSERT_TRUE(encrypted1.parms_id() == context.first_parms_id());

            plain1 = "1x^16";
            plain2 = "1x^8";
            encryptor.encrypt(plain1, encrypted1);
            encryptor.encrypt(plain2, encrypted2);
            evaluator.multiply_inplace(encrypted1, encrypted2);
            decryptor.decrypt(encrypted1, plain);
            ASSERT_EQ(plain.to_string(), "1x^24");
            ASSERT_TRUE(encrypted2.parms_id() == encrypted1.parms_id());
            ASSERT_TRUE(encrypted1.parms_id() == context.first_parms_id());
        }
        {
            EncryptionParameters parms(scheme_type::bgv);
            Modulus plain_modulus(1 << 6);
            parms.set_poly_modulus_degree(128);
            parms.set_plain_modulus(plain_modulus);
            parms.set_coeff_modulus(CoeffModulus::Create(128, { 40, 40 }));

            SEALContext context(parms, false, sec_level_type::none);
            KeyGenerator keygen(context);
            PublicKey pk;
            keygen.create_public_key(pk);

            Encryptor encryptor(context, pk);
            Evaluator evaluator(context);
            Decryptor decryptor(context, keygen.secret_key());

            Ciphertext encrypted1;
            Ciphertext encrypted2;
            Plaintext plain, plain1, plain2;

            plain1 = "1x^28 + 1x^25 + 1x^21 + 1x^20 + 1x^18 + 1x^14 + 1x^12 + 1x^10 + 1x^9 + 1x^6 + 1x^5 + 1x^4 + 1x^3";
            plain2 = "1x^18 + 1x^16 + 1x^14 + 1x^9 + 1x^8 + 1x^5 + 1";
            encryptor.encrypt(plain1, encrypted1);
            encryptor.encrypt(plain2, encrypted2);
            evaluator.multiply_inplace(encrypted1, encrypted2);
            decryptor.decrypt(encrypted1, plain);
            ASSERT_EQ(
                plain.to_string(), "1x^46 + 1x^44 + 1x^43 + 1x^42 + 1x^41 + 2x^39 + 1x^38 + 2x^37 + 3x^36 + 1x^35 + "
                                   "3x^34 + 2x^33 + 2x^32 + 4x^30 + 2x^29 + 5x^28 + 2x^27 + 4x^26 + 3x^25 + 2x^24 + "
                                   "4x^23 + 3x^22 + 4x^21 + 4x^20 + 4x^19 + 4x^18 + 3x^17 + 2x^15 + 4x^14 + 2x^13 + "
                                   "3x^12 + 2x^11 + 2x^10 + 2x^9 + 1x^8 + 1x^6 + 1x^5 + 1x^4 + 1x^3");
            ASSERT_TRUE(encrypted2.parms_id() == encrypted1.parms_id());
            ASSERT_TRUE(encrypted1.parms_id() == context.first_parms_id());

            plain1 = "0";
            plain2 = "0";
            encryptor.encrypt(plain1, encrypted1);
            encryptor.encrypt(plain2, encrypted2);
            evaluator.multiply_inplace(encrypted1, encrypted2);
            decryptor.decrypt(encrypted1, plain);
            ASSERT_EQ(plain.to_string(), "0");
            ASSERT_TRUE(encrypted2.parms_id() == encrypted1.parms_id());
            ASSERT_TRUE(encrypted1.parms_id() == context.first_parms_id());

            plain1 = "0";
            plain2 = "1x^2 + 1";
            encryptor.encrypt(plain1, encrypted1);
            encryptor.encrypt(plain2, encrypted2);
            evaluator.multiply_inplace(encrypted1, encrypted2);
            decryptor.decrypt(encrypted1, plain);
            ASSERT_EQ(plain.to_string(), "0");
            ASSERT_TRUE(encrypted2.parms_id() == encrypted1.parms_id());
            ASSERT_TRUE(encrypted1.parms_id() == context.first_parms_id());

            plain1 = "1x^2 + 1x^1 + 1";
            plain2 = "1";
            encryptor.encrypt(plain1, encrypted1);
            encryptor.encrypt(plain2, encrypted2);
            evaluator.multiply_inplace(encrypted1, encrypted2);
            decryptor.decrypt(encrypted1, plain);
            ASSERT_EQ(plain.to_string(), "1x^2 + 1x^1 + 1");
            ASSERT_TRUE(encrypted2.parms_id() == encrypted1.parms_id());
            ASSERT_TRUE(encrypted1.parms_id() == context.first_parms_id());

            plain1 = "1x^2 + 1";
            plain2 = "3Fx^1 + 3F";
            encryptor.encrypt(plain1, encrypted1);
            encryptor.encrypt(plain2, encrypted2);
            evaluator.multiply_inplace(encrypted1, encrypted2);
            decryptor.decrypt(encrypted1, plain);
            ASSERT_EQ(plain.to_string(), "3Fx^3 + 3Fx^2 + 3Fx^1 + 3F");
            ASSERT_TRUE(encrypted2.parms_id() == encrypted1.parms_id());
            ASSERT_TRUE(encrypted1.parms_id() == context.first_parms_id());

            plain1 = "1x^16";
            plain2 = "1x^8";
            encryptor.encrypt(plain1, encrypted1);
            encryptor.encrypt(plain2, encrypted2);
            evaluator.multiply_inplace(encrypted1, encrypted2);
            decryptor.decrypt(encrypted1, plain);
            ASSERT_EQ(plain.to_string(), "1x^24");
            ASSERT_TRUE(encrypted2.parms_id() == encrypted1.parms_id());
            ASSERT_TRUE(encrypted1.parms_id() == context.first_parms_id());
        }
        {
            EncryptionParameters parms(scheme_type::bgv);
            Modulus plain_modulus(1 << 8);
            parms.set_poly_modulus_degree(128);
            parms.set_plain_modulus(plain_modulus);
            parms.set_coeff_modulus(CoeffModulus::Create(128, { 40, 40, 40 }));

            SEALContext context(parms, false, sec_level_type::none);
            KeyGenerator keygen(context);
            PublicKey pk;
            keygen.create_public_key(pk);

            Encryptor encryptor(context, pk);
            Evaluator evaluator(context);
            Decryptor decryptor(context, keygen.secret_key());

            Ciphertext encrypted1;
            Plaintext plain, plain1;

            plain1 = "1x^6 + 1x^5 + 1x^4 + 1x^3 + 1x^1 + 1";
            encryptor.encrypt(plain1, encrypted1);
            evaluator.multiply(encrypted1, encrypted1, encrypted1);
            evaluator.multiply(encrypted1, encrypted1, encrypted1);
            decryptor.decrypt(encrypted1, plain);
            ASSERT_EQ(
                plain.to_string(), "1x^24 + 4x^23 + Ax^22 + 14x^21 + 1Fx^20 + 2Cx^19 + 3Cx^18 + 4Cx^17 + 5Fx^16 + "
                                   "6Cx^15 + 70x^14 + 74x^13 + 71x^12 + 6Cx^11 + 64x^10 + 50x^9 + 40x^8 + 34x^7 + "
                                   "26x^6 + 1Cx^5 + 11x^4 + 8x^3 + 6x^2 + 4x^1 + 1");
            ASSERT_TRUE(encrypted1.parms_id() == context.first_parms_id());
        }
    }

#include "seal/randomgen.h"
    TEST(EvaluatorTest, BFVRelinearize)
    {
        EncryptionParameters parms(scheme_type::bfv);
        Modulus plain_modulus(1 << 6);
        parms.set_poly_modulus_degree(128);
        parms.set_plain_modulus(plain_modulus);
        parms.set_coeff_modulus(CoeffModulus::Create(128, { 40, 40, 40, 40 }));

        SEALContext context(parms, true, sec_level_type::none);
        KeyGenerator keygen(context);
        PublicKey pk;
        keygen.create_public_key(pk);
        RelinKeys rlk;
        keygen.create_relin_keys(rlk);

        Encryptor encryptor(context, pk);
        Evaluator evaluator(context);
        Decryptor decryptor(context, keygen.secret_key());

        Ciphertext encrypted(context);
        Ciphertext encrypted2(context);

        Plaintext plain;
        Plaintext plain2;

        plain = 0;
        encryptor.encrypt(plain, encrypted);
        evaluator.square_inplace(encrypted);
        evaluator.relinearize_inplace(encrypted, rlk);
        decryptor.decrypt(encrypted, plain2);
        ASSERT_TRUE(plain == plain2);

        encryptor.encrypt(plain, encrypted);
        evaluator.square_inplace(encrypted);
        evaluator.relinearize_inplace(encrypted, rlk);
        evaluator.square_inplace(encrypted);
        evaluator.relinearize_inplace(encrypted, rlk);
        decryptor.decrypt(encrypted, plain2);
        ASSERT_TRUE(plain == plain2);

        plain = "1x^10 + 2";
        encryptor.encrypt(plain, encrypted);
        evaluator.square_inplace(encrypted);
        evaluator.relinearize_inplace(encrypted, rlk);
        decryptor.decrypt(encrypted, plain2);
        ASSERT_TRUE(plain2.to_string() == "1x^20 + 4x^10 + 4");

        encryptor.encrypt(plain, encrypted);
        evaluator.square_inplace(encrypted);
        evaluator.relinearize_inplace(encrypted, rlk);
        evaluator.square_inplace(encrypted);
        evaluator.relinearize_inplace(encrypted, rlk);
        decryptor.decrypt(encrypted, plain2);
        ASSERT_TRUE(plain2.to_string() == "1x^40 + 8x^30 + 18x^20 + 20x^10 + 10");

        // Relinearization with modulus switching
        plain = "1x^10 + 2";
        encryptor.encrypt(plain, encrypted);
        evaluator.square_inplace(encrypted);
        evaluator.relinearize_inplace(encrypted, rlk);
        evaluator.mod_switch_to_next_inplace(encrypted);
        decryptor.decrypt(encrypted, plain2);
        ASSERT_TRUE(plain2.to_string() == "1x^20 + 4x^10 + 4");

        encryptor.encrypt(plain, encrypted);
        evaluator.square_inplace(encrypted);
        evaluator.relinearize_inplace(encrypted, rlk);
        evaluator.mod_switch_to_next_inplace(encrypted);
        evaluator.square_inplace(encrypted);
        evaluator.relinearize_inplace(encrypted, rlk);
        evaluator.mod_switch_to_next_inplace(encrypted);
        decryptor.decrypt(encrypted, plain2);
        ASSERT_TRUE(plain2.to_string() == "1x^40 + 8x^30 + 18x^20 + 20x^10 + 10");
    }

    TEST(EvaluatorTest, RelinearizeEmptyKeySlot)
    {
        EncryptionParameters parms(scheme_type::bfv);
        parms.set_poly_modulus_degree(128);
        parms.set_plain_modulus(1 << 6);
        parms.set_coeff_modulus(CoeffModulus::Create(128, { 40, 40, 40, 40 }));

        SEALContext context(parms, true, sec_level_type::none);
        KeyGenerator keygen(context);
        PublicKey pk;
        keygen.create_public_key(pk);
        RelinKeys rlk;
        keygen.create_relin_keys(rlk);

        Encryptor encryptor(context, pk);
        Evaluator evaluator(context);

        Ciphertext encrypted(context);
        Plaintext plain("1x^10 + 2");
        encryptor.encrypt(plain, encrypted);
        evaluator.square_inplace(encrypted);

        // Prepend an empty slot so the switched index (get_index(2) == 0) lands on an empty vector.
        rlk.data().insert(rlk.data().begin(), vector<PublicKey>());
        ASSERT_THROW(evaluator.relinearize_inplace(encrypted, rlk), invalid_argument);
    }

    TEST(EvaluatorTest, RelinearizeShortKeyVector)
    {
        EncryptionParameters parms(scheme_type::bfv);
        parms.set_poly_modulus_degree(128);
        parms.set_plain_modulus(1 << 6);
        parms.set_coeff_modulus(CoeffModulus::Create(128, { 40, 40, 40, 40 }));

        SEALContext context(parms, true, sec_level_type::none);
        KeyGenerator keygen(context);
        PublicKey pk;
        keygen.create_public_key(pk);
        RelinKeys rlk;
        keygen.create_relin_keys(rlk);

        Encryptor encryptor(context, pk);
        Evaluator evaluator(context);

        Ciphertext encrypted(context);
        Plaintext plain("1x^10 + 2");
        encryptor.encrypt(plain, encrypted);
        evaluator.square_inplace(encrypted);

        // Truncate the used key slot to a single PublicKey, as a truncated unsafe_load'd blob could.
        auto &slot = rlk.data()[RelinKeys::get_index(2)];
        ASSERT_GT(slot.size(), 1ULL);
        vector<PublicKey> short_slot;
        short_slot.reserve(1);
        short_slot.push_back(slot[0]);
        slot.swap(short_slot);

        ASSERT_THROW(evaluator.relinearize_inplace(encrypted, rlk), invalid_argument);
    }

    TEST(EvaluatorTest, SeededCiphertextRejectedByComputation)
    {
        EncryptionParameters parms(scheme_type::bfv);
        parms.set_poly_modulus_degree(128);
        parms.set_plain_modulus(1 << 6);
        parms.set_coeff_modulus(CoeffModulus::Create(128, { 40, 40 }));

        SEALContext context(parms, false, sec_level_type::none);
        KeyGenerator keygen(context);
        Encryptor encryptor(context, keygen.secret_key());
        Decryptor decryptor(context, keygen.secret_key());
        Evaluator evaluator(context);

        // Ordinary unseeded computation is unaffected: encrypt, negate twice, recover the input.
        Ciphertext normal;
        encryptor.encrypt_symmetric(Plaintext("5"), normal);
        ASSERT_FALSE(normal.contains_seed());
        ASSERT_TRUE(is_buffer_valid(normal));
        evaluator.negate_inplace(normal);
        evaluator.negate_inplace(normal);
        Plaintext decrypted;
        decryptor.decrypt(normal, decrypted);
        ASSERT_EQ("5", decrypted.to_string());

        // Stamp the seed marker into the second polynomial to reproduce the in-memory
        // serialization-only representation and confirm computation rejects it.
        Ciphertext seeded;
        encryptor.encrypt_symmetric(Plaintext("5"), seeded);
        seeded.data(1)[0] = 0xFFFFFFFFFFFFFFFFULL;
        ASSERT_TRUE(seeded.contains_seed());
        ASSERT_FALSE(is_buffer_valid(seeded));
        ASSERT_THROW(evaluator.negate_inplace(seeded), invalid_argument);
    }

    TEST(EvaluatorTest, SeededRelinKeyRejectedByRelinearize)
    {
        EncryptionParameters parms(scheme_type::bfv);
        parms.set_poly_modulus_degree(128);
        parms.set_plain_modulus(1 << 6);
        parms.set_coeff_modulus(CoeffModulus::Create(128, { 40, 40, 40, 40 }));

        SEALContext context(parms, true, sec_level_type::none);
        KeyGenerator keygen(context);
        RelinKeys rlk;
        keygen.create_relin_keys(rlk);

        Encryptor encryptor(context, keygen.secret_key());
        Evaluator evaluator(context);

        Ciphertext squared;
        encryptor.encrypt_symmetric(Plaintext("1x^10 + 2"), squared);
        evaluator.square_inplace(squared);
        ASSERT_EQ(3ULL, squared.size());

        // A well-formed relinearization on the unmodified keys succeeds.
        Ciphertext control = squared;
        evaluator.relinearize_inplace(control, rlk);
        ASSERT_EQ(2ULL, control.size());

        // Stamp the seed marker into the used key slot. is_buffer_valid delegates through
        // PublicKey to Ciphertext, so relinearization rejects the seeded key entry.
        auto &slot = rlk.data()[RelinKeys::get_index(2)];
        slot[0].data().data(1)[0] = 0xFFFFFFFFFFFFFFFFULL;
        ASSERT_TRUE(slot[0].data().contains_seed());
        ASSERT_FALSE(is_buffer_valid(rlk));
        ASSERT_THROW(evaluator.relinearize_inplace(squared, rlk), invalid_argument);
    }

    TEST(EvaluatorTest, RelinearizeLowerLevel)
    {
        EncryptionParameters parms(scheme_type::bfv);
        parms.set_poly_modulus_degree(128);
        parms.set_plain_modulus(1 << 6);
        parms.set_coeff_modulus(CoeffModulus::Create(128, { 40, 40, 40, 40 }));

        SEALContext context(parms, true, sec_level_type::none);
        KeyGenerator keygen(context);
        PublicKey pk;
        keygen.create_public_key(pk);
        RelinKeys rlk;
        keygen.create_relin_keys(rlk);

        Encryptor encryptor(context, pk);
        Evaluator evaluator(context);
        Decryptor decryptor(context, keygen.secret_key());

        Ciphertext encrypted(context);
        Plaintext plain("1x^10 + 2");
        Plaintext plain2;
        encryptor.encrypt(plain, encrypted);
        evaluator.square_inplace(encrypted);

        // Mod switch down first so decomp_modulus_size < key_vector.size(); relinearization must
        // still succeed (guards against tightening the inner-dimension check from >= to ==).
        evaluator.mod_switch_to_next_inplace(encrypted);
        evaluator.relinearize_inplace(encrypted, rlk);
        decryptor.decrypt(encrypted, plain2);
        ASSERT_TRUE(plain2.to_string() == "1x^20 + 4x^10 + 4");
    }

    TEST(EvaluatorTest, BGVRelinearize)
    {
        EncryptionParameters parms(scheme_type::bgv);
        Modulus plain_modulus(65);
        parms.set_poly_modulus_degree(128);
        parms.set_plain_modulus(plain_modulus);
        parms.set_coeff_modulus(CoeffModulus::Create(128, { 60, 60, 60, 60 }));

        SEALContext context(parms, true, sec_level_type::none);
        KeyGenerator keygen(context);
        PublicKey pk;
        keygen.create_public_key(pk);
        RelinKeys rlk;
        keygen.create_relin_keys(rlk);

        Encryptor encryptor(context, pk);
        Evaluator evaluator(context);
        Decryptor decryptor(context, keygen.secret_key());

        Ciphertext encrypted(context);
        Ciphertext encrypted2(context);

        Plaintext plain;
        Plaintext plain2;

        plain = 0;
        encryptor.encrypt(plain, encrypted);
        evaluator.square_inplace(encrypted);
        evaluator.relinearize_inplace(encrypted, rlk);
        decryptor.decrypt(encrypted, plain2);
        std::cout << plain2.to_string() << std::endl;
        ASSERT_TRUE(plain == plain2);

        encryptor.encrypt(plain, encrypted);
        evaluator.square_inplace(encrypted);
        evaluator.relinearize_inplace(encrypted, rlk);
        evaluator.square_inplace(encrypted);
        evaluator.relinearize_inplace(encrypted, rlk);
        decryptor.decrypt(encrypted, plain2);
        ASSERT_TRUE(plain == plain2);

        plain = "1x^10 + 2";
        encryptor.encrypt(plain, encrypted);
        evaluator.square_inplace(encrypted);
        evaluator.relinearize_inplace(encrypted, rlk);
        decryptor.decrypt(encrypted, plain2);
        ASSERT_TRUE(plain2.to_string() == "1x^20 + 4x^10 + 4");

        encryptor.encrypt(plain, encrypted);
        evaluator.square_inplace(encrypted);
        evaluator.relinearize_inplace(encrypted, rlk);
        evaluator.square_inplace(encrypted);
        evaluator.relinearize_inplace(encrypted, rlk);
        decryptor.decrypt(encrypted, plain2);
        ASSERT_TRUE(plain2.to_string() == "1x^40 + 8x^30 + 18x^20 + 20x^10 + 10");

        // Relinearization with modulus switching
        plain = "1x^10 + 2";
        encryptor.encrypt(plain, encrypted);
        evaluator.square_inplace(encrypted);
        evaluator.relinearize_inplace(encrypted, rlk);
        evaluator.mod_switch_to_next_inplace(encrypted);
        decryptor.decrypt(encrypted, plain2);
        ASSERT_TRUE(plain2.to_string() == "1x^20 + 4x^10 + 4");

        encryptor.encrypt(plain, encrypted);
        evaluator.square_inplace(encrypted);
        evaluator.relinearize_inplace(encrypted, rlk);
        evaluator.mod_switch_to_next_inplace(encrypted);
        evaluator.square_inplace(encrypted);
        evaluator.relinearize_inplace(encrypted, rlk);
        evaluator.mod_switch_to_next_inplace(encrypted);
        decryptor.decrypt(encrypted, plain2);
        ASSERT_TRUE(plain2.to_string() == "1x^40 + 8x^30 + 18x^20 + 20x^10 + 10");
    }

    TEST(EvaluatorTest, CKKSEncryptNaiveMultiplyDecrypt)
    {
        EncryptionParameters parms(scheme_type::ckks);
        {
            // Multiplying two zero vectors
            size_t slot_size = 32;
            parms.set_poly_modulus_degree(slot_size * 2);
            parms.set_coeff_modulus(CoeffModulus::Create(slot_size * 2, { 30, 30, 30, 30 }));

            SEALContext context(parms, false, sec_level_type::none);
            KeyGenerator keygen(context);
            PublicKey pk;
            keygen.create_public_key(pk);

            CKKSEncoder encoder(context);
            Encryptor encryptor(context, pk);
            Decryptor decryptor(context, keygen.secret_key());
            Evaluator evaluator(context);

            Ciphertext encrypted;
            Plaintext plain;
            Plaintext plainRes;

            vector<complex<double>> input(slot_size, 0.0);
            vector<complex<double>> output(slot_size);
            const double delta = static_cast<double>(1 << 30);
            encoder.encode(input, context.first_parms_id(), delta, plain);

            encryptor.encrypt(plain, encrypted);
            evaluator.multiply_inplace(encrypted, encrypted);

            // Check correctness of encryption
            ASSERT_TRUE(encrypted.parms_id() == context.first_parms_id());

            decryptor.decrypt(encrypted, plainRes);
            encoder.decode(plainRes, output);
            for (size_t i = 0; i < slot_size; i++)
            {
                auto tmp = abs(input[i].real() - output[i].real());
                ASSERT_TRUE(tmp < 0.5);
            }
        }
        {
            // Multiplying two random vectors
            size_t slot_size = 32;
            parms.set_poly_modulus_degree(slot_size * 2);
            parms.set_coeff_modulus(CoeffModulus::Create(slot_size * 2, { 60, 60, 60 }));

            SEALContext context(parms, false, sec_level_type::none);
            KeyGenerator keygen(context);
            PublicKey pk;
            keygen.create_public_key(pk);

            CKKSEncoder encoder(context);
            Encryptor encryptor(context, pk);
            Decryptor decryptor(context, keygen.secret_key());
            Evaluator evaluator(context);

            Ciphertext encrypted1;
            Ciphertext encrypted2;
            Plaintext plain1;
            Plaintext plain2;
            Plaintext plainRes;

            vector<complex<double>> input1(slot_size, 0.0);
            vector<complex<double>> input2(slot_size, 0.0);
            vector<complex<double>> expected(slot_size, 0.0);
            vector<complex<double>> output(slot_size);
            const double delta = static_cast<double>(1ULL << 40);

            int data_bound = (1 << 10);
            srand(seal_test_seed);

            for (int round = 0; round < 100; round++)
            {
                for (size_t i = 0; i < slot_size; i++)
                {
                    input1[i] = static_cast<double>(rand() % data_bound);
                    input2[i] = static_cast<double>(rand() % data_bound);
                    expected[i] = input1[i] * input2[i];
                }
                encoder.encode(input1, context.first_parms_id(), delta, plain1);
                encoder.encode(input2, context.first_parms_id(), delta, plain2);

                encryptor.encrypt(plain1, encrypted1);
                encryptor.encrypt(plain2, encrypted2);
                evaluator.multiply_inplace(encrypted1, encrypted2);

                // Check correctness of encryption
                ASSERT_TRUE(encrypted1.parms_id() == context.first_parms_id());

                decryptor.decrypt(encrypted1, plainRes);
                encoder.decode(plainRes, output);
                for (size_t i = 0; i < slot_size; i++)
                {
                    auto tmp = abs(expected[i].real() - output[i].real());
                    ASSERT_TRUE(tmp < 0.5);
                }
            }
        }
        {
            // Multiplying two random vectors
            size_t slot_size = 16;
            parms.set_poly_modulus_degree(64);
            parms.set_coeff_modulus(CoeffModulus::Create(64, { 60, 60, 60 }));

            SEALContext context(parms, false, sec_level_type::none);
            KeyGenerator keygen(context);
            PublicKey pk;
            keygen.create_public_key(pk);

            CKKSEncoder encoder(context);
            Encryptor encryptor(context, pk);
            Decryptor decryptor(context, keygen.secret_key());
            Evaluator evaluator(context);

            Ciphertext encrypted1;
            Ciphertext encrypted2;
            Plaintext plain1;
            Plaintext plain2;
            Plaintext plainRes;

            vector<complex<double>> input1(slot_size, 0.0);
            vector<complex<double>> input2(slot_size, 0.0);
            vector<complex<double>> expected(slot_size, 0.0);
            vector<complex<double>> output(slot_size);
            const double delta = static_cast<double>(1ULL << 40);

            int data_bound = (1 << 10);
            srand(seal_test_seed);

            for (int round = 0; round < 100; round++)
            {
                for (size_t i = 0; i < slot_size; i++)
                {
                    input1[i] = static_cast<double>(rand() % data_bound);
                    input2[i] = static_cast<double>(rand() % data_bound);
                    expected[i] = input1[i] * input2[i];
                }
                encoder.encode(input1, context.first_parms_id(), delta, plain1);
                encoder.encode(input2, context.first_parms_id(), delta, plain2);

                encryptor.encrypt(plain1, encrypted1);
                encryptor.encrypt(plain2, encrypted2);
                evaluator.multiply_inplace(encrypted1, encrypted2);

                // Check correctness of encryption
                ASSERT_TRUE(encrypted1.parms_id() == context.first_parms_id());

                decryptor.decrypt(encrypted1, plainRes);
                encoder.decode(plainRes, output);
                for (size_t i = 0; i < slot_size; i++)
                {
                    auto tmp = abs(expected[i].real() - output[i].real());
                    ASSERT_TRUE(tmp < 0.5);
                }
            }
        }
    }

    TEST(EvaluatorTest, CKKSEncryptMultiplyByNumberDecrypt)
    {
        EncryptionParameters parms(scheme_type::ckks);
        {
            // Multiplying two random vectors by an integer
            size_t slot_size = 32;
            parms.set_poly_modulus_degree(slot_size * 2);
            parms.set_coeff_modulus(CoeffModulus::Create(slot_size * 2, { 60, 60, 40 }));

            SEALContext context(parms, false, sec_level_type::none);
            KeyGenerator keygen(context);
            PublicKey pk;
            keygen.create_public_key(pk);

            CKKSEncoder encoder(context);
            Encryptor encryptor(context, pk);
            Decryptor decryptor(context, keygen.secret_key());
            Evaluator evaluator(context);

            Ciphertext encrypted1;
            Plaintext plain1;
            Plaintext plain2;
            Plaintext plainRes;

            vector<complex<double>> input1(slot_size, 0.0);
            int64_t input2;
            vector<complex<double>> expected(slot_size, 0.0);

            int data_bound = (1 << 10);
            srand(seal_test_seed);

            for (int iExp = 0; iExp < 50; iExp++)
            {
                input2 = max(rand() % data_bound, 1);
                for (size_t i = 0; i < slot_size; i++)
                {
                    input1[i] = static_cast<double>(rand() % data_bound);
                    expected[i] = input1[i] * static_cast<double>(input2);
                }

                vector<complex<double>> output(slot_size);
                const double delta = static_cast<double>(1ULL << 40);
                encoder.encode(input1, context.first_parms_id(), delta, plain1);
                encoder.encode(input2, context.first_parms_id(), plain2);

                encryptor.encrypt(plain1, encrypted1);
                evaluator.multiply_plain_inplace(encrypted1, plain2);

                // Check correctness of encryption
                ASSERT_TRUE(encrypted1.parms_id() == context.first_parms_id());

                decryptor.decrypt(encrypted1, plainRes);
                encoder.decode(plainRes, output);
                for (size_t i = 0; i < slot_size; i++)
                {
                    auto tmp = abs(expected[i].real() - output[i].real());
                    ASSERT_TRUE(tmp < 0.5);
                }
            }
        }
        {
            // Multiplying two random vectors by an integer
            size_t slot_size = 8;
            parms.set_poly_modulus_degree(64);
            parms.set_coeff_modulus(CoeffModulus::Create(64, { 60, 60 }));

            SEALContext context(parms, false, sec_level_type::none);
            KeyGenerator keygen(context);
            PublicKey pk;
            keygen.create_public_key(pk);

            CKKSEncoder encoder(context);
            Encryptor encryptor(context, pk);
            Decryptor decryptor(context, keygen.secret_key());
            Evaluator evaluator(context);

            Ciphertext encrypted1;
            Plaintext plain1;
            Plaintext plain2;
            Plaintext plainRes;

            vector<complex<double>> input1(slot_size, 0.0);
            int64_t input2;
            vector<complex<double>> expected(slot_size, 0.0);

            int data_bound = (1 << 10);
            srand(seal_test_seed);

            for (int iExp = 0; iExp < 50; iExp++)
            {
                input2 = max(rand() % data_bound, 1);
                for (size_t i = 0; i < slot_size; i++)
                {
                    input1[i] = static_cast<double>(rand() % data_bound);
                    expected[i] = input1[i] * static_cast<double>(input2);
                }

                vector<complex<double>> output(slot_size);
                const double delta = static_cast<double>(1ULL << 40);
                encoder.encode(input1, context.first_parms_id(), delta, plain1);
                encoder.encode(input2, context.first_parms_id(), plain2);

                encryptor.encrypt(plain1, encrypted1);
                evaluator.multiply_plain_inplace(encrypted1, plain2);

                // Check correctness of encryption
                ASSERT_TRUE(encrypted1.parms_id() == context.first_parms_id());

                decryptor.decrypt(encrypted1, plainRes);
                encoder.decode(plainRes, output);
                for (size_t i = 0; i < slot_size; i++)
                {
                    auto tmp = abs(expected[i].real() - output[i].real());
                    ASSERT_TRUE(tmp < 0.5);
                }
            }
        }
        {
            // Multiplying two random vectors by a double
            size_t slot_size = 32;
            parms.set_poly_modulus_degree(slot_size * 2);
            parms.set_coeff_modulus(CoeffModulus::Create(slot_size * 2, { 60, 60, 60 }));

            SEALContext context(parms, false, sec_level_type::none);
            KeyGenerator keygen(context);
            PublicKey pk;
            keygen.create_public_key(pk);

            CKKSEncoder encoder(context);
            Encryptor encryptor(context, pk);
            Decryptor decryptor(context, keygen.secret_key());
            Evaluator evaluator(context);

            Ciphertext encrypted1;
            Plaintext plain1;
            Plaintext plain2;
            Plaintext plainRes;

            vector<complex<double>> input1(slot_size, 0.0);
            double input2;
            vector<complex<double>> expected(slot_size, 0.0);
            vector<complex<double>> output(slot_size);

            int data_bound = (1 << 10);
            srand(seal_test_seed);

            for (int iExp = 0; iExp < 50; iExp++)
            {
                input2 = static_cast<double>(rand() % (data_bound * data_bound)) / static_cast<double>(data_bound);
                for (size_t i = 0; i < slot_size; i++)
                {
                    input1[i] = static_cast<double>(rand() % data_bound);
                    expected[i] = input1[i] * input2;
                }

                const double delta = static_cast<double>(1ULL << 40);
                encoder.encode(input1, context.first_parms_id(), delta, plain1);
                encoder.encode(input2, context.first_parms_id(), delta, plain2);

                encryptor.encrypt(plain1, encrypted1);
                evaluator.multiply_plain_inplace(encrypted1, plain2);

                // Check correctness of encryption
                ASSERT_TRUE(encrypted1.parms_id() == context.first_parms_id());

                decryptor.decrypt(encrypted1, plainRes);
                encoder.decode(plainRes, output);
                for (size_t i = 0; i < slot_size; i++)
                {
                    auto tmp = abs(expected[i].real() - output[i].real());
                    ASSERT_TRUE(tmp < 0.5);
                }
            }
        }
        {
            // Multiplying two random vectors by a double
            size_t slot_size = 16;
            parms.set_poly_modulus_degree(64);
            parms.set_coeff_modulus(CoeffModulus::Create(64, { 60, 60, 60 }));

            SEALContext context(parms, false, sec_level_type::none);
            KeyGenerator keygen(context);
            PublicKey pk;
            keygen.create_public_key(pk);

            CKKSEncoder encoder(context);
            Encryptor encryptor(context, pk);
            Decryptor decryptor(context, keygen.secret_key());
            Evaluator evaluator(context);

            Ciphertext encrypted1;
            Plaintext plain1;
            Plaintext plain2;
            Plaintext plainRes;

            vector<complex<double>> input1(slot_size, 2.1);
            double input2;
            vector<complex<double>> expected(slot_size, 2.1);
            vector<complex<double>> output(slot_size);

            int data_bound = (1 << 10);
            srand(seal_test_seed);

            for (int iExp = 0; iExp < 50; iExp++)
            {
                input2 = static_cast<double>(rand() % (data_bound * data_bound)) / static_cast<double>(data_bound);
                for (size_t i = 0; i < slot_size; i++)
                {
                    input1[i] = static_cast<double>(rand() % data_bound);
                    expected[i] = input1[i] * input2;
                }

                const double delta = static_cast<double>(1ULL << 40);
                encoder.encode(input1, context.first_parms_id(), delta, plain1);
                encoder.encode(input2, context.first_parms_id(), delta, plain2);

                encryptor.encrypt(plain1, encrypted1);
                evaluator.multiply_plain_inplace(encrypted1, plain2);

                // Check correctness of encryption
                ASSERT_TRUE(encrypted1.parms_id() == context.first_parms_id());

                decryptor.decrypt(encrypted1, plainRes);
                encoder.decode(plainRes, output);
                for (size_t i = 0; i < slot_size; i++)
                {
                    auto tmp = abs(expected[i].real() - output[i].real());
                    ASSERT_TRUE(tmp < 0.5);
                }
            }
        }
    }

    TEST(EvaluatorTest, CKKSEncryptMultiplyRelinDecrypt)
    {
        EncryptionParameters parms(scheme_type::ckks);
        {
            // Multiplying two random vectors 50 times
            size_t slot_size = 32;
            parms.set_poly_modulus_degree(slot_size * 2);
            parms.set_coeff_modulus(CoeffModulus::Create(slot_size * 2, { 60, 60, 60 }));

            SEALContext context(parms, false, sec_level_type::none);
            KeyGenerator keygen(context);
            PublicKey pk;
            keygen.create_public_key(pk);
            RelinKeys rlk;
            keygen.create_relin_keys(rlk);

            CKKSEncoder encoder(context);
            Encryptor encryptor(context, pk);
            Decryptor decryptor(context, keygen.secret_key());
            Evaluator evaluator(context);

            Ciphertext encrypted1;
            Ciphertext encrypted2;
            Ciphertext encryptedRes;
            Plaintext plain1;
            Plaintext plain2;
            Plaintext plainRes;

            vector<complex<double>> input1(slot_size, 0.0);
            vector<complex<double>> input2(slot_size, 0.0);
            vector<complex<double>> expected(slot_size, 0.0);
            int data_bound = 1 << 10;

            for (int round = 0; round < 50; round++)
            {
                srand(seal_test_seed);
                for (size_t i = 0; i < slot_size; i++)
                {
                    input1[i] = static_cast<double>(rand() % data_bound);
                    input2[i] = static_cast<double>(rand() % data_bound);
                    expected[i] = input1[i] * input2[i];
                }

                vector<complex<double>> output(slot_size);
                const double delta = static_cast<double>(1ULL << 40);
                encoder.encode(input1, context.first_parms_id(), delta, plain1);
                encoder.encode(input2, context.first_parms_id(), delta, plain2);

                encryptor.encrypt(plain1, encrypted1);
                encryptor.encrypt(plain2, encrypted2);

                // Check correctness of encryption
                ASSERT_TRUE(encrypted1.parms_id() == context.first_parms_id());
                // Check correctness of encryption
                ASSERT_TRUE(encrypted2.parms_id() == context.first_parms_id());

                evaluator.multiply_inplace(encrypted1, encrypted2);
                evaluator.relinearize_inplace(encrypted1, rlk);

                decryptor.decrypt(encrypted1, plainRes);
                encoder.decode(plainRes, output);
                for (size_t i = 0; i < slot_size; i++)
                {
                    auto tmp = abs(expected[i].real() - output[i].real());
                    ASSERT_TRUE(tmp < 0.5);
                }
            }
        }
        {
            // Multiplying two random vectors 50 times
            size_t slot_size = 32;
            parms.set_poly_modulus_degree(slot_size * 2);
            parms.set_coeff_modulus(CoeffModulus::Create(slot_size * 2, { 60, 30, 30, 30 }));

            SEALContext context(parms, false, sec_level_type::none);
            KeyGenerator keygen(context);
            PublicKey pk;
            keygen.create_public_key(pk);
            RelinKeys rlk;
            keygen.create_relin_keys(rlk);

            CKKSEncoder encoder(context);
            Encryptor encryptor(context, pk);
            Decryptor decryptor(context, keygen.secret_key());
            Evaluator evaluator(context);

            Ciphertext encrypted1;
            Ciphertext encrypted2;
            Ciphertext encryptedRes;
            Plaintext plain1;
            Plaintext plain2;
            Plaintext plainRes;

            vector<complex<double>> input1(slot_size, 0.0);
            vector<complex<double>> input2(slot_size, 0.0);
            vector<complex<double>> expected(slot_size, 0.0);
            int data_bound = 1 << 10;

            for (int round = 0; round < 50; round++)
            {
                srand(seal_test_seed);
                for (size_t i = 0; i < slot_size; i++)
                {
                    input1[i] = static_cast<double>(rand() % data_bound);
                    input2[i] = static_cast<double>(rand() % data_bound);
                    expected[i] = input1[i] * input2[i];
                }

                vector<complex<double>> output(slot_size);
                const double delta = static_cast<double>(1ULL << 40);
                encoder.encode(input1, context.first_parms_id(), delta, plain1);
                encoder.encode(input2, context.first_parms_id(), delta, plain2);

                encryptor.encrypt(plain1, encrypted1);
                encryptor.encrypt(plain2, encrypted2);

                // Check correctness of encryption
                ASSERT_TRUE(encrypted1.parms_id() == context.first_parms_id());
                // Check correctness of encryption
                ASSERT_TRUE(encrypted2.parms_id() == context.first_parms_id());

                evaluator.multiply_inplace(encrypted1, encrypted2);
                evaluator.relinearize_inplace(encrypted1, rlk);

                decryptor.decrypt(encrypted1, plainRes);
                encoder.decode(plainRes, output);
                for (size_t i = 0; i < slot_size; i++)
                {
                    auto tmp = abs(expected[i].real() - output[i].real());
                    ASSERT_TRUE(tmp < 0.5);
                }
            }
        }
        {
            // Multiplying two random vectors 50 times
            size_t slot_size = 2;
            parms.set_poly_modulus_degree(8);
            parms.set_coeff_modulus(CoeffModulus::Create(8, { 60, 30, 30, 30 }));

            SEALContext context(parms, false, sec_level_type::none);
            KeyGenerator keygen(context);
            PublicKey pk;
            keygen.create_public_key(pk);
            RelinKeys rlk;
            keygen.create_relin_keys(rlk);

            CKKSEncoder encoder(context);
            Encryptor encryptor(context, pk);
            Decryptor decryptor(context, keygen.secret_key());
            Evaluator evaluator(context);

            Ciphertext encrypted1;
            Ciphertext encrypted2;
            Ciphertext encryptedRes;
            Plaintext plain1;
            Plaintext plain2;
            Plaintext plainRes;

            vector<complex<double>> input1(slot_size, 0.0);
            vector<complex<double>> input2(slot_size, 0.0);
            vector<complex<double>> expected(slot_size, 0.0);
            vector<complex<double>> output(slot_size);
            int data_bound = 1 << 10;
            const double delta = static_cast<double>(1ULL << 40);

            for (int round = 0; round < 50; round++)
            {
                srand(seal_test_seed);
                for (size_t i = 0; i < slot_size; i++)
                {
                    input1[i] = static_cast<double>(rand() % data_bound);
                    input2[i] = static_cast<double>(rand() % data_bound);
                    expected[i] = input1[i] * input2[i];
                }

                encoder.encode(input1, context.first_parms_id(), delta, plain1);
                encoder.encode(input2, context.first_parms_id(), delta, plain2);

                encryptor.encrypt(plain1, encrypted1);
                encryptor.encrypt(plain2, encrypted2);

                // Check correctness of encryption
                ASSERT_TRUE(encrypted1.parms_id() == context.first_parms_id());
                // Check correctness of encryption
                ASSERT_TRUE(encrypted2.parms_id() == context.first_parms_id());

                evaluator.multiply_inplace(encrypted1, encrypted2);
                // Evaluator.relinearize_inplace(encrypted1, rlk);

                decryptor.decrypt(encrypted1, plainRes);
                encoder.decode(plainRes, output);
                for (size_t i = 0; i < slot_size; i++)
                {
                    auto tmp = abs(expected[i].real() - output[i].real());
                    ASSERT_TRUE(tmp < 0.5);
                }
            }
        }
    }

    TEST(EvaluatorTest, CKKSEncryptSquareRelinDecrypt)
    {
        EncryptionParameters parms(scheme_type::ckks);
        {
            // Squaring two random vectors 100 times
            size_t slot_size = 32;
            parms.set_poly_modulus_degree(slot_size * 2);
            parms.set_coeff_modulus(CoeffModulus::Create(slot_size * 2, { 60, 60, 60 }));

            SEALContext context(parms, false, sec_level_type::none);
            KeyGenerator keygen(context);
            PublicKey pk;
            keygen.create_public_key(pk);
            RelinKeys rlk;
            keygen.create_relin_keys(rlk);

            CKKSEncoder encoder(context);
            Encryptor encryptor(context, pk);
            Decryptor decryptor(context, keygen.secret_key());
            Evaluator evaluator(context);

            Ciphertext encrypted;
            Plaintext plain;
            Plaintext plainRes;

            vector<complex<double>> input(slot_size, 0.0);
            vector<complex<double>> expected(slot_size, 0.0);

            int data_bound = 1 << 7;
            srand(seal_test_seed);

            for (int round = 0; round < 100; round++)
            {
                for (size_t i = 0; i < slot_size; i++)
                {
                    input[i] = static_cast<double>(rand() % data_bound);
                    expected[i] = input[i] * input[i];
                }

                vector<complex<double>> output(slot_size);
                const double delta = static_cast<double>(1ULL << 40);
                encoder.encode(input, context.first_parms_id(), delta, plain);

                encryptor.encrypt(plain, encrypted);

                // Check correctness of encryption
                ASSERT_TRUE(encrypted.parms_id() == context.first_parms_id());

                // Evaluator.square_inplace(encrypted);
                evaluator.multiply_inplace(encrypted, encrypted);
                evaluator.relinearize_inplace(encrypted, rlk);

                decryptor.decrypt(encrypted, plainRes);
                encoder.decode(plainRes, output);
                for (size_t i = 0; i < slot_size; i++)
                {
                    auto tmp = abs(expected[i].real() - output[i].real());
                    ASSERT_TRUE(tmp < 0.5);
                }
            }
        }
        {
            // Squaring two random vectors 100 times
            size_t slot_size = 32;
            parms.set_poly_modulus_degree(slot_size * 2);
            parms.set_coeff_modulus(CoeffModulus::Create(slot_size * 2, { 60, 30, 30, 30 }));

            SEALContext context(parms, false, sec_level_type::none);
            KeyGenerator keygen(context);
            PublicKey pk;
            keygen.create_public_key(pk);
            RelinKeys rlk;
            keygen.create_relin_keys(rlk);

            CKKSEncoder encoder(context);
            Encryptor encryptor(context, pk);
            Decryptor decryptor(context, keygen.secret_key());
            Evaluator evaluator(context);

            Ciphertext encrypted;
            Plaintext plain;
            Plaintext plainRes;

            vector<complex<double>> input(slot_size, 0.0);
            vector<complex<double>> expected(slot_size, 0.0);

            int data_bound = 1 << 7;
            srand(seal_test_seed);

            for (int round = 0; round < 100; round++)
            {
                for (size_t i = 0; i < slot_size; i++)
                {
                    input[i] = static_cast<double>(rand() % data_bound);
                    expected[i] = input[i] * input[i];
                }

                vector<complex<double>> output(slot_size);
                const double delta = static_cast<double>(1ULL << 40);
                encoder.encode(input, context.first_parms_id(), delta, plain);

                encryptor.encrypt(plain, encrypted);

                // Check correctness of encryption
                ASSERT_TRUE(encrypted.parms_id() == context.first_parms_id());

                // Evaluator.square_inplace(encrypted);
                evaluator.multiply_inplace(encrypted, encrypted);
                evaluator.relinearize_inplace(encrypted, rlk);

                decryptor.decrypt(encrypted, plainRes);
                encoder.decode(plainRes, output);
                for (size_t i = 0; i < slot_size; i++)
                {
                    auto tmp = abs(expected[i].real() - output[i].real());
                    ASSERT_TRUE(tmp < 0.5);
                }
            }
        }
        {
            // Squaring two random vectors 100 times
            size_t slot_size = 16;
            parms.set_poly_modulus_degree(64);
            parms.set_coeff_modulus(CoeffModulus::Create(64, { 60, 30, 30, 30 }));

            SEALContext context(parms, false, sec_level_type::none);
            KeyGenerator keygen(context);
            PublicKey pk;
            keygen.create_public_key(pk);
            RelinKeys rlk;
            keygen.create_relin_keys(rlk);

            CKKSEncoder encoder(context);
            Encryptor encryptor(context, pk);
            Decryptor decryptor(context, keygen.secret_key());
            Evaluator evaluator(context);

            Ciphertext encrypted;
            Plaintext plain;
            Plaintext plainRes;

            vector<complex<double>> input(slot_size, 0.0);
            vector<complex<double>> expected(slot_size, 0.0);

            int data_bound = 1 << 7;
            srand(seal_test_seed);

            for (int round = 0; round < 100; round++)
            {
                for (size_t i = 0; i < slot_size; i++)
                {
                    input[i] = static_cast<double>(rand() % data_bound);
                    expected[i] = input[i] * input[i];
                }

                vector<complex<double>> output(slot_size);
                const double delta = static_cast<double>(1ULL << 40);
                encoder.encode(input, context.first_parms_id(), delta, plain);

                encryptor.encrypt(plain, encrypted);

                // Check correctness of encryption
                ASSERT_TRUE(encrypted.parms_id() == context.first_parms_id());

                // Evaluator.square_inplace(encrypted);
                evaluator.multiply_inplace(encrypted, encrypted);
                evaluator.relinearize_inplace(encrypted, rlk);

                decryptor.decrypt(encrypted, plainRes);
                encoder.decode(plainRes, output);
                for (size_t i = 0; i < slot_size; i++)
                {
                    auto tmp = abs(expected[i].real() - output[i].real());
                    ASSERT_TRUE(tmp < 0.5);
                }
            }
        }
    }

    TEST(EvaluatorTest, CKKSEncryptMultiplyRelinRescaleDecrypt)
    {
        EncryptionParameters parms(scheme_type::ckks);
        {
            // Multiplying two random vectors 100 times
            size_t slot_size = 64;
            parms.set_poly_modulus_degree(slot_size * 2);
            parms.set_coeff_modulus(CoeffModulus::Create(slot_size * 2, { 30, 30, 30, 30, 30, 30 }));

            SEALContext context(parms, true, sec_level_type::none);
            auto next_parms_id = context.first_context_data()->next_context_data()->parms_id();
            KeyGenerator keygen(context);
            PublicKey pk;
            keygen.create_public_key(pk);
            RelinKeys rlk;
            keygen.create_relin_keys(rlk);

            CKKSEncoder encoder(context);
            Encryptor encryptor(context, pk);
            Decryptor decryptor(context, keygen.secret_key());
            Evaluator evaluator(context);

            Ciphertext encrypted1;
            Ciphertext encrypted2;
            Ciphertext encryptedRes;
            Plaintext plain1;
            Plaintext plain2;
            Plaintext plainRes;

            vector<complex<double>> input1(slot_size, 0.0);
            vector<complex<double>> input2(slot_size, 0.0);
            vector<complex<double>> expected(slot_size, 0.0);

            for (int round = 0; round < 100; round++)
            {
                int data_bound = 1 << 7;
                srand(seal_test_seed);
                for (size_t i = 0; i < slot_size; i++)
                {
                    input1[i] = static_cast<double>(rand() % data_bound);
                    input2[i] = static_cast<double>(rand() % data_bound);
                    expected[i] = input1[i] * input2[i];
                }

                vector<complex<double>> output(slot_size);
                double delta = static_cast<double>(1ULL << 40);
                encoder.encode(input1, context.first_parms_id(), delta, plain1);
                encoder.encode(input2, context.first_parms_id(), delta, plain2);

                encryptor.encrypt(plain1, encrypted1);
                encryptor.encrypt(plain2, encrypted2);

                // Check correctness of encryption
                ASSERT_TRUE(encrypted1.parms_id() == context.first_parms_id());
                // Check correctness of encryption
                ASSERT_TRUE(encrypted2.parms_id() == context.first_parms_id());

                evaluator.multiply_inplace(encrypted1, encrypted2);
                evaluator.relinearize_inplace(encrypted1, rlk);
                evaluator.rescale_to_next_inplace(encrypted1);

                // Check correctness of modulus switching
                ASSERT_TRUE(encrypted1.parms_id() == next_parms_id);

                decryptor.decrypt(encrypted1, plainRes);
                encoder.decode(plainRes, output);
                for (size_t i = 0; i < slot_size; i++)
                {
                    auto tmp = abs(expected[i].real() - output[i].real());
                    ASSERT_TRUE(tmp < 0.5);
                }
            }
        }
        {
            // Multiplying two random vectors 100 times
            size_t slot_size = 16;
            parms.set_poly_modulus_degree(128);
            parms.set_coeff_modulus(CoeffModulus::Create(128, { 30, 30, 30, 30, 30 }));

            SEALContext context(parms, true, sec_level_type::none);
            auto next_parms_id = context.first_context_data()->next_context_data()->parms_id();
            KeyGenerator keygen(context);
            PublicKey pk;
            keygen.create_public_key(pk);
            RelinKeys rlk;
            keygen.create_relin_keys(rlk);

            CKKSEncoder encoder(context);
            Encryptor encryptor(context, pk);
            Decryptor decryptor(context, keygen.secret_key());
            Evaluator evaluator(context);

            Ciphertext encrypted1;
            Ciphertext encrypted2;
            Ciphertext encryptedRes;
            Plaintext plain1;
            Plaintext plain2;
            Plaintext plainRes;

            vector<complex<double>> input1(slot_size, 0.0);
            vector<complex<double>> input2(slot_size, 0.0);
            vector<complex<double>> expected(slot_size, 0.0);

            for (int round = 0; round < 100; round++)
            {
                int data_bound = 1 << 7;
                srand(seal_test_seed);
                for (size_t i = 0; i < slot_size; i++)
                {
                    input1[i] = static_cast<double>(rand() % data_bound);
                    input2[i] = static_cast<double>(rand() % data_bound);
                    expected[i] = input1[i] * input2[i];
                }

                vector<complex<double>> output(slot_size);
                double delta = static_cast<double>(1ULL << 40);
                encoder.encode(input1, context.first_parms_id(), delta, plain1);
                encoder.encode(input2, context.first_parms_id(), delta, plain2);

                encryptor.encrypt(plain1, encrypted1);
                encryptor.encrypt(plain2, encrypted2);

                // Check correctness of encryption
                ASSERT_TRUE(encrypted1.parms_id() == context.first_parms_id());
                // Check correctness of encryption
                ASSERT_TRUE(encrypted2.parms_id() == context.first_parms_id());

                evaluator.multiply_inplace(encrypted1, encrypted2);
                evaluator.relinearize_inplace(encrypted1, rlk);
                evaluator.rescale_to_next_inplace(encrypted1);

                // Check correctness of modulus switching
                ASSERT_TRUE(encrypted1.parms_id() == next_parms_id);

                decryptor.decrypt(encrypted1, plainRes);
                encoder.decode(plainRes, output);
                for (size_t i = 0; i < slot_size; i++)
                {
                    auto tmp = abs(expected[i].real() - output[i].real());
                    ASSERT_TRUE(tmp < 0.5);
                }
            }
        }
        {
            // Multiplying two random vectors 100 times
            size_t slot_size = 16;
            parms.set_poly_modulus_degree(128);
            parms.set_coeff_modulus(CoeffModulus::Create(128, { 60, 60, 60, 60, 60 }));

            SEALContext context(parms, true, sec_level_type::none);
            KeyGenerator keygen(context);
            PublicKey pk;
            keygen.create_public_key(pk);
            RelinKeys rlk;
            keygen.create_relin_keys(rlk);

            CKKSEncoder encoder(context);
            Encryptor encryptor(context, pk);
            Decryptor decryptor(context, keygen.secret_key());
            Evaluator evaluator(context);

            Ciphertext encrypted1;
            Ciphertext encrypted2;
            Ciphertext encryptedRes;
            Plaintext plain1;
            Plaintext plain2;
            Plaintext plainRes;

            vector<complex<double>> input1(slot_size, 0.0);
            vector<complex<double>> input2(slot_size, 0.0);
            vector<complex<double>> expected(slot_size, 0.0);

            for (int round = 0; round < 100; round++)
            {
                int data_bound = 1 << 7;
                srand(seal_test_seed);
                for (size_t i = 0; i < slot_size; i++)
                {
                    input1[i] = static_cast<double>(rand() % data_bound);
                    input2[i] = static_cast<double>(rand() % data_bound);
                    expected[i] = input1[i] * input2[i] * input2[i];
                }

                vector<complex<double>> output(slot_size);
                double delta = static_cast<double>(1ULL << 60);
                encoder.encode(input1, context.first_parms_id(), delta, plain1);
                encoder.encode(input2, context.first_parms_id(), delta, plain2);

                encryptor.encrypt(plain1, encrypted1);
                encryptor.encrypt(plain2, encrypted2);

                // Check correctness of encryption
                ASSERT_TRUE(encrypted1.parms_id() == context.first_parms_id());
                // Check correctness of encryption
                ASSERT_TRUE(encrypted2.parms_id() == context.first_parms_id());

                evaluator.multiply_inplace(encrypted1, encrypted2);
                evaluator.relinearize_inplace(encrypted1, rlk);
                evaluator.multiply_inplace(encrypted1, encrypted2);
                evaluator.relinearize_inplace(encrypted1, rlk);

                // Scale down by two levels
                auto target_parms = context.first_context_data()->next_context_data()->next_context_data()->parms_id();
                evaluator.rescale_to_inplace(encrypted1, target_parms);

                // Check correctness of modulus switching
                ASSERT_TRUE(encrypted1.parms_id() == target_parms);

                decryptor.decrypt(encrypted1, plainRes);
                encoder.decode(plainRes, output);
                for (size_t i = 0; i < slot_size; i++)
                {
                    auto tmp = abs(expected[i].real() - output[i].real());
                    ASSERT_TRUE(tmp < 0.5);
                }
            }

            // Test with inverted order: rescale then relin
            for (int round = 0; round < 100; round++)
            {
                int data_bound = 1 << 7;
                srand(seal_test_seed);
                for (size_t i = 0; i < slot_size; i++)
                {
                    input1[i] = static_cast<double>(rand() % data_bound);
                    input2[i] = static_cast<double>(rand() % data_bound);
                    expected[i] = input1[i] * input2[i] * input2[i];
                }

                vector<complex<double>> output(slot_size);
                double delta = static_cast<double>(1ULL << 50);
                encoder.encode(input1, context.first_parms_id(), delta, plain1);
                encoder.encode(input2, context.first_parms_id(), delta, plain2);

                encryptor.encrypt(plain1, encrypted1);
                encryptor.encrypt(plain2, encrypted2);

                // Check correctness of encryption
                ASSERT_TRUE(encrypted1.parms_id() == context.first_parms_id());
                // Check correctness of encryption
                ASSERT_TRUE(encrypted2.parms_id() == context.first_parms_id());

                evaluator.multiply_inplace(encrypted1, encrypted2);
                evaluator.relinearize_inplace(encrypted1, rlk);
                evaluator.multiply_inplace(encrypted1, encrypted2);

                // Scale down by two levels
                auto target_parms = context.first_context_data()->next_context_data()->next_context_data()->parms_id();
                evaluator.rescale_to_inplace(encrypted1, target_parms);

                // Relinearize now
                evaluator.relinearize_inplace(encrypted1, rlk);

                // Check correctness of modulus switching
                ASSERT_TRUE(encrypted1.parms_id() == target_parms);

                decryptor.decrypt(encrypted1, plainRes);
                encoder.decode(plainRes, output);
                for (size_t i = 0; i < slot_size; i++)
                {
                    auto tmp = abs(expected[i].real() - output[i].real());
                    ASSERT_TRUE(tmp < 0.5);
                }
            }
        }
    }

    TEST(EvaluatorTest, CKKSRescaleRejectsSubnormalScale)
    {
        EncryptionParameters parms(scheme_type::ckks);
        parms.set_poly_modulus_degree(8);
        parms.set_coeff_modulus(CoeffModulus::Create(8, { 40, 40, 40 }));
        SEALContext context(parms, true, sec_level_type::none);

        KeyGenerator keygen(context);
        PublicKey public_key;
        keygen.create_public_key(public_key);
        CKKSEncoder encoder(context);
        Encryptor encryptor(context, public_key);
        Evaluator evaluator(context);

        vector<double> values(encoder.slot_count(), 0.0);
        Plaintext plain;
        encoder.encode(values, context.first_parms_id(), (numeric_limits<double>::min)(), plain);

        Ciphertext encrypted;
        encryptor.encrypt(plain, encrypted);
        ASSERT_TRUE(isnormal(encrypted.scale()));
        ASSERT_THROW(evaluator.rescale_to_next_inplace(encrypted), invalid_argument);
    }

    TEST(EvaluatorTest, CKKSEncryptSquareRelinRescaleDecrypt)
    {
        EncryptionParameters parms(scheme_type::ckks);
        {
            // Squaring two random vectors 100 times
            size_t slot_size = 64;
            parms.set_poly_modulus_degree(slot_size * 2);
            parms.set_coeff_modulus(CoeffModulus::Create(slot_size * 2, { 50, 50, 50 }));

            SEALContext context(parms, true, sec_level_type::none);
            auto next_parms_id = context.first_context_data()->next_context_data()->parms_id();
            KeyGenerator keygen(context);
            PublicKey pk;
            keygen.create_public_key(pk);
            RelinKeys rlk;
            keygen.create_relin_keys(rlk);

            CKKSEncoder encoder(context);
            Encryptor encryptor(context, pk);
            Decryptor decryptor(context, keygen.secret_key());
            Evaluator evaluator(context);

            Ciphertext encrypted;
            Plaintext plain;
            Plaintext plainRes;

            vector<complex<double>> input(slot_size, 0.0);
            vector<complex<double>> output(slot_size);
            vector<complex<double>> expected(slot_size, 0.0);
            int data_bound = 1 << 8;

            for (int round = 0; round < 100; round++)
            {
                srand(seal_test_seed);
                for (size_t i = 0; i < slot_size; i++)
                {
                    input[i] = static_cast<double>(rand() % data_bound);
                    expected[i] = input[i] * input[i];
                }

                double delta = static_cast<double>(1ULL << 40);
                encoder.encode(input, context.first_parms_id(), delta, plain);

                encryptor.encrypt(plain, encrypted);

                // Check correctness of encryption
                ASSERT_TRUE(encrypted.parms_id() == context.first_parms_id());

                evaluator.square_inplace(encrypted);
                evaluator.relinearize_inplace(encrypted, rlk);
                evaluator.rescale_to_next_inplace(encrypted);

                // Check correctness of modulus switching
                ASSERT_TRUE(encrypted.parms_id() == next_parms_id);

                decryptor.decrypt(encrypted, plainRes);
                encoder.decode(plainRes, output);
                for (size_t i = 0; i < slot_size; i++)
                {
                    auto tmp = abs(expected[i].real() - output[i].real());
                    ASSERT_TRUE(tmp < 0.5);
                }
            }
        }
        {
            // Squaring two random vectors 100 times
            size_t slot_size = 16;
            parms.set_poly_modulus_degree(128);
            parms.set_coeff_modulus(CoeffModulus::Create(128, { 50, 50, 50 }));

            SEALContext context(parms, true, sec_level_type::none);
            auto next_parms_id = context.first_context_data()->next_context_data()->parms_id();
            KeyGenerator keygen(context);
            PublicKey pk;
            keygen.create_public_key(pk);
            RelinKeys rlk;
            keygen.create_relin_keys(rlk);

            CKKSEncoder encoder(context);
            Encryptor encryptor(context, pk);
            Decryptor decryptor(context, keygen.secret_key());
            Evaluator evaluator(context);

            Ciphertext encrypted;
            Plaintext plain;
            Plaintext plainRes;

            vector<complex<double>> input(slot_size, 0.0);
            vector<complex<double>> output(slot_size);
            vector<complex<double>> expected(slot_size, 0.0);
            int data_bound = 1 << 8;

            for (int round = 0; round < 100; round++)
            {
                srand(seal_test_seed);
                for (size_t i = 0; i < slot_size; i++)
                {
                    input[i] = static_cast<double>(rand() % data_bound);
                    expected[i] = input[i] * input[i];
                }

                double delta = static_cast<double>(1ULL << 40);
                encoder.encode(input, context.first_parms_id(), delta, plain);

                encryptor.encrypt(plain, encrypted);

                // Check correctness of encryption
                ASSERT_TRUE(encrypted.parms_id() == context.first_parms_id());

                evaluator.square_inplace(encrypted);
                evaluator.relinearize_inplace(encrypted, rlk);
                evaluator.rescale_to_next_inplace(encrypted);

                // Check correctness of modulus switching
                ASSERT_TRUE(encrypted.parms_id() == next_parms_id);

                decryptor.decrypt(encrypted, plainRes);
                encoder.decode(plainRes, output);
                for (size_t i = 0; i < slot_size; i++)
                {
                    auto tmp = abs(expected[i].real() - output[i].real());
                    ASSERT_TRUE(tmp < 0.5);
                }
            }
        }
    }

    TEST(EvaluatorTest, CKKSEncryptModSwitchDecrypt)
    {
        EncryptionParameters parms(scheme_type::ckks);
        {
            // Modulus switching without rescaling for random vectors
            size_t slot_size = 64;
            parms.set_poly_modulus_degree(slot_size * 2);
            parms.set_coeff_modulus(CoeffModulus::Create(slot_size * 2, { 60, 60, 60, 60, 60 }));

            SEALContext context(parms, true, sec_level_type::none);
            auto next_parms_id = context.first_context_data()->next_context_data()->parms_id();
            KeyGenerator keygen(context);
            PublicKey pk;
            keygen.create_public_key(pk);

            CKKSEncoder encoder(context);
            Encryptor encryptor(context, pk);
            Decryptor decryptor(context, keygen.secret_key());
            Evaluator evaluator(context);

            int data_bound = 1 << 30;
            srand(seal_test_seed);

            vector<complex<double>> input(slot_size, 0.0);
            vector<complex<double>> output(slot_size);

            Ciphertext encrypted;
            Plaintext plain;
            Plaintext plainRes;

            for (int round = 0; round < 100; round++)
            {
                for (size_t i = 0; i < slot_size; i++)
                {
                    input[i] = static_cast<double>(rand() % data_bound);
                }

                double delta = static_cast<double>(1ULL << 40);
                encoder.encode(input, context.first_parms_id(), delta, plain);

                encryptor.encrypt(plain, encrypted);

                // Check correctness of encryption
                ASSERT_TRUE(encrypted.parms_id() == context.first_parms_id());

                // Not inplace
                Ciphertext destination;
                evaluator.mod_switch_to_next(encrypted, destination);

                // Check correctness of modulus switching
                ASSERT_TRUE(destination.parms_id() == next_parms_id);

                decryptor.decrypt(destination, plainRes);
                encoder.decode(plainRes, output);

                for (size_t i = 0; i < slot_size; i++)
                {
                    auto tmp = abs(input[i].real() - output[i].real());
                    ASSERT_TRUE(tmp < 0.5);
                }

                // Inplace
                evaluator.mod_switch_to_next_inplace(encrypted);

                // Check correctness of modulus switching
                ASSERT_TRUE(encrypted.parms_id() == next_parms_id);

                decryptor.decrypt(encrypted, plainRes);
                encoder.decode(plainRes, output);
                for (size_t i = 0; i < slot_size; i++)
                {
                    auto tmp = abs(input[i].real() - output[i].real());
                    ASSERT_TRUE(tmp < 0.5);
                }
            }
        }
        {
            // Modulus switching without rescaling for random vectors
            size_t slot_size = 32;
            parms.set_poly_modulus_degree(slot_size * 2);
            parms.set_coeff_modulus(CoeffModulus::Create(slot_size * 2, { 40, 40, 40, 40, 40 }));

            SEALContext context(parms, true, sec_level_type::none);
            auto next_parms_id = context.first_context_data()->next_context_data()->parms_id();
            KeyGenerator keygen(context);
            PublicKey pk;
            keygen.create_public_key(pk);

            CKKSEncoder encoder(context);
            Encryptor encryptor(context, pk);
            Decryptor decryptor(context, keygen.secret_key());
            Evaluator evaluator(context);

            int data_bound = 1 << 30;
            srand(seal_test_seed);

            vector<complex<double>> input(slot_size, 0.0);
            vector<complex<double>> output(slot_size);

            Ciphertext encrypted;
            Plaintext plain;
            Plaintext plainRes;

            for (int round = 0; round < 100; round++)
            {
                for (size_t i = 0; i < slot_size; i++)
                {
                    input[i] = static_cast<double>(rand() % data_bound);
                }

                double delta = static_cast<double>(1ULL << 40);
                encoder.encode(input, context.first_parms_id(), delta, plain);

                encryptor.encrypt(plain, encrypted);

                // Check correctness of encryption
                ASSERT_TRUE(encrypted.parms_id() == context.first_parms_id());

                // Not inplace
                Ciphertext destination;
                evaluator.mod_switch_to_next(encrypted, destination);

                // Check correctness of modulus switching
                ASSERT_TRUE(destination.parms_id() == next_parms_id);

                decryptor.decrypt(destination, plainRes);
                encoder.decode(plainRes, output);

                for (size_t i = 0; i < slot_size; i++)
                {
                    auto tmp = abs(input[i].real() - output[i].real());
                    ASSERT_TRUE(tmp < 0.5);
                }

                // Inplace
                evaluator.mod_switch_to_next_inplace(encrypted);

                // Check correctness of modulus switching
                ASSERT_TRUE(encrypted.parms_id() == next_parms_id);

                decryptor.decrypt(encrypted, plainRes);
                encoder.decode(plainRes, output);
                for (size_t i = 0; i < slot_size; i++)
                {
                    auto tmp = abs(input[i].real() - output[i].real());
                    ASSERT_TRUE(tmp < 0.5);
                }
            }
        }
        {
            // Modulus switching without rescaling for random vectors
            size_t slot_size = 32;
            parms.set_poly_modulus_degree(128);
            parms.set_coeff_modulus(CoeffModulus::Create(128, { 40, 40, 40, 40, 40 }));

            SEALContext context(parms, true, sec_level_type::none);
            auto next_parms_id = context.first_context_data()->next_context_data()->parms_id();
            KeyGenerator keygen(context);
            PublicKey pk;
            keygen.create_public_key(pk);

            CKKSEncoder encoder(context);
            Encryptor encryptor(context, pk);
            Decryptor decryptor(context, keygen.secret_key());
            Evaluator evaluator(context);

            int data_bound = 1 << 30;
            srand(seal_test_seed);

            vector<complex<double>> input(slot_size, 0.0);
            vector<complex<double>> output(slot_size);

            Ciphertext encrypted;
            Plaintext plain;
            Plaintext plainRes;

            for (int round = 0; round < 100; round++)
            {
                for (size_t i = 0; i < slot_size; i++)
                {
                    input[i] = static_cast<double>(rand() % data_bound);
                }

                double delta = static_cast<double>(1ULL << 40);
                encoder.encode(input, context.first_parms_id(), delta, plain);

                encryptor.encrypt(plain, encrypted);

                // Check correctness of encryption
                ASSERT_TRUE(encrypted.parms_id() == context.first_parms_id());

                // Not inplace
                Ciphertext destination;
                evaluator.mod_switch_to_next(encrypted, destination);

                // Check correctness of modulus switching
                ASSERT_TRUE(destination.parms_id() == next_parms_id);

                decryptor.decrypt(destination, plainRes);
                encoder.decode(plainRes, output);

                for (size_t i = 0; i < slot_size; i++)
                {
                    auto tmp = abs(input[i].real() - output[i].real());
                    ASSERT_TRUE(tmp < 0.5);
                }

                // Inplace
                evaluator.mod_switch_to_next_inplace(encrypted);

                // Check correctness of modulus switching
                ASSERT_TRUE(encrypted.parms_id() == next_parms_id);

                decryptor.decrypt(encrypted, plainRes);
                encoder.decode(plainRes, output);
                for (size_t i = 0; i < slot_size; i++)
                {
                    auto tmp = abs(input[i].real() - output[i].real());
                    ASSERT_TRUE(tmp < 0.5);
                }
            }
        }
    }

    TEST(EvaluatorTest, CKKSEncryptMultiplyRelinRescaleModSwitchAddDecrypt)
    {
        EncryptionParameters parms(scheme_type::ckks);
        {
            // Multiplication and addition without rescaling for random vectors
            size_t slot_size = 64;
            parms.set_poly_modulus_degree(slot_size * 2);
            parms.set_coeff_modulus(CoeffModulus::Create(slot_size * 2, { 50, 50, 50 }));

            SEALContext context(parms, true, sec_level_type::none);
            auto next_parms_id = context.first_context_data()->next_context_data()->parms_id();
            KeyGenerator keygen(context);
            PublicKey pk;
            keygen.create_public_key(pk);
            RelinKeys rlk;
            keygen.create_relin_keys(rlk);

            CKKSEncoder encoder(context);
            Encryptor encryptor(context, pk);
            Decryptor decryptor(context, keygen.secret_key());
            Evaluator evaluator(context);

            Ciphertext encrypted1;
            Ciphertext encrypted2;
            Ciphertext encrypted3;
            Plaintext plain1;
            Plaintext plain2;
            Plaintext plain3;
            Plaintext plainRes;

            vector<complex<double>> input1(slot_size, 0.0);
            vector<complex<double>> input2(slot_size, 0.0);
            vector<complex<double>> input3(slot_size, 0.0);
            vector<complex<double>> expected(slot_size, 0.0);

            for (int round = 0; round < 100; round++)
            {
                int data_bound = 1 << 8;
                srand(seal_test_seed);
                for (size_t i = 0; i < slot_size; i++)
                {
                    input1[i] = static_cast<double>(rand() % data_bound);
                    input2[i] = static_cast<double>(rand() % data_bound);
                    expected[i] = input1[i] * input2[i] + input3[i];
                }

                vector<complex<double>> output(slot_size);
                double delta = static_cast<double>(1ULL << 40);
                encoder.encode(input1, context.first_parms_id(), delta, plain1);
                encoder.encode(input2, context.first_parms_id(), delta, plain2);
                encoder.encode(input3, context.first_parms_id(), delta * delta, plain3);

                encryptor.encrypt(plain1, encrypted1);
                encryptor.encrypt(plain2, encrypted2);
                encryptor.encrypt(plain3, encrypted3);

                // Check correctness of encryption
                ASSERT_TRUE(encrypted1.parms_id() == context.first_parms_id());
                // Check correctness of encryption
                ASSERT_TRUE(encrypted2.parms_id() == context.first_parms_id());
                // Check correctness of encryption
                ASSERT_TRUE(encrypted3.parms_id() == context.first_parms_id());

                // Enc1*enc2
                evaluator.multiply_inplace(encrypted1, encrypted2);
                evaluator.relinearize_inplace(encrypted1, rlk);
                evaluator.rescale_to_next_inplace(encrypted1);

                // Check correctness of modulus switching with rescaling
                ASSERT_TRUE(encrypted1.parms_id() == next_parms_id);

                // Move enc3 to the level of enc1 * enc2
                evaluator.rescale_to_inplace(encrypted3, next_parms_id);

                // Enc1*enc2 + enc3
                evaluator.add_inplace(encrypted1, encrypted3);

                decryptor.decrypt(encrypted1, plainRes);
                encoder.decode(plainRes, output);
                for (size_t i = 0; i < slot_size; i++)
                {
                    auto tmp = abs(expected[i].real() - output[i].real());
                    ASSERT_TRUE(tmp < 0.5);
                }
            }
        }
        {
            // Multiplication and addition without rescaling for random vectors
            size_t slot_size = 16;
            parms.set_poly_modulus_degree(128);
            parms.set_coeff_modulus(CoeffModulus::Create(128, { 50, 50, 50 }));

            SEALContext context(parms, true, sec_level_type::none);
            auto next_parms_id = context.first_context_data()->next_context_data()->parms_id();
            KeyGenerator keygen(context);
            PublicKey pk;
            keygen.create_public_key(pk);
            RelinKeys rlk;
            keygen.create_relin_keys(rlk);

            CKKSEncoder encoder(context);
            Encryptor encryptor(context, pk);
            Decryptor decryptor(context, keygen.secret_key());
            Evaluator evaluator(context);

            Ciphertext encrypted1;
            Ciphertext encrypted2;
            Ciphertext encrypted3;
            Plaintext plain1;
            Plaintext plain2;
            Plaintext plain3;
            Plaintext plainRes;

            vector<complex<double>> input1(slot_size, 0.0);
            vector<complex<double>> input2(slot_size, 0.0);
            vector<complex<double>> input3(slot_size, 0.0);
            vector<complex<double>> expected(slot_size, 0.0);
            vector<complex<double>> output(slot_size);

            for (int round = 0; round < 100; round++)
            {
                int data_bound = 1 << 8;
                srand(seal_test_seed);
                for (size_t i = 0; i < slot_size; i++)
                {
                    input1[i] = static_cast<double>(rand() % data_bound);
                    input2[i] = static_cast<double>(rand() % data_bound);
                    expected[i] = input1[i] * input2[i] + input3[i];
                }

                double delta = static_cast<double>(1ULL << 40);
                encoder.encode(input1, context.first_parms_id(), delta, plain1);
                encoder.encode(input2, context.first_parms_id(), delta, plain2);
                encoder.encode(input3, context.first_parms_id(), delta * delta, plain3);

                encryptor.encrypt(plain1, encrypted1);
                encryptor.encrypt(plain2, encrypted2);
                encryptor.encrypt(plain3, encrypted3);

                // Check correctness of encryption
                ASSERT_TRUE(encrypted1.parms_id() == context.first_parms_id());
                // Check correctness of encryption
                ASSERT_TRUE(encrypted2.parms_id() == context.first_parms_id());
                // Check correctness of encryption
                ASSERT_TRUE(encrypted3.parms_id() == context.first_parms_id());

                // Enc1*enc2
                evaluator.multiply_inplace(encrypted1, encrypted2);
                evaluator.relinearize_inplace(encrypted1, rlk);
                evaluator.rescale_to_next_inplace(encrypted1);

                // Check correctness of modulus switching with rescaling
                ASSERT_TRUE(encrypted1.parms_id() == next_parms_id);

                // Move enc3 to the level of enc1 * enc2
                evaluator.rescale_to_inplace(encrypted3, next_parms_id);

                // Enc1*enc2 + enc3
                evaluator.add_inplace(encrypted1, encrypted3);

                decryptor.decrypt(encrypted1, plainRes);
                encoder.decode(plainRes, output);
                for (size_t i = 0; i < slot_size; i++)
                {
                    auto tmp = abs(expected[i].real() - output[i].real());
                    ASSERT_TRUE(tmp < 0.5);
                }
            }
        }
    }

    TEST(EvaluatorTest, CKKSEncryptRotateDecrypt)
    {
        EncryptionParameters parms(scheme_type::ckks);
        {
            // Maximal number of slots
            size_t slot_size = 4;
            parms.set_poly_modulus_degree(slot_size * 2);
            parms.set_coeff_modulus(CoeffModulus::Create(slot_size * 2, { 40, 40, 40, 40 }));

            SEALContext context(parms, false, sec_level_type::none);
            KeyGenerator keygen(context);
            PublicKey pk;
            keygen.create_public_key(pk);
            GaloisKeys glk;
            keygen.create_galois_keys(glk);

            Encryptor encryptor(context, pk);
            Evaluator evaluator(context);
            Decryptor decryptor(context, keygen.secret_key());
            CKKSEncoder encoder(context);
            const double delta = static_cast<double>(1ULL << 30);

            Ciphertext encrypted;
            Plaintext plain;

            vector<complex<double>> input{ complex<double>(1, 1), complex<double>(2, 2), complex<double>(3, 3),
                                           complex<double>(4, 4) };
            input.resize(slot_size);

            vector<complex<double>> output(slot_size, 0);

            encoder.encode(input, context.first_parms_id(), delta, plain);
            int shift = 1;
            encryptor.encrypt(plain, encrypted);
            evaluator.rotate_vector_inplace(encrypted, shift, glk);
            decryptor.decrypt(encrypted, plain);
            encoder.decode(plain, output);
            for (size_t i = 0; i < slot_size; i++)
            {
                ASSERT_EQ(input[(i + static_cast<size_t>(shift)) % slot_size].real(), round(output[i].real()));
                ASSERT_EQ(input[(i + static_cast<size_t>(shift)) % slot_size].imag(), round(output[i].imag()));
            }

            encoder.encode(input, context.first_parms_id(), delta, plain);
            shift = 2;
            encryptor.encrypt(plain, encrypted);
            evaluator.rotate_vector_inplace(encrypted, shift, glk);
            decryptor.decrypt(encrypted, plain);
            encoder.decode(plain, output);
            for (size_t i = 0; i < slot_size; i++)
            {
                ASSERT_EQ(input[(i + static_cast<size_t>(shift)) % slot_size].real(), round(output[i].real()));
                ASSERT_EQ(input[(i + static_cast<size_t>(shift)) % slot_size].imag(), round(output[i].imag()));
            }

            encoder.encode(input, context.first_parms_id(), delta, plain);
            shift = 3;
            encryptor.encrypt(plain, encrypted);
            evaluator.rotate_vector_inplace(encrypted, shift, glk);
            decryptor.decrypt(encrypted, plain);
            encoder.decode(plain, output);
            for (size_t i = 0; i < slot_size; i++)
            {
                ASSERT_EQ(input[(i + static_cast<size_t>(shift)) % slot_size].real(), round(output[i].real()));
                ASSERT_EQ(input[(i + static_cast<size_t>(shift)) % slot_size].imag(), round(output[i].imag()));
            }

            encoder.encode(input, context.first_parms_id(), delta, plain);
            encryptor.encrypt(plain, encrypted);
            evaluator.complex_conjugate_inplace(encrypted, glk);
            decryptor.decrypt(encrypted, plain);
            encoder.decode(plain, output);
            for (size_t i = 0; i < slot_size; i++)
            {
                ASSERT_EQ(input[i].real(), round(output[i].real()));
                ASSERT_EQ(-input[i].imag(), round(output[i].imag()));
            }
        }
        {
            size_t slot_size = 32;
            parms.set_poly_modulus_degree(64);
            parms.set_coeff_modulus(CoeffModulus::Create(64, { 40, 40, 40, 40 }));

            SEALContext context(parms, false, sec_level_type::none);
            KeyGenerator keygen(context);
            PublicKey pk;
            keygen.create_public_key(pk);
            GaloisKeys glk;
            keygen.create_galois_keys(glk);

            Encryptor encryptor(context, pk);
            Evaluator evaluator(context);
            Decryptor decryptor(context, keygen.secret_key());
            CKKSEncoder encoder(context);
            const double delta = static_cast<double>(1ULL << 30);

            Ciphertext encrypted;
            Plaintext plain;

            vector<complex<double>> input{ complex<double>(1, 1), complex<double>(2, 2), complex<double>(3, 3),
                                           complex<double>(4, 4) };
            input.resize(slot_size);

            vector<complex<double>> output(slot_size, 0);

            encoder.encode(input, context.first_parms_id(), delta, plain);
            int shift = 1;
            encryptor.encrypt(plain, encrypted);
            evaluator.rotate_vector_inplace(encrypted, shift, glk);
            decryptor.decrypt(encrypted, plain);
            encoder.decode(plain, output);
            for (size_t i = 0; i < input.size(); i++)
            {
                ASSERT_EQ(round(input[(i + static_cast<size_t>(shift)) % slot_size].real()), round(output[i].real()));
                ASSERT_EQ(round(input[(i + static_cast<size_t>(shift)) % slot_size].imag()), round(output[i].imag()));
            }

            encoder.encode(input, context.first_parms_id(), delta, plain);
            shift = 2;
            encryptor.encrypt(plain, encrypted);
            evaluator.rotate_vector_inplace(encrypted, shift, glk);
            decryptor.decrypt(encrypted, plain);
            encoder.decode(plain, output);
            for (size_t i = 0; i < slot_size; i++)
            {
                ASSERT_EQ(round(input[(i + static_cast<size_t>(shift)) % slot_size].real()), round(output[i].real()));
                ASSERT_EQ(round(input[(i + static_cast<size_t>(shift)) % slot_size].imag()), round(output[i].imag()));
            }

            encoder.encode(input, context.first_parms_id(), delta, plain);
            shift = 3;
            encryptor.encrypt(plain, encrypted);
            evaluator.rotate_vector_inplace(encrypted, shift, glk);
            decryptor.decrypt(encrypted, plain);
            encoder.decode(plain, output);
            for (size_t i = 0; i < slot_size; i++)
            {
                ASSERT_EQ(round(input[(i + static_cast<size_t>(shift)) % slot_size].real()), round(output[i].real()));
                ASSERT_EQ(round(input[(i + static_cast<size_t>(shift)) % slot_size].imag()), round(output[i].imag()));
            }

            encoder.encode(input, context.first_parms_id(), delta, plain);
            encryptor.encrypt(plain, encrypted);
            evaluator.complex_conjugate_inplace(encrypted, glk);
            decryptor.decrypt(encrypted, plain);
            encoder.decode(plain, output);
            for (size_t i = 0; i < slot_size; i++)
            {
                ASSERT_EQ(round(input[i].real()), round(output[i].real()));
                ASSERT_EQ(round(-input[i].imag()), round(output[i].imag()));
            }
        }
    }

    TEST(EvaluatorTest, CKKSEncryptRescaleRotateDecrypt)
    {
        EncryptionParameters parms(scheme_type::ckks);
        {
            // Maximal number of slots
            size_t slot_size = 4;
            parms.set_poly_modulus_degree(slot_size * 2);
            parms.set_coeff_modulus(CoeffModulus::Create(slot_size * 2, { 40, 40, 40, 40 }));

            SEALContext context(parms, true, sec_level_type::none);
            KeyGenerator keygen(context);
            PublicKey pk;
            keygen.create_public_key(pk);
            GaloisKeys glk;
            keygen.create_galois_keys(glk);

            Encryptor encryptor(context, pk);
            Evaluator evaluator(context);
            Decryptor decryptor(context, keygen.secret_key());
            CKKSEncoder encoder(context);
            const double delta = pow(2.0, 70);

            Ciphertext encrypted;
            Plaintext plain;

            vector<complex<double>> input{ complex<double>(1, 1), complex<double>(2, 2), complex<double>(3, 3),
                                           complex<double>(4, 4) };
            input.resize(slot_size);

            vector<complex<double>> output(slot_size, 0);

            encoder.encode(input, context.first_parms_id(), delta, plain);
            int shift = 1;
            encryptor.encrypt(plain, encrypted);
            evaluator.rescale_to_next_inplace(encrypted);
            evaluator.rotate_vector_inplace(encrypted, shift, glk);
            decryptor.decrypt(encrypted, plain);
            encoder.decode(plain, output);
            for (size_t i = 0; i < slot_size; i++)
            {
                ASSERT_EQ(input[(i + static_cast<size_t>(shift)) % slot_size].real(), round(output[i].real()));
                ASSERT_EQ(input[(i + static_cast<size_t>(shift)) % slot_size].imag(), round(output[i].imag()));
            }

            encoder.encode(input, context.first_parms_id(), delta, plain);
            shift = 2;
            encryptor.encrypt(plain, encrypted);
            evaluator.rescale_to_next_inplace(encrypted);
            evaluator.rotate_vector_inplace(encrypted, shift, glk);
            decryptor.decrypt(encrypted, plain);
            encoder.decode(plain, output);
            for (size_t i = 0; i < slot_size; i++)
            {
                ASSERT_EQ(input[(i + static_cast<size_t>(shift)) % slot_size].real(), round(output[i].real()));
                ASSERT_EQ(input[(i + static_cast<size_t>(shift)) % slot_size].imag(), round(output[i].imag()));
            }

            encoder.encode(input, context.first_parms_id(), delta, plain);
            shift = 3;
            encryptor.encrypt(plain, encrypted);
            evaluator.rescale_to_next_inplace(encrypted);
            evaluator.rotate_vector_inplace(encrypted, shift, glk);
            decryptor.decrypt(encrypted, plain);
            encoder.decode(plain, output);
            for (size_t i = 0; i < slot_size; i++)
            {
                ASSERT_EQ(input[(i + static_cast<size_t>(shift)) % slot_size].real(), round(output[i].real()));
                ASSERT_EQ(input[(i + static_cast<size_t>(shift)) % slot_size].imag(), round(output[i].imag()));
            }

            encoder.encode(input, context.first_parms_id(), delta, plain);
            encryptor.encrypt(plain, encrypted);
            evaluator.rescale_to_next_inplace(encrypted);
            evaluator.complex_conjugate_inplace(encrypted, glk);
            decryptor.decrypt(encrypted, plain);
            encoder.decode(plain, output);
            for (size_t i = 0; i < slot_size; i++)
            {
                ASSERT_EQ(input[i].real(), round(output[i].real()));
                ASSERT_EQ(-input[i].imag(), round(output[i].imag()));
            }
        }
        {
            size_t slot_size = 32;
            parms.set_poly_modulus_degree(64);
            parms.set_coeff_modulus(CoeffModulus::Create(64, { 40, 40, 40, 40 }));

            SEALContext context(parms, true, sec_level_type::none);
            KeyGenerator keygen(context);
            PublicKey pk;
            keygen.create_public_key(pk);
            GaloisKeys glk;
            keygen.create_galois_keys(glk);

            Encryptor encryptor(context, pk);
            Evaluator evaluator(context);
            Decryptor decryptor(context, keygen.secret_key());
            CKKSEncoder encoder(context);
            const double delta = pow(2, 70);

            Ciphertext encrypted;
            Plaintext plain;

            vector<complex<double>> input{ complex<double>(1, 1), complex<double>(2, 2), complex<double>(3, 3),
                                           complex<double>(4, 4) };
            input.resize(slot_size);

            vector<complex<double>> output(slot_size, 0);

            encoder.encode(input, context.first_parms_id(), delta, plain);
            int shift = 1;
            encryptor.encrypt(plain, encrypted);
            evaluator.rescale_to_next_inplace(encrypted);
            evaluator.rotate_vector_inplace(encrypted, shift, glk);
            decryptor.decrypt(encrypted, plain);
            encoder.decode(plain, output);
            for (size_t i = 0; i < slot_size; i++)
            {
                ASSERT_EQ(round(input[(i + static_cast<size_t>(shift)) % slot_size].real()), round(output[i].real()));
                ASSERT_EQ(round(input[(i + static_cast<size_t>(shift)) % slot_size].imag()), round(output[i].imag()));
            }

            encoder.encode(input, context.first_parms_id(), delta, plain);
            shift = 2;
            encryptor.encrypt(plain, encrypted);
            evaluator.rescale_to_next_inplace(encrypted);
            evaluator.rotate_vector_inplace(encrypted, shift, glk);
            decryptor.decrypt(encrypted, plain);
            encoder.decode(plain, output);
            for (size_t i = 0; i < slot_size; i++)
            {
                ASSERT_EQ(round(input[(i + static_cast<size_t>(shift)) % slot_size].real()), round(output[i].real()));
                ASSERT_EQ(round(input[(i + static_cast<size_t>(shift)) % slot_size].imag()), round(output[i].imag()));
            }

            encoder.encode(input, context.first_parms_id(), delta, plain);
            shift = 3;
            encryptor.encrypt(plain, encrypted);
            evaluator.rescale_to_next_inplace(encrypted);
            evaluator.rotate_vector_inplace(encrypted, shift, glk);
            decryptor.decrypt(encrypted, plain);
            encoder.decode(plain, output);
            for (size_t i = 0; i < slot_size; i++)
            {
                ASSERT_EQ(round(input[(i + static_cast<size_t>(shift)) % slot_size].real()), round(output[i].real()));
                ASSERT_EQ(round(input[(i + static_cast<size_t>(shift)) % slot_size].imag()), round(output[i].imag()));
            }

            encoder.encode(input, context.first_parms_id(), delta, plain);
            encryptor.encrypt(plain, encrypted);
            evaluator.rescale_to_next_inplace(encrypted);
            evaluator.complex_conjugate_inplace(encrypted, glk);
            decryptor.decrypt(encrypted, plain);
            encoder.decode(plain, output);
            for (size_t i = 0; i < slot_size; i++)
            {
                ASSERT_EQ(round(input[i].real()), round(output[i].real()));
                ASSERT_EQ(round(-input[i].imag()), round(output[i].imag()));
            }
        }
    }

    TEST(EvaluatorTest, BFVEncryptSquareDecrypt)
    {
        EncryptionParameters parms(scheme_type::bfv);
        Modulus plain_modulus(1 << 8);
        parms.set_poly_modulus_degree(128);
        parms.set_plain_modulus(plain_modulus);
        parms.set_coeff_modulus(CoeffModulus::Create(128, { 40, 40, 40 }));

        SEALContext context(parms, false, sec_level_type::none);
        KeyGenerator keygen(context);
        PublicKey pk;
        keygen.create_public_key(pk);

        Encryptor encryptor(context, pk);
        Evaluator evaluator(context);
        Decryptor decryptor(context, keygen.secret_key());

        Ciphertext encrypted;
        Plaintext plain;

        plain = "1";
        encryptor.encrypt(plain, encrypted);
        evaluator.square_inplace(encrypted);
        decryptor.decrypt(encrypted, plain);
        ASSERT_EQ(plain.to_string(), "1");
        ASSERT_TRUE(encrypted.parms_id() == context.first_parms_id());

        plain = "0";
        encryptor.encrypt(plain, encrypted);
        evaluator.square_inplace(encrypted);
        decryptor.decrypt(encrypted, plain);
        ASSERT_EQ(plain.to_string(), "0");
        ASSERT_TRUE(encrypted.parms_id() == context.first_parms_id());

        plain = "FFx^2 + FF";
        encryptor.encrypt(plain, encrypted);
        evaluator.square_inplace(encrypted);
        decryptor.decrypt(encrypted, plain);
        ASSERT_EQ(plain.to_string(), "1x^4 + 2x^2 + 1");
        ASSERT_TRUE(encrypted.parms_id() == context.first_parms_id());

        plain = "FF";
        encryptor.encrypt(plain, encrypted);
        evaluator.square_inplace(encrypted);
        decryptor.decrypt(encrypted, plain);
        ASSERT_EQ(plain.to_string(), "1");
        ASSERT_TRUE(encrypted.parms_id() == context.first_parms_id());

        plain = "1x^6 + 1x^5 + 1x^4 + 1x^3 + 1x^1 + 1";
        encryptor.encrypt(plain, encrypted);
        evaluator.square_inplace(encrypted);
        decryptor.decrypt(encrypted, plain);
        ASSERT_EQ(
            plain.to_string(),
            "1x^12 + 2x^11 + 3x^10 + 4x^9 + 3x^8 + 4x^7 + 5x^6 + 4x^5 + 4x^4 + 2x^3 + 1x^2 + 2x^1 + 1");
        ASSERT_TRUE(encrypted.parms_id() == context.first_parms_id());

        plain = "1x^16";
        encryptor.encrypt(plain, encrypted);
        evaluator.square_inplace(encrypted);
        decryptor.decrypt(encrypted, plain);
        ASSERT_EQ(plain.to_string(), "1x^32");
        ASSERT_TRUE(encrypted.parms_id() == context.first_parms_id());

        plain = "1x^6 + 1x^5 + 1x^4 + 1x^3 + 1x^1 + 1";
        encryptor.encrypt(plain, encrypted);
        evaluator.square_inplace(encrypted);
        evaluator.square_inplace(encrypted);
        decryptor.decrypt(encrypted, plain);
        ASSERT_EQ(
            plain.to_string(),
            "1x^24 + 4x^23 + Ax^22 + 14x^21 + 1Fx^20 + 2Cx^19 + 3Cx^18 + 4Cx^17 + 5Fx^16 + 6Cx^15 + 70x^14 + 74x^13 + "
            "71x^12 + 6Cx^11 + 64x^10 + 50x^9 + 40x^8 + 34x^7 + 26x^6 + 1Cx^5 + 11x^4 + 8x^3 + 6x^2 + 4x^1 + 1");
        ASSERT_TRUE(encrypted.parms_id() == context.first_parms_id());
    }

    TEST(EvaluatorTest, BFVEncryptMultiplyManyDecrypt)
    {
        EncryptionParameters parms(scheme_type::bfv);
        Modulus plain_modulus(1 << 6);
        parms.set_poly_modulus_degree(128);
        parms.set_plain_modulus(plain_modulus);
        parms.set_coeff_modulus(CoeffModulus::Create(128, { 40, 40, 40 }));

        SEALContext context(parms, false, sec_level_type::none);
        KeyGenerator keygen(context);
        PublicKey pk;
        keygen.create_public_key(pk);
        RelinKeys rlk;
        keygen.create_relin_keys(rlk);

        Encryptor encryptor(context, pk);
        Evaluator evaluator(context);
        Decryptor decryptor(context, keygen.secret_key());

        Ciphertext encrypted1, encrypted2, encrypted3, encrypted4, product;
        Plaintext plain, plain1, plain2, plain3, plain4;

        plain1 = "1x^2 + 1";
        plain2 = "1x^2 + 1x^1";
        plain3 = "1x^2 + 1x^1 + 1";
        encryptor.encrypt(plain1, encrypted1);
        encryptor.encrypt(plain2, encrypted2);
        encryptor.encrypt(plain3, encrypted3);
        vector<Ciphertext> encrypteds{ encrypted1, encrypted2, encrypted3 };
        evaluator.multiply_many(encrypteds, rlk, product);
        ASSERT_EQ(3, encrypteds.size());
        decryptor.decrypt(product, plain);
        ASSERT_EQ(plain.to_string(), "1x^6 + 2x^5 + 3x^4 + 3x^3 + 2x^2 + 1x^1");
        ASSERT_TRUE(encrypted1.parms_id() == product.parms_id());
        ASSERT_TRUE(encrypted2.parms_id() == product.parms_id());
        ASSERT_TRUE(encrypted3.parms_id() == product.parms_id());
        ASSERT_TRUE(product.parms_id() == context.first_parms_id());

        plain1 = "3Fx^3 + 3F";
        plain2 = "3Fx^4 + 3F";
        encryptor.encrypt(plain1, encrypted1);
        encryptor.encrypt(plain2, encrypted2);
        encrypteds = { encrypted1, encrypted2 };
        evaluator.multiply_many(encrypteds, rlk, product);
        ASSERT_EQ(2, encrypteds.size());
        decryptor.decrypt(product, plain);
        ASSERT_EQ(plain.to_string(), "1x^7 + 1x^4 + 1x^3 + 1");
        ASSERT_TRUE(encrypted1.parms_id() == product.parms_id());
        ASSERT_TRUE(encrypted2.parms_id() == product.parms_id());
        ASSERT_TRUE(product.parms_id() == context.first_parms_id());

        plain1 = "1x^1";
        plain2 = "3Fx^4 + 3Fx^3 + 3Fx^2 + 3Fx^1 + 3F";
        plain3 = "1x^2 + 1x^1 + 1";
        encryptor.encrypt(plain1, encrypted1);
        encryptor.encrypt(plain2, encrypted2);
        encryptor.encrypt(plain3, encrypted3);
        encrypteds = { encrypted1, encrypted2, encrypted3 };
        evaluator.multiply_many(encrypteds, rlk, product);
        ASSERT_EQ(3, encrypteds.size());
        decryptor.decrypt(product, plain);
        ASSERT_EQ(plain.to_string(), "3Fx^7 + 3Ex^6 + 3Dx^5 + 3Dx^4 + 3Dx^3 + 3Ex^2 + 3Fx^1");
        ASSERT_TRUE(encrypted1.parms_id() == product.parms_id());
        ASSERT_TRUE(encrypted2.parms_id() == product.parms_id());
        ASSERT_TRUE(encrypted3.parms_id() == product.parms_id());
        ASSERT_TRUE(product.parms_id() == context.first_parms_id());

        plain1 = "1";
        plain2 = "3F";
        plain3 = "1";
        plain4 = "3F";
        encryptor.encrypt(plain1, encrypted1);
        encryptor.encrypt(plain2, encrypted2);
        encryptor.encrypt(plain3, encrypted3);
        encryptor.encrypt(plain4, encrypted4);
        encrypteds = { encrypted1, encrypted2, encrypted3, encrypted4 };
        evaluator.multiply_many(encrypteds, rlk, product);
        ASSERT_EQ(4, encrypteds.size());
        decryptor.decrypt(product, plain);
        ASSERT_EQ(plain.to_string(), "1");
        ASSERT_TRUE(encrypted1.parms_id() == product.parms_id());
        ASSERT_TRUE(encrypted2.parms_id() == product.parms_id());
        ASSERT_TRUE(encrypted3.parms_id() == product.parms_id());
        ASSERT_TRUE(encrypted4.parms_id() == product.parms_id());
        ASSERT_TRUE(product.parms_id() == context.first_parms_id());

        plain1 = "1x^16 + 1x^15 + 1x^8 + 1x^7 + 1x^6 + 1x^3 + 1x^2 + 1";
        plain2 = "0";
        plain3 = "1x^13 + 1x^12 + 1x^5 + 1x^4 + 1x^3 + 1";
        plain4 = "1x^15 + 1x^10 + 1x^9 + 1x^8 + 1x^2 + 1x^1 + 1";
        encryptor.encrypt(plain1, encrypted1);
        encryptor.encrypt(plain2, encrypted2);
        encryptor.encrypt(plain3, encrypted3);
        encryptor.encrypt(plain4, encrypted4);
        encrypteds = { encrypted1, encrypted2, encrypted3, encrypted4 };
        evaluator.multiply_many(encrypteds, rlk, product);
        ASSERT_EQ(4, encrypteds.size());
        decryptor.decrypt(product, plain);
        ASSERT_EQ(plain.to_string(), "0");
        ASSERT_TRUE(encrypted1.parms_id() == product.parms_id());
        ASSERT_TRUE(encrypted2.parms_id() == product.parms_id());
        ASSERT_TRUE(encrypted3.parms_id() == product.parms_id());
        ASSERT_TRUE(encrypted4.parms_id() == product.parms_id());
        ASSERT_TRUE(product.parms_id() == context.first_parms_id());
    }

    TEST(EvaluatorTest, BFVEncryptExponentiateDecrypt)
    {
        EncryptionParameters parms(scheme_type::bfv);
        Modulus plain_modulus(1 << 6);
        parms.set_poly_modulus_degree(128);
        parms.set_plain_modulus(plain_modulus);
        parms.set_coeff_modulus(CoeffModulus::Create(128, { 40, 40, 40 }));

        SEALContext context(parms, false, sec_level_type::none);
        KeyGenerator keygen(context);
        PublicKey pk;
        keygen.create_public_key(pk);
        RelinKeys rlk;
        keygen.create_relin_keys(rlk);

        Encryptor encryptor(context, pk);
        Evaluator evaluator(context);
        Decryptor decryptor(context, keygen.secret_key());

        Ciphertext encrypted;
        Plaintext plain;

        plain = "1x^2 + 1";
        encryptor.encrypt(plain, encrypted);
        evaluator.exponentiate_inplace(encrypted, 1, rlk);
        decryptor.decrypt(encrypted, plain);
        ASSERT_EQ(plain.to_string(), "1x^2 + 1");
        ASSERT_TRUE(encrypted.parms_id() == context.first_parms_id());

        plain = "1x^2 + 1x^1 + 1";
        encryptor.encrypt(plain, encrypted);
        evaluator.exponentiate_inplace(encrypted, 2, rlk);
        decryptor.decrypt(encrypted, plain);
        ASSERT_EQ(plain.to_string(), "1x^4 + 2x^3 + 3x^2 + 2x^1 + 1");
        ASSERT_TRUE(encrypted.parms_id() == context.first_parms_id());

        plain = "3Fx^2 + 3Fx^1 + 3F";
        encryptor.encrypt(plain, encrypted);
        evaluator.exponentiate_inplace(encrypted, 3, rlk);
        decryptor.decrypt(encrypted, plain);
        ASSERT_EQ(plain.to_string(), "3Fx^6 + 3Dx^5 + 3Ax^4 + 39x^3 + 3Ax^2 + 3Dx^1 + 3F");
        ASSERT_TRUE(encrypted.parms_id() == context.first_parms_id());

        plain = "1x^8";
        encryptor.encrypt(plain, encrypted);
        evaluator.exponentiate_inplace(encrypted, 4, rlk);
        decryptor.decrypt(encrypted, plain);
        ASSERT_EQ(plain.to_string(), "1x^32");
        ASSERT_TRUE(encrypted.parms_id() == context.first_parms_id());
    }

    TEST(EvaluatorTest, BFVEncryptAddManyDecrypt)
    {
        EncryptionParameters parms(scheme_type::bfv);
        Modulus plain_modulus(1 << 6);
        parms.set_poly_modulus_degree(128);
        parms.set_plain_modulus(plain_modulus);
        parms.set_coeff_modulus(CoeffModulus::Create(128, { 40, 40 }));

        SEALContext context(parms, false, sec_level_type::none);
        KeyGenerator keygen(context);
        PublicKey pk;
        keygen.create_public_key(pk);

        Encryptor encryptor(context, pk);
        Evaluator evaluator(context);
        Decryptor decryptor(context, keygen.secret_key());

        Ciphertext encrypted1, encrypted2, encrypted3, encrypted4, sum;
        Plaintext plain, plain1, plain2, plain3, plain4;

        plain1 = "1x^2 + 1";
        plain2 = "1x^2 + 1x^1";
        plain3 = "1x^2 + 1x^1 + 1";
        encryptor.encrypt(plain1, encrypted1);
        encryptor.encrypt(plain2, encrypted2);
        encryptor.encrypt(plain3, encrypted3);
        vector<Ciphertext> encrypteds = { encrypted1, encrypted2, encrypted3 };
        evaluator.add_many(encrypteds, sum);
        decryptor.decrypt(sum, plain);
        ASSERT_EQ(plain.to_string(), "3x^2 + 2x^1 + 2");
        ASSERT_TRUE(encrypted1.parms_id() == sum.parms_id());
        ASSERT_TRUE(encrypted2.parms_id() == sum.parms_id());
        ASSERT_TRUE(encrypted3.parms_id() == sum.parms_id());
        ASSERT_TRUE(sum.parms_id() == context.first_parms_id());

        plain1 = "3Fx^3 + 3F";
        plain2 = "3Fx^4 + 3F";
        encryptor.encrypt(plain1, encrypted1);
        encryptor.encrypt(plain2, encrypted2);
        encrypteds = {
            encrypted1,
            encrypted2,
        };
        evaluator.add_many(encrypteds, sum);
        decryptor.decrypt(sum, plain);
        ASSERT_EQ(plain.to_string(), "3Fx^4 + 3Fx^3 + 3E");
        ASSERT_TRUE(encrypted1.parms_id() == sum.parms_id());
        ASSERT_TRUE(encrypted2.parms_id() == sum.parms_id());
        ASSERT_TRUE(sum.parms_id() == context.first_parms_id());

        plain1 = "1x^1";
        plain2 = "3Fx^4 + 3Fx^3 + 3Fx^2 + 3Fx^1 + 3F";
        plain3 = "1x^2 + 1x^1 + 1";
        encryptor.encrypt(plain1, encrypted1);
        encryptor.encrypt(plain2, encrypted2);
        encryptor.encrypt(plain3, encrypted3);
        encrypteds = { encrypted1, encrypted2, encrypted3 };
        evaluator.add_many(encrypteds, sum);
        decryptor.decrypt(sum, plain);
        ASSERT_EQ(plain.to_string(), "3Fx^4 + 3Fx^3 + 1x^1");
        ASSERT_TRUE(encrypted1.parms_id() == sum.parms_id());
        ASSERT_TRUE(encrypted2.parms_id() == sum.parms_id());
        ASSERT_TRUE(encrypted3.parms_id() == sum.parms_id());
        ASSERT_TRUE(sum.parms_id() == context.first_parms_id());

        plain1 = "1";
        plain2 = "3F";
        plain3 = "1";
        plain4 = "3F";
        encryptor.encrypt(plain1, encrypted1);
        encryptor.encrypt(plain2, encrypted2);
        encryptor.encrypt(plain3, encrypted3);
        encryptor.encrypt(plain4, encrypted4);
        encrypteds = { encrypted1, encrypted2, encrypted3, encrypted4 };
        evaluator.add_many(encrypteds, sum);
        decryptor.decrypt(sum, plain);
        ASSERT_EQ(plain.to_string(), "0");
        ASSERT_TRUE(encrypted1.parms_id() == sum.parms_id());
        ASSERT_TRUE(encrypted2.parms_id() == sum.parms_id());
        ASSERT_TRUE(encrypted3.parms_id() == sum.parms_id());
        ASSERT_TRUE(encrypted4.parms_id() == sum.parms_id());
        ASSERT_TRUE(sum.parms_id() == context.first_parms_id());

        plain1 = "1x^16 + 1x^15 + 1x^8 + 1x^7 + 1x^6 + 1x^3 + 1x^2 + 1";
        plain2 = "0";
        plain3 = "1x^13 + 1x^12 + 1x^5 + 1x^4 + 1x^3 + 1";
        plain4 = "1x^15 + 1x^10 + 1x^9 + 1x^8 + 1x^2 + 1x^1 + 1";
        encryptor.encrypt(plain1, encrypted1);
        encryptor.encrypt(plain2, encrypted2);
        encryptor.encrypt(plain3, encrypted3);
        encryptor.encrypt(plain4, encrypted4);
        encrypteds = { encrypted1, encrypted2, encrypted3, encrypted4 };
        evaluator.add_many(encrypteds, sum);
        decryptor.decrypt(sum, plain);
        ASSERT_EQ(
            plain.to_string(),
            "1x^16 + 2x^15 + 1x^13 + 1x^12 + 1x^10 + 1x^9 + 2x^8 + 1x^7 + 1x^6 + 1x^5 + 1x^4 + 2x^3 + 2x^2 + 1x^1 + 3");
        ASSERT_TRUE(encrypted1.parms_id() == sum.parms_id());
        ASSERT_TRUE(encrypted2.parms_id() == sum.parms_id());
        ASSERT_TRUE(encrypted3.parms_id() == sum.parms_id());
        ASSERT_TRUE(encrypted4.parms_id() == sum.parms_id());
        ASSERT_TRUE(sum.parms_id() == context.first_parms_id());
    }

    TEST(EvaluatorTest, BGVEncryptSquareDecrypt)
    {
        EncryptionParameters parms(scheme_type::bgv);
        Modulus plain_modulus(257);
        parms.set_poly_modulus_degree(128);
        parms.set_plain_modulus(plain_modulus);
        parms.set_coeff_modulus(CoeffModulus::Create(128, { 40, 40, 40 }));

        SEALContext context(parms, false, sec_level_type::none);
        KeyGenerator keygen(context);
        PublicKey pk;
        keygen.create_public_key(pk);

        Encryptor encryptor(context, pk);
        Evaluator evaluator(context);
        Decryptor decryptor(context, keygen.secret_key());

        Ciphertext encrypted;
        Plaintext plain;

        plain = "1";
        encryptor.encrypt(plain, encrypted);
        evaluator.square_inplace(encrypted);
        decryptor.decrypt(encrypted, plain);
        ASSERT_EQ(plain.to_string(), "1");
        ASSERT_TRUE(encrypted.parms_id() == context.first_parms_id());

        plain = "0";
        encryptor.encrypt(plain, encrypted);
        evaluator.square_inplace(encrypted);
        decryptor.decrypt(encrypted, plain);
        ASSERT_EQ(plain.to_string(), "0");
        ASSERT_TRUE(encrypted.parms_id() == context.first_parms_id());

        plain = "100x^2 + 100";
        encryptor.encrypt(plain, encrypted);
        evaluator.square_inplace(encrypted);
        decryptor.decrypt(encrypted, plain);
        ASSERT_EQ(plain.to_string(), "1x^4 + 2x^2 + 1");
        ASSERT_TRUE(encrypted.parms_id() == context.first_parms_id());

        plain = "100";
        encryptor.encrypt(plain, encrypted);
        evaluator.square_inplace(encrypted);
        decryptor.decrypt(encrypted, plain);
        ASSERT_EQ(plain.to_string(), "1");
        ASSERT_TRUE(encrypted.parms_id() == context.first_parms_id());

        plain = "1x^6 + 1x^5 + 1x^4 + 1x^3 + 1x^1 + 1";
        encryptor.encrypt(plain, encrypted);
        evaluator.square_inplace(encrypted);
        decryptor.decrypt(encrypted, plain);
        ASSERT_EQ(
            plain.to_string(),
            "1x^12 + 2x^11 + 3x^10 + 4x^9 + 3x^8 + 4x^7 + 5x^6 + 4x^5 + 4x^4 + 2x^3 + 1x^2 + 2x^1 + 1");
        ASSERT_TRUE(encrypted.parms_id() == context.first_parms_id());

        plain = "1x^16";
        encryptor.encrypt(plain, encrypted);
        evaluator.square_inplace(encrypted);
        decryptor.decrypt(encrypted, plain);
        ASSERT_EQ(plain.to_string(), "1x^32");
        ASSERT_TRUE(encrypted.parms_id() == context.first_parms_id());

        plain = "1x^6 + 1x^5 + 1x^4 + 1x^3 + 1x^1 + 1";
        encryptor.encrypt(plain, encrypted);
        evaluator.square_inplace(encrypted);
        evaluator.square_inplace(encrypted);
        decryptor.decrypt(encrypted, plain);
        ASSERT_EQ(
            plain.to_string(),
            "1x^24 + 4x^23 + Ax^22 + 14x^21 + 1Fx^20 + 2Cx^19 + 3Cx^18 + 4Cx^17 + 5Fx^16 + 6Cx^15 + 70x^14 + 74x^13 + "
            "71x^12 + 6Cx^11 + 64x^10 + 50x^9 + 40x^8 + 34x^7 + 26x^6 + 1Cx^5 + 11x^4 + 8x^3 + 6x^2 + 4x^1 + 1");
        ASSERT_TRUE(encrypted.parms_id() == context.first_parms_id());
    }

    TEST(EvaluatorTest, BGVEncryptMultiplyManyDecrypt)
    {
        EncryptionParameters parms(scheme_type::bgv);
        Modulus plain_modulus(65);
        parms.set_poly_modulus_degree(128);
        parms.set_plain_modulus(plain_modulus);
        parms.set_coeff_modulus(CoeffModulus::Create(128, { 40, 40, 40 }));

        SEALContext context(parms, false, sec_level_type::none);
        KeyGenerator keygen(context);
        PublicKey pk;
        keygen.create_public_key(pk);
        RelinKeys rlk;
        keygen.create_relin_keys(rlk);

        Encryptor encryptor(context, pk);
        Evaluator evaluator(context);
        Decryptor decryptor(context, keygen.secret_key());

        Ciphertext encrypted1, encrypted2, encrypted3, encrypted4, product;
        Plaintext plain, plain1, plain2, plain3, plain4;

        plain1 = "1x^2 + 1";
        plain2 = "1x^2 + 1x^1";
        plain3 = "1x^2 + 1x^1 + 1";
        encryptor.encrypt(plain1, encrypted1);
        encryptor.encrypt(plain2, encrypted2);
        encryptor.encrypt(plain3, encrypted3);
        vector<Ciphertext> encrypteds{ encrypted1, encrypted2, encrypted3 };
        evaluator.multiply_many(encrypteds, rlk, product);
        ASSERT_EQ(3, encrypteds.size());
        decryptor.decrypt(product, plain);
        ASSERT_EQ(plain.to_string(), "1x^6 + 2x^5 + 3x^4 + 3x^3 + 2x^2 + 1x^1");
        ASSERT_TRUE(encrypted1.parms_id() == product.parms_id());
        ASSERT_TRUE(encrypted2.parms_id() == product.parms_id());
        ASSERT_TRUE(encrypted3.parms_id() == product.parms_id());
        ASSERT_TRUE(product.parms_id() == context.first_parms_id());

        plain1 = "40x^3 + 40";
        plain2 = "40x^4 + 40";
        encryptor.encrypt(plain1, encrypted1);
        encryptor.encrypt(plain2, encrypted2);
        encrypteds = { encrypted1, encrypted2 };
        evaluator.multiply_many(encrypteds, rlk, product);
        ASSERT_EQ(2, encrypteds.size());
        decryptor.decrypt(product, plain);
        ASSERT_EQ(plain.to_string(), "1x^7 + 1x^4 + 1x^3 + 1");
        ASSERT_TRUE(encrypted1.parms_id() == product.parms_id());
        ASSERT_TRUE(encrypted2.parms_id() == product.parms_id());
        ASSERT_TRUE(product.parms_id() == context.first_parms_id());

        plain1 = "1x^1";
        plain2 = "40x^4 + 40x^3 + 40x^2 + 40x^1 + 40";
        plain3 = "1x^2 + 1x^1 + 1";
        encryptor.encrypt(plain1, encrypted1);
        encryptor.encrypt(plain2, encrypted2);
        encryptor.encrypt(plain3, encrypted3);
        encrypteds = { encrypted1, encrypted2, encrypted3 };
        evaluator.multiply_many(encrypteds, rlk, product);
        ASSERT_EQ(3, encrypteds.size());
        decryptor.decrypt(product, plain);
        ASSERT_EQ(plain.to_string(), "40x^7 + 3Fx^6 + 3Ex^5 + 3Ex^4 + 3Ex^3 + 3Fx^2 + 40x^1");
        ASSERT_TRUE(encrypted1.parms_id() == product.parms_id());
        ASSERT_TRUE(encrypted2.parms_id() == product.parms_id());
        ASSERT_TRUE(encrypted3.parms_id() == product.parms_id());
        ASSERT_TRUE(product.parms_id() == context.first_parms_id());

        plain1 = "1";
        plain2 = "40";
        plain3 = "1";
        plain4 = "40";
        encryptor.encrypt(plain1, encrypted1);
        encryptor.encrypt(plain2, encrypted2);
        encryptor.encrypt(plain3, encrypted3);
        encryptor.encrypt(plain4, encrypted4);
        encrypteds = { encrypted1, encrypted2, encrypted3, encrypted4 };
        evaluator.multiply_many(encrypteds, rlk, product);
        ASSERT_EQ(4, encrypteds.size());
        decryptor.decrypt(product, plain);
        ASSERT_EQ(plain.to_string(), "1");
        ASSERT_TRUE(encrypted1.parms_id() == product.parms_id());
        ASSERT_TRUE(encrypted2.parms_id() == product.parms_id());
        ASSERT_TRUE(encrypted3.parms_id() == product.parms_id());
        ASSERT_TRUE(encrypted4.parms_id() == product.parms_id());
        ASSERT_TRUE(product.parms_id() == context.first_parms_id());

        plain1 = "1x^16 + 1x^15 + 1x^8 + 1x^7 + 1x^6 + 1x^3 + 1x^2 + 1";
        plain2 = "0";
        plain3 = "1x^13 + 1x^12 + 1x^5 + 1x^4 + 1x^3 + 1";
        plain4 = "1x^15 + 1x^10 + 1x^9 + 1x^8 + 1x^2 + 1x^1 + 1";
        encryptor.encrypt(plain1, encrypted1);
        encryptor.encrypt(plain2, encrypted2);
        encryptor.encrypt(plain3, encrypted3);
        encryptor.encrypt(plain4, encrypted4);
        encrypteds = { encrypted1, encrypted2, encrypted3, encrypted4 };
        evaluator.multiply_many(encrypteds, rlk, product);
        ASSERT_EQ(4, encrypteds.size());
        decryptor.decrypt(product, plain);
        ASSERT_EQ(plain.to_string(), "0");
        ASSERT_TRUE(encrypted1.parms_id() == product.parms_id());
        ASSERT_TRUE(encrypted2.parms_id() == product.parms_id());
        ASSERT_TRUE(encrypted3.parms_id() == product.parms_id());
        ASSERT_TRUE(encrypted4.parms_id() == product.parms_id());
        ASSERT_TRUE(product.parms_id() == context.first_parms_id());
    }

    TEST(EvaluatorTest, BGVEncryptExponentiateDecrypt)
    {
        EncryptionParameters parms(scheme_type::bgv);
        Modulus plain_modulus(65);
        parms.set_poly_modulus_degree(128);
        parms.set_plain_modulus(plain_modulus);
        parms.set_coeff_modulus(CoeffModulus::Create(128, { 40, 40, 40 }));

        SEALContext context(parms, false, sec_level_type::none);
        KeyGenerator keygen(context);
        PublicKey pk;
        keygen.create_public_key(pk);
        RelinKeys rlk;
        keygen.create_relin_keys(rlk);

        Encryptor encryptor(context, pk);
        Evaluator evaluator(context);
        Decryptor decryptor(context, keygen.secret_key());

        Ciphertext encrypted;
        Plaintext plain;

        plain = "1x^2 + 1";
        encryptor.encrypt(plain, encrypted);
        evaluator.exponentiate_inplace(encrypted, 1, rlk);
        decryptor.decrypt(encrypted, plain);
        ASSERT_EQ(plain.to_string(), "1x^2 + 1");
        ASSERT_TRUE(encrypted.parms_id() == context.first_parms_id());

        plain = "1x^2 + 1x^1 + 1";
        encryptor.encrypt(plain, encrypted);
        evaluator.exponentiate_inplace(encrypted, 2, rlk);
        decryptor.decrypt(encrypted, plain);
        ASSERT_EQ(plain.to_string(), "1x^4 + 2x^3 + 3x^2 + 2x^1 + 1");
        ASSERT_TRUE(encrypted.parms_id() == context.first_parms_id());

        plain = "40x^2 + 40x^1 + 40";
        encryptor.encrypt(plain, encrypted);
        evaluator.exponentiate_inplace(encrypted, 3, rlk);
        decryptor.decrypt(encrypted, plain);
        ASSERT_EQ(plain.to_string(), "40x^6 + 3Ex^5 + 3Bx^4 + 3Ax^3 + 3Bx^2 + 3Ex^1 + 40");
        ASSERT_TRUE(encrypted.parms_id() == context.first_parms_id());

        plain = "1x^8";
        encryptor.encrypt(plain, encrypted);
        evaluator.exponentiate_inplace(encrypted, 4, rlk);
        decryptor.decrypt(encrypted, plain);
        ASSERT_EQ(plain.to_string(), "1x^32");
        ASSERT_TRUE(encrypted.parms_id() == context.first_parms_id());
    }

    TEST(EvaluatorTest, BGVEncryptAddManyDecrypt)
    {
        EncryptionParameters parms(scheme_type::bgv);
        Modulus plain_modulus(65);
        parms.set_poly_modulus_degree(128);
        parms.set_plain_modulus(plain_modulus);
        parms.set_coeff_modulus(CoeffModulus::Create(128, { 40, 40 }));

        SEALContext context(parms, false, sec_level_type::none);
        KeyGenerator keygen(context);
        PublicKey pk;
        keygen.create_public_key(pk);

        Encryptor encryptor(context, pk);
        Evaluator evaluator(context);
        Decryptor decryptor(context, keygen.secret_key());

        Ciphertext encrypted1, encrypted2, encrypted3, encrypted4, sum;
        Plaintext plain, plain1, plain2, plain3, plain4;

        plain1 = "1x^2 + 1";
        plain2 = "1x^2 + 1x^1";
        plain3 = "1x^2 + 1x^1 + 1";
        encryptor.encrypt(plain1, encrypted1);
        encryptor.encrypt(plain2, encrypted2);
        encryptor.encrypt(plain3, encrypted3);
        vector<Ciphertext> encrypteds = { encrypted1, encrypted2, encrypted3 };
        evaluator.add_many(encrypteds, sum);
        decryptor.decrypt(sum, plain);
        ASSERT_EQ(plain.to_string(), "3x^2 + 2x^1 + 2");
        ASSERT_TRUE(encrypted1.parms_id() == sum.parms_id());
        ASSERT_TRUE(encrypted2.parms_id() == sum.parms_id());
        ASSERT_TRUE(encrypted3.parms_id() == sum.parms_id());
        ASSERT_TRUE(sum.parms_id() == context.first_parms_id());

        plain1 = "40x^3 + 40";
        plain2 = "40x^4 + 40";
        encryptor.encrypt(plain1, encrypted1);
        encryptor.encrypt(plain2, encrypted2);
        encrypteds = {
            encrypted1,
            encrypted2,
        };
        evaluator.add_many(encrypteds, sum);
        decryptor.decrypt(sum, plain);
        ASSERT_EQ(plain.to_string(), "40x^4 + 40x^3 + 3F");
        ASSERT_TRUE(encrypted1.parms_id() == sum.parms_id());
        ASSERT_TRUE(encrypted2.parms_id() == sum.parms_id());
        ASSERT_TRUE(sum.parms_id() == context.first_parms_id());

        plain1 = "1x^1";
        plain2 = "40x^4 + 40x^3 + 40x^2 + 40x^1 + 40";
        plain3 = "1x^2 + 1x^1 + 1";
        encryptor.encrypt(plain1, encrypted1);
        encryptor.encrypt(plain2, encrypted2);
        encryptor.encrypt(plain3, encrypted3);
        encrypteds = { encrypted1, encrypted2, encrypted3 };
        evaluator.add_many(encrypteds, sum);
        decryptor.decrypt(sum, plain);
        ASSERT_EQ(plain.to_string(), "40x^4 + 40x^3 + 1x^1");
        ASSERT_TRUE(encrypted1.parms_id() == sum.parms_id());
        ASSERT_TRUE(encrypted2.parms_id() == sum.parms_id());
        ASSERT_TRUE(encrypted3.parms_id() == sum.parms_id());
        ASSERT_TRUE(sum.parms_id() == context.first_parms_id());

        plain1 = "1";
        plain2 = "40";
        plain3 = "1";
        plain4 = "40";
        encryptor.encrypt(plain1, encrypted1);
        encryptor.encrypt(plain2, encrypted2);
        encryptor.encrypt(plain3, encrypted3);
        encryptor.encrypt(plain4, encrypted4);
        encrypteds = { encrypted1, encrypted2, encrypted3, encrypted4 };
        evaluator.add_many(encrypteds, sum);
        decryptor.decrypt(sum, plain);
        ASSERT_EQ(plain.to_string(), "0");
        ASSERT_TRUE(encrypted1.parms_id() == sum.parms_id());
        ASSERT_TRUE(encrypted2.parms_id() == sum.parms_id());
        ASSERT_TRUE(encrypted3.parms_id() == sum.parms_id());
        ASSERT_TRUE(encrypted4.parms_id() == sum.parms_id());
        ASSERT_TRUE(sum.parms_id() == context.first_parms_id());

        plain1 = "1x^16 + 1x^15 + 1x^8 + 1x^7 + 1x^6 + 1x^3 + 1x^2 + 1";
        plain2 = "0";
        plain3 = "1x^13 + 1x^12 + 1x^5 + 1x^4 + 1x^3 + 1";
        plain4 = "1x^15 + 1x^10 + 1x^9 + 1x^8 + 1x^2 + 1x^1 + 1";
        encryptor.encrypt(plain1, encrypted1);
        encryptor.encrypt(plain2, encrypted2);
        encryptor.encrypt(plain3, encrypted3);
        encryptor.encrypt(plain4, encrypted4);
        encrypteds = { encrypted1, encrypted2, encrypted3, encrypted4 };
        evaluator.add_many(encrypteds, sum);
        decryptor.decrypt(sum, plain);
        ASSERT_EQ(
            plain.to_string(),
            "1x^16 + 2x^15 + 1x^13 + 1x^12 + 1x^10 + 1x^9 + 2x^8 + 1x^7 + 1x^6 + 1x^5 + 1x^4 + 2x^3 + 2x^2 + 1x^1 + 3");
        ASSERT_TRUE(encrypted1.parms_id() == sum.parms_id());
        ASSERT_TRUE(encrypted2.parms_id() == sum.parms_id());
        ASSERT_TRUE(encrypted3.parms_id() == sum.parms_id());
        ASSERT_TRUE(encrypted4.parms_id() == sum.parms_id());
        ASSERT_TRUE(sum.parms_id() == context.first_parms_id());
    }

    TEST(EvaluatorTest, TransformPlainToNTT)
    {
        auto evaluator_transform_plain_to_ntt = [](scheme_type scheme) {
            EncryptionParameters parms(scheme);
            Modulus plain_modulus(1 << 6);
            parms.set_poly_modulus_degree(128);
            parms.set_plain_modulus(plain_modulus);
            parms.set_coeff_modulus(CoeffModulus::Create(128, { 40, 40, 40 }));
            SEALContext context(parms, true, sec_level_type::none);

            Evaluator evaluator(context);
            Plaintext plain("0");
            ASSERT_FALSE(plain.is_ntt_form());
            evaluator.transform_to_ntt_inplace(plain, context.first_parms_id());
            ASSERT_TRUE(plain.is_zero());
            ASSERT_TRUE(plain.is_ntt_form());
            ASSERT_TRUE(plain.parms_id() == context.first_parms_id());

            plain.release();
            plain = "0";
            ASSERT_FALSE(plain.is_ntt_form());
            auto next_parms_id = context.first_context_data()->next_context_data()->parms_id();
            evaluator.transform_to_ntt_inplace(plain, next_parms_id);
            ASSERT_TRUE(plain.is_zero());
            ASSERT_TRUE(plain.is_ntt_form());
            ASSERT_TRUE(plain.parms_id() == next_parms_id);

            plain.release();
            plain = "1";
            ASSERT_FALSE(plain.is_ntt_form());
            evaluator.transform_to_ntt_inplace(plain, context.first_parms_id());
            for (size_t i = 0; i < 256; i++)
            {
                ASSERT_TRUE(plain[i] == uint64_t(1));
            }
            ASSERT_TRUE(plain.is_ntt_form());
            ASSERT_TRUE(plain.parms_id() == context.first_parms_id());

            plain.release();
            plain = "1";
            ASSERT_FALSE(plain.is_ntt_form());
            evaluator.transform_to_ntt_inplace(plain, next_parms_id);
            for (size_t i = 0; i < 128; i++)
            {
                ASSERT_TRUE(plain[i] == uint64_t(1));
            }
            ASSERT_TRUE(plain.is_ntt_form());
            ASSERT_TRUE(plain.parms_id() == next_parms_id);

            plain.release();
            plain = "2";
            ASSERT_FALSE(plain.is_ntt_form());
            evaluator.transform_to_ntt_inplace(plain, context.first_parms_id());
            for (size_t i = 0; i < 256; i++)
            {
                ASSERT_TRUE(plain[i] == uint64_t(2));
            }
            ASSERT_TRUE(plain.is_ntt_form());
            ASSERT_TRUE(plain.parms_id() == context.first_parms_id());

            plain.release();
            plain = "2";
            evaluator.transform_to_ntt_inplace(plain, next_parms_id);
            for (size_t i = 0; i < 128; i++)
            {
                ASSERT_TRUE(plain[i] == uint64_t(2));
            }
            ASSERT_TRUE(plain.is_ntt_form());
            ASSERT_TRUE(plain.parms_id() == next_parms_id);
        };
        evaluator_transform_plain_to_ntt(scheme_type::bfv);
        evaluator_transform_plain_to_ntt(scheme_type::bgv);
    }

    TEST(EvaluatorTest, TransformEncryptedToFromNTT)
    {
        auto evaluator_transform_encrypted_to_from_ntt = [](scheme_type scheme) {
            EncryptionParameters parms(scheme);
            Modulus plain_modulus(1 << 6);
            parms.set_poly_modulus_degree(128);
            parms.set_plain_modulus(plain_modulus);
            parms.set_coeff_modulus(CoeffModulus::Create(128, { 40, 40 }));

            SEALContext context(parms, false, sec_level_type::none);
            KeyGenerator keygen(context);
            PublicKey pk;
            keygen.create_public_key(pk);

            Encryptor encryptor(context, pk);
            Evaluator evaluator(context);
            Decryptor decryptor(context, keygen.secret_key());

            Plaintext plain;
            Ciphertext encrypted;
            plain = "0";
            encryptor.encrypt(plain, encrypted);
            evaluator.transform_to_ntt_inplace(encrypted);
            evaluator.transform_from_ntt_inplace(encrypted);
            decryptor.decrypt(encrypted, plain);
            ASSERT_TRUE(plain.to_string() == "0");
            ASSERT_TRUE(encrypted.parms_id() == context.first_parms_id());

            plain = "1";
            encryptor.encrypt(plain, encrypted);
            evaluator.transform_to_ntt_inplace(encrypted);
            evaluator.transform_from_ntt_inplace(encrypted);
            decryptor.decrypt(encrypted, plain);
            ASSERT_TRUE(plain.to_string() == "1");
            ASSERT_TRUE(encrypted.parms_id() == context.first_parms_id());

            plain = "Fx^10 + Ex^9 + Dx^8 + Cx^7 + Bx^6 + Ax^5 + 1x^4 + 2x^3 + 3x^2 + 4x^1 + 5";
            encryptor.encrypt(plain, encrypted);
            evaluator.transform_to_ntt_inplace(encrypted);
            evaluator.transform_from_ntt_inplace(encrypted);
            decryptor.decrypt(encrypted, plain);
            ASSERT_TRUE(
                plain.to_string() == "Fx^10 + Ex^9 + Dx^8 + Cx^7 + Bx^6 + Ax^5 + 1x^4 + 2x^3 + 3x^2 + 4x^1 + 5");
            ASSERT_TRUE(encrypted.parms_id() == context.first_parms_id());
        };
        evaluator_transform_encrypted_to_from_ntt(scheme_type::bfv);
    }

    TEST(EvaluatorTest, BFVEncryptMultiplyPlainNTTDecrypt)
    {
        EncryptionParameters parms(scheme_type::bfv);
        Modulus plain_modulus(1 << 6);
        parms.set_poly_modulus_degree(128);
        parms.set_plain_modulus(plain_modulus);
        parms.set_coeff_modulus(CoeffModulus::Create(128, { 40, 40 }));

        SEALContext context(parms, false, sec_level_type::none);
        KeyGenerator keygen(context);
        PublicKey pk;
        keygen.create_public_key(pk);

        Encryptor encryptor(context, pk);
        Evaluator evaluator(context);
        Decryptor decryptor(context, keygen.secret_key());

        Plaintext plain;
        Plaintext plain_multiplier;
        Ciphertext encrypted;

        plain = 0;
        encryptor.encrypt(plain, encrypted);
        evaluator.transform_to_ntt_inplace(encrypted);
        plain_multiplier = 1;
        evaluator.transform_to_ntt_inplace(plain_multiplier, context.first_parms_id());
        evaluator.multiply_plain_inplace(encrypted, plain_multiplier);
        evaluator.transform_from_ntt_inplace(encrypted);
        decryptor.decrypt(encrypted, plain);
        ASSERT_TRUE(plain.to_string() == "0");
        ASSERT_TRUE(encrypted.parms_id() == context.first_parms_id());

        plain = 2;
        encryptor.encrypt(plain, encrypted);
        evaluator.transform_to_ntt_inplace(encrypted);
        plain_multiplier.release();
        plain_multiplier = 3;
        evaluator.transform_to_ntt_inplace(plain_multiplier, context.first_parms_id());
        evaluator.multiply_plain_inplace(encrypted, plain_multiplier);
        evaluator.transform_from_ntt_inplace(encrypted);
        decryptor.decrypt(encrypted, plain);
        ASSERT_TRUE(plain.to_string() == "6");
        ASSERT_TRUE(encrypted.parms_id() == context.first_parms_id());

        plain = 1;
        encryptor.encrypt(plain, encrypted);
        evaluator.transform_to_ntt_inplace(encrypted);
        plain_multiplier.release();
        plain_multiplier = "Fx^10 + Ex^9 + Dx^8 + Cx^7 + Bx^6 + Ax^5 + 1x^4 + 2x^3 + 3x^2 + 4x^1 + 5";
        evaluator.transform_to_ntt_inplace(plain_multiplier, context.first_parms_id());
        evaluator.multiply_plain_inplace(encrypted, plain_multiplier);
        evaluator.transform_from_ntt_inplace(encrypted);
        decryptor.decrypt(encrypted, plain);
        ASSERT_TRUE(plain.to_string() == "Fx^10 + Ex^9 + Dx^8 + Cx^7 + Bx^6 + Ax^5 + 1x^4 + 2x^3 + 3x^2 + 4x^1 + 5");
        ASSERT_TRUE(encrypted.parms_id() == context.first_parms_id());

        plain = "1x^20";
        encryptor.encrypt(plain, encrypted);
        evaluator.transform_to_ntt_inplace(encrypted);
        plain_multiplier.release();
        plain_multiplier = "Fx^10 + Ex^9 + Dx^8 + Cx^7 + Bx^6 + Ax^5 + 1x^4 + 2x^3 + 3x^2 + 4x^1 + 5";
        evaluator.transform_to_ntt_inplace(plain_multiplier, context.first_parms_id());
        evaluator.multiply_plain_inplace(encrypted, plain_multiplier);
        evaluator.transform_from_ntt_inplace(encrypted);
        decryptor.decrypt(encrypted, plain);
        ASSERT_TRUE(
            plain.to_string() ==
            "Fx^30 + Ex^29 + Dx^28 + Cx^27 + Bx^26 + Ax^25 + 1x^24 + 2x^23 + 3x^22 + 4x^21 + 5x^20");
        ASSERT_TRUE(encrypted.parms_id() == context.first_parms_id());
    }

    TEST(EvaluatorTest, BFVEncryptApplyGaloisDecrypt)
    {
        EncryptionParameters parms(scheme_type::bfv);
        Modulus plain_modulus(257);
        parms.set_poly_modulus_degree(8);
        parms.set_plain_modulus(plain_modulus);
        parms.set_coeff_modulus(CoeffModulus::Create(8, { 40, 40 }));

        SEALContext context(parms, false, sec_level_type::none);
        KeyGenerator keygen(context);
        PublicKey pk;
        keygen.create_public_key(pk);
        GaloisKeys glk;
        keygen.create_galois_keys(vector<uint32_t>{ 1, 3, 5, 15 }, glk);

        Encryptor encryptor(context, pk);
        Evaluator evaluator(context);
        Decryptor decryptor(context, keygen.secret_key());

        Plaintext plain("1");
        Ciphertext encrypted;
        encryptor.encrypt(plain, encrypted);
        evaluator.apply_galois_inplace(encrypted, 1, glk);
        decryptor.decrypt(encrypted, plain);
        ASSERT_TRUE("1" == plain.to_string());
        evaluator.apply_galois_inplace(encrypted, 3, glk);
        decryptor.decrypt(encrypted, plain);
        ASSERT_TRUE("1" == plain.to_string());
        evaluator.apply_galois_inplace(encrypted, 5, glk);
        decryptor.decrypt(encrypted, plain);
        ASSERT_TRUE("1" == plain.to_string());
        evaluator.apply_galois_inplace(encrypted, 15, glk);
        decryptor.decrypt(encrypted, plain);
        ASSERT_TRUE("1" == plain.to_string());

        plain = "1x^1";
        encryptor.encrypt(plain, encrypted);
        evaluator.apply_galois_inplace(encrypted, 1, glk);
        decryptor.decrypt(encrypted, plain);
        ASSERT_TRUE("1x^1" == plain.to_string());
        evaluator.apply_galois_inplace(encrypted, 3, glk);
        decryptor.decrypt(encrypted, plain);
        ASSERT_TRUE("1x^3" == plain.to_string());
        evaluator.apply_galois_inplace(encrypted, 5, glk);
        decryptor.decrypt(encrypted, plain);
        ASSERT_TRUE("100x^7" == plain.to_string());
        evaluator.apply_galois_inplace(encrypted, 15, glk);
        decryptor.decrypt(encrypted, plain);
        ASSERT_TRUE("1x^1" == plain.to_string());

        plain = "1x^2";
        encryptor.encrypt(plain, encrypted);
        evaluator.apply_galois_inplace(encrypted, 1, glk);
        decryptor.decrypt(encrypted, plain);
        ASSERT_TRUE("1x^2" == plain.to_string());
        evaluator.apply_galois_inplace(encrypted, 3, glk);
        decryptor.decrypt(encrypted, plain);
        ASSERT_TRUE("1x^6" == plain.to_string());
        evaluator.apply_galois_inplace(encrypted, 5, glk);
        decryptor.decrypt(encrypted, plain);
        ASSERT_TRUE("100x^6" == plain.to_string());
        evaluator.apply_galois_inplace(encrypted, 15, glk);
        decryptor.decrypt(encrypted, plain);
        ASSERT_TRUE("1x^2" == plain.to_string());

        plain = "1x^3 + 2x^2 + 1x^1 + 1";
        encryptor.encrypt(plain, encrypted);
        evaluator.apply_galois_inplace(encrypted, 1, glk);
        decryptor.decrypt(encrypted, plain);
        ASSERT_TRUE("1x^3 + 2x^2 + 1x^1 + 1" == plain.to_string());
        evaluator.apply_galois_inplace(encrypted, 3, glk);
        decryptor.decrypt(encrypted, plain);
        ASSERT_TRUE("2x^6 + 1x^3 + 100x^1 + 1" == plain.to_string());
        evaluator.apply_galois_inplace(encrypted, 5, glk);
        decryptor.decrypt(encrypted, plain);
        ASSERT_TRUE("100x^7 + FFx^6 + 100x^5 + 1" == plain.to_string());
        evaluator.apply_galois_inplace(encrypted, 15, glk);
        decryptor.decrypt(encrypted, plain);
        ASSERT_TRUE("1x^3 + 2x^2 + 1x^1 + 1" == plain.to_string());
    }

    TEST(EvaluatorTest, ApplyGaloisRejectsWrongNttFormWithoutMutating)
    {
        EncryptionParameters parms(scheme_type::bfv);
        parms.set_poly_modulus_degree(8);
        parms.set_plain_modulus(257);
        parms.set_coeff_modulus(CoeffModulus::Create(8, { 40, 40 }));

        SEALContext context(parms, false, sec_level_type::none);
        KeyGenerator keygen(context);
        PublicKey pk;
        keygen.create_public_key(pk);
        GaloisKeys glk;
        keygen.create_galois_keys(vector<uint32_t>{ 3 }, glk);

        Encryptor encryptor(context, pk);
        Evaluator evaluator(context);

        Plaintext plain("1x^3 + 2x^2 + 1x^1 + 1");
        Ciphertext encrypted;
        encryptor.encrypt(plain, encrypted);

        // A BFV ciphertext carrying an NTT-form flag is inconsistent with the scheme; the
        // operand must be left unchanged when the operation is rejected.
        encrypted.is_ntt_form() = true;
        Ciphertext expected(encrypted);

        ASSERT_THROW(evaluator.apply_galois_inplace(encrypted, 3, glk), invalid_argument);

        size_t total = encrypted.size() * encrypted.poly_modulus_degree() * encrypted.coeff_modulus_size();
        bool unchanged = true;
        for (size_t i = 0; i < total; i++)
        {
            unchanged = unchanged && (encrypted.data()[i] == expected.data()[i]);
        }
        ASSERT_TRUE(unchanged);
        ASSERT_TRUE(encrypted.is_ntt_form());
    }

    TEST(EvaluatorTest, BFVRotateSizeZeroCiphertext)
    {
        EncryptionParameters parms(scheme_type::bfv);
        parms.set_poly_modulus_degree(8);
        parms.set_plain_modulus(257);
        parms.set_coeff_modulus(CoeffModulus::Create(8, { 40, 40 }));

        SEALContext context(parms, false, sec_level_type::none);
        KeyGenerator keygen(context);
        GaloisKeys glk;
        keygen.create_galois_keys(glk);
        Evaluator evaluator(context);

        Ciphertext encrypted;
        encrypted.resize(context, context.first_parms_id(), 0);
        ASSERT_EQ(0ULL, encrypted.size());

        ASSERT_THROW(evaluator.rotate_rows_inplace(encrypted, 1, glk), invalid_argument);
        ASSERT_THROW(evaluator.rotate_columns_inplace(encrypted, glk), invalid_argument);
        ASSERT_THROW(evaluator.apply_galois_inplace(encrypted, 3, glk), invalid_argument);
    }

    TEST(EvaluatorTest, CKKSRotateSizeZeroCiphertext)
    {
        EncryptionParameters parms(scheme_type::ckks);
        parms.set_poly_modulus_degree(8);
        parms.set_coeff_modulus(CoeffModulus::Create(8, { 40, 40, 40 }));

        SEALContext context(parms, false, sec_level_type::none);
        KeyGenerator keygen(context);
        GaloisKeys glk;
        keygen.create_galois_keys(glk);
        Evaluator evaluator(context);

        Ciphertext encrypted;
        encrypted.resize(context, context.first_parms_id(), 0);
        ASSERT_EQ(0ULL, encrypted.size());

        ASSERT_THROW(evaluator.rotate_vector_inplace(encrypted, 1, glk), invalid_argument);
        ASSERT_THROW(evaluator.complex_conjugate_inplace(encrypted, glk), invalid_argument);
    }

    TEST(EvaluatorTest, BFVEncryptRotateMatrixDecrypt)
    {
        EncryptionParameters parms(scheme_type::bfv);
        Modulus plain_modulus(257);
        parms.set_poly_modulus_degree(8);
        parms.set_plain_modulus(plain_modulus);
        parms.set_coeff_modulus(CoeffModulus::Create(8, { 40, 40 }));

        SEALContext context(parms, false, sec_level_type::none);
        KeyGenerator keygen(context);
        PublicKey pk;
        keygen.create_public_key(pk);
        GaloisKeys glk;
        keygen.create_galois_keys(glk);

        Encryptor encryptor(context, pk);
        Evaluator evaluator(context);
        Decryptor decryptor(context, keygen.secret_key());
        BatchEncoder batch_encoder(context);

        Plaintext plain;
        vector<uint64_t> plain_vec{ 1, 2, 3, 4, 5, 6, 7, 8 };
        batch_encoder.encode(plain_vec, plain);
        Ciphertext encrypted;
        encryptor.encrypt(plain, encrypted);

        evaluator.rotate_columns_inplace(encrypted, glk);
        decryptor.decrypt(encrypted, plain);
        batch_encoder.decode(plain, plain_vec);
        ASSERT_TRUE((plain_vec == vector<uint64_t>{ 5, 6, 7, 8, 1, 2, 3, 4 }));

        evaluator.rotate_rows_inplace(encrypted, -1, glk);
        decryptor.decrypt(encrypted, plain);
        batch_encoder.decode(plain, plain_vec);
        ASSERT_TRUE((plain_vec == vector<uint64_t>{ 8, 5, 6, 7, 4, 1, 2, 3 }));

        evaluator.rotate_rows_inplace(encrypted, 2, glk);
        decryptor.decrypt(encrypted, plain);
        batch_encoder.decode(plain, plain_vec);
        ASSERT_TRUE((plain_vec == vector<uint64_t>{ 6, 7, 8, 5, 2, 3, 4, 1 }));

        evaluator.rotate_columns_inplace(encrypted, glk);
        decryptor.decrypt(encrypted, plain);
        batch_encoder.decode(plain, plain_vec);
        ASSERT_TRUE((plain_vec == vector<uint64_t>{ 2, 3, 4, 1, 6, 7, 8, 5 }));

        evaluator.rotate_rows_inplace(encrypted, 0, glk);
        decryptor.decrypt(encrypted, plain);
        batch_encoder.decode(plain, plain_vec);
        ASSERT_TRUE((plain_vec == vector<uint64_t>{ 2, 3, 4, 1, 6, 7, 8, 5 }));
    }

    TEST(EvaluatorTest, BFVEncryptModSwitchToNextDecrypt)
    {
        // The common parameters: the plaintext and the polynomial moduli
        Modulus plain_modulus(1 << 6);

        // The parameters and the context of the higher level
        EncryptionParameters parms(scheme_type::bfv);
        parms.set_poly_modulus_degree(128);
        parms.set_plain_modulus(plain_modulus);
        parms.set_coeff_modulus(CoeffModulus::Create(128, { 30, 30, 30, 30 }));

        SEALContext context(parms, true, sec_level_type::none);
        KeyGenerator keygen(context);
        SecretKey secret_key = keygen.secret_key();
        PublicKey pk;
        keygen.create_public_key(pk);

        Encryptor encryptor(context, pk);
        Evaluator evaluator(context);
        Decryptor decryptor(context, keygen.secret_key());
        auto parms_id = context.first_parms_id();

        Ciphertext encrypted(context);
        Ciphertext encryptedRes;
        Plaintext plain;

        plain = 0;
        encryptor.encrypt(plain, encrypted);
        evaluator.mod_switch_to_next(encrypted, encryptedRes);
        decryptor.decrypt(encryptedRes, plain);
        parms_id = context.get_context_data(parms_id)->next_context_data()->parms_id();
        ASSERT_TRUE(encryptedRes.parms_id() == parms_id);
        ASSERT_TRUE(plain.to_string() == "0");

        evaluator.mod_switch_to_next_inplace(encryptedRes);
        decryptor.decrypt(encryptedRes, plain);
        parms_id = context.get_context_data(parms_id)->next_context_data()->parms_id();
        ASSERT_TRUE(encryptedRes.parms_id() == parms_id);
        ASSERT_TRUE(plain.to_string() == "0");

        parms_id = context.first_parms_id();
        plain = 1;
        encryptor.encrypt(plain, encrypted);
        evaluator.mod_switch_to_next(encrypted, encryptedRes);
        decryptor.decrypt(encryptedRes, plain);
        parms_id = context.get_context_data(parms_id)->next_context_data()->parms_id();
        ASSERT_TRUE(encryptedRes.parms_id() == parms_id);
        ASSERT_TRUE(plain.to_string() == "1");

        evaluator.mod_switch_to_next_inplace(encryptedRes);
        decryptor.decrypt(encryptedRes, plain);
        parms_id = context.get_context_data(parms_id)->next_context_data()->parms_id();
        ASSERT_TRUE(encryptedRes.parms_id() == parms_id);
        ASSERT_TRUE(plain.to_string() == "1");

        parms_id = context.first_parms_id();
        plain = "1x^127";
        encryptor.encrypt(plain, encrypted);
        evaluator.mod_switch_to_next(encrypted, encryptedRes);
        decryptor.decrypt(encryptedRes, plain);
        parms_id = context.get_context_data(parms_id)->next_context_data()->parms_id();
        ASSERT_TRUE(encryptedRes.parms_id() == parms_id);
        ASSERT_TRUE(plain.to_string() == "1x^127");

        evaluator.mod_switch_to_next_inplace(encryptedRes);
        decryptor.decrypt(encryptedRes, plain);
        parms_id = context.get_context_data(parms_id)->next_context_data()->parms_id();
        ASSERT_TRUE(encryptedRes.parms_id() == parms_id);
        ASSERT_TRUE(plain.to_string() == "1x^127");

        parms_id = context.first_parms_id();
        plain = "5x^64 + Ax^5";
        encryptor.encrypt(plain, encrypted);
        evaluator.mod_switch_to_next(encrypted, encryptedRes);
        decryptor.decrypt(encryptedRes, plain);
        parms_id = context.get_context_data(parms_id)->next_context_data()->parms_id();
        ASSERT_TRUE(encryptedRes.parms_id() == parms_id);
        ASSERT_TRUE(plain.to_string() == "5x^64 + Ax^5");

        evaluator.mod_switch_to_next_inplace(encryptedRes);
        decryptor.decrypt(encryptedRes, plain);
        parms_id = context.get_context_data(parms_id)->next_context_data()->parms_id();
        ASSERT_TRUE(encryptedRes.parms_id() == parms_id);
        ASSERT_TRUE(plain.to_string() == "5x^64 + Ax^5");
    }

    TEST(EvaluatorTest, BFVEncryptModReduceToNextDecrypt)
    {
        Modulus plain_modulus(1 << 6);

        EncryptionParameters parms(scheme_type::bfv);
        parms.set_poly_modulus_degree(128);
        parms.set_plain_modulus(plain_modulus);
        parms.set_coeff_modulus(CoeffModulus::Create(128, { 30, 30, 30, 30 }));

        SEALContext context(parms, true, sec_level_type::none);
        KeyGenerator keygen(context);
        SecretKey secret_key = keygen.secret_key();
        PublicKey pk;
        keygen.create_public_key(pk);

        Encryptor encryptor(context, pk);
        Evaluator evaluator(context);
        Decryptor decryptor(context, secret_key);

        Plaintext original("Ax^5 + 3x^2 + 7");
        Ciphertext encrypted(context);
        encryptor.encrypt(original, encrypted);

        uint64_t dropped = context.get_context_data(encrypted.parms_id())->parms().coeff_modulus().back().value();
        uint64_t t = plain_modulus.value();
        uint64_t factor = dropped % t;

        Ciphertext reduced;
        evaluator.mod_reduce_to_next(encrypted, reduced);

        ASSERT_FALSE(reduced.is_ntt_form());
        auto next_parms_id = context.get_context_data(encrypted.parms_id())->next_context_data()->parms_id();
        ASSERT_TRUE(reduced.parms_id() == next_parms_id);

        Plaintext result;
        decryptor.decrypt(reduced, result);

        Plaintext expected = original;
        for (size_t i = 0; i < expected.coeff_count(); i++)
        {
            expected[i] = (factor * expected[i]) % t;
        }
        ASSERT_EQ(expected.to_string(), result.to_string());

        Ciphertext ntt_form(context);
        encryptor.encrypt(original, ntt_form);
        evaluator.transform_to_ntt_inplace(ntt_form);
        Ciphertext unused;
        ASSERT_THROW(evaluator.mod_reduce_to_next(ntt_form, unused), invalid_argument);
    }

    TEST(EvaluatorTest, BGVEncryptModReduceToNextDecrypt)
    {
        Modulus plain_modulus(65);

        EncryptionParameters parms(scheme_type::bgv);
        parms.set_poly_modulus_degree(128);
        parms.set_plain_modulus(plain_modulus);
        parms.set_coeff_modulus(CoeffModulus::Create(128, { 30, 30, 30, 30 }));

        SEALContext context(parms, true, sec_level_type::none);
        KeyGenerator keygen(context);
        SecretKey secret_key = keygen.secret_key();
        PublicKey pk;
        keygen.create_public_key(pk);

        Encryptor encryptor(context, pk);
        Evaluator evaluator(context);
        Decryptor decryptor(context, secret_key);

        Plaintext original("9x^3 + 2");
        Ciphertext encrypted(context);
        encryptor.encrypt(original, encrypted);
        ASSERT_TRUE(encrypted.is_ntt_form());

        Ciphertext reduced;
        evaluator.mod_reduce_to_next(encrypted, reduced);

        ASSERT_TRUE(reduced.is_ntt_form());
        auto next_parms_id = context.get_context_data(encrypted.parms_id())->next_context_data()->parms_id();
        ASSERT_TRUE(reduced.parms_id() == next_parms_id);

        Plaintext result;
        ASSERT_NO_THROW(decryptor.decrypt(reduced, result));
    }

    TEST(EvaluatorTest, BFVEncryptModSwitchToDecrypt)
    {
        // The common parameters: the plaintext and the polynomial moduli
        Modulus plain_modulus(1 << 6);

        // The parameters and the context of the higher level
        EncryptionParameters parms(scheme_type::bfv);
        parms.set_poly_modulus_degree(128);
        parms.set_plain_modulus(plain_modulus);
        parms.set_coeff_modulus(CoeffModulus::Create(128, { 30, 30, 30, 30 }));

        SEALContext context(parms, true, sec_level_type::none);
        KeyGenerator keygen(context);
        SecretKey secret_key = keygen.secret_key();
        PublicKey pk;
        keygen.create_public_key(pk);

        Encryptor encryptor(context, pk);
        Evaluator evaluator(context);
        Decryptor decryptor(context, keygen.secret_key());
        auto parms_id = context.first_parms_id();

        Ciphertext encrypted(context);
        Plaintext plain;

        plain = 0;
        encryptor.encrypt(plain, encrypted);
        evaluator.mod_switch_to_inplace(encrypted, parms_id);
        decryptor.decrypt(encrypted, plain);
        ASSERT_TRUE(encrypted.parms_id() == parms_id);
        ASSERT_TRUE(plain.to_string() == "0");

        parms_id = context.get_context_data(parms_id)->next_context_data()->parms_id();
        encryptor.encrypt(plain, encrypted);
        evaluator.mod_switch_to_inplace(encrypted, parms_id);
        decryptor.decrypt(encrypted, plain);
        ASSERT_TRUE(encrypted.parms_id() == parms_id);
        ASSERT_TRUE(plain.to_string() == "0");

        parms_id = context.get_context_data(parms_id)->next_context_data()->parms_id();
        encryptor.encrypt(plain, encrypted);
        evaluator.mod_switch_to_inplace(encrypted, parms_id);
        decryptor.decrypt(encrypted, plain);
        ASSERT_TRUE(encrypted.parms_id() == parms_id);
        ASSERT_TRUE(plain.to_string() == "0");

        parms_id = context.first_parms_id();
        encryptor.encrypt(plain, encrypted);
        parms_id = context.get_context_data(parms_id)->next_context_data()->next_context_data()->parms_id();
        evaluator.mod_switch_to_inplace(encrypted, parms_id);
        decryptor.decrypt(encrypted, plain);
        ASSERT_TRUE(encrypted.parms_id() == parms_id);
        ASSERT_TRUE(plain.to_string() == "0");

        parms_id = context.first_parms_id();
        plain = 1;
        encryptor.encrypt(plain, encrypted);
        evaluator.mod_switch_to_inplace(encrypted, parms_id);
        decryptor.decrypt(encrypted, plain);
        ASSERT_TRUE(encrypted.parms_id() == parms_id);
        ASSERT_TRUE(plain.to_string() == "1");

        parms_id = context.get_context_data(parms_id)->next_context_data()->parms_id();
        encryptor.encrypt(plain, encrypted);
        evaluator.mod_switch_to_inplace(encrypted, parms_id);
        decryptor.decrypt(encrypted, plain);
        ASSERT_TRUE(encrypted.parms_id() == parms_id);
        ASSERT_TRUE(plain.to_string() == "1");

        parms_id = context.get_context_data(parms_id)->next_context_data()->parms_id();
        encryptor.encrypt(plain, encrypted);
        evaluator.mod_switch_to_inplace(encrypted, parms_id);
        decryptor.decrypt(encrypted, plain);
        ASSERT_TRUE(encrypted.parms_id() == parms_id);
        ASSERT_TRUE(plain.to_string() == "1");

        parms_id = context.first_parms_id();
        encryptor.encrypt(plain, encrypted);
        parms_id = context.get_context_data(parms_id)->next_context_data()->next_context_data()->parms_id();
        evaluator.mod_switch_to_inplace(encrypted, parms_id);
        decryptor.decrypt(encrypted, plain);
        ASSERT_TRUE(encrypted.parms_id() == parms_id);
        ASSERT_TRUE(plain.to_string() == "1");

        parms_id = context.first_parms_id();
        plain = "1x^127";
        encryptor.encrypt(plain, encrypted);
        evaluator.mod_switch_to_inplace(encrypted, parms_id);
        decryptor.decrypt(encrypted, plain);
        ASSERT_TRUE(encrypted.parms_id() == parms_id);
        ASSERT_TRUE(plain.to_string() == "1x^127");

        parms_id = context.get_context_data(parms_id)->next_context_data()->parms_id();
        encryptor.encrypt(plain, encrypted);
        evaluator.mod_switch_to_inplace(encrypted, parms_id);
        decryptor.decrypt(encrypted, plain);
        ASSERT_TRUE(encrypted.parms_id() == parms_id);
        ASSERT_TRUE(plain.to_string() == "1x^127");

        parms_id = context.get_context_data(parms_id)->next_context_data()->parms_id();
        encryptor.encrypt(plain, encrypted);
        evaluator.mod_switch_to_inplace(encrypted, parms_id);
        decryptor.decrypt(encrypted, plain);
        ASSERT_TRUE(encrypted.parms_id() == parms_id);
        ASSERT_TRUE(plain.to_string() == "1x^127");

        parms_id = context.first_parms_id();
        encryptor.encrypt(plain, encrypted);
        parms_id = context.get_context_data(parms_id)->next_context_data()->next_context_data()->parms_id();
        evaluator.mod_switch_to_inplace(encrypted, parms_id);
        decryptor.decrypt(encrypted, plain);
        ASSERT_TRUE(encrypted.parms_id() == parms_id);
        ASSERT_TRUE(plain.to_string() == "1x^127");

        parms_id = context.first_parms_id();
        plain = "5x^64 + Ax^5";
        encryptor.encrypt(plain, encrypted);
        evaluator.mod_switch_to_inplace(encrypted, parms_id);
        decryptor.decrypt(encrypted, plain);
        ASSERT_TRUE(encrypted.parms_id() == parms_id);
        ASSERT_TRUE(plain.to_string() == "5x^64 + Ax^5");

        parms_id = context.get_context_data(parms_id)->next_context_data()->parms_id();
        encryptor.encrypt(plain, encrypted);
        evaluator.mod_switch_to_inplace(encrypted, parms_id);
        decryptor.decrypt(encrypted, plain);
        ASSERT_TRUE(encrypted.parms_id() == parms_id);
        ASSERT_TRUE(plain.to_string() == "5x^64 + Ax^5");

        parms_id = context.get_context_data(parms_id)->next_context_data()->parms_id();
        encryptor.encrypt(plain, encrypted);
        evaluator.mod_switch_to_inplace(encrypted, parms_id);
        decryptor.decrypt(encrypted, plain);
        ASSERT_TRUE(encrypted.parms_id() == parms_id);
        ASSERT_TRUE(plain.to_string() == "5x^64 + Ax^5");

        parms_id = context.first_parms_id();
        encryptor.encrypt(plain, encrypted);
        parms_id = context.get_context_data(parms_id)->next_context_data()->next_context_data()->parms_id();
        evaluator.mod_switch_to_inplace(encrypted, parms_id);
        decryptor.decrypt(encrypted, plain);
        ASSERT_TRUE(encrypted.parms_id() == parms_id);
        ASSERT_TRUE(plain.to_string() == "5x^64 + Ax^5");
    }

    TEST(EvaluatorTest, BGVEncryptMultiplyPlainNTTDecrypt)
    {
        EncryptionParameters parms(scheme_type::bgv);
        Modulus plain_modulus(65);
        parms.set_poly_modulus_degree(128);
        parms.set_plain_modulus(plain_modulus);
        parms.set_coeff_modulus(CoeffModulus::Create(128, { 40, 40 }));

        SEALContext context(parms, false, sec_level_type::none);
        KeyGenerator keygen(context);
        PublicKey pk;
        keygen.create_public_key(pk);

        Encryptor encryptor(context, pk);
        Evaluator evaluator(context);
        Decryptor decryptor(context, keygen.secret_key());

        Plaintext plain;
        Plaintext plain_multiplier;
        Ciphertext encrypted;

        plain = 0;
        encryptor.encrypt(plain, encrypted);
        plain_multiplier = 1;
        evaluator.transform_to_ntt_inplace(plain_multiplier, context.first_parms_id());
        evaluator.multiply_plain_inplace(encrypted, plain_multiplier);
        decryptor.decrypt(encrypted, plain);
        ASSERT_TRUE(plain.to_string() == "0");
        ASSERT_TRUE(encrypted.parms_id() == context.first_parms_id());

        plain = 2;
        encryptor.encrypt(plain, encrypted);
        plain_multiplier.release();
        plain_multiplier = 3;
        evaluator.transform_to_ntt_inplace(plain_multiplier, context.first_parms_id());
        evaluator.multiply_plain_inplace(encrypted, plain_multiplier);
        decryptor.decrypt(encrypted, plain);
        ASSERT_TRUE(plain.to_string() == "6");
        ASSERT_TRUE(encrypted.parms_id() == context.first_parms_id());

        plain = 1;
        encryptor.encrypt(plain, encrypted);
        plain_multiplier.release();
        plain_multiplier = "Fx^10 + Ex^9 + Dx^8 + Cx^7 + Bx^6 + Ax^5 + 1x^4 + 2x^3 + 3x^2 + 4x^1 + 5";
        evaluator.transform_to_ntt_inplace(plain_multiplier, context.first_parms_id());
        evaluator.multiply_plain_inplace(encrypted, plain_multiplier);
        decryptor.decrypt(encrypted, plain);
        ASSERT_TRUE(plain.to_string() == "Fx^10 + Ex^9 + Dx^8 + Cx^7 + Bx^6 + Ax^5 + 1x^4 + 2x^3 + 3x^2 + 4x^1 + 5");
        ASSERT_TRUE(encrypted.parms_id() == context.first_parms_id());

        plain = "1x^20";
        encryptor.encrypt(plain, encrypted);
        plain_multiplier.release();
        plain_multiplier = "Fx^10 + Ex^9 + Dx^8 + Cx^7 + Bx^6 + Ax^5 + 1x^4 + 2x^3 + 3x^2 + 4x^1 + 5";
        evaluator.transform_to_ntt_inplace(plain_multiplier, context.first_parms_id());
        evaluator.multiply_plain_inplace(encrypted, plain_multiplier);
        decryptor.decrypt(encrypted, plain);
        ASSERT_TRUE(
            plain.to_string() ==
            "Fx^30 + Ex^29 + Dx^28 + Cx^27 + Bx^26 + Ax^25 + 1x^24 + 2x^23 + 3x^22 + 4x^21 + 5x^20");
        ASSERT_TRUE(encrypted.parms_id() == context.first_parms_id());
    }

    TEST(EvaluatorTest, BGVEncryptApplyGaloisDecrypt)
    {
        EncryptionParameters parms(scheme_type::bgv);
        Modulus plain_modulus(257);
        parms.set_poly_modulus_degree(8);
        parms.set_plain_modulus(plain_modulus);
        parms.set_coeff_modulus(CoeffModulus::Create(8, { 60, 40 }));

        SEALContext context(parms, false, sec_level_type::none);
        KeyGenerator keygen(context);
        PublicKey pk;
        keygen.create_public_key(pk);
        GaloisKeys glk;
        keygen.create_galois_keys(vector<uint32_t>{ 1, 3, 5, 15 }, glk);

        Encryptor encryptor(context, pk);
        Evaluator evaluator(context);
        Decryptor decryptor(context, keygen.secret_key());

        Plaintext plain("1");
        Ciphertext encrypted;
        encryptor.encrypt(plain, encrypted);
        evaluator.apply_galois_inplace(encrypted, 1, glk);
        decryptor.decrypt(encrypted, plain);
        ASSERT_TRUE("1" == plain.to_string());
        evaluator.apply_galois_inplace(encrypted, 3, glk);
        decryptor.decrypt(encrypted, plain);
        ASSERT_TRUE("1" == plain.to_string());
        evaluator.apply_galois_inplace(encrypted, 5, glk);
        decryptor.decrypt(encrypted, plain);
        ASSERT_TRUE("1" == plain.to_string());
        evaluator.apply_galois_inplace(encrypted, 15, glk);
        decryptor.decrypt(encrypted, plain);
        ASSERT_TRUE("1" == plain.to_string());

        plain = "1x^1";
        encryptor.encrypt(plain, encrypted);
        evaluator.apply_galois_inplace(encrypted, 1, glk);
        decryptor.decrypt(encrypted, plain);
        ASSERT_TRUE("1x^1" == plain.to_string());
        evaluator.apply_galois_inplace(encrypted, 3, glk);
        decryptor.decrypt(encrypted, plain);
        ASSERT_TRUE("1x^3" == plain.to_string());
        evaluator.apply_galois_inplace(encrypted, 5, glk);
        decryptor.decrypt(encrypted, plain);
        ASSERT_TRUE("100x^7" == plain.to_string());
        evaluator.apply_galois_inplace(encrypted, 15, glk);
        decryptor.decrypt(encrypted, plain);
        ASSERT_TRUE("1x^1" == plain.to_string());

        plain = "1x^2";
        encryptor.encrypt(plain, encrypted);
        evaluator.apply_galois_inplace(encrypted, 1, glk);
        decryptor.decrypt(encrypted, plain);
        ASSERT_TRUE("1x^2" == plain.to_string());
        evaluator.apply_galois_inplace(encrypted, 3, glk);
        decryptor.decrypt(encrypted, plain);
        ASSERT_TRUE("1x^6" == plain.to_string());
        evaluator.apply_galois_inplace(encrypted, 5, glk);
        decryptor.decrypt(encrypted, plain);
        ASSERT_TRUE("100x^6" == plain.to_string());
        evaluator.apply_galois_inplace(encrypted, 15, glk);
        decryptor.decrypt(encrypted, plain);
        ASSERT_TRUE("1x^2" == plain.to_string());

        plain = "1x^3 + 2x^2 + 1x^1 + 1";
        encryptor.encrypt(plain, encrypted);
        evaluator.apply_galois_inplace(encrypted, 1, glk);
        decryptor.decrypt(encrypted, plain);
        ASSERT_TRUE("1x^3 + 2x^2 + 1x^1 + 1" == plain.to_string());
        evaluator.apply_galois_inplace(encrypted, 3, glk);
        decryptor.decrypt(encrypted, plain);
        ASSERT_TRUE("2x^6 + 1x^3 + 100x^1 + 1" == plain.to_string());
        evaluator.apply_galois_inplace(encrypted, 5, glk);
        decryptor.decrypt(encrypted, plain);
        ASSERT_TRUE("100x^7 + FFx^6 + 100x^5 + 1" == plain.to_string());
        evaluator.apply_galois_inplace(encrypted, 15, glk);
        decryptor.decrypt(encrypted, plain);
        ASSERT_TRUE("1x^3 + 2x^2 + 1x^1 + 1" == plain.to_string());
    }

    TEST(EvaluatorTest, BGVEncryptRotateMatrixDecrypt)
    {
        EncryptionParameters parms(scheme_type::bgv);
        Modulus plain_modulus(257);
        parms.set_poly_modulus_degree(8);
        parms.set_plain_modulus(plain_modulus);
        parms.set_coeff_modulus(CoeffModulus::Create(8, { 40, 40 }));

        SEALContext context(parms, false, sec_level_type::none);
        KeyGenerator keygen(context);
        PublicKey pk;
        keygen.create_public_key(pk);
        GaloisKeys glk;
        keygen.create_galois_keys(glk);

        Encryptor encryptor(context, pk);
        Evaluator evaluator(context);
        Decryptor decryptor(context, keygen.secret_key());
        BatchEncoder batch_encoder(context);

        Plaintext plain;
        vector<uint64_t> plain_vec{ 1, 2, 3, 4, 5, 6, 7, 8 };
        batch_encoder.encode(plain_vec, plain);
        Ciphertext encrypted;
        encryptor.encrypt(plain, encrypted);

        evaluator.rotate_columns_inplace(encrypted, glk);
        decryptor.decrypt(encrypted, plain);
        batch_encoder.decode(plain, plain_vec);
        ASSERT_TRUE((plain_vec == vector<uint64_t>{ 5, 6, 7, 8, 1, 2, 3, 4 }));

        evaluator.rotate_rows_inplace(encrypted, -1, glk);
        decryptor.decrypt(encrypted, plain);
        batch_encoder.decode(plain, plain_vec);
        ASSERT_TRUE((plain_vec == vector<uint64_t>{ 8, 5, 6, 7, 4, 1, 2, 3 }));

        evaluator.rotate_rows_inplace(encrypted, 2, glk);
        decryptor.decrypt(encrypted, plain);
        batch_encoder.decode(plain, plain_vec);
        ASSERT_TRUE((plain_vec == vector<uint64_t>{ 6, 7, 8, 5, 2, 3, 4, 1 }));

        evaluator.rotate_columns_inplace(encrypted, glk);
        decryptor.decrypt(encrypted, plain);
        batch_encoder.decode(plain, plain_vec);
        ASSERT_TRUE((plain_vec == vector<uint64_t>{ 2, 3, 4, 1, 6, 7, 8, 5 }));

        evaluator.rotate_rows_inplace(encrypted, 0, glk);
        decryptor.decrypt(encrypted, plain);
        batch_encoder.decode(plain, plain_vec);
        ASSERT_TRUE((plain_vec == vector<uint64_t>{ 2, 3, 4, 1, 6, 7, 8, 5 }));
    }

    namespace
    {
        // Same metadata and data
        bool same_ciphertext(const Ciphertext &a, const Ciphertext &b)
        {
            return a.parms_id() == b.parms_id() && a.size() == b.size() && a.is_ntt_form() == b.is_ntt_form() &&
                   a.scale() == b.scale() && a.correction_factor() == b.correction_factor() &&
                   a.dyn_array().size() == b.dyn_array().size() &&
                   equal(a.dyn_array().cbegin(), a.dyn_array().cend(), b.dyn_array().cbegin());
        }

        void rotate(
            const Evaluator &evaluator, scheme_type scheme, const Ciphertext &encrypted, int steps,
            const GaloisKeys &galois_keys, Ciphertext &destination)
        {
            if (scheme == scheme_type::ckks)
            {
                evaluator.rotate_vector(encrypted, steps, galois_keys, destination);
            }
            else
            {
                evaluator.rotate_rows(encrypted, steps, galois_keys, destination);
            }
        }

        void rotate(
            const Evaluator &evaluator, scheme_type scheme, const Ciphertext &encrypted, const vector<int> &steps,
            const GaloisKeys &galois_keys, vector<Ciphertext> &destinations,
            MemoryPoolHandle pool = MemoryManager::GetPool())
        {
            if (scheme == scheme_type::ckks)
            {
                evaluator.rotate_vector(encrypted, steps, galois_keys, destinations, std::move(pool));
            }
            else
            {
                evaluator.rotate_rows(encrypted, steps, galois_keys, destinations, std::move(pool));
            }
        }

        // Mixed prime sizes, so that key switching reduces only some digits before the NTT
        EncryptionParameters rotation_parms(scheme_type scheme)
        {
            size_t n = 64;
            EncryptionParameters parms(scheme);
            parms.set_poly_modulus_degree(n);
            parms.set_coeff_modulus(CoeffModulus::Create(n, { 40, 30, 50, 60 }));
            if (scheme != scheme_type::ckks)
            {
                parms.set_plain_modulus(PlainModulus::Batching(n, 17));
            }
            return parms;
        }
    } // namespace

    TEST(EvaluatorTest, BFVBGVEncryptRotateRowsMultipleStepsDecrypt)
    {
        for (auto scheme : { scheme_type::bfv, scheme_type::bgv })
        {
            SEALContext context(rotation_parms(scheme), true, sec_level_type::none);
            KeyGenerator keygen(context);
            PublicKey pk;
            keygen.create_public_key(pk);
            GaloisKeys glk;
            keygen.create_galois_keys(vector<int>{ 1, -1, 3, 8 }, glk);

            Encryptor encryptor(context, pk);
            Evaluator evaluator(context);
            Decryptor decryptor(context, keygen.secret_key());
            BatchEncoder batch_encoder(context);

            size_t row_size = batch_encoder.slot_count() / 2;
            uint64_t plain_modulus = context.first_context_data()->parms().plain_modulus().value();
            vector<uint64_t> plain_vec(batch_encoder.slot_count());
            for (size_t i = 0; i < plain_vec.size(); i++)
            {
                plain_vec[i] = (i * 37 + 11) % plain_modulus;
            }
            Plaintext plain;
            batch_encoder.encode(plain_vec, plain);
            Ciphertext encrypted;
            encryptor.encrypt(plain, encrypted);

            // Zero, repeated, and composed (9 = 8 + 1) steps
            vector<vector<int>> step_lists{ { 1, -1, 3, 0, 9, 1, -1 }, { 3 }, { 9 }, { 0, 0 }, { -1, 8 } };
            while (true)
            {
                for (auto &steps : step_lists)
                {
                    vector<Ciphertext> destinations;
                    evaluator.rotate_rows(encrypted, steps, glk, destinations);
                    ASSERT_EQ(steps.size(), destinations.size());
                    for (size_t i = 0; i < steps.size(); i++)
                    {
                        Ciphertext expected;
                        evaluator.rotate_rows(encrypted, steps[i], glk, expected);
                        ASSERT_TRUE(same_ciphertext(expected, destinations[i]));

                        Plaintext plain_result;
                        decryptor.decrypt(destinations[i], plain_result);
                        vector<uint64_t> result;
                        batch_encoder.decode(plain_result, result);
                        size_t shift = static_cast<size_t>(steps[i] + static_cast<int>(row_size)) % row_size;
                        for (size_t j = 0; j < row_size; j++)
                        {
                            ASSERT_EQ(plain_vec[(j + shift) % row_size], result[j]);
                            ASSERT_EQ(plain_vec[row_size + (j + shift) % row_size], result[row_size + j]);
                        }
                    }
                }
                if (encrypted.parms_id() == context.last_parms_id())
                {
                    break;
                }
                evaluator.mod_switch_to_next_inplace(encrypted);
            }
        }
    }

    TEST(EvaluatorTest, CKKSEncryptRotateVectorMultipleStepsDecrypt)
    {
        SEALContext context(rotation_parms(scheme_type::ckks), true, sec_level_type::none);
        KeyGenerator keygen(context);
        PublicKey pk;
        keygen.create_public_key(pk);
        GaloisKeys glk;
        keygen.create_galois_keys(vector<int>{ 1, -2, 4 }, glk);

        Encryptor encryptor(context, pk);
        Evaluator evaluator(context);
        Decryptor decryptor(context, keygen.secret_key());
        CKKSEncoder encoder(context);

        size_t slot_count = encoder.slot_count();
        vector<complex<double>> input(slot_count);
        for (size_t i = 0; i < slot_count; i++)
        {
            input[i] = complex<double>(static_cast<double>(i % 7) - 3.0, static_cast<double>(i % 3));
        }
        Plaintext plain;
        encoder.encode(input, pow(2.0, 25), plain);
        Ciphertext encrypted;
        encryptor.encrypt(plain, encrypted);

        // Zero, repeated, and composed (5 = 4 + 1) steps
        vector<vector<int>> step_lists{ { 1, -2, 4, 0, 5, 1 }, { 4 }, { 5 }, { 0 } };
        while (true)
        {
            for (auto &steps : step_lists)
            {
                vector<Ciphertext> destinations;
                evaluator.rotate_vector(encrypted, steps, glk, destinations);
                ASSERT_EQ(steps.size(), destinations.size());
                for (size_t i = 0; i < steps.size(); i++)
                {
                    Ciphertext expected;
                    evaluator.rotate_vector(encrypted, steps[i], glk, expected);
                    ASSERT_TRUE(same_ciphertext(expected, destinations[i]));

                    Plaintext plain_result;
                    decryptor.decrypt(destinations[i], plain_result);
                    vector<complex<double>> result;
                    encoder.decode(plain_result, result);
                    size_t shift = static_cast<size_t>(steps[i] + static_cast<int>(slot_count)) % slot_count;
                    for (size_t j = 0; j < slot_count; j++)
                    {
                        ASSERT_NEAR(input[(j + shift) % slot_count].real(), result[j].real(), 0.01);
                        ASSERT_NEAR(input[(j + shift) % slot_count].imag(), result[j].imag(), 0.01);
                    }
                }
            }
            if (encrypted.parms_id() == context.last_parms_id())
            {
                break;
            }
            evaluator.mod_switch_to_next_inplace(encrypted);
        }
    }

    TEST(EvaluatorTest, RotateMultipleStepsZeroDigits)
    {
        // Hoisted rotations recompute digits with zero coefficients
        for (auto scheme : { scheme_type::bfv, scheme_type::bgv, scheme_type::ckks })
        {
            SEALContext context(rotation_parms(scheme), true, sec_level_type::none);
            KeyGenerator keygen(context);
            PublicKey pk;
            keygen.create_public_key(pk);
            GaloisKeys glk;
            keygen.create_galois_keys(vector<int>{ 1, -1, 3 }, glk);

            Encryptor encryptor(context, pk);
            Evaluator evaluator(context);

            Ciphertext encrypted;
            encryptor.encrypt_zero(encrypted);
            vector<int> steps{ 1, -1, 3 };
            for (size_t level = 0; level < 2; level++)
            {
                // Zero some coefficients of digit 0 and all of digit 2 (if any)
                Ciphertext crafted = encrypted;
                size_t n = crafted.poly_modulus_degree();
                auto ntt_tables = context.get_context_data(crafted.parms_id())->small_ntt_tables();
                for (size_t j = 0; j < crafted.coeff_modulus_size(); j++)
                {
                    util::CoeffIter digit(crafted.data(1) + j * n);
                    if (crafted.is_ntt_form())
                    {
                        util::inverse_ntt_negacyclic_harvey(digit, ntt_tables[j]);
                    }
                    for (size_t l = 0; l < n; l++)
                    {
                        if ((j == 0 && l % 5 == 0) || j == 2)
                        {
                            digit[l] = 0;
                        }
                    }
                    if (crafted.is_ntt_form())
                    {
                        util::ntt_negacyclic_harvey(digit, ntt_tables[j]);
                    }
                }

                vector<Ciphertext> destinations;
                rotate(evaluator, scheme, crafted, steps, glk, destinations);
                ASSERT_EQ(steps.size(), destinations.size());
                for (size_t i = 0; i < steps.size(); i++)
                {
                    Ciphertext expected;
                    rotate(evaluator, scheme, crafted, steps[i], glk, expected);
                    ASSERT_TRUE(same_ciphertext(expected, destinations[i]));
                }

                evaluator.mod_switch_to_next_inplace(encrypted);
            }
        }
    }

    TEST(EvaluatorTest, RotateMultipleStepsDestinations)
    {
        for (auto scheme : { scheme_type::bfv, scheme_type::bgv, scheme_type::ckks })
        {
            SEALContext context(rotation_parms(scheme), true, sec_level_type::none);
            KeyGenerator keygen(context);
            PublicKey pk;
            keygen.create_public_key(pk);
            GaloisKeys glk;
            keygen.create_galois_keys(vector<int>{ 1, 8, -1 }, glk);

            Encryptor encryptor(context, pk);
            Evaluator evaluator(context);

            Ciphertext encrypted;
            Ciphertext other;
            encryptor.encrypt_zero(encrypted);
            encryptor.encrypt_zero(other);

            // Zero and composed (9 = 8 + 1) steps
            vector<int> steps{ 1, 8, 0, 9, -1 };
            vector<Ciphertext> expected(steps.size());
            for (size_t i = 0; i < steps.size(); i++)
            {
                rotate(evaluator, scheme, encrypted, steps[i], glk, expected[i]);
            }

            // Existing elements keep their pools, and memory if large enough; new ones use pool
            auto pool = MemoryPoolHandle::New();
            auto destination_pool = MemoryPoolHandle::New();
            vector<Ciphertext> destinations;
            destinations.emplace_back(context, encrypted.parms_id(), 2, destination_pool);
            destinations.emplace_back(destination_pool);
            destinations[0].resize(context, encrypted.parms_id(), 2);
            const uint64_t *buffer = destinations[0].data();

            rotate(evaluator, scheme, encrypted, steps, glk, destinations, pool);
            ASSERT_EQ(steps.size(), destinations.size());
            ASSERT_TRUE(destinations[0].pool() == destination_pool);
            ASSERT_EQ(buffer, destinations[0].data());
            ASSERT_TRUE(destinations[1].pool() == destination_pool);
            for (size_t i = 0; i < steps.size(); i++)
            {
                ASSERT_TRUE(i < 2 || destinations[i].pool() == pool);
                ASSERT_TRUE(same_ciphertext(expected[i], destinations[i]));
            }

            // Temporary memory comes from pool
            {
                MMProfGuard guard(make_unique<MMProfFixed>(MemoryPoolHandle::New()));
                rotate(evaluator, scheme, encrypted, steps, glk, destinations, pool);
                ASSERT_EQ(0ULL, MemoryManager::GetPool().alloc_byte_count());
            }
            ASSERT_TRUE(pool.alloc_byte_count() > 0);
            for (size_t i = 0; i < steps.size(); i++)
            {
                ASSERT_TRUE(same_ciphertext(expected[i], destinations[i]));
            }

            rotate(evaluator, scheme, encrypted, vector<int>{ 8 }, glk, destinations, pool);
            ASSERT_EQ(1ULL, destinations.size());
            ASSERT_TRUE(destinations[0].pool() == destination_pool);
            ASSERT_TRUE(same_ciphertext(expected[1], destinations[0]));

            // encrypted may be any element of destinations
            vector<vector<int>> step_lists{ steps, { -1, 1 } };
            for (auto &alias_steps : step_lists)
            {
                for (size_t alias = 0; alias < 3; alias++)
                {
                    vector<Ciphertext> aliased{ other, other, other };
                    aliased[alias] = encrypted;
                    rotate(evaluator, scheme, aliased[alias], alias_steps, glk, aliased);
                    ASSERT_EQ(alias_steps.size(), aliased.size());
                    for (size_t i = 0; i < alias_steps.size(); i++)
                    {
                        Ciphertext alias_expected;
                        rotate(evaluator, scheme, encrypted, alias_steps[i], glk, alias_expected);
                        ASSERT_TRUE(same_ciphertext(alias_expected, aliased[i]));
                    }
                }
            }

            rotate(evaluator, scheme, encrypted, vector<int>{}, glk, destinations);
            ASSERT_TRUE(destinations.empty());
        }
    }

    TEST(EvaluatorTest, RotateMultipleStepsValidatesBeforeWork)
    {
        for (auto scheme : { scheme_type::bfv, scheme_type::bgv, scheme_type::ckks })
        {
            SEALContext context(rotation_parms(scheme), true, sec_level_type::none);
            KeyGenerator keygen(context);
            PublicKey pk;
            keygen.create_public_key(pk);
            GaloisKeys glk;
            keygen.create_galois_keys(vector<int>{ 1, -1, 8 }, glk);
            RelinKeys rlk;
            keygen.create_relin_keys(rlk);

            Encryptor encryptor(context, pk);
            Evaluator evaluator(context);

            Ciphertext encrypted;
            encryptor.encrypt_zero(encrypted);
            const Ciphertext encrypted_copy = encrypted;

            Ciphertext other;
            encryptor.encrypt_zero(other);
            vector<Ciphertext> destinations{ other, other };
            const vector<Ciphertext> destinations_copy = destinations;
            const uint64_t *buffer = destinations[0].data();

            auto unchanged = [&]() {
                return destinations.size() == 2 && same_ciphertext(destinations[0], destinations_copy[0]) &&
                       same_ciphertext(destinations[1], destinations_copy[1]) && destinations[0].data() == buffer &&
                       same_ciphertext(encrypted, encrypted_copy);
            };

            // Steps without keys or out of range, after valid steps (9 = 8 + 1)
            int half = static_cast<int>(encrypted.poly_modulus_degree() / 2);
            vector<int> invalid_steps{ 2, 5, half, -half, numeric_limits<int>::min() };
            for (int invalid_step : invalid_steps)
            {
                ASSERT_THROW(
                    rotate(evaluator, scheme, encrypted, vector<int>{ 1, 9, invalid_step }, glk, destinations),
                    invalid_argument);
                ASSERT_TRUE(unchanged());

                Ciphertext single;
                ASSERT_THROW(rotate(evaluator, scheme, encrypted, invalid_step, glk, single), invalid_argument);
            }

            // Invalid ciphertexts
            Ciphertext size3;
            evaluator.square(encrypted, size3);
            ASSERT_THROW(rotate(evaluator, scheme, size3, vector<int>{ 1, -1 }, glk, destinations), invalid_argument);
            ASSERT_TRUE(unchanged());

            Ciphertext wrong_form = encrypted;
            wrong_form.is_ntt_form() = !wrong_form.is_ntt_form();
            ASSERT_THROW(
                rotate(evaluator, scheme, wrong_form, vector<int>{ 1, -1 }, glk, destinations), invalid_argument);
            ASSERT_TRUE(unchanged());

            Ciphertext wrong_scale = encrypted;
            wrong_scale.scale() = 0.0;
            ASSERT_THROW(
                rotate(evaluator, scheme, wrong_scale, vector<int>{ 1, -1 }, glk, destinations), invalid_argument);
            ASSERT_TRUE(unchanged());

            Ciphertext seed_marker = encrypted;
            seed_marker.data(1)[0] = numeric_limits<uint64_t>::max();
            ASSERT_THROW(
                rotate(evaluator, scheme, seed_marker, vector<int>{ 1, -1 }, glk, destinations), invalid_argument);
            ASSERT_TRUE(unchanged());

            // Zero steps only copy, so a size-3 ciphertext is accepted
            vector<Ciphertext> copies;
            rotate(evaluator, scheme, size3, vector<int>{ 0 }, glk, copies);
            ASSERT_TRUE(same_ciphertext(size3, copies[0]));

            // Invalid keys
            GaloisKeys wrong_level = glk;
            wrong_level.parms_id() = context.first_parms_id();
            ASSERT_THROW(
                rotate(evaluator, scheme, encrypted, vector<int>{ 1, -1 }, wrong_level, destinations),
                invalid_argument);
            ASSERT_TRUE(unchanged());

            uint32_t galois_elt = context.key_context_data()->galois_tool()->get_elt_from_step(1);
            GaloisKeys short_key = glk;
            short_key.data()[GaloisKeys::get_index(galois_elt)].resize(1);
            ASSERT_THROW(
                rotate(evaluator, scheme, encrypted, vector<int>{ -1, 1 }, short_key, destinations), invalid_argument);
            ASSERT_TRUE(unchanged());
            ASSERT_THROW(
                rotate(evaluator, scheme, encrypted, vector<int>{ -1, 9 }, short_key, destinations), invalid_argument);
            ASSERT_TRUE(unchanged());

            GaloisKeys invalid_key = glk;
            invalid_key.data()[GaloisKeys::get_index(galois_elt)][0].data().resize(context, context.key_parms_id(), 3);
            ASSERT_THROW(
                rotate(evaluator, scheme, encrypted, vector<int>{ -1, 1 }, invalid_key, destinations),
                invalid_argument);
            ASSERT_TRUE(unchanged());

            // Uninitialized pool
            ASSERT_THROW(
                rotate(evaluator, scheme, encrypted, vector<int>{ 1, -1 }, glk, destinations, MemoryPoolHandle()),
                invalid_argument);
            ASSERT_TRUE(unchanged());

            // Wrong scheme
            if (scheme == scheme_type::ckks)
            {
                ASSERT_THROW(evaluator.rotate_rows(encrypted, vector<int>{ 1 }, glk, destinations), logic_error);
            }
            else
            {
                ASSERT_THROW(evaluator.rotate_vector(encrypted, vector<int>{ 1 }, glk, destinations), logic_error);
            }
            ASSERT_TRUE(unchanged());
        }

        // Parameters without batching
        EncryptionParameters parms(scheme_type::bfv);
        parms.set_poly_modulus_degree(64);
        parms.set_coeff_modulus(CoeffModulus::Create(64, { 40, 40 }));
        parms.set_plain_modulus(1 << 6);

        SEALContext context(parms, false, sec_level_type::none);
        KeyGenerator keygen(context);
        PublicKey pk;
        keygen.create_public_key(pk);
        GaloisKeys glk;
        keygen.create_galois_keys(vector<uint32_t>{ 3 }, glk);

        Encryptor encryptor(context, pk);
        Evaluator evaluator(context);

        Ciphertext encrypted;
        encryptor.encrypt_zero(encrypted);
        vector<Ciphertext> destinations;
        ASSERT_THROW(evaluator.rotate_rows(encrypted, vector<int>{ 1 }, glk, destinations), logic_error);
    }

    TEST(EvaluatorTest, ApplyGaloisValidatesOnlyItsInput)
    {
        // c0 holds 2^64 - 1, so that the intermediate c1 = galois(c0) has the seed marker
#ifndef SEAL_DEBUG
        for (auto scheme : { scheme_type::bfv, scheme_type::bgv, scheme_type::ckks })
        {
            SEALContext context(rotation_parms(scheme), true, sec_level_type::none);
            KeyGenerator keygen(context);
            PublicKey pk;
            keygen.create_public_key(pk);
            GaloisKeys glk;
            keygen.create_galois_keys(vector<int>{ 1, -1 }, glk);

            Encryptor encryptor(context, pk);
            Evaluator evaluator(context);

            Ciphertext encrypted;
            encryptor.encrypt_zero(encrypted);
            size_t n = encrypted.poly_modulus_degree();
            fill_n(encrypted.data(0), n, numeric_limits<uint64_t>::max());
            ASSERT_TRUE(is_metadata_valid_for(encrypted, context) && is_buffer_valid(encrypted));

            Ciphertext destination;
            ASSERT_NO_THROW(rotate(evaluator, scheme, encrypted, 1, glk, destination));
            vector<Ciphertext> destinations;
            ASSERT_NO_THROW(rotate(evaluator, scheme, encrypted, vector<int>{ 1, -1 }, glk, destinations));
        }
#endif
    }

    TEST(EvaluatorTest, BGVEncryptModSwitchToNextDecrypt)
    {
        {
            // The common parameters: the plaintext and the polynomial moduli
            Modulus plain_modulus(65);

            // The parameters and the context of the higher level
            EncryptionParameters parms(scheme_type::bgv);
            parms.set_poly_modulus_degree(128);
            parms.set_plain_modulus(plain_modulus);
            parms.set_coeff_modulus(CoeffModulus::Create(128, { 30, 30, 30, 30 }));

            SEALContext context(parms, true, sec_level_type::none);
            KeyGenerator keygen(context);
            SecretKey secret_key = keygen.secret_key();
            PublicKey pk;
            keygen.create_public_key(pk);

            Encryptor encryptor(context, pk);
            Evaluator evaluator(context);
            Decryptor decryptor(context, keygen.secret_key());
            auto parms_id = context.first_parms_id();

            Ciphertext encrypted(context);
            Ciphertext encryptedRes;
            Plaintext plain;

            plain = 0;
            encryptor.encrypt(plain, encrypted);
            evaluator.mod_switch_to_next(encrypted, encryptedRes);
            decryptor.decrypt(encryptedRes, plain);
            parms_id = context.get_context_data(parms_id)->next_context_data()->parms_id();
            ASSERT_TRUE(encryptedRes.parms_id() == parms_id);
            ASSERT_TRUE(plain.to_string() == "0");

            evaluator.mod_switch_to_next_inplace(encryptedRes);
            decryptor.decrypt(encryptedRes, plain);
            parms_id = context.get_context_data(parms_id)->next_context_data()->parms_id();
            ASSERT_TRUE(encryptedRes.parms_id() == parms_id);
            ASSERT_TRUE(plain.to_string() == "0");

            parms_id = context.first_parms_id();
            plain = 1;
            encryptor.encrypt(plain, encrypted);
            evaluator.mod_switch_to_next(encrypted, encryptedRes);
            decryptor.decrypt(encryptedRes, plain);
            parms_id = context.get_context_data(parms_id)->next_context_data()->parms_id();
            ASSERT_TRUE(encryptedRes.parms_id() == parms_id);
            ASSERT_TRUE(plain.to_string() == "1");

            evaluator.mod_switch_to_next_inplace(encryptedRes);
            decryptor.decrypt(encryptedRes, plain);
            parms_id = context.get_context_data(parms_id)->next_context_data()->parms_id();
            ASSERT_TRUE(encryptedRes.parms_id() == parms_id);
            ASSERT_TRUE(plain.to_string() == "1");

            parms_id = context.first_parms_id();
            plain = "1x^127";
            encryptor.encrypt(plain, encrypted);
            evaluator.mod_switch_to_next(encrypted, encryptedRes);
            decryptor.decrypt(encryptedRes, plain);
            parms_id = context.get_context_data(parms_id)->next_context_data()->parms_id();
            ASSERT_TRUE(encryptedRes.parms_id() == parms_id);
            ASSERT_TRUE(plain.to_string() == "1x^127");

            evaluator.mod_switch_to_next_inplace(encryptedRes);
            decryptor.decrypt(encryptedRes, plain);
            parms_id = context.get_context_data(parms_id)->next_context_data()->parms_id();
            ASSERT_TRUE(encryptedRes.parms_id() == parms_id);
            ASSERT_TRUE(plain.to_string() == "1x^127");

            parms_id = context.first_parms_id();
            plain = "5x^64 + Ax^5";
            encryptor.encrypt(plain, encrypted);
            evaluator.mod_switch_to_next(encrypted, encryptedRes);
            decryptor.decrypt(encryptedRes, plain);
            parms_id = context.get_context_data(parms_id)->next_context_data()->parms_id();
            ASSERT_TRUE(encryptedRes.parms_id() == parms_id);
            ASSERT_TRUE(plain.to_string() == "5x^64 + Ax^5");

            evaluator.mod_switch_to_next_inplace(encryptedRes);
            decryptor.decrypt(encryptedRes, plain);
            parms_id = context.get_context_data(parms_id)->next_context_data()->parms_id();
            ASSERT_TRUE(encryptedRes.parms_id() == parms_id);
            ASSERT_TRUE(plain.to_string() == "5x^64 + Ax^5");
        }
        {
            // Consider the case of qi mod p != 1
            Modulus plain_modulus(786433);

            EncryptionParameters parms(scheme_type::bgv);
            parms.set_poly_modulus_degree(8192);
            parms.set_plain_modulus(plain_modulus);
            parms.set_coeff_modulus(CoeffModulus::BFVDefault(8192));
            SEALContext context(parms, true, sec_level_type::tc128);

            KeyGenerator keygen(context);
            SecretKey secret_key = keygen.secret_key();
            PublicKey pk;
            keygen.create_public_key(pk);

            Encryptor encryptor(context, pk);
            Evaluator evaluator(context);
            Decryptor decryptor(context, keygen.secret_key());

            Ciphertext encrypted(context);
            Plaintext plain;

            plain = "1";
            encryptor.encrypt(plain, encrypted);
            evaluator.mod_switch_to_next_inplace(encrypted);
            evaluator.mod_switch_to_next_inplace(encrypted);
            decryptor.decrypt(encrypted, plain);
            ASSERT_TRUE(plain.to_string() == "1");
        }
    }

    TEST(EvaluatorTest, BGVEncryptModSwitchToDecrypt)
    {
        // The common parameters: the plaintext and the polynomial moduli
        Modulus plain_modulus(65);

        // The parameters and the context of the higher level
        EncryptionParameters parms(scheme_type::bgv);
        parms.set_poly_modulus_degree(128);
        parms.set_plain_modulus(plain_modulus);
        parms.set_coeff_modulus(CoeffModulus::Create(128, { 30, 30, 30, 30 }));

        SEALContext context(parms, true, sec_level_type::none);
        KeyGenerator keygen(context);
        SecretKey secret_key = keygen.secret_key();
        PublicKey pk;
        keygen.create_public_key(pk);

        Encryptor encryptor(context, pk);
        Evaluator evaluator(context);
        Decryptor decryptor(context, keygen.secret_key());
        auto parms_id = context.first_parms_id();

        Ciphertext encrypted(context);
        Plaintext plain;

        plain = 0;
        encryptor.encrypt(plain, encrypted);
        evaluator.mod_switch_to_inplace(encrypted, parms_id);
        decryptor.decrypt(encrypted, plain);
        ASSERT_TRUE(encrypted.parms_id() == parms_id);
        ASSERT_TRUE(plain.to_string() == "0");

        parms_id = context.get_context_data(parms_id)->next_context_data()->parms_id();
        encryptor.encrypt(plain, encrypted);
        evaluator.mod_switch_to_inplace(encrypted, parms_id);
        decryptor.decrypt(encrypted, plain);
        ASSERT_TRUE(encrypted.parms_id() == parms_id);
        ASSERT_TRUE(plain.to_string() == "0");

        parms_id = context.get_context_data(parms_id)->next_context_data()->parms_id();
        encryptor.encrypt(plain, encrypted);
        evaluator.mod_switch_to_inplace(encrypted, parms_id);
        decryptor.decrypt(encrypted, plain);
        ASSERT_TRUE(encrypted.parms_id() == parms_id);
        ASSERT_TRUE(plain.to_string() == "0");

        parms_id = context.first_parms_id();
        encryptor.encrypt(plain, encrypted);
        parms_id = context.get_context_data(parms_id)->next_context_data()->next_context_data()->parms_id();
        evaluator.mod_switch_to_inplace(encrypted, parms_id);
        decryptor.decrypt(encrypted, plain);
        ASSERT_TRUE(encrypted.parms_id() == parms_id);
        ASSERT_TRUE(plain.to_string() == "0");

        parms_id = context.first_parms_id();
        plain = 1;
        encryptor.encrypt(plain, encrypted);
        evaluator.mod_switch_to_inplace(encrypted, parms_id);
        decryptor.decrypt(encrypted, plain);
        ASSERT_TRUE(encrypted.parms_id() == parms_id);
        ASSERT_TRUE(plain.to_string() == "1");

        parms_id = context.get_context_data(parms_id)->next_context_data()->parms_id();
        encryptor.encrypt(plain, encrypted);
        evaluator.mod_switch_to_inplace(encrypted, parms_id);
        decryptor.decrypt(encrypted, plain);
        ASSERT_TRUE(encrypted.parms_id() == parms_id);
        ASSERT_TRUE(plain.to_string() == "1");

        parms_id = context.get_context_data(parms_id)->next_context_data()->parms_id();
        encryptor.encrypt(plain, encrypted);
        evaluator.mod_switch_to_inplace(encrypted, parms_id);
        decryptor.decrypt(encrypted, plain);
        ASSERT_TRUE(encrypted.parms_id() == parms_id);
        ASSERT_TRUE(plain.to_string() == "1");

        parms_id = context.first_parms_id();
        encryptor.encrypt(plain, encrypted);
        parms_id = context.get_context_data(parms_id)->next_context_data()->next_context_data()->parms_id();
        evaluator.mod_switch_to_inplace(encrypted, parms_id);
        decryptor.decrypt(encrypted, plain);
        ASSERT_TRUE(encrypted.parms_id() == parms_id);
        ASSERT_TRUE(plain.to_string() == "1");

        parms_id = context.first_parms_id();
        plain = "1x^127";
        encryptor.encrypt(plain, encrypted);
        evaluator.mod_switch_to_inplace(encrypted, parms_id);
        decryptor.decrypt(encrypted, plain);
        ASSERT_TRUE(encrypted.parms_id() == parms_id);
        ASSERT_TRUE(plain.to_string() == "1x^127");

        parms_id = context.get_context_data(parms_id)->next_context_data()->parms_id();
        encryptor.encrypt(plain, encrypted);
        evaluator.mod_switch_to_inplace(encrypted, parms_id);
        decryptor.decrypt(encrypted, plain);
        ASSERT_TRUE(encrypted.parms_id() == parms_id);
        ASSERT_TRUE(plain.to_string() == "1x^127");

        parms_id = context.get_context_data(parms_id)->next_context_data()->parms_id();
        encryptor.encrypt(plain, encrypted);
        evaluator.mod_switch_to_inplace(encrypted, parms_id);
        decryptor.decrypt(encrypted, plain);
        ASSERT_TRUE(encrypted.parms_id() == parms_id);
        ASSERT_TRUE(plain.to_string() == "1x^127");

        parms_id = context.first_parms_id();
        encryptor.encrypt(plain, encrypted);
        parms_id = context.get_context_data(parms_id)->next_context_data()->next_context_data()->parms_id();
        evaluator.mod_switch_to_inplace(encrypted, parms_id);
        decryptor.decrypt(encrypted, plain);
        ASSERT_TRUE(encrypted.parms_id() == parms_id);
        ASSERT_TRUE(plain.to_string() == "1x^127");

        parms_id = context.first_parms_id();
        plain = "5x^64 + Ax^5";
        encryptor.encrypt(plain, encrypted);
        evaluator.mod_switch_to_inplace(encrypted, parms_id);
        decryptor.decrypt(encrypted, plain);
        ASSERT_TRUE(encrypted.parms_id() == parms_id);
        ASSERT_TRUE(plain.to_string() == "5x^64 + Ax^5");

        parms_id = context.get_context_data(parms_id)->next_context_data()->parms_id();
        encryptor.encrypt(plain, encrypted);
        evaluator.mod_switch_to_inplace(encrypted, parms_id);
        decryptor.decrypt(encrypted, plain);
        ASSERT_TRUE(encrypted.parms_id() == parms_id);
        ASSERT_TRUE(plain.to_string() == "5x^64 + Ax^5");

        parms_id = context.get_context_data(parms_id)->next_context_data()->parms_id();
        encryptor.encrypt(plain, encrypted);
        evaluator.mod_switch_to_inplace(encrypted, parms_id);
        decryptor.decrypt(encrypted, plain);
        ASSERT_TRUE(encrypted.parms_id() == parms_id);
        ASSERT_TRUE(plain.to_string() == "5x^64 + Ax^5");

        parms_id = context.first_parms_id();
        encryptor.encrypt(plain, encrypted);
        parms_id = context.get_context_data(parms_id)->next_context_data()->next_context_data()->parms_id();
        evaluator.mod_switch_to_inplace(encrypted, parms_id);
        decryptor.decrypt(encrypted, plain);
        ASSERT_TRUE(encrypted.parms_id() == parms_id);
        ASSERT_TRUE(plain.to_string() == "5x^64 + Ax^5");
    }

    TEST(EvaluatorTest, AddManyValidatesEveryInput)
    {
        auto make_parms = [](vector<int> bit_sizes) {
            EncryptionParameters parms(scheme_type::bfv);
            parms.set_poly_modulus_degree(128);
            parms.set_coeff_modulus(CoeffModulus::Create(128, bit_sizes));
            parms.set_plain_modulus(1 << 6);
            return parms;
        };

        SEALContext foreign_context(make_parms({ 50, 50, 50 }), false, sec_level_type::none);
        SEALContext context(make_parms({ 40, 40, 40 }), false, sec_level_type::none);

        KeyGenerator foreign_keygen(foreign_context);
        PublicKey foreign_pk;
        foreign_keygen.create_public_key(foreign_pk);
        Encryptor foreign_encryptor(foreign_context, foreign_pk);
        Ciphertext foreign;
        foreign_encryptor.encrypt(Plaintext("1"), foreign);

        KeyGenerator keygen(context);
        PublicKey pk;
        keygen.create_public_key(pk);
        Encryptor encryptor(context, pk);
        Decryptor decryptor(context, keygen.secret_key());
        Evaluator evaluator(context);

        Ciphertext destination;
        encryptor.encrypt(Plaintext("2"), destination);
        ASSERT_FALSE(is_valid_for(foreign, context));

        // A single-element vector must be validated too.
        ASSERT_THROW(evaluator.add_many(vector<Ciphertext>{ foreign }, destination), invalid_argument);
        Plaintext plain;
        decryptor.decrypt(destination, plain);
        ASSERT_TRUE(plain.to_string() == "2");

        ASSERT_THROW(evaluator.add_many(vector<Ciphertext>{ foreign, foreign }, destination), invalid_argument);
        decryptor.decrypt(destination, plain);
        ASSERT_TRUE(plain.to_string() == "2");
    }

    TEST(EvaluatorTest, AddManyPreservesDestinationOnThrow)
    {
        EncryptionParameters parms(scheme_type::bfv);
        parms.set_poly_modulus_degree(128);
        parms.set_coeff_modulus(CoeffModulus::Create(128, { 40, 40, 40 }));
        parms.set_plain_modulus(1 << 6);
        SEALContext context(parms, true, sec_level_type::none);

        KeyGenerator keygen(context);
        PublicKey pk;
        keygen.create_public_key(pk);
        Encryptor encryptor(context, pk);
        Decryptor decryptor(context, keygen.secret_key());
        Evaluator evaluator(context);

        Ciphertext first;
        encryptor.encrypt(Plaintext("1"), first);
        Ciphertext mismatched = first;
        evaluator.mod_switch_to_next_inplace(mismatched);

        Ciphertext destination;
        encryptor.encrypt(Plaintext("2"), destination);
        auto destination_parms_id = destination.parms_id();

        ASSERT_THROW(evaluator.add_many(vector<Ciphertext>{ first, mismatched }, destination), invalid_argument);

        Plaintext plain;
        decryptor.decrypt(destination, plain);
        ASSERT_TRUE(plain.to_string() == "2");
        ASSERT_TRUE(destination.parms_id() == destination_parms_id);
    }

    TEST(EvaluatorTest, MultiplyManyValidatesEveryInput)
    {
        auto make_parms = [](vector<int> bit_sizes) {
            EncryptionParameters parms(scheme_type::bfv);
            parms.set_poly_modulus_degree(128);
            parms.set_coeff_modulus(CoeffModulus::Create(128, bit_sizes));
            parms.set_plain_modulus(1 << 6);
            return parms;
        };

        SEALContext foreign_context(make_parms({ 50, 50, 50 }), false, sec_level_type::none);
        SEALContext context(make_parms({ 40, 40, 40 }), false, sec_level_type::none);

        KeyGenerator foreign_keygen(foreign_context);
        PublicKey foreign_pk;
        foreign_keygen.create_public_key(foreign_pk);
        Encryptor foreign_encryptor(foreign_context, foreign_pk);
        Ciphertext foreign;
        foreign_encryptor.encrypt(Plaintext("1"), foreign);

        KeyGenerator keygen(context);
        PublicKey pk;
        keygen.create_public_key(pk);
        RelinKeys rlk;
        keygen.create_relin_keys(rlk);
        Encryptor encryptor(context, pk);
        Decryptor decryptor(context, keygen.secret_key());
        Evaluator evaluator(context);

        Ciphertext destination;
        encryptor.encrypt(Plaintext("2"), destination);

        ASSERT_THROW(evaluator.multiply_many(vector<Ciphertext>{ foreign }, rlk, destination), invalid_argument);
        Plaintext plain;
        decryptor.decrypt(destination, plain);
        ASSERT_TRUE(plain.to_string() == "2");

        ASSERT_THROW(
            evaluator.multiply_many(vector<Ciphertext>{ foreign, foreign }, rlk, destination), invalid_argument);
        decryptor.decrypt(destination, plain);
        ASSERT_TRUE(plain.to_string() == "2");

        // A ciphertext whose parms_id resolves in this context but whose metadata does not
        // match it is rejected on the same path.
        Ciphertext wrong_scale;
        encryptor.encrypt(Plaintext("3"), wrong_scale);
        wrong_scale.scale() = 2.0;
        ASSERT_TRUE(context.get_context_data(wrong_scale.parms_id()) != nullptr);
        ASSERT_FALSE(is_valid_for(wrong_scale, context));

        ASSERT_THROW(evaluator.multiply_many(vector<Ciphertext>{ wrong_scale }, rlk, destination), invalid_argument);
        decryptor.decrypt(destination, plain);
        ASSERT_TRUE(plain.to_string() == "2");
    }

    TEST(EvaluatorTest, MultiplyManyPreservesDestinationOnThrow)
    {
        EncryptionParameters parms(scheme_type::bfv);
        parms.set_poly_modulus_degree(128);
        parms.set_coeff_modulus(CoeffModulus::Create(128, { 40, 40, 40 }));
        parms.set_plain_modulus(1 << 6);
        SEALContext context(parms, true, sec_level_type::none);

        KeyGenerator keygen(context);
        PublicKey pk;
        keygen.create_public_key(pk);
        RelinKeys rlk;
        keygen.create_relin_keys(rlk);
        Encryptor encryptor(context, pk);
        Decryptor decryptor(context, keygen.secret_key());
        Evaluator evaluator(context);

        Ciphertext first;
        encryptor.encrypt(Plaintext("1"), first);
        Ciphertext mismatched = first;
        evaluator.mod_switch_to_next_inplace(mismatched);

        Ciphertext destination;
        encryptor.encrypt(Plaintext("2"), destination);
        auto destination_parms_id = destination.parms_id();

        ASSERT_THROW(
            evaluator.multiply_many(vector<Ciphertext>{ first, mismatched }, rlk, destination), invalid_argument);

        Plaintext plain;
        decryptor.decrypt(destination, plain);
        ASSERT_TRUE(plain.to_string() == "2");
        ASSERT_TRUE(destination.parms_id() == destination_parms_id);
    }

    TEST(EvaluatorTest, ExponentiateValidatesCiphertext)
    {
        EncryptionParameters parms(scheme_type::bfv);
        parms.set_poly_modulus_degree(128);
        parms.set_coeff_modulus(CoeffModulus::Create(128, { 40, 40, 40 }));
        parms.set_plain_modulus(1 << 6);
        SEALContext context(parms, false, sec_level_type::none);

        KeyGenerator keygen(context);
        PublicKey pk;
        keygen.create_public_key(pk);
        RelinKeys rlk;
        keygen.create_relin_keys(rlk);
        Encryptor encryptor(context, pk);
        Decryptor decryptor(context, keygen.secret_key());
        Evaluator evaluator(context);

        Ciphertext encrypted;
        encryptor.encrypt(Plaintext("2"), encrypted);
        encrypted.scale() = 2.0;
        ASSERT_TRUE(context.get_context_data(encrypted.parms_id()) != nullptr);
        ASSERT_FALSE(is_valid_for(encrypted, context));

        // The exponent == 1 fast path returns without reaching multiply_many.
        ASSERT_THROW(evaluator.exponentiate_inplace(encrypted, 1, rlk), invalid_argument);
        ASSERT_THROW(evaluator.exponentiate_inplace(encrypted, 2, rlk), invalid_argument);

        Ciphertext destination;
        encryptor.encrypt(Plaintext("3"), destination);
        ASSERT_THROW(evaluator.exponentiate(encrypted, 1, rlk, destination), invalid_argument);
    }

    TEST(EvaluatorTest, ModSwitchToValidatesCiphertext)
    {
        EncryptionParameters parms(scheme_type::bfv);
        parms.set_poly_modulus_degree(128);
        parms.set_coeff_modulus(CoeffModulus::Create(128, { 40, 40, 40 }));
        parms.set_plain_modulus(1 << 6);
        SEALContext context(parms, true, sec_level_type::none);

        KeyGenerator keygen(context);
        PublicKey pk;
        keygen.create_public_key(pk);
        Encryptor encryptor(context, pk);
        Evaluator evaluator(context);

        Ciphertext encrypted;
        encryptor.encrypt(Plaintext("2"), encrypted);
        encrypted.scale() = 2.0;
        ASSERT_FALSE(is_valid_for(encrypted, context));

        // Switching to the level the ciphertext already occupies performs no iterations.
        auto same_parms_id = encrypted.parms_id();
        ASSERT_THROW(evaluator.mod_switch_to_inplace(encrypted, same_parms_id), invalid_argument);
        ASSERT_THROW(evaluator.mod_reduce_to_inplace(encrypted, same_parms_id), invalid_argument);
    }

    TEST(EvaluatorTest, MultiplyPlainValidatesBeforeTransforming)
    {
        EncryptionParameters parms(scheme_type::bfv);
        parms.set_poly_modulus_degree(128);
        parms.set_coeff_modulus(CoeffModulus::Create(128, { 40, 40, 40 }));
        parms.set_plain_modulus(1 << 6);
        SEALContext context(parms, true, sec_level_type::none);

        KeyGenerator keygen(context);
        PublicKey pk;
        keygen.create_public_key(pk);
        Encryptor encryptor(context, pk);
        Decryptor decryptor(context, keygen.secret_key());
        Evaluator evaluator(context);

        Ciphertext encrypted;
        encryptor.encrypt(Plaintext("2"), encrypted);
        ASSERT_FALSE(encrypted.is_ntt_form());

        // An NTT-form plaintext at a level the ciphertext is not at.
        Plaintext plain("3");
        auto next_parms_id = context.first_context_data()->next_context_data()->parms_id();
        evaluator.transform_to_ntt_inplace(plain, next_parms_id);
        ASSERT_TRUE(plain.parms_id() != encrypted.parms_id());

        ASSERT_THROW(evaluator.multiply_plain_inplace(encrypted, plain), invalid_argument);

        // The ciphertext must not have been transformed on the way to that throw.
        ASSERT_FALSE(encrypted.is_ntt_form());
        Plaintext result;
        decryptor.decrypt(encrypted, result);
        ASSERT_TRUE(result.to_string() == "2");
    }

    TEST(EvaluatorTest, RelinearizeValidatesCiphertext)
    {
        EncryptionParameters parms(scheme_type::bfv);
        parms.set_poly_modulus_degree(128);
        parms.set_coeff_modulus(CoeffModulus::Create(128, { 40, 40, 40 }));
        parms.set_plain_modulus(1 << 6);
        SEALContext context(parms, false, sec_level_type::none);

        KeyGenerator keygen(context);
        PublicKey pk;
        keygen.create_public_key(pk);
        RelinKeys rlk;
        keygen.create_relin_keys(rlk);
        Encryptor encryptor(context, pk);
        Evaluator evaluator(context);

        Ciphertext encrypted;
        encryptor.encrypt(Plaintext("2"), encrypted);
        encrypted.scale() = 2.0;
        ASSERT_TRUE(context.get_context_data(encrypted.parms_id()) != nullptr);
        ASSERT_FALSE(is_valid_for(encrypted, context));

        // A ciphertext that is already at the destination size takes the early return.
        ASSERT_TRUE(encrypted.size() == 2);
        ASSERT_THROW(evaluator.relinearize_inplace(encrypted, rlk), invalid_argument);

        // The destination-taking overload uses destination as scratch space, so only the
        // rejection is guaranteed here.
        Ciphertext destination;
        encryptor.encrypt(Plaintext("3"), destination);
        ASSERT_THROW(evaluator.relinearize(encrypted, rlk, destination), invalid_argument);
    }

    TEST(EvaluatorTest, ApplyGaloisValidatesKeysBeforeMutating)
    {
        EncryptionParameters parms(scheme_type::bfv);
        parms.set_poly_modulus_degree(128);
        parms.set_coeff_modulus(CoeffModulus::Create(128, { 40, 40, 40 }));
        parms.set_plain_modulus(257);
        SEALContext context(parms, false, sec_level_type::none);

        KeyGenerator keygen(context);
        PublicKey pk;
        keygen.create_public_key(pk);
        Encryptor encryptor(context, pk);
        Decryptor decryptor(context, keygen.secret_key());
        Evaluator evaluator(context);

        Ciphertext encrypted;
        encryptor.encrypt(Plaintext("1x^1 + 2"), encrypted);
        vector<uint64_t> before(
            encrypted.data(),
            encrypted.data() + encrypted.size() * encrypted.coeff_modulus_size() * encrypted.poly_modulus_degree());

        uint32_t galois_elt = context.key_context_data()->galois_tool()->get_elt_from_step(1);
        size_t index = GaloisKeys::get_index(galois_elt);

        // has_key only checks that the outer slot is non-empty, so this passes that check while
        // the selected inner key vector is unusable.
        GaloisKeys malformed;
        malformed.parms_id() = context.key_parms_id();
        malformed.data().resize(index + 1);
        malformed.data()[index].emplace_back();
        ASSERT_TRUE(malformed.has_key(galois_elt));
        ASSERT_FALSE(is_metadata_valid_for(malformed, context));

        ASSERT_THROW(evaluator.apply_galois_inplace(encrypted, galois_elt, malformed), invalid_argument);

        vector<uint64_t> after(
            encrypted.data(),
            encrypted.data() + encrypted.size() * encrypted.coeff_modulus_size() * encrypted.poly_modulus_degree());
        ASSERT_TRUE(before == after);

        Plaintext plain;
        decryptor.decrypt(encrypted, plain);
        ASSERT_TRUE(plain.to_string() == "1x^1 + 2");

        // An inner vector of the right length but holding an invalid key is also rejected first.
        GaloisKeys wrong_keys;
        wrong_keys.parms_id() = context.key_parms_id();
        wrong_keys.data().resize(index + 1);
        wrong_keys.data()[index].resize(context.first_context_data()->parms().coeff_modulus().size());
        ASSERT_THROW(evaluator.apply_galois_inplace(encrypted, galois_elt, wrong_keys), invalid_argument);

        vector<uint64_t> after_second(
            encrypted.data(),
            encrypted.data() + encrypted.size() * encrypted.coeff_modulus_size() * encrypted.poly_modulus_degree());
        ASSERT_TRUE(before == after_second);
    }

    TEST(EvaluatorTest, MultiplyRejectsSizeZeroCiphertext)
    {
        for (auto scheme : { scheme_type::bfv, scheme_type::bgv, scheme_type::ckks })
        {
            EncryptionParameters parms(scheme);
            parms.set_poly_modulus_degree(64);
            parms.set_coeff_modulus(CoeffModulus::Create(64, { 40, 40, 40 }));
            if (scheme != scheme_type::ckks)
            {
                parms.set_plain_modulus(PlainModulus::Batching(64, 20));
            }

            SEALContext context(parms, true, sec_level_type::none);
            KeyGenerator keygen(context);
            PublicKey pk;
            keygen.create_public_key(pk);
            RelinKeys rlk;
            keygen.create_relin_keys(rlk);

            Encryptor encryptor(context, pk);
            Evaluator evaluator(context);

            Ciphertext empty;
            empty.resize(context, context.first_parms_id(), 0);
            empty.is_ntt_form() = (scheme != scheme_type::bfv);
            ASSERT_TRUE(is_valid_for(empty, context));

            Ciphertext encrypted;
            encryptor.encrypt_zero(encrypted);
            Ciphertext encrypted3;
            evaluator.square(encrypted, encrypted3);
            const Ciphertext encrypted3_copy = encrypted3;

            Ciphertext destination;
            ASSERT_THROW(evaluator.multiply(empty, encrypted3, destination), invalid_argument);
            ASSERT_THROW(evaluator.multiply(encrypted3, empty, destination), invalid_argument);
            ASSERT_THROW(evaluator.multiply(empty, empty, destination), invalid_argument);
            ASSERT_THROW(evaluator.multiply_inplace(encrypted3, empty), invalid_argument);
            ASSERT_TRUE(same_ciphertext(encrypted3, encrypted3_copy));

            ASSERT_THROW(evaluator.square(empty, destination), invalid_argument);
            Ciphertext empty_copy = empty;
            ASSERT_THROW(evaluator.square_inplace(empty_copy), invalid_argument);
            ASSERT_TRUE(same_ciphertext(empty, empty_copy));

            if (scheme != scheme_type::ckks)
            {
                ASSERT_THROW(evaluator.exponentiate(empty, 2, rlk, destination), invalid_argument);
                ASSERT_THROW(
                    evaluator.multiply_many(vector<Ciphertext>{ empty, encrypted }, rlk, destination),
                    invalid_argument);
            }
        }
    }

    namespace
    {
        // Relinearization key for s^power, created as in KeyGenerator
        vector<PublicKey> create_relin_key(const SEALContext &context, const SecretKey &secret_key, size_t power)
        {
            auto &key_context_data = *context.key_context_data();
            auto &key_modulus = key_context_data.parms().coeff_modulus();
            size_t coeff_count = key_context_data.parms().poly_modulus_degree();
            size_t decomp_mod_count = context.first_context_data()->parms().coeff_modulus().size();

            // s^power in NTT form
            const uint64_t *s = secret_key.data().data();
            vector<uint64_t> s_power(s, s + key_modulus.size() * coeff_count);
            for (size_t p = 1; p < power; p++)
            {
                for (size_t i = 0; i < key_modulus.size(); i++)
                {
                    for (size_t l = 0; l < coeff_count; l++)
                    {
                        uint64_t &x = s_power[i * coeff_count + l];
                        x = util::multiply_uint_mod(x, s[i * coeff_count + l], key_modulus[i]);
                    }
                }
            }

            // Encryptions of zero with special prime * s^power added to component i of c0
            vector<PublicKey> key(decomp_mod_count);
            for (size_t i = 0; i < decomp_mod_count; i++)
            {
                util::encrypt_zero_symmetric(secret_key, context, context.key_parms_id(), true, false, key[i].data());
                uint64_t factor = util::barrett_reduce_64(key_modulus.back().value(), key_modulus[i]);
                uint64_t *c0 = key[i].data().data(0) + i * coeff_count;
                for (size_t l = 0; l < coeff_count; l++)
                {
                    uint64_t x = util::multiply_uint_mod(s_power[i * coeff_count + l], factor, key_modulus[i]);
                    c0[l] = util::add_uint_mod(c0[l], x, key_modulus[i]);
                }
            }
            return key;
        }
    } // namespace

    TEST(EvaluatorTest, RelinearizeSizeFourCiphertext)
    {
        for (auto scheme : { scheme_type::bfv, scheme_type::bgv, scheme_type::ckks })
        {
            size_t n = 64;
            EncryptionParameters parms(scheme);
            parms.set_poly_modulus_degree(n);
            parms.set_coeff_modulus(CoeffModulus::Create(n, { 60, 60, 60, 60 }));
            if (scheme != scheme_type::ckks)
            {
                parms.set_plain_modulus(PlainModulus::Batching(n, 20));
            }

            SEALContext context(parms, true, sec_level_type::none);
            KeyGenerator keygen(context);
            PublicKey pk;
            keygen.create_public_key(pk);
            RelinKeys rlk;
            keygen.create_relin_keys(rlk);
            rlk.data().push_back(create_relin_key(context, keygen.secret_key(), 3));
            ASSERT_EQ(2ULL, rlk.size());
            ASSERT_TRUE(is_valid_for(rlk, context));

            Encryptor encryptor(context, pk);
            Evaluator evaluator(context);
            Decryptor decryptor(context, keygen.secret_key());

            Plaintext plain("3x^2 + 2");
            if (scheme == scheme_type::ckks)
            {
                CKKSEncoder encoder(context);
                encoder.encode(1.25, pow(2.0, 25), plain);
            }
            Ciphertext encrypted;
            encryptor.encrypt(plain, encrypted);
            Ciphertext encrypted3;
            evaluator.square(encrypted, encrypted3);
            evaluator.multiply_inplace(encrypted3, encrypted);
            ASSERT_EQ(4ULL, encrypted3.size());

            Ciphertext relinearized;
            evaluator.relinearize(encrypted3, rlk, relinearized);
            ASSERT_EQ(2ULL, relinearized.size());

            Plaintext expected;
            Plaintext result;
            decryptor.decrypt(encrypted3, expected);
            decryptor.decrypt(relinearized, result);
            if (scheme == scheme_type::ckks)
            {
                CKKSEncoder encoder(context);
                vector<double> expected_values;
                vector<double> result_values;
                encoder.decode(expected, expected_values);
                encoder.decode(result, result_values);
                for (size_t i = 0; i < result_values.size(); i++)
                {
                    ASSERT_NEAR(1.953125, expected_values[i], 0.001);
                    ASSERT_NEAR(1.953125, result_values[i], 0.001);
                }
            }
            else
            {
                ASSERT_EQ(expected.to_string(), result.to_string());
                ASSERT_EQ("1Bx^6 + 36x^4 + 24x^2 + 8", result.to_string());
            }
        }
    }

    TEST(EvaluatorTest, RelinearizeValidatesKeysBeforeMutating)
    {
        // Relinearization uses the key for s^3 before the invalid key for s^2
        size_t n = 64;
        EncryptionParameters parms(scheme_type::bfv);
        parms.set_poly_modulus_degree(n);
        parms.set_coeff_modulus(CoeffModulus::Create(n, { 60, 60, 60, 60 }));
        parms.set_plain_modulus(PlainModulus::Batching(n, 20));

        SEALContext context(parms, true, sec_level_type::none);
        KeyGenerator keygen(context);
        PublicKey pk;
        keygen.create_public_key(pk);
        RelinKeys rlk;
        keygen.create_relin_keys(rlk);
        rlk.data().push_back(create_relin_key(context, keygen.secret_key(), 3));

        Encryptor encryptor(context, pk);
        Evaluator evaluator(context);

        Ciphertext encrypted;
        encryptor.encrypt(Plaintext("3x^2 + 2"), encrypted);
        Ciphertext encrypted3;
        evaluator.square(encrypted, encrypted3);
        evaluator.multiply_inplace(encrypted3, encrypted);
        ASSERT_EQ(4ULL, encrypted3.size());

        rlk.data()[RelinKeys::get_index(2)].resize(1);
        Ciphertext encrypted3_copy = encrypted3;
        ASSERT_THROW(evaluator.relinearize_inplace(encrypted3, rlk), invalid_argument);
        ASSERT_TRUE(same_ciphertext(encrypted3, encrypted3_copy));
    }

    TEST(EvaluatorTest, KeySwitchingManyPrimes)
    {
        // More 60-bit digits (199) than 128-bit accumulators can sum unreduced
        size_t n = 16;
        EncryptionParameters parms(scheme_type::ckks);
        parms.set_poly_modulus_degree(n);
        parms.set_coeff_modulus(CoeffModulus::Create(n, vector<int>(200, 60)));

        SEALContext context(parms, false, sec_level_type::none);
        ASSERT_TRUE(context.parameters_set());
        KeyGenerator keygen(context);
        PublicKey pk;
        keygen.create_public_key(pk);
        RelinKeys rlk;
        keygen.create_relin_keys(rlk);
        GaloisKeys glk;
        keygen.create_galois_keys(vector<int>{ 1, -1 }, glk);

        Encryptor encryptor(context, pk);
        Evaluator evaluator(context);
        Decryptor decryptor(context, keygen.secret_key());
        CKKSEncoder encoder(context);

        size_t slot_count = encoder.slot_count();
        vector<double> input(slot_count);
        for (size_t i = 0; i < slot_count; i++)
        {
            input[i] = 0.5 * static_cast<double>(i + 1);
        }
        Plaintext plain;
        encoder.encode(input, pow(2.0, 40), plain);
        Ciphertext encrypted;
        encryptor.encrypt(plain, encrypted);

        evaluator.square_inplace(encrypted);
        evaluator.relinearize_inplace(encrypted, rlk);
        vector<int> steps{ 1, -1 };
        vector<Ciphertext> rotated;
        evaluator.rotate_vector(encrypted, steps, glk, rotated);
        for (size_t s = 0; s < steps.size(); s++)
        {
            Ciphertext expected;
            evaluator.rotate_vector(encrypted, steps[s], glk, expected);
            ASSERT_TRUE(same_ciphertext(expected, rotated[s]));
        }

        vector<double> result;
        decryptor.decrypt(encrypted, plain);
        encoder.decode(plain, result);
        for (size_t i = 0; i < slot_count; i++)
        {
            ASSERT_NEAR(input[i] * input[i], result[i], 0.001);
        }

        for (size_t s = 0; s < steps.size(); s++)
        {
            decryptor.decrypt(rotated[s], plain);
            encoder.decode(plain, result);
            size_t shift = static_cast<size_t>(steps[s] + static_cast<int>(slot_count)) % slot_count;
            for (size_t i = 0; i < slot_count; i++)
            {
                double x = input[(i + shift) % slot_count];
                ASSERT_NEAR(x * x, result[i], 0.001);
            }
        }
    }

    TEST(EvaluatorTest, KeySwitchingMixedPrimeSizes)
    {
        // Key switching reduces only some digits before the NTT, and in BGV only some special-prime parts
        size_t n = 64;
        for (auto scheme : { scheme_type::bfv, scheme_type::bgv, scheme_type::ckks })
        {
            for (auto &bit_sizes : vector<vector<int>>{ { 40, 30, 50, 60 }, { 60, 40, 60 } })
            {
                EncryptionParameters parms(scheme);
                parms.set_poly_modulus_degree(n);
                parms.set_coeff_modulus(CoeffModulus::Create(n, bit_sizes));
                if (scheme != scheme_type::ckks)
                {
                    parms.set_plain_modulus(PlainModulus::Batching(n, 17));
                }

                SEALContext context(parms, true, sec_level_type::none);
                KeyGenerator keygen(context);
                PublicKey pk;
                keygen.create_public_key(pk);
                RelinKeys rlk;
                keygen.create_relin_keys(rlk);
                GaloisKeys glk;
                keygen.create_galois_keys(vector<int>{ 1 }, glk);

                Encryptor encryptor(context, pk);
                Evaluator evaluator(context);
                Decryptor decryptor(context, keygen.secret_key());

                size_t slot_count = (scheme == scheme_type::ckks) ? n / 2 : n;
                Plaintext plain;
                if (scheme == scheme_type::ckks)
                {
                    vector<double> input(slot_count);
                    for (size_t i = 0; i < slot_count; i++)
                    {
                        input[i] = static_cast<double>(i) / 8;
                    }
                    CKKSEncoder encoder(context);
                    encoder.encode(input, pow(2.0, 20), plain);
                }
                else
                {
                    vector<uint64_t> input(slot_count);
                    for (size_t i = 0; i < slot_count; i++)
                    {
                        input[i] = i;
                    }
                    BatchEncoder encoder(context);
                    encoder.encode(input, plain);
                }
                Ciphertext encrypted;
                encryptor.encrypt(plain, encrypted);

                for (int level = 0; level < 2; level++)
                {
                    if (level > 0)
                    {
                        evaluator.mod_switch_to_next_inplace(encrypted);
                    }

                    Ciphertext squared;
                    evaluator.square(encrypted, squared);
                    evaluator.relinearize_inplace(squared, rlk);
                    Ciphertext rotated;
                    rotate(evaluator, scheme, encrypted, 1, glk, rotated);

                    Plaintext squared_plain;
                    Plaintext rotated_plain;
                    decryptor.decrypt(squared, squared_plain);
                    decryptor.decrypt(rotated, rotated_plain);
                    if (scheme == scheme_type::ckks)
                    {
                        CKKSEncoder encoder(context);
                        vector<double> squared_result;
                        vector<double> rotated_result;
                        encoder.decode(squared_plain, squared_result);
                        encoder.decode(rotated_plain, rotated_result);
                        for (size_t i = 0; i < slot_count; i++)
                        {
                            double x = static_cast<double>(i) / 8;
                            ASSERT_NEAR(x * x, squared_result[i], 0.01);
                            ASSERT_NEAR(static_cast<double>((i + 1) % slot_count) / 8, rotated_result[i], 0.01);
                        }
                    }
                    else
                    {
                        // Rows rotate separately
                        BatchEncoder encoder(context);
                        uint64_t t = parms.plain_modulus().value();
                        size_t row_size = slot_count / 2;
                        vector<uint64_t> squared_result;
                        vector<uint64_t> rotated_result;
                        encoder.decode(squared_plain, squared_result);
                        encoder.decode(rotated_plain, rotated_result);
                        for (size_t i = 0; i < slot_count; i++)
                        {
                            ASSERT_EQ((i * i) % t, squared_result[i]);
                            ASSERT_EQ(i - i % row_size + (i + 1) % row_size, rotated_result[i]);
                        }
                    }
                }
            }
        }
    }

    TEST(EvaluatorTest, ModSwitchInPlaceMatchesOutOfPlace)
    {
        for (auto scheme : { scheme_type::bfv, scheme_type::bgv, scheme_type::ckks })
        {
            size_t n = 64;
            EncryptionParameters parms(scheme);
            parms.set_poly_modulus_degree(n);
            parms.set_coeff_modulus(CoeffModulus::Create(n, { 40, 40, 40, 40, 60 }));
            if (scheme != scheme_type::ckks)
            {
                parms.set_plain_modulus(PlainModulus::Batching(n, 20));
            }

            SEALContext context(parms, true, sec_level_type::none);
            KeyGenerator keygen(context);
            PublicKey pk;
            keygen.create_public_key(pk);

            Encryptor encryptor(context, pk);
            Evaluator evaluator(context);
            Decryptor decryptor(context, keygen.secret_key());

            Plaintext plain("3x^2 + 2");
            if (scheme == scheme_type::ckks)
            {
                CKKSEncoder encoder(context);
                encoder.encode(1.5, pow(2.0, 60), plain);
            }
            Ciphertext encrypted;
            encryptor.encrypt(plain, encrypted);
            Ciphertext encrypted3;
            evaluator.square(encrypted, encrypted3);

            // Sizes 2 and 3 at every level
            while (encrypted.parms_id() != context.last_parms_id())
            {
                for (auto ct : { &encrypted, &encrypted3 })
                {
                    Ciphertext destination;
                    auto pool = MemoryPoolHandle::New();
                    Ciphertext in_place(pool);
                    in_place = *ct;

                    if (scheme == scheme_type::ckks)
                    {
                        evaluator.rescale_to_next(*ct, destination);
                        evaluator.rescale_to_next_inplace(in_place);
                    }
                    else
                    {
                        evaluator.mod_switch_to_next(*ct, destination);
                        evaluator.mod_switch_to_next_inplace(in_place);
                    }
                    ASSERT_TRUE(same_ciphertext(destination, in_place));
                    ASSERT_TRUE(in_place.pool() == pool);

                    // A rejected switch changes nothing
                    Ciphertext copy = *ct;
                    ASSERT_THROW(evaluator.mod_switch_to_next_inplace(*ct, MemoryPoolHandle()), invalid_argument);
                    ASSERT_TRUE(same_ciphertext(copy, *ct));

                    // CKKS without rescaling (only the scale of encrypted fits the next level)
                    if (scheme == scheme_type::ckks && ct == &encrypted)
                    {
                        Ciphertext dropped;
                        evaluator.mod_switch_to_next(*ct, dropped);
                        evaluator.mod_switch_to_next_inplace(copy);
                        ASSERT_TRUE(same_ciphertext(dropped, copy));
                    }

                    *ct = in_place;
                }

                Plaintext result;
                decryptor.decrypt(encrypted, result);
                if (scheme == scheme_type::ckks)
                {
                    if (encrypted.scale() > pow(2.0, 15))
                    {
                        CKKSEncoder encoder(context);
                        vector<double> values;
                        encoder.decode(result, values);
                        ASSERT_NEAR(1.5, values[0], 0.001);
                    }
                }
                else
                {
                    ASSERT_EQ(plain.to_string(), result.to_string());
                }
            }

            // At the last level
            Ciphertext copy = encrypted;
            ASSERT_THROW(evaluator.mod_switch_to_next_inplace(encrypted), invalid_argument);
            ASSERT_TRUE(same_ciphertext(copy, encrypted));
        }
    }

    TEST(EvaluatorTest, BFVEncryptMultiplySizesDecrypt)
    {
        // Results up to the maximal size 16
        size_t n = 64;
        EncryptionParameters parms(scheme_type::bfv);
        parms.set_poly_modulus_degree(n);
        parms.set_coeff_modulus(CoeffModulus::Create(n, { 60, 60, 60, 60, 60, 60, 60, 60 }));
        parms.set_plain_modulus(257);

        SEALContext context(parms, true, sec_level_type::none);
        KeyGenerator keygen(context);
        PublicKey pk;
        keygen.create_public_key(pk);

        Encryptor encryptor(context, pk);
        Evaluator evaluator(context);
        Decryptor decryptor(context, keygen.secret_key());

        auto decrypts_to_power_of_two = [&](const Ciphertext &encrypted, size_t exponent) {
            Plaintext plain;
            decryptor.decrypt(encrypted, plain);
            uint64_t expected = 1;
            for (size_t i = 0; i < exponent; i++)
            {
                expected = (expected * 2) % 257;
            }
            return plain.significant_coeff_count() <= 1 && plain[0] == expected;
        };

        Ciphertext two;
        encryptor.encrypt(Plaintext("2"), two);
        for (size_t level = 0; level < 2; level++)
        {
            // powers[i] has size i + 2 and decrypts to 2^(i + 1)
            vector<Ciphertext> powers(8);
            powers[0] = two;
            for (size_t i = 1; i < powers.size(); i++)
            {
                evaluator.multiply(powers[i - 1], two, powers[i]);
                ASSERT_EQ(i + 2, powers[i].size());
                ASSERT_TRUE(decrypts_to_power_of_two(powers[i], i + 1));
            }

            vector<pair<size_t, size_t>> sizes{ { 2, 2 }, { 3, 2 }, { 2, 3 }, { 8, 9 }, { 9, 8 } };
            for (auto &size : sizes)
            {
                Ciphertext product;
                evaluator.multiply(powers[size.first - 2], powers[size.second - 2], product);
                ASSERT_EQ(size.first + size.second - 1, product.size());
                ASSERT_TRUE(decrypts_to_power_of_two(product, size.first + size.second - 2));
            }

            // Squares equal products with a copy and with itself
            for (size_t size = 2; size <= 8; size++)
            {
                const Ciphertext &encrypted = powers[size - 2];
                Ciphertext square;
                evaluator.square(encrypted, square);
                ASSERT_EQ(2 * size - 1, square.size());
                ASSERT_TRUE(decrypts_to_power_of_two(square, 2 * (size - 1)));

                Ciphertext copy = encrypted;
                Ciphertext product;
                evaluator.multiply(encrypted, copy, product);
                ASSERT_TRUE(same_ciphertext(square, product));
                evaluator.multiply_inplace(copy, copy);
                ASSERT_TRUE(same_ciphertext(square, copy));
            }
            evaluator.mod_switch_to_next_inplace(two);
        }
    }

    namespace
    {
        struct SignedUInt
        {
            vector<uint64_t> magnitude;

            bool negative;
        };

        // value has as many words as sum
        void add_signed(SignedUInt &sum, const uint64_t *value, bool negative)
        {
            size_t count = sum.magnitude.size();
            if (sum.negative == negative)
            {
                util::add_uint(sum.magnitude.data(), value, count, sum.magnitude.data());
            }
            else if (util::is_greater_than_or_equal_uint(sum.magnitude.data(), value, count))
            {
                util::sub_uint(sum.magnitude.data(), value, count, sum.magnitude.data());
            }
            else
            {
                util::sub_uint(value, sum.magnitude.data(), count, sum.magnitude.data());
                sum.negative = negative;
            }
        }
    } // namespace

    TEST(EvaluatorTest, BFVMultiplyMatchesExactReference)
    {
        // Coefficients (q - 1) / 2 test that Bsk is large enough
        size_t n = 16;
        auto pool = MemoryManager::GetPool();
        vector<uint64_t> plain_moduli{ 2, PlainModulus::Batching(n, 20).value(), (uint64_t(1) << 40) - 87,
                                       (uint64_t(1) << 60) - 93 };
        for (auto t : plain_moduli)
        {
            EncryptionParameters parms(scheme_type::bfv);
            parms.set_poly_modulus_degree(n);
            parms.set_coeff_modulus(CoeffModulus::Create(n, { 60, 60, 60, 60, 60 }));
            parms.set_plain_modulus(t);

            SEALContext context(parms, true, sec_level_type::none);
            ASSERT_TRUE(context.parameters_set());
            Evaluator evaluator(context);
            mt19937_64 rng(t);

            auto context_data = context.first_context_data();
            for (size_t level = 0; level < 2; level++, context_data = context_data->next_context_data())
            {
                auto &coeff_modulus = context_data->parms().coeff_modulus();
                auto &base_q = *context_data->rns_tool()->base_q();
                size_t k = coeff_modulus.size();

                // Fits t times a sum of 8 * n products
                size_t words = 2 * k + 2;
                vector<uint64_t> q(words, 0);
                util::set_uint(base_q.base_prod(), k, q.data());

                struct Coefficients
                {
                    vector<uint64_t> magnitudes;

                    vector<bool> negative;
                };
                auto make = [&](size_t size, bool extreme, Coefficients &coeffs) {
                    Ciphertext encrypted(context);
                    encrypted.resize(context, context_data->parms_id(), size);
                    coeffs.magnitudes.assign(size * n * k, 0);
                    coeffs.negative.assign(size * n, false);

                    // Bound (q - 1) / 2 - q / 2^17, so that BEHZ uses centered representatives
                    vector<uint64_t> bound(k);
                    util::right_shift_uint(base_q.base_prod(), 1, k, bound.data());
                    vector<uint64_t> margin(k);
                    util::right_shift_uint(base_q.base_prod(), 17, k, margin.data());
                    util::sub_uint(bound.data(), margin.data(), k, bound.data());

                    for (size_t p = 0; p < size; p++)
                    {
                        for (size_t l = 0; l < n; l++)
                        {
                            uint64_t *magnitude = coeffs.magnitudes.data() + (p * n + l) * k;
                            vector<uint64_t> value(k);
                            if (extreme)
                            {
                                util::right_shift_uint(base_q.base_prod(), 1, k, magnitude);
                                util::set_uint(magnitude, k, value.data());
                            }
                            else
                            {
                                vector<uint64_t> random(k);
                                generate(random.begin(), random.end(), [&]() { return rng(); });
                                vector<uint64_t> quotient(k);
                                util::divide_uint(random.data(), bound.data(), k, quotient.data(), magnitude, pool);
                                coeffs.negative[p * n + l] = rng() & 1;
                                if (coeffs.negative[p * n + l])
                                {
                                    util::sub_uint(base_q.base_prod(), magnitude, k, value.data());
                                }
                                else
                                {
                                    util::set_uint(magnitude, k, value.data());
                                }
                            }
                            base_q.decompose(value.data(), pool);
                            for (size_t i = 0; i < k; i++)
                            {
                                encrypted.data(p)[i * n + l] = value[i];
                            }
                        }
                    }
                    return encrypted;
                };

                // result = floor(t * a * b / q) - e mod q with 0 <= e < k
                auto check = [&](const Ciphertext &result, size_t size1, const Coefficients &a, size_t size2,
                                 const Coefficients &b) {
                    vector<uint64_t> product(words);
                    vector<uint64_t> scaled(words);
                    vector<uint64_t> quotient(words);
                    vector<uint64_t> remainder(words);

                    for (size_t c = 0; c < size1 + size2 - 1; c++)
                    {
                        for (size_t l = 0; l < n; l++)
                        {
                            SignedUInt sum{ vector<uint64_t>(words, 0), false };
                            for (size_t i = 0; i < size1; i++)
                            {
                                if (c < i || c - i >= size2)
                                {
                                    continue;
                                }
                                size_t j = c - i;

                                // Negacyclic convolution
                                for (size_t m = 0; m < n; m++)
                                {
                                    size_t m2 = (l + n - m) % n;
                                    util::multiply_uint(
                                        a.magnitudes.data() + (i * n + m) * k, k,
                                        b.magnitudes.data() + (j * n + m2) * k, k, words, product.data());
                                    bool negative = a.negative[i * n + m] ^ b.negative[j * n + m2] ^ (m > l);
                                    add_signed(sum, product.data(), negative);
                                }
                            }

                            // floor(t * sum / q)
                            util::multiply_uint(sum.magnitude.data(), words, t, words, scaled.data());
                            util::divide_uint(scaled.data(), q.data(), words, quotient.data(), remainder.data(), pool);
                            if (sum.negative && !util::is_zero_uint(remainder.data(), words))
                            {
                                util::increment_uint(quotient.data(), words, quotient.data());
                            }

                            // Same e < k modulo every prime
                            uint64_t e = 0;
                            for (size_t i = 0; i < k; i++)
                            {
                                uint64_t expected = util::modulo_uint(quotient.data(), words, coeff_modulus[i]);
                                if (sum.negative)
                                {
                                    expected = util::negate_uint_mod(expected, coeff_modulus[i]);
                                }
                                uint64_t d = util::sub_uint_mod(expected, result.data(c)[i * n + l], coeff_modulus[i]);
                                if (i == 0)
                                {
                                    e = d;
                                }
                                if (d != e || e >= k)
                                {
                                    return false;
                                }
                            }
                        }
                    }
                    return true;
                };

                vector<pair<size_t, size_t>> sizes{ { 2, 2 }, { 3, 2 }, { 8, 9 } };
                for (bool extreme : { true, false })
                {
                    for (auto &size : sizes)
                    {
                        Coefficients a;
                        Coefficients b;
                        Ciphertext encrypted1 = make(size.first, extreme, a);
                        Ciphertext encrypted2 = make(size.second, extreme, b);
                        Ciphertext product;
                        evaluator.multiply(encrypted1, encrypted2, product);
                        ASSERT_TRUE(check(product, size.first, a, size.second, b));
                    }

                    Coefficients a;
                    Ciphertext encrypted = make(8, extreme, a);
                    Ciphertext square;
                    evaluator.square(encrypted, square);
                    ASSERT_TRUE(check(square, 8, a, 8, a));
                    evaluator.multiply_inplace(encrypted, encrypted);
                    ASSERT_TRUE(check(encrypted, 8, a, 8, a));
                }
            }
        }
    }

    TEST(EvaluatorTest, MultiplyPlainNTTUnreducedPlaintext)
    {
        // Unreduced plaintext data, as after unsafe_load, gives the same products
        EncryptionParameters parms(scheme_type::bfv);
        parms.set_poly_modulus_degree(128);
        parms.set_plain_modulus(1 << 6);
        parms.set_coeff_modulus(CoeffModulus::Create(128, { 40, 40 }));

        SEALContext context(parms, false, sec_level_type::none);
        KeyGenerator keygen(context);
        PublicKey pk;
        keygen.create_public_key(pk);

        Encryptor encryptor(context, pk);
        Evaluator evaluator(context);

        auto &coeff_modulus = context.first_context_data()->parms().coeff_modulus();
        size_t coeff_count = parms.poly_modulus_degree();
        Plaintext plain_ntt("Fx^10 + Ex^9 + 1x^4 + 5");
        evaluator.transform_to_ntt_inplace(plain_ntt, context.first_parms_id());

        Ciphertext encrypted;
        encryptor.encrypt(Plaintext("1x^3 + 2x^1 + 3"), encrypted);
        for (size_t size : { size_t(2), size_t(3) })
        {
            Ciphertext operand = encrypted;
            if (size == 3)
            {
                evaluator.square_inplace(operand);
            }
            evaluator.transform_to_ntt_inplace(operand);

            Ciphertext expected;
            evaluator.multiply_plain(operand, plain_ntt, expected);

            // Unreduced in the second component only, then in both
            for (size_t first : { size_t(1), size_t(0) })
            {
                Plaintext unreduced = plain_ntt;
                for (size_t i = first; i < coeff_modulus.size(); i++)
                {
                    for (size_t j = 0; j < coeff_count; j += 2)
                    {
                        unreduced.data()[i * coeff_count + j] += coeff_modulus[i].value();
                    }
                }

                Ciphertext result;
                evaluator.multiply_plain(operand, unreduced, result);
                ASSERT_EQ(expected.size(), result.size());
                ASSERT_TRUE(equal(expected.data(), expected.data() + expected.dyn_array().size(), result.data()));
            }
        }
    }
} // namespace sealtest
