// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include "seal/batchencoder.h"
#include "seal/ckks.h"
#include "seal/context.h"
#include "seal/decryptor.h"
#include "seal/encryptor.h"
#include "seal/evaluator.h"
#include "seal/keygenerator.h"
#include "seal/modulus.h"
#include <cstddef>
#include <cstdint>
#include <ctime>
#include <string>
#include "gtest/gtest.h"

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

            srand(static_cast<unsigned>(time(NULL)));

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

            srand(static_cast<unsigned>(time(NULL)));

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

            srand(static_cast<unsigned>(time(NULL)));

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

            srand(static_cast<unsigned>(time(NULL)));

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

            srand(static_cast<unsigned>(time(NULL)));

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

            srand(static_cast<unsigned>(time(NULL)));

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

            srand(static_cast<unsigned>(time(NULL)));

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
            srand(static_cast<unsigned>(time(NULL)));

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
            srand(static_cast<unsigned>(time(NULL)));

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
            srand(static_cast<unsigned>(time(NULL)));

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
            srand(static_cast<unsigned>(time(NULL)));

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
            srand(static_cast<unsigned>(time(NULL)));

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
            srand(static_cast<unsigned>(time(NULL)));

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
                srand(static_cast<unsigned>(time(NULL)));
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
                srand(static_cast<unsigned>(time(NULL)));
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
                srand(static_cast<unsigned>(time(NULL)));
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
            srand(static_cast<unsigned>(time(NULL)));

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
            srand(static_cast<unsigned>(time(NULL)));

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
            srand(static_cast<unsigned>(time(NULL)));

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
                srand(static_cast<unsigned>(time(NULL)));
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
                srand(static_cast<unsigned>(time(NULL)));
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
                srand(static_cast<unsigned>(time(NULL)));
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
                srand(static_cast<unsigned>(time(NULL)));
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
                srand(static_cast<unsigned>(time(NULL)));
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
                srand(static_cast<unsigned>(time(NULL)));
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
            srand(static_cast<unsigned>(time(NULL)));

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
            srand(static_cast<unsigned>(time(NULL)));

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
            srand(static_cast<unsigned>(time(NULL)));

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
                srand(static_cast<unsigned>(time(NULL)));
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
                srand(static_cast<unsigned>(time(NULL)));
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
} // namespace sealtest
