// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include "seal/batchencoder.h"
#include "seal/ckks.h"
#include "seal/context.h"
#include "seal/decryptor.h"
#include "seal/encryptor.h"
#include "seal/evaluator.h"
#include "seal/intencoder.h"
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
        EncryptionParameters parms(scheme_type::BFV);
        Modulus plain_modulus(1 << 6);
        parms.set_poly_modulus_degree(64);
        parms.set_plain_modulus(plain_modulus);
        parms.set_coeff_modulus(CoeffModulus::Create(64, { 40 }));
        auto context = SEALContext::Create(parms, false, sec_level_type::none);
        KeyGenerator keygen(context);

        IntegerEncoder encoder(context);
        Encryptor encryptor(context, keygen.public_key());
        Evaluator evaluator(context);
        Decryptor decryptor(context, keygen.secret_key());

        Ciphertext encrypted;
        encryptor.encrypt(encoder.encode(0x12345678), encrypted);
        evaluator.negate_inplace(encrypted);
        Plaintext plain;
        decryptor.decrypt(encrypted, plain);
        ASSERT_EQ(static_cast<int32_t>(-0x12345678), encoder.decode_int32(plain));
        ASSERT_TRUE(encrypted.parms_id() == context->first_parms_id());

        encryptor.encrypt(encoder.encode(0), encrypted);
        evaluator.negate_inplace(encrypted);
        decryptor.decrypt(encrypted, plain);
        ASSERT_EQ(static_cast<int32_t>(0), encoder.decode_int32(plain));
        ASSERT_TRUE(encrypted.parms_id() == context->first_parms_id());

        encryptor.encrypt(encoder.encode(1), encrypted);
        evaluator.negate_inplace(encrypted);
        decryptor.decrypt(encrypted, plain);
        ASSERT_EQ(static_cast<int32_t>(-1), encoder.decode_int32(plain));
        ASSERT_TRUE(encrypted.parms_id() == context->first_parms_id());

        encryptor.encrypt(encoder.encode(-1), encrypted);
        evaluator.negate_inplace(encrypted);
        decryptor.decrypt(encrypted, plain);
        ASSERT_EQ(static_cast<int32_t>(1), encoder.decode_int32(plain));
        ASSERT_TRUE(encrypted.parms_id() == context->first_parms_id());

        encryptor.encrypt(encoder.encode(2), encrypted);
        evaluator.negate_inplace(encrypted);
        decryptor.decrypt(encrypted, plain);
        ASSERT_EQ(static_cast<int32_t>(-2), encoder.decode_int32(plain));
        ASSERT_TRUE(encrypted.parms_id() == context->first_parms_id());

        encryptor.encrypt(encoder.encode(-5), encrypted);
        evaluator.negate_inplace(encrypted);
        decryptor.decrypt(encrypted, plain);
        ASSERT_EQ(static_cast<int32_t>(5), encoder.decode_int32(plain));
        ASSERT_TRUE(encrypted.parms_id() == context->first_parms_id());
    }

    TEST(EvaluatorTest, BFVEncryptAddDecrypt)
    {
        EncryptionParameters parms(scheme_type::BFV);
        Modulus plain_modulus(1 << 6);
        parms.set_poly_modulus_degree(64);
        parms.set_plain_modulus(plain_modulus);
        parms.set_coeff_modulus(CoeffModulus::Create(64, { 40 }));
        auto context = SEALContext::Create(parms, false, sec_level_type::none);
        KeyGenerator keygen(context);

        IntegerEncoder encoder(context);
        Encryptor encryptor(context, keygen.public_key());
        Evaluator evaluator(context);
        Decryptor decryptor(context, keygen.secret_key());

        Ciphertext encrypted1;
        encryptor.encrypt(encoder.encode(0x12345678), encrypted1);
        Ciphertext encrypted2;
        encryptor.encrypt(encoder.encode(0x54321), encrypted2);
        evaluator.add_inplace(encrypted1, encrypted2);
        Plaintext plain;
        decryptor.decrypt(encrypted1, plain);
        ASSERT_EQ(static_cast<uint64_t>(0x12399999), encoder.decode_uint64(plain));
        ASSERT_TRUE(encrypted2.parms_id() == encrypted1.parms_id());
        ASSERT_TRUE(encrypted1.parms_id() == context->first_parms_id());

        encryptor.encrypt(encoder.encode(0), encrypted1);
        encryptor.encrypt(encoder.encode(0), encrypted2);
        evaluator.add_inplace(encrypted1, encrypted2);
        decryptor.decrypt(encrypted1, plain);
        ASSERT_EQ(static_cast<uint64_t>(0), encoder.decode_uint64(plain));
        ASSERT_TRUE(encrypted2.parms_id() == encrypted1.parms_id());
        ASSERT_TRUE(encrypted1.parms_id() == context->first_parms_id());

        encryptor.encrypt(encoder.encode(0), encrypted1);
        encryptor.encrypt(encoder.encode(5), encrypted2);
        evaluator.add_inplace(encrypted1, encrypted2);
        decryptor.decrypt(encrypted1, plain);
        ASSERT_EQ(static_cast<uint64_t>(5), encoder.decode_uint64(plain));
        ASSERT_TRUE(encrypted2.parms_id() == encrypted1.parms_id());
        ASSERT_TRUE(encrypted1.parms_id() == context->first_parms_id());

        encryptor.encrypt(encoder.encode(5), encrypted1);
        encryptor.encrypt(encoder.encode(-3), encrypted2);
        evaluator.add_inplace(encrypted1, encrypted2);
        decryptor.decrypt(encrypted1, plain);
        ASSERT_EQ(static_cast<int32_t>(2), encoder.decode_int32(plain));
        ASSERT_TRUE(encrypted2.parms_id() == encrypted1.parms_id());
        ASSERT_TRUE(encrypted1.parms_id() == context->first_parms_id());

        encryptor.encrypt(encoder.encode(-7), encrypted1);
        encryptor.encrypt(encoder.encode(2), encrypted2);
        evaluator.add_inplace(encrypted1, encrypted2);
        decryptor.decrypt(encrypted1, plain);
        ASSERT_EQ(static_cast<int32_t>(-5), encoder.decode_int32(plain));
        ASSERT_TRUE(encrypted2.parms_id() == encrypted1.parms_id());
        ASSERT_TRUE(encrypted1.parms_id() == context->first_parms_id());

        Plaintext plain1("2x^2 + 1x^1 + 3");
        Plaintext plain2("3x^3 + 4x^2 + 5x^1 + 6");
        encryptor.encrypt(plain1, encrypted1);
        encryptor.encrypt(plain2, encrypted2);
        evaluator.add_inplace(encrypted1, encrypted2);
        decryptor.decrypt(encrypted1, plain);
        ASSERT_TRUE(plain.to_string() == "3x^3 + 6x^2 + 6x^1 + 9");
        ASSERT_TRUE(encrypted2.parms_id() == encrypted1.parms_id());
        ASSERT_TRUE(encrypted1.parms_id() == context->first_parms_id());

        plain1 = "3x^5 + 1x^4 + 4x^3 + 1";
        plain2 = "5x^2 + 9x^1 + 2";
        encryptor.encrypt(plain1, encrypted1);
        encryptor.encrypt(plain2, encrypted2);
        evaluator.add_inplace(encrypted1, encrypted2);
        decryptor.decrypt(encrypted1, plain);
        ASSERT_TRUE(plain.to_string() == "3x^5 + 1x^4 + 4x^3 + 5x^2 + 9x^1 + 3");
        ASSERT_TRUE(encrypted2.parms_id() == encrypted1.parms_id());
        ASSERT_TRUE(encrypted1.parms_id() == context->first_parms_id());
    }

    TEST(EvaluatorTest, CKKSEncryptAddDecrypt)
    {
        EncryptionParameters parms(scheme_type::CKKS);
        {
            // adding two zero vectors
            size_t slot_size = 32;
            parms.set_poly_modulus_degree(slot_size * 2);
            parms.set_coeff_modulus(CoeffModulus::Create(slot_size * 2, { 30, 30, 30, 30, 30 }));
            auto context = SEALContext::Create(parms, false, sec_level_type::none);
            KeyGenerator keygen(context);

            CKKSEncoder encoder(context);
            Encryptor encryptor(context, keygen.public_key());
            Decryptor decryptor(context, keygen.secret_key());
            Evaluator evaluator(context);

            Ciphertext encrypted;
            Plaintext plain;
            Plaintext plainRes;

            vector<complex<double>> input(slot_size, 0.0);
            vector<complex<double>> output(slot_size);
            const double delta = static_cast<double>(1 << 16);
            encoder.encode(input, context->first_parms_id(), delta, plain);

            encryptor.encrypt(plain, encrypted);
            evaluator.add_inplace(encrypted, encrypted);

            // check correctness of encryption
            ASSERT_TRUE(encrypted.parms_id() == context->first_parms_id());

            decryptor.decrypt(encrypted, plainRes);

            encoder.decode(plainRes, output);

            for (size_t i = 0; i < slot_size; i++)
            {
                auto tmp = abs(input[i].real() - output[i].real());
                ASSERT_TRUE(tmp < 0.5);
            }
        }
        {
            // adding two random vectors 100 times
            size_t slot_size = 32;
            parms.set_poly_modulus_degree(slot_size * 2);
            parms.set_coeff_modulus(CoeffModulus::Create(slot_size * 2, { 60, 60, 60 }));

            auto context = SEALContext::Create(parms, false, sec_level_type::none);
            KeyGenerator keygen(context);

            CKKSEncoder encoder(context);
            Encryptor encryptor(context, keygen.public_key());
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

                encoder.encode(input1, context->first_parms_id(), delta, plain1);
                encoder.encode(input2, context->first_parms_id(), delta, plain2);

                encryptor.encrypt(plain1, encrypted1);
                encryptor.encrypt(plain2, encrypted2);
                evaluator.add_inplace(encrypted1, encrypted2);

                // check correctness of encryption
                ASSERT_TRUE(encrypted1.parms_id() == context->first_parms_id());

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
            // adding two random vectors 100 times
            size_t slot_size = 8;
            parms.set_poly_modulus_degree(64);
            parms.set_coeff_modulus(CoeffModulus::Create(64, { 60, 60, 60 }));

            auto context = SEALContext::Create(parms, false, sec_level_type::none);
            KeyGenerator keygen(context);

            CKKSEncoder encoder(context);
            Encryptor encryptor(context, keygen.public_key());
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

                encoder.encode(input1, context->first_parms_id(), delta, plain1);
                encoder.encode(input2, context->first_parms_id(), delta, plain2);

                encryptor.encrypt(plain1, encrypted1);
                encryptor.encrypt(plain2, encrypted2);
                evaluator.add_inplace(encrypted1, encrypted2);

                // check correctness of encryption
                ASSERT_TRUE(encrypted1.parms_id() == context->first_parms_id());

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
        EncryptionParameters parms(scheme_type::CKKS);
        {
            // adding two zero vectors
            size_t slot_size = 32;
            parms.set_poly_modulus_degree(slot_size * 2);
            parms.set_coeff_modulus(CoeffModulus::Create(slot_size * 2, { 30, 30, 30, 30, 30 }));

            auto context = SEALContext::Create(parms, false, sec_level_type::none);
            KeyGenerator keygen(context);

            CKKSEncoder encoder(context);
            Encryptor encryptor(context, keygen.public_key());
            Decryptor decryptor(context, keygen.secret_key());
            Evaluator evaluator(context);

            Ciphertext encrypted;
            Plaintext plain;
            Plaintext plainRes;

            vector<complex<double>> input(slot_size, 0.0);
            vector<complex<double>> output(slot_size);
            const double delta = static_cast<double>(1 << 16);
            encoder.encode(input, context->first_parms_id(), delta, plain);

            encryptor.encrypt(plain, encrypted);
            evaluator.add_plain_inplace(encrypted, plain);

            // check correctness of encryption
            ASSERT_TRUE(encrypted.parms_id() == context->first_parms_id());

            decryptor.decrypt(encrypted, plainRes);

            encoder.decode(plainRes, output);

            for (size_t i = 0; i < slot_size; i++)
            {
                auto tmp = abs(input[i].real() - output[i].real());
                ASSERT_TRUE(tmp < 0.5);
            }
        }
        {
            // adding two random vectors 50 times
            size_t slot_size = 32;
            parms.set_poly_modulus_degree(slot_size * 2);
            parms.set_coeff_modulus(CoeffModulus::Create(slot_size * 2, { 60, 60, 60 }));

            auto context = SEALContext::Create(parms, false, sec_level_type::none);
            KeyGenerator keygen(context);

            CKKSEncoder encoder(context);
            Encryptor encryptor(context, keygen.public_key());
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

                encoder.encode(input1, context->first_parms_id(), delta, plain1);
                encoder.encode(input2, context->first_parms_id(), delta, plain2);

                encryptor.encrypt(plain1, encrypted1);
                evaluator.add_plain_inplace(encrypted1, plain2);

                // check correctness of encryption
                ASSERT_TRUE(encrypted1.parms_id() == context->first_parms_id());

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
            // adding two random vectors 50 times
            size_t slot_size = 32;
            parms.set_poly_modulus_degree(slot_size * 2);
            parms.set_coeff_modulus(CoeffModulus::Create(slot_size * 2, { 60, 60, 60 }));

            auto context = SEALContext::Create(parms, false, sec_level_type::none);
            KeyGenerator keygen(context);

            CKKSEncoder encoder(context);
            Encryptor encryptor(context, keygen.public_key());
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

                encoder.encode(input1, context->first_parms_id(), delta, plain1);
                encoder.encode(input2, context->first_parms_id(), delta, plain2);

                encryptor.encrypt(plain1, encrypted1);
                evaluator.add_plain_inplace(encrypted1, plain2);

                // check correctness of encryption
                ASSERT_TRUE(encrypted1.parms_id() == context->first_parms_id());

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
            // adding two random vectors 50 times
            size_t slot_size = 8;
            parms.set_poly_modulus_degree(64);
            parms.set_coeff_modulus(CoeffModulus::Create(64, { 60, 60, 60 }));

            auto context = SEALContext::Create(parms, false, sec_level_type::none);
            KeyGenerator keygen(context);

            CKKSEncoder encoder(context);
            Encryptor encryptor(context, keygen.public_key());
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

                encoder.encode(input1, context->first_parms_id(), delta, plain1);
                encoder.encode(input2, context->first_parms_id(), delta, plain2);

                encryptor.encrypt(plain1, encrypted1);
                evaluator.add_plain_inplace(encrypted1, plain2);

                // check correctness of encryption
                ASSERT_TRUE(encrypted1.parms_id() == context->first_parms_id());

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
        EncryptionParameters parms(scheme_type::CKKS);
        {
            // adding two zero vectors
            size_t slot_size = 32;
            parms.set_poly_modulus_degree(slot_size * 2);
            parms.set_coeff_modulus(CoeffModulus::Create(slot_size * 2, { 30, 30, 30, 30, 30 }));

            auto context = SEALContext::Create(parms, false, sec_level_type::none);
            KeyGenerator keygen(context);

            CKKSEncoder encoder(context);
            Encryptor encryptor(context, keygen.public_key());
            Decryptor decryptor(context, keygen.secret_key());
            Evaluator evaluator(context);

            Ciphertext encrypted;
            Plaintext plain;
            Plaintext plainRes;

            vector<complex<double>> input(slot_size, 0.0);
            vector<complex<double>> output(slot_size);
            const double delta = static_cast<double>(1 << 16);
            encoder.encode(input, context->first_parms_id(), delta, plain);

            encryptor.encrypt(plain, encrypted);
            evaluator.add_plain_inplace(encrypted, plain);

            // check correctness of encryption
            ASSERT_TRUE(encrypted.parms_id() == context->first_parms_id());

            decryptor.decrypt(encrypted, plainRes);

            encoder.decode(plainRes, output);

            for (size_t i = 0; i < slot_size; i++)
            {
                auto tmp = abs(input[i].real() - output[i].real());
                ASSERT_TRUE(tmp < 0.5);
            }
        }
        {
            // adding two random vectors 100 times
            size_t slot_size = 32;
            parms.set_poly_modulus_degree(slot_size * 2);
            parms.set_coeff_modulus(CoeffModulus::Create(slot_size * 2, { 60, 60, 60 }));

            auto context = SEALContext::Create(parms, false, sec_level_type::none);
            KeyGenerator keygen(context);

            CKKSEncoder encoder(context);
            Encryptor encryptor(context, keygen.public_key());
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

                encoder.encode(input1, context->first_parms_id(), delta, plain1);
                encoder.encode(input2, context->first_parms_id(), delta, plain2);

                encryptor.encrypt(plain1, encrypted1);
                evaluator.sub_plain_inplace(encrypted1, plain2);

                // check correctness of encryption
                ASSERT_TRUE(encrypted1.parms_id() == context->first_parms_id());

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
            // adding two random vectors 100 times
            size_t slot_size = 8;
            parms.set_poly_modulus_degree(64);
            parms.set_coeff_modulus(CoeffModulus::Create(64, { 60, 60, 60 }));

            auto context = SEALContext::Create(parms, false, sec_level_type::none);
            KeyGenerator keygen(context);

            CKKSEncoder encoder(context);
            Encryptor encryptor(context, keygen.public_key());
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

                encoder.encode(input1, context->first_parms_id(), delta, plain1);
                encoder.encode(input2, context->first_parms_id(), delta, plain2);

                encryptor.encrypt(plain1, encrypted1);
                evaluator.sub_plain_inplace(encrypted1, plain2);

                // check correctness of encryption
                ASSERT_TRUE(encrypted1.parms_id() == context->first_parms_id());

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
        EncryptionParameters parms(scheme_type::BFV);
        Modulus plain_modulus(1 << 6);
        parms.set_poly_modulus_degree(64);
        parms.set_plain_modulus(plain_modulus);
        parms.set_coeff_modulus(CoeffModulus::Create(64, { 40 }));

        auto context = SEALContext::Create(parms, false, sec_level_type::none);
        KeyGenerator keygen(context);

        IntegerEncoder encoder(context);
        Encryptor encryptor(context, keygen.public_key());
        Evaluator evaluator(context);
        Decryptor decryptor(context, keygen.secret_key());

        Ciphertext encrypted1;
        encryptor.encrypt(encoder.encode(0x12345678), encrypted1);
        Ciphertext encrypted2;
        encryptor.encrypt(encoder.encode(0x54321), encrypted2);
        evaluator.sub_inplace(encrypted1, encrypted2);
        Plaintext plain;
        decryptor.decrypt(encrypted1, plain);
        ASSERT_EQ(static_cast<int32_t>(0x122F1357), encoder.decode_int32(plain));
        ASSERT_TRUE(encrypted2.parms_id() == encrypted1.parms_id());
        ASSERT_TRUE(encrypted1.parms_id() == context->first_parms_id());

        encryptor.encrypt(encoder.encode(0), encrypted1);
        encryptor.encrypt(encoder.encode(0), encrypted2);
        evaluator.sub_inplace(encrypted1, encrypted2);
        decryptor.decrypt(encrypted1, plain);
        ASSERT_EQ(static_cast<int32_t>(0), encoder.decode_int32(plain));
        ASSERT_TRUE(encrypted2.parms_id() == encrypted1.parms_id());
        ASSERT_TRUE(encrypted1.parms_id() == context->first_parms_id());

        encryptor.encrypt(encoder.encode(0), encrypted1);
        encryptor.encrypt(encoder.encode(5), encrypted2);
        evaluator.sub_inplace(encrypted1, encrypted2);
        decryptor.decrypt(encrypted1, plain);
        ASSERT_EQ(static_cast<int32_t>(-5), encoder.decode_int32(plain));
        ASSERT_TRUE(encrypted2.parms_id() == encrypted1.parms_id());
        ASSERT_TRUE(encrypted1.parms_id() == context->first_parms_id());

        encryptor.encrypt(encoder.encode(5), encrypted1);
        encryptor.encrypt(encoder.encode(-3), encrypted2);
        evaluator.sub_inplace(encrypted1, encrypted2);
        decryptor.decrypt(encrypted1, plain);
        ASSERT_EQ(static_cast<int32_t>(8), encoder.decode_int32(plain));
        ASSERT_TRUE(encrypted2.parms_id() == encrypted1.parms_id());
        ASSERT_TRUE(encrypted1.parms_id() == context->first_parms_id());

        encryptor.encrypt(encoder.encode(-7), encrypted1);
        encryptor.encrypt(encoder.encode(2), encrypted2);
        evaluator.sub_inplace(encrypted1, encrypted2);
        decryptor.decrypt(encrypted1, plain);
        ASSERT_EQ(static_cast<int32_t>(-9), encoder.decode_int32(plain));
        ASSERT_TRUE(encrypted2.parms_id() == encrypted1.parms_id());
        ASSERT_TRUE(encrypted1.parms_id() == context->first_parms_id());
    }

    TEST(EvaluatorTest, BFVEncryptAddPlainDecrypt)
    {
        EncryptionParameters parms(scheme_type::BFV);
        Modulus plain_modulus(1 << 6);
        parms.set_poly_modulus_degree(64);
        parms.set_plain_modulus(plain_modulus);
        parms.set_coeff_modulus(CoeffModulus::Create(64, { 40 }));

        auto context = SEALContext::Create(parms, false, sec_level_type::none);
        KeyGenerator keygen(context);

        IntegerEncoder encoder(context);
        Encryptor encryptor(context, keygen.public_key());
        Evaluator evaluator(context);
        Decryptor decryptor(context, keygen.secret_key());

        Ciphertext encrypted1;
        Ciphertext encrypted2;
        Plaintext plain;
        encryptor.encrypt(encoder.encode(0x12345678), encrypted1);
        plain = encoder.encode(0x54321);
        evaluator.add_plain_inplace(encrypted1, plain);
        decryptor.decrypt(encrypted1, plain);
        ASSERT_EQ(static_cast<uint64_t>(0x12399999), encoder.decode_uint64(plain));
        ASSERT_TRUE(encrypted1.parms_id() == context->first_parms_id());

        encryptor.encrypt(encoder.encode(0), encrypted1);
        plain = encoder.encode(0);
        evaluator.add_plain_inplace(encrypted1, plain);
        decryptor.decrypt(encrypted1, plain);
        ASSERT_EQ(static_cast<uint64_t>(0), encoder.decode_uint64(plain));
        ASSERT_TRUE(encrypted1.parms_id() == context->first_parms_id());

        encryptor.encrypt(encoder.encode(0), encrypted1);
        plain = encoder.encode(5);
        evaluator.add_plain_inplace(encrypted1, plain);
        decryptor.decrypt(encrypted1, plain);
        ASSERT_EQ(static_cast<uint64_t>(5), encoder.decode_uint64(plain));
        ASSERT_TRUE(encrypted1.parms_id() == context->first_parms_id());

        encryptor.encrypt(encoder.encode(5), encrypted1);
        plain = encoder.encode(-3);
        evaluator.add_plain_inplace(encrypted1, plain);
        decryptor.decrypt(encrypted1, plain);
        ASSERT_EQ(static_cast<uint64_t>(2), encoder.decode_uint64(plain));
        ASSERT_TRUE(encrypted1.parms_id() == context->first_parms_id());

        encryptor.encrypt(encoder.encode(-7), encrypted1);
        plain = encoder.encode(7);
        evaluator.add_plain_inplace(encrypted1, plain);
        decryptor.decrypt(encrypted1, plain);
        ASSERT_EQ(static_cast<uint64_t>(0), encoder.decode_uint64(plain));
        ASSERT_TRUE(encrypted1.parms_id() == context->first_parms_id());
    }

    TEST(EvaluatorTest, BFVEncryptSubPlainDecrypt)
    {
        EncryptionParameters parms(scheme_type::BFV);
        Modulus plain_modulus(1 << 6);
        parms.set_poly_modulus_degree(64);
        parms.set_plain_modulus(plain_modulus);
        parms.set_coeff_modulus(CoeffModulus::Create(64, { 40 }));

        auto context = SEALContext::Create(parms, false, sec_level_type::none);
        KeyGenerator keygen(context);

        IntegerEncoder encoder(context);
        Encryptor encryptor(context, keygen.public_key());
        Evaluator evaluator(context);
        Decryptor decryptor(context, keygen.secret_key());

        Ciphertext encrypted1;
        Plaintext plain;
        encryptor.encrypt(encoder.encode(0x12345678), encrypted1);
        plain = encoder.encode(0x54321);
        evaluator.sub_plain_inplace(encrypted1, plain);
        decryptor.decrypt(encrypted1, plain);
        ASSERT_EQ(static_cast<uint64_t>(0x122F1357), encoder.decode_uint64(plain));
        ASSERT_TRUE(encrypted1.parms_id() == context->first_parms_id());

        encryptor.encrypt(encoder.encode(0), encrypted1);
        plain = encoder.encode(0);
        evaluator.sub_plain_inplace(encrypted1, plain);
        decryptor.decrypt(encrypted1, plain);
        ASSERT_EQ(static_cast<uint64_t>(0), encoder.decode_uint64(plain));
        ASSERT_TRUE(encrypted1.parms_id() == context->first_parms_id());

        encryptor.encrypt(encoder.encode(0), encrypted1);
        plain = encoder.encode(5);
        evaluator.sub_plain_inplace(encrypted1, plain);
        decryptor.decrypt(encrypted1, plain);
        ASSERT_TRUE(static_cast<int64_t>(-5) == encoder.decode_int64(plain));
        ASSERT_TRUE(encrypted1.parms_id() == context->first_parms_id());

        encryptor.encrypt(encoder.encode(5), encrypted1);
        plain = encoder.encode(-3);
        evaluator.sub_plain_inplace(encrypted1, plain);
        decryptor.decrypt(encrypted1, plain);
        ASSERT_EQ(static_cast<uint64_t>(8), encoder.decode_uint64(plain));
        ASSERT_TRUE(encrypted1.parms_id() == context->first_parms_id());

        encryptor.encrypt(encoder.encode(-7), encrypted1);
        plain = encoder.encode(2);
        evaluator.sub_plain_inplace(encrypted1, plain);
        decryptor.decrypt(encrypted1, plain);
        ASSERT_TRUE(static_cast<int64_t>(-9) == encoder.decode_int64(plain));
        ASSERT_TRUE(encrypted1.parms_id() == context->first_parms_id());
    }

    TEST(EvaluatorTest, BFVEncryptMultiplyPlainDecrypt)
    {
        {
            EncryptionParameters parms(scheme_type::BFV);
            Modulus plain_modulus(1 << 6);
            parms.set_poly_modulus_degree(64);
            parms.set_plain_modulus(plain_modulus);
            parms.set_coeff_modulus(CoeffModulus::Create(64, { 40 }));

            auto context = SEALContext::Create(parms, false, sec_level_type::none);
            KeyGenerator keygen(context);

            IntegerEncoder encoder(context);
            Encryptor encryptor(context, keygen.public_key());
            Evaluator evaluator(context);
            Decryptor decryptor(context, keygen.secret_key());

            Ciphertext encrypted;
            Plaintext plain;
            encryptor.encrypt(encoder.encode(0x12345678), encrypted);
            plain = encoder.encode(0x54321);
            evaluator.multiply_plain_inplace(encrypted, plain);
            decryptor.decrypt(encrypted, plain);
            ASSERT_EQ(static_cast<uint64_t>(0x5FCBBBB88D78), encoder.decode_uint64(plain));
            ASSERT_TRUE(encrypted.parms_id() == context->first_parms_id());

            encryptor.encrypt(encoder.encode(0), encrypted);
            plain = encoder.encode(5);
            evaluator.multiply_plain_inplace(encrypted, plain);
            decryptor.decrypt(encrypted, plain);
            ASSERT_EQ(static_cast<uint64_t>(0), encoder.decode_uint64(plain));
            ASSERT_TRUE(encrypted.parms_id() == context->first_parms_id());

            encryptor.encrypt(encoder.encode(7), encrypted);
            plain = encoder.encode(4);
            evaluator.multiply_plain_inplace(encrypted, plain);
            decryptor.decrypt(encrypted, plain);
            ASSERT_EQ(static_cast<uint64_t>(28), encoder.decode_uint64(plain));
            ASSERT_TRUE(encrypted.parms_id() == context->first_parms_id());

            encryptor.encrypt(encoder.encode(7), encrypted);
            plain = encoder.encode(2);
            evaluator.multiply_plain_inplace(encrypted, plain);
            decryptor.decrypt(encrypted, plain);
            ASSERT_EQ(static_cast<uint64_t>(14), encoder.decode_uint64(plain));
            ASSERT_TRUE(encrypted.parms_id() == context->first_parms_id());

            encryptor.encrypt(encoder.encode(7), encrypted);
            plain = encoder.encode(1);
            evaluator.multiply_plain_inplace(encrypted, plain);
            decryptor.decrypt(encrypted, plain);
            ASSERT_EQ(static_cast<uint64_t>(7), encoder.decode_uint64(plain));
            ASSERT_TRUE(encrypted.parms_id() == context->first_parms_id());

            encryptor.encrypt(encoder.encode(5), encrypted);
            plain = encoder.encode(-3);
            evaluator.multiply_plain_inplace(encrypted, plain);
            decryptor.decrypt(encrypted, plain);
            ASSERT_TRUE(static_cast<int64_t>(-15) == encoder.decode_int64(plain));
            ASSERT_TRUE(encrypted.parms_id() == context->first_parms_id());

            encryptor.encrypt(encoder.encode(-7), encrypted);
            plain = encoder.encode(2);
            evaluator.multiply_plain_inplace(encrypted, plain);
            decryptor.decrypt(encrypted, plain);
            ASSERT_TRUE(static_cast<int64_t>(-14) == encoder.decode_int64(plain));
            ASSERT_TRUE(encrypted.parms_id() == context->first_parms_id());
        }
        {
            EncryptionParameters parms(scheme_type::BFV);
            Modulus plain_modulus((1ULL << 20) - 1);
            parms.set_poly_modulus_degree(64);
            parms.set_plain_modulus(plain_modulus);
            parms.set_coeff_modulus(CoeffModulus::Create(64, { 30, 60, 60 }));

            auto context = SEALContext::Create(parms, false, sec_level_type::none);
            KeyGenerator keygen(context);

            IntegerEncoder encoder(context);
            Encryptor encryptor(context, keygen.public_key());
            Evaluator evaluator(context);
            Decryptor decryptor(context, keygen.secret_key());

            Ciphertext encrypted;
            Plaintext plain;
            encryptor.encrypt(encoder.encode(0x12345678), encrypted);
            plain = "1";
            evaluator.multiply_plain_inplace(encrypted, plain);
            decryptor.decrypt(encrypted, plain);
            ASSERT_EQ(static_cast<uint64_t>(0x12345678), encoder.decode_uint64(plain));
            ASSERT_TRUE(encrypted.parms_id() == context->first_parms_id());

            plain = "5";
            evaluator.multiply_plain_inplace(encrypted, plain);
            decryptor.decrypt(encrypted, plain);
            ASSERT_EQ(static_cast<uint64_t>(0x5B05B058), encoder.decode_uint64(plain));
            ASSERT_TRUE(encrypted.parms_id() == context->first_parms_id());
        }
        {
            EncryptionParameters parms(scheme_type::BFV);
            Modulus plain_modulus((1ULL << 40) - 1);
            parms.set_poly_modulus_degree(64);
            parms.set_plain_modulus(plain_modulus);
            parms.set_coeff_modulus(CoeffModulus::Create(64, { 30, 60, 60 }));

            auto context = SEALContext::Create(parms, false, sec_level_type::none);
            KeyGenerator keygen(context);

            IntegerEncoder encoder(context);
            Encryptor encryptor(context, keygen.public_key());
            Evaluator evaluator(context);
            Decryptor decryptor(context, keygen.secret_key());

            Ciphertext encrypted;
            Plaintext plain;
            encryptor.encrypt(encoder.encode(0x12345678), encrypted);
            plain = "1";
            evaluator.multiply_plain_inplace(encrypted, plain);
            decryptor.decrypt(encrypted, plain);
            ASSERT_EQ(static_cast<uint64_t>(0x12345678), encoder.decode_uint64(plain));
            ASSERT_TRUE(encrypted.parms_id() == context->first_parms_id());

            plain = "5";
            evaluator.multiply_plain_inplace(encrypted, plain);
            decryptor.decrypt(encrypted, plain);
            ASSERT_EQ(static_cast<uint64_t>(0x5B05B058), encoder.decode_uint64(plain));
            ASSERT_TRUE(encrypted.parms_id() == context->first_parms_id());
        }
        {
            EncryptionParameters parms(scheme_type::BFV);
            Modulus plain_modulus(PlainModulus::Batching(64, 20));
            parms.set_poly_modulus_degree(64);
            parms.set_plain_modulus(plain_modulus);
            parms.set_coeff_modulus(CoeffModulus::Create(64, { 30, 30, 30 }));

            auto context = SEALContext::Create(parms, false, sec_level_type::none);
            KeyGenerator keygen(context);

            BatchEncoder batch_encoder(context);
            Encryptor encryptor(context, keygen.public_key());
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
            ASSERT_TRUE(encrypted.parms_id() == context->first_parms_id());

            batch_encoder.encode(vector<int64_t>(batch_encoder.slot_count(), -7), plain);
            encryptor.encrypt(plain, encrypted);
            evaluator.multiply_plain_inplace(encrypted, plain);
            decryptor.decrypt(encrypted, plain);
            batch_encoder.decode(plain, result);
            ASSERT_TRUE(vector<int64_t>(batch_encoder.slot_count(), 49) == result);
            ASSERT_TRUE(encrypted.parms_id() == context->first_parms_id());
        }
        {
            EncryptionParameters parms(scheme_type::BFV);
            Modulus plain_modulus(PlainModulus::Batching(64, 40));
            parms.set_poly_modulus_degree(64);
            parms.set_plain_modulus(plain_modulus);
            parms.set_coeff_modulus(CoeffModulus::Create(64, { 30, 30, 30, 30, 30 }));

            auto context = SEALContext::Create(parms, false, sec_level_type::none);
            KeyGenerator keygen(context);

            BatchEncoder batch_encoder(context);
            Encryptor encryptor(context, keygen.public_key());
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
            ASSERT_TRUE(encrypted.parms_id() == context->first_parms_id());

            batch_encoder.encode(vector<int64_t>(batch_encoder.slot_count(), -7), plain);
            encryptor.encrypt(plain, encrypted);
            evaluator.multiply_plain_inplace(encrypted, plain);
            decryptor.decrypt(encrypted, plain);
            batch_encoder.decode(plain, result);
            ASSERT_TRUE(vector<int64_t>(batch_encoder.slot_count(), 49) == result);
            ASSERT_TRUE(encrypted.parms_id() == context->first_parms_id());

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
            ASSERT_TRUE(encrypted.parms_id() == context->first_parms_id());

            input = vector<int64_t>(batch_encoder.slot_count() - 1, -7);
            input.push_back(1);
            batch_encoder.encode(input, plain);
            encryptor.encrypt(plain, encrypted);
            evaluator.multiply_plain_inplace(encrypted, plain);
            decryptor.decrypt(encrypted, plain);
            batch_encoder.decode(plain, result);
            ASSERT_TRUE(true_result == result);
            ASSERT_TRUE(encrypted.parms_id() == context->first_parms_id());
        }
    }

    TEST(EvaluatorTest, BFVEncryptMultiplyDecrypt)
    {
        {
            EncryptionParameters parms(scheme_type::BFV);
            Modulus plain_modulus(1 << 6);
            parms.set_poly_modulus_degree(64);
            parms.set_plain_modulus(plain_modulus);
            parms.set_coeff_modulus(CoeffModulus::Create(64, { 40 }));

            auto context = SEALContext::Create(parms, false, sec_level_type::none);
            KeyGenerator keygen(context);

            IntegerEncoder encoder(context);
            Encryptor encryptor(context, keygen.public_key());
            Evaluator evaluator(context);
            Decryptor decryptor(context, keygen.secret_key());

            Ciphertext encrypted1;
            Ciphertext encrypted2;
            Plaintext plain;
            encryptor.encrypt(encoder.encode(0x12345678), encrypted1);
            encryptor.encrypt(encoder.encode(0x54321), encrypted2);
            evaluator.multiply_inplace(encrypted1, encrypted2);
            decryptor.decrypt(encrypted1, plain);
            ASSERT_EQ(static_cast<uint64_t>(0x5FCBBBB88D78), encoder.decode_uint64(plain));
            ASSERT_TRUE(encrypted2.parms_id() == encrypted1.parms_id());
            ASSERT_TRUE(encrypted1.parms_id() == context->first_parms_id());

            encryptor.encrypt(encoder.encode(0), encrypted1);
            encryptor.encrypt(encoder.encode(0), encrypted2);
            evaluator.multiply_inplace(encrypted1, encrypted2);
            decryptor.decrypt(encrypted1, plain);
            ASSERT_EQ(static_cast<uint64_t>(0), encoder.decode_uint64(plain));
            ASSERT_TRUE(encrypted2.parms_id() == encrypted1.parms_id());
            ASSERT_TRUE(encrypted1.parms_id() == context->first_parms_id());

            encryptor.encrypt(encoder.encode(0), encrypted1);
            encryptor.encrypt(encoder.encode(5), encrypted2);
            evaluator.multiply_inplace(encrypted1, encrypted2);
            decryptor.decrypt(encrypted1, plain);
            ASSERT_EQ(static_cast<uint64_t>(0), encoder.decode_uint64(plain));
            ASSERT_TRUE(encrypted2.parms_id() == encrypted1.parms_id());
            ASSERT_TRUE(encrypted1.parms_id() == context->first_parms_id());

            encryptor.encrypt(encoder.encode(7), encrypted1);
            encryptor.encrypt(encoder.encode(1), encrypted2);
            evaluator.multiply_inplace(encrypted1, encrypted2);
            decryptor.decrypt(encrypted1, plain);
            ASSERT_EQ(static_cast<uint64_t>(7), encoder.decode_uint64(plain));
            ASSERT_TRUE(encrypted2.parms_id() == encrypted1.parms_id());
            ASSERT_TRUE(encrypted1.parms_id() == context->first_parms_id());

            encryptor.encrypt(encoder.encode(5), encrypted1);
            encryptor.encrypt(encoder.encode(-3), encrypted2);
            evaluator.multiply_inplace(encrypted1, encrypted2);
            decryptor.decrypt(encrypted1, plain);
            ASSERT_TRUE(static_cast<int64_t>(-15) == encoder.decode_int64(plain));
            ASSERT_TRUE(encrypted2.parms_id() == encrypted1.parms_id());
            ASSERT_TRUE(encrypted1.parms_id() == context->first_parms_id());

            encryptor.encrypt(encoder.encode(0x10000), encrypted1);
            encryptor.encrypt(encoder.encode(0x100), encrypted2);
            evaluator.multiply_inplace(encrypted1, encrypted2);
            decryptor.decrypt(encrypted1, plain);
            ASSERT_EQ(static_cast<uint64_t>(0x1000000), encoder.decode_uint64(plain));
            ASSERT_TRUE(encrypted2.parms_id() == encrypted1.parms_id());
            ASSERT_TRUE(encrypted1.parms_id() == context->first_parms_id());
        }
        {
            EncryptionParameters parms(scheme_type::BFV);
            Modulus plain_modulus((1ULL << 60) - 1);
            parms.set_poly_modulus_degree(64);
            parms.set_plain_modulus(plain_modulus);
            parms.set_coeff_modulus(CoeffModulus::Create(64, { 60, 60, 60, 60 }));

            auto context = SEALContext::Create(parms, false, sec_level_type::none);
            KeyGenerator keygen(context);

            IntegerEncoder encoder(context);
            Encryptor encryptor(context, keygen.public_key());
            Evaluator evaluator(context);
            Decryptor decryptor(context, keygen.secret_key());

            Ciphertext encrypted1;
            Ciphertext encrypted2;
            Plaintext plain;
            encryptor.encrypt(encoder.encode(0x12345678), encrypted1);
            encryptor.encrypt(encoder.encode(0x54321), encrypted2);
            evaluator.multiply_inplace(encrypted1, encrypted2);
            decryptor.decrypt(encrypted1, plain);
            ASSERT_EQ(static_cast<uint64_t>(0x5FCBBBB88D78), encoder.decode_uint64(plain));
            ASSERT_TRUE(encrypted2.parms_id() == encrypted1.parms_id());
            ASSERT_TRUE(encrypted1.parms_id() == context->first_parms_id());

            encryptor.encrypt(encoder.encode(0), encrypted1);
            encryptor.encrypt(encoder.encode(0), encrypted2);
            evaluator.multiply_inplace(encrypted1, encrypted2);
            decryptor.decrypt(encrypted1, plain);
            ASSERT_EQ(static_cast<uint64_t>(0), encoder.decode_uint64(plain));
            ASSERT_TRUE(encrypted2.parms_id() == encrypted1.parms_id());
            ASSERT_TRUE(encrypted1.parms_id() == context->first_parms_id());

            encryptor.encrypt(encoder.encode(0), encrypted1);
            encryptor.encrypt(encoder.encode(5), encrypted2);
            evaluator.multiply_inplace(encrypted1, encrypted2);
            decryptor.decrypt(encrypted1, plain);
            ASSERT_EQ(static_cast<uint64_t>(0), encoder.decode_uint64(plain));
            ASSERT_TRUE(encrypted2.parms_id() == encrypted1.parms_id());
            ASSERT_TRUE(encrypted1.parms_id() == context->first_parms_id());

            encryptor.encrypt(encoder.encode(7), encrypted1);
            encryptor.encrypt(encoder.encode(1), encrypted2);
            evaluator.multiply_inplace(encrypted1, encrypted2);
            decryptor.decrypt(encrypted1, plain);
            ASSERT_EQ(static_cast<uint64_t>(7), encoder.decode_uint64(plain));
            ASSERT_TRUE(encrypted2.parms_id() == encrypted1.parms_id());
            ASSERT_TRUE(encrypted1.parms_id() == context->first_parms_id());

            encryptor.encrypt(encoder.encode(5), encrypted1);
            encryptor.encrypt(encoder.encode(-3), encrypted2);
            evaluator.multiply_inplace(encrypted1, encrypted2);
            decryptor.decrypt(encrypted1, plain);
            ASSERT_TRUE(static_cast<int64_t>(-15) == encoder.decode_int64(plain));
            ASSERT_TRUE(encrypted2.parms_id() == encrypted1.parms_id());
            ASSERT_TRUE(encrypted1.parms_id() == context->first_parms_id());

            encryptor.encrypt(encoder.encode(0x10000), encrypted1);
            encryptor.encrypt(encoder.encode(0x100), encrypted2);
            evaluator.multiply_inplace(encrypted1, encrypted2);
            decryptor.decrypt(encrypted1, plain);
            ASSERT_EQ(static_cast<uint64_t>(0x1000000), encoder.decode_uint64(plain));
            ASSERT_TRUE(encrypted2.parms_id() == encrypted1.parms_id());
            ASSERT_TRUE(encrypted1.parms_id() == context->first_parms_id());
        }
        {
            EncryptionParameters parms(scheme_type::BFV);
            Modulus plain_modulus(1 << 6);
            parms.set_poly_modulus_degree(128);
            parms.set_plain_modulus(plain_modulus);
            parms.set_coeff_modulus(CoeffModulus::Create(128, { 40, 40 }));

            auto context = SEALContext::Create(parms, false, sec_level_type::none);
            KeyGenerator keygen(context);

            IntegerEncoder encoder(context);
            Encryptor encryptor(context, keygen.public_key());
            Evaluator evaluator(context);
            Decryptor decryptor(context, keygen.secret_key());

            Ciphertext encrypted1;
            Ciphertext encrypted2;
            Plaintext plain;
            encryptor.encrypt(encoder.encode(0x12345678), encrypted1);
            encryptor.encrypt(encoder.encode(0x54321), encrypted2);
            evaluator.multiply_inplace(encrypted1, encrypted2);
            decryptor.decrypt(encrypted1, plain);
            ASSERT_EQ(static_cast<uint64_t>(0x5FCBBBB88D78), encoder.decode_uint64(plain));
            ASSERT_TRUE(encrypted2.parms_id() == encrypted1.parms_id());
            ASSERT_TRUE(encrypted1.parms_id() == context->first_parms_id());

            encryptor.encrypt(encoder.encode(0), encrypted1);
            encryptor.encrypt(encoder.encode(0), encrypted2);
            evaluator.multiply_inplace(encrypted1, encrypted2);
            decryptor.decrypt(encrypted1, plain);
            ASSERT_EQ(static_cast<uint64_t>(0), encoder.decode_uint64(plain));
            ASSERT_TRUE(encrypted2.parms_id() == encrypted1.parms_id());
            ASSERT_TRUE(encrypted1.parms_id() == context->first_parms_id());

            encryptor.encrypt(encoder.encode(0), encrypted1);
            encryptor.encrypt(encoder.encode(5), encrypted2);
            evaluator.multiply_inplace(encrypted1, encrypted2);
            decryptor.decrypt(encrypted1, plain);
            ASSERT_EQ(static_cast<uint64_t>(0), encoder.decode_uint64(plain));
            ASSERT_TRUE(encrypted2.parms_id() == encrypted1.parms_id());
            ASSERT_TRUE(encrypted1.parms_id() == context->first_parms_id());

            encryptor.encrypt(encoder.encode(7), encrypted1);
            encryptor.encrypt(encoder.encode(1), encrypted2);
            evaluator.multiply_inplace(encrypted1, encrypted2);
            decryptor.decrypt(encrypted1, plain);
            ASSERT_EQ(static_cast<uint64_t>(7), encoder.decode_uint64(plain));
            ASSERT_TRUE(encrypted2.parms_id() == encrypted1.parms_id());
            ASSERT_TRUE(encrypted1.parms_id() == context->first_parms_id());

            encryptor.encrypt(encoder.encode(5), encrypted1);
            encryptor.encrypt(encoder.encode(-3), encrypted2);
            evaluator.multiply_inplace(encrypted1, encrypted2);
            decryptor.decrypt(encrypted1, plain);
            ASSERT_TRUE(static_cast<int64_t>(-15) == encoder.decode_int64(plain));
            ASSERT_TRUE(encrypted2.parms_id() == encrypted1.parms_id());
            ASSERT_TRUE(encrypted1.parms_id() == context->first_parms_id());

            encryptor.encrypt(encoder.encode(0x10000), encrypted1);
            encryptor.encrypt(encoder.encode(0x100), encrypted2);
            evaluator.multiply_inplace(encrypted1, encrypted2);
            decryptor.decrypt(encrypted1, plain);
            ASSERT_EQ(static_cast<uint64_t>(0x1000000), encoder.decode_uint64(plain));
            ASSERT_TRUE(encrypted2.parms_id() == encrypted1.parms_id());
            ASSERT_TRUE(encrypted1.parms_id() == context->first_parms_id());
        }
        {
            EncryptionParameters parms(scheme_type::BFV);
            Modulus plain_modulus(1 << 8);
            parms.set_poly_modulus_degree(128);
            parms.set_plain_modulus(plain_modulus);
            parms.set_coeff_modulus(CoeffModulus::Create(128, { 40, 40, 40 }));

            auto context = SEALContext::Create(parms, false, sec_level_type::none);
            KeyGenerator keygen(context);

            IntegerEncoder encoder(context);
            Encryptor encryptor(context, keygen.public_key());
            Evaluator evaluator(context);
            Decryptor decryptor(context, keygen.secret_key());

            Ciphertext encrypted1;
            Plaintext plain;
            encryptor.encrypt(encoder.encode(123), encrypted1);
            evaluator.multiply(encrypted1, encrypted1, encrypted1);
            evaluator.multiply(encrypted1, encrypted1, encrypted1);
            decryptor.decrypt(encrypted1, plain);
            ASSERT_EQ(static_cast<uint64_t>(228886641), encoder.decode_uint64(plain));
            ASSERT_TRUE(encrypted1.parms_id() == context->first_parms_id());
        }
    }

#include "seal/randomgen.h"
    TEST(EvaluatorTest, BFVRelinearize)
    {
        EncryptionParameters parms(scheme_type::BFV);
        Modulus plain_modulus(1 << 6);
        parms.set_poly_modulus_degree(128);
        parms.set_plain_modulus(plain_modulus);
        parms.set_coeff_modulus(CoeffModulus::Create(128, { 40, 40, 40, 40 }));

        auto context = SEALContext::Create(parms, true, sec_level_type::none);
        KeyGenerator keygen(context);
        RelinKeys rlk = keygen.relin_keys_local();

        Encryptor encryptor(context, keygen.public_key());
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
        EncryptionParameters parms(scheme_type::CKKS);
        {
            // multiplying two zero vectors
            size_t slot_size = 32;
            parms.set_poly_modulus_degree(slot_size * 2);
            parms.set_coeff_modulus(CoeffModulus::Create(slot_size * 2, { 30, 30, 30, 30 }));

            auto context = SEALContext::Create(parms, false, sec_level_type::none);
            KeyGenerator keygen(context);

            CKKSEncoder encoder(context);
            Encryptor encryptor(context, keygen.public_key());
            Decryptor decryptor(context, keygen.secret_key());
            Evaluator evaluator(context);

            Ciphertext encrypted;
            Plaintext plain;
            Plaintext plainRes;

            vector<complex<double>> input(slot_size, 0.0);
            vector<complex<double>> output(slot_size);
            const double delta = static_cast<double>(1 << 30);
            encoder.encode(input, context->first_parms_id(), delta, plain);

            encryptor.encrypt(plain, encrypted);
            evaluator.multiply_inplace(encrypted, encrypted);

            // check correctness of encryption
            ASSERT_TRUE(encrypted.parms_id() == context->first_parms_id());

            decryptor.decrypt(encrypted, plainRes);
            encoder.decode(plainRes, output);
            for (size_t i = 0; i < slot_size; i++)
            {
                auto tmp = abs(input[i].real() - output[i].real());
                ASSERT_TRUE(tmp < 0.5);
            }
        }
        {
            // multiplying two random vectors
            size_t slot_size = 32;
            parms.set_poly_modulus_degree(slot_size * 2);
            parms.set_coeff_modulus(CoeffModulus::Create(slot_size * 2, { 60, 60, 60 }));

            auto context = SEALContext::Create(parms, false, sec_level_type::none);
            KeyGenerator keygen(context);

            CKKSEncoder encoder(context);
            Encryptor encryptor(context, keygen.public_key());
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
                encoder.encode(input1, context->first_parms_id(), delta, plain1);
                encoder.encode(input2, context->first_parms_id(), delta, plain2);

                encryptor.encrypt(plain1, encrypted1);
                encryptor.encrypt(plain2, encrypted2);
                evaluator.multiply_inplace(encrypted1, encrypted2);

                // check correctness of encryption
                ASSERT_TRUE(encrypted1.parms_id() == context->first_parms_id());

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
            // multiplying two random vectors
            size_t slot_size = 16;
            parms.set_poly_modulus_degree(64);
            parms.set_coeff_modulus(CoeffModulus::Create(64, { 60, 60, 60 }));

            auto context = SEALContext::Create(parms, false, sec_level_type::none);
            KeyGenerator keygen(context);

            CKKSEncoder encoder(context);
            Encryptor encryptor(context, keygen.public_key());
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
                encoder.encode(input1, context->first_parms_id(), delta, plain1);
                encoder.encode(input2, context->first_parms_id(), delta, plain2);

                encryptor.encrypt(plain1, encrypted1);
                encryptor.encrypt(plain2, encrypted2);
                evaluator.multiply_inplace(encrypted1, encrypted2);

                // check correctness of encryption
                ASSERT_TRUE(encrypted1.parms_id() == context->first_parms_id());

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
        EncryptionParameters parms(scheme_type::CKKS);
        {
            // multiplying two random vectors by an integer
            size_t slot_size = 32;
            parms.set_poly_modulus_degree(slot_size * 2);
            parms.set_coeff_modulus(CoeffModulus::Create(slot_size * 2, { 60, 60, 40 }));

            auto context = SEALContext::Create(parms, false, sec_level_type::none);
            KeyGenerator keygen(context);

            CKKSEncoder encoder(context);
            Encryptor encryptor(context, keygen.public_key());
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
                encoder.encode(input1, context->first_parms_id(), delta, plain1);
                encoder.encode(input2, context->first_parms_id(), plain2);

                encryptor.encrypt(plain1, encrypted1);
                evaluator.multiply_plain_inplace(encrypted1, plain2);

                // check correctness of encryption
                ASSERT_TRUE(encrypted1.parms_id() == context->first_parms_id());

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
            // multiplying two random vectors by an integer
            size_t slot_size = 8;
            parms.set_poly_modulus_degree(64);
            parms.set_coeff_modulus(CoeffModulus::Create(64, { 60, 60 }));

            auto context = SEALContext::Create(parms, false, sec_level_type::none);
            KeyGenerator keygen(context);

            CKKSEncoder encoder(context);
            Encryptor encryptor(context, keygen.public_key());
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
                encoder.encode(input1, context->first_parms_id(), delta, plain1);
                encoder.encode(input2, context->first_parms_id(), plain2);

                encryptor.encrypt(plain1, encrypted1);
                evaluator.multiply_plain_inplace(encrypted1, plain2);

                // check correctness of encryption
                ASSERT_TRUE(encrypted1.parms_id() == context->first_parms_id());

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
            // multiplying two random vectors by a double
            size_t slot_size = 32;
            parms.set_poly_modulus_degree(slot_size * 2);
            parms.set_coeff_modulus(CoeffModulus::Create(slot_size * 2, { 60, 60, 60 }));

            auto context = SEALContext::Create(parms, false, sec_level_type::none);
            KeyGenerator keygen(context);

            CKKSEncoder encoder(context);
            Encryptor encryptor(context, keygen.public_key());
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
                encoder.encode(input1, context->first_parms_id(), delta, plain1);
                encoder.encode(input2, context->first_parms_id(), delta, plain2);

                encryptor.encrypt(plain1, encrypted1);
                evaluator.multiply_plain_inplace(encrypted1, plain2);

                // check correctness of encryption
                ASSERT_TRUE(encrypted1.parms_id() == context->first_parms_id());

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
            // multiplying two random vectors by a double
            size_t slot_size = 16;
            parms.set_poly_modulus_degree(64);
            parms.set_coeff_modulus(CoeffModulus::Create(64, { 60, 60, 60 }));

            auto context = SEALContext::Create(parms, false, sec_level_type::none);
            KeyGenerator keygen(context);

            CKKSEncoder encoder(context);
            Encryptor encryptor(context, keygen.public_key());
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
                encoder.encode(input1, context->first_parms_id(), delta, plain1);
                encoder.encode(input2, context->first_parms_id(), delta, plain2);

                encryptor.encrypt(plain1, encrypted1);
                evaluator.multiply_plain_inplace(encrypted1, plain2);

                // check correctness of encryption
                ASSERT_TRUE(encrypted1.parms_id() == context->first_parms_id());

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
        EncryptionParameters parms(scheme_type::CKKS);
        {
            // multiplying two random vectors 50 times
            size_t slot_size = 32;
            parms.set_poly_modulus_degree(slot_size * 2);
            parms.set_coeff_modulus(CoeffModulus::Create(slot_size * 2, { 60, 60, 60 }));

            auto context = SEALContext::Create(parms, false, sec_level_type::none);
            KeyGenerator keygen(context);

            CKKSEncoder encoder(context);
            Encryptor encryptor(context, keygen.public_key());
            Decryptor decryptor(context, keygen.secret_key());
            Evaluator evaluator(context);
            RelinKeys rlk = keygen.relin_keys_local();

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
                encoder.encode(input1, context->first_parms_id(), delta, plain1);
                encoder.encode(input2, context->first_parms_id(), delta, plain2);

                encryptor.encrypt(plain1, encrypted1);
                encryptor.encrypt(plain2, encrypted2);

                // check correctness of encryption
                ASSERT_TRUE(encrypted1.parms_id() == context->first_parms_id());
                // check correctness of encryption
                ASSERT_TRUE(encrypted2.parms_id() == context->first_parms_id());

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
            // multiplying two random vectors 50 times
            size_t slot_size = 32;
            parms.set_poly_modulus_degree(slot_size * 2);
            parms.set_coeff_modulus(CoeffModulus::Create(slot_size * 2, { 60, 30, 30, 30 }));

            auto context = SEALContext::Create(parms, false, sec_level_type::none);
            KeyGenerator keygen(context);

            CKKSEncoder encoder(context);
            Encryptor encryptor(context, keygen.public_key());
            Decryptor decryptor(context, keygen.secret_key());
            Evaluator evaluator(context);
            RelinKeys rlk = keygen.relin_keys_local();

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
                encoder.encode(input1, context->first_parms_id(), delta, plain1);
                encoder.encode(input2, context->first_parms_id(), delta, plain2);

                encryptor.encrypt(plain1, encrypted1);
                encryptor.encrypt(plain2, encrypted2);

                // check correctness of encryption
                ASSERT_TRUE(encrypted1.parms_id() == context->first_parms_id());
                // check correctness of encryption
                ASSERT_TRUE(encrypted2.parms_id() == context->first_parms_id());

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
            // multiplying two random vectors 50 times
            size_t slot_size = 2;
            parms.set_poly_modulus_degree(8);
            parms.set_coeff_modulus(CoeffModulus::Create(8, { 60, 30, 30, 30 }));

            auto context = SEALContext::Create(parms, false, sec_level_type::none);
            KeyGenerator keygen(context);

            CKKSEncoder encoder(context);
            Encryptor encryptor(context, keygen.public_key());
            Decryptor decryptor(context, keygen.secret_key());
            Evaluator evaluator(context);
            RelinKeys rlk = keygen.relin_keys_local();

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

                encoder.encode(input1, context->first_parms_id(), delta, plain1);
                encoder.encode(input2, context->first_parms_id(), delta, plain2);

                encryptor.encrypt(plain1, encrypted1);
                encryptor.encrypt(plain2, encrypted2);

                // check correctness of encryption
                ASSERT_TRUE(encrypted1.parms_id() == context->first_parms_id());
                // check correctness of encryption
                ASSERT_TRUE(encrypted2.parms_id() == context->first_parms_id());

                evaluator.multiply_inplace(encrypted1, encrypted2);
                // evaluator.relinearize_inplace(encrypted1, rlk);

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
        EncryptionParameters parms(scheme_type::CKKS);
        {
            // squaring two random vectors 100 times
            size_t slot_size = 32;
            parms.set_poly_modulus_degree(slot_size * 2);
            parms.set_coeff_modulus(CoeffModulus::Create(slot_size * 2, { 60, 60, 60 }));

            auto context = SEALContext::Create(parms, false, sec_level_type::none);
            KeyGenerator keygen(context);

            CKKSEncoder encoder(context);
            Encryptor encryptor(context, keygen.public_key());
            Decryptor decryptor(context, keygen.secret_key());
            Evaluator evaluator(context);
            RelinKeys rlk = keygen.relin_keys_local();

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
                encoder.encode(input, context->first_parms_id(), delta, plain);

                encryptor.encrypt(plain, encrypted);

                // check correctness of encryption
                ASSERT_TRUE(encrypted.parms_id() == context->first_parms_id());

                // evaluator.square_inplace(encrypted);
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
            // squaring two random vectors 100 times
            size_t slot_size = 32;
            parms.set_poly_modulus_degree(slot_size * 2);
            parms.set_coeff_modulus(CoeffModulus::Create(slot_size * 2, { 60, 30, 30, 30 }));

            auto context = SEALContext::Create(parms, false, sec_level_type::none);
            KeyGenerator keygen(context);

            CKKSEncoder encoder(context);
            Encryptor encryptor(context, keygen.public_key());
            Decryptor decryptor(context, keygen.secret_key());
            Evaluator evaluator(context);
            RelinKeys rlk = keygen.relin_keys_local();

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
                encoder.encode(input, context->first_parms_id(), delta, plain);

                encryptor.encrypt(plain, encrypted);

                // check correctness of encryption
                ASSERT_TRUE(encrypted.parms_id() == context->first_parms_id());

                // evaluator.square_inplace(encrypted);
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
            // squaring two random vectors 100 times
            size_t slot_size = 16;
            parms.set_poly_modulus_degree(64);
            parms.set_coeff_modulus(CoeffModulus::Create(64, { 60, 30, 30, 30 }));

            auto context = SEALContext::Create(parms, false, sec_level_type::none);
            KeyGenerator keygen(context);

            CKKSEncoder encoder(context);
            Encryptor encryptor(context, keygen.public_key());
            Decryptor decryptor(context, keygen.secret_key());
            Evaluator evaluator(context);
            RelinKeys rlk = keygen.relin_keys_local();

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
                encoder.encode(input, context->first_parms_id(), delta, plain);

                encryptor.encrypt(plain, encrypted);

                // check correctness of encryption
                ASSERT_TRUE(encrypted.parms_id() == context->first_parms_id());

                // evaluator.square_inplace(encrypted);
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
        EncryptionParameters parms(scheme_type::CKKS);
        {
            // multiplying two random vectors 100 times
            size_t slot_size = 64;
            parms.set_poly_modulus_degree(slot_size * 2);
            parms.set_coeff_modulus(CoeffModulus::Create(slot_size * 2, { 30, 30, 30, 30, 30, 30 }));

            auto context = SEALContext::Create(parms, true, sec_level_type::none);
            auto next_parms_id = context->first_context_data()->next_context_data()->parms_id();
            KeyGenerator keygen(context);

            CKKSEncoder encoder(context);
            Encryptor encryptor(context, keygen.public_key());
            Decryptor decryptor(context, keygen.secret_key());
            Evaluator evaluator(context);
            RelinKeys rlk = keygen.relin_keys_local();

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
                encoder.encode(input1, context->first_parms_id(), delta, plain1);
                encoder.encode(input2, context->first_parms_id(), delta, plain2);

                encryptor.encrypt(plain1, encrypted1);
                encryptor.encrypt(plain2, encrypted2);

                // check correctness of encryption
                ASSERT_TRUE(encrypted1.parms_id() == context->first_parms_id());
                // check correctness of encryption
                ASSERT_TRUE(encrypted2.parms_id() == context->first_parms_id());

                evaluator.multiply_inplace(encrypted1, encrypted2);
                evaluator.relinearize_inplace(encrypted1, rlk);
                evaluator.rescale_to_next_inplace(encrypted1);

                // check correctness of modulus switching
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
            // multiplying two random vectors 100 times
            size_t slot_size = 16;
            parms.set_poly_modulus_degree(128);
            parms.set_coeff_modulus(CoeffModulus::Create(128, { 30, 30, 30, 30, 30 }));

            auto context = SEALContext::Create(parms, true, sec_level_type::none);
            auto next_parms_id = context->first_context_data()->next_context_data()->parms_id();
            KeyGenerator keygen(context);

            CKKSEncoder encoder(context);
            Encryptor encryptor(context, keygen.public_key());
            Decryptor decryptor(context, keygen.secret_key());
            Evaluator evaluator(context);
            RelinKeys rlk = keygen.relin_keys_local();

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
                encoder.encode(input1, context->first_parms_id(), delta, plain1);
                encoder.encode(input2, context->first_parms_id(), delta, plain2);

                encryptor.encrypt(plain1, encrypted1);
                encryptor.encrypt(plain2, encrypted2);

                // check correctness of encryption
                ASSERT_TRUE(encrypted1.parms_id() == context->first_parms_id());
                // check correctness of encryption
                ASSERT_TRUE(encrypted2.parms_id() == context->first_parms_id());

                evaluator.multiply_inplace(encrypted1, encrypted2);
                evaluator.relinearize_inplace(encrypted1, rlk);
                evaluator.rescale_to_next_inplace(encrypted1);

                // check correctness of modulus switching
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
            // multiplying two random vectors 100 times
            size_t slot_size = 16;
            parms.set_poly_modulus_degree(128);
            parms.set_coeff_modulus(CoeffModulus::Create(128, { 60, 60, 60, 60, 60 }));

            auto context = SEALContext::Create(parms, true, sec_level_type::none);
            KeyGenerator keygen(context);

            CKKSEncoder encoder(context);
            Encryptor encryptor(context, keygen.public_key());
            Decryptor decryptor(context, keygen.secret_key());
            Evaluator evaluator(context);
            RelinKeys rlk = keygen.relin_keys_local();

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
                encoder.encode(input1, context->first_parms_id(), delta, plain1);
                encoder.encode(input2, context->first_parms_id(), delta, plain2);

                encryptor.encrypt(plain1, encrypted1);
                encryptor.encrypt(plain2, encrypted2);

                // check correctness of encryption
                ASSERT_TRUE(encrypted1.parms_id() == context->first_parms_id());
                // check correctness of encryption
                ASSERT_TRUE(encrypted2.parms_id() == context->first_parms_id());

                evaluator.multiply_inplace(encrypted1, encrypted2);
                evaluator.relinearize_inplace(encrypted1, rlk);
                evaluator.multiply_inplace(encrypted1, encrypted2);
                evaluator.relinearize_inplace(encrypted1, rlk);

                // Scale down by two levels
                auto target_parms = context->first_context_data()->next_context_data()->next_context_data()->parms_id();
                evaluator.rescale_to_inplace(encrypted1, target_parms);

                // check correctness of modulus switching
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
                encoder.encode(input1, context->first_parms_id(), delta, plain1);
                encoder.encode(input2, context->first_parms_id(), delta, plain2);

                encryptor.encrypt(plain1, encrypted1);
                encryptor.encrypt(plain2, encrypted2);

                // check correctness of encryption
                ASSERT_TRUE(encrypted1.parms_id() == context->first_parms_id());
                // check correctness of encryption
                ASSERT_TRUE(encrypted2.parms_id() == context->first_parms_id());

                evaluator.multiply_inplace(encrypted1, encrypted2);
                evaluator.relinearize_inplace(encrypted1, rlk);
                evaluator.multiply_inplace(encrypted1, encrypted2);

                // Scale down by two levels
                auto target_parms = context->first_context_data()->next_context_data()->next_context_data()->parms_id();
                evaluator.rescale_to_inplace(encrypted1, target_parms);

                // Relinearize now
                evaluator.relinearize_inplace(encrypted1, rlk);

                // check correctness of modulus switching
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
        EncryptionParameters parms(scheme_type::CKKS);
        {
            // squaring two random vectors 100 times
            size_t slot_size = 64;
            parms.set_poly_modulus_degree(slot_size * 2);
            parms.set_coeff_modulus(CoeffModulus::Create(slot_size * 2, { 50, 50, 50 }));

            auto context = SEALContext::Create(parms, true, sec_level_type::none);
            auto next_parms_id = context->first_context_data()->next_context_data()->parms_id();
            KeyGenerator keygen(context);

            CKKSEncoder encoder(context);
            Encryptor encryptor(context, keygen.public_key());
            Decryptor decryptor(context, keygen.secret_key());
            Evaluator evaluator(context);
            RelinKeys rlk = keygen.relin_keys_local();

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
                encoder.encode(input, context->first_parms_id(), delta, plain);

                encryptor.encrypt(plain, encrypted);

                // check correctness of encryption
                ASSERT_TRUE(encrypted.parms_id() == context->first_parms_id());

                evaluator.square_inplace(encrypted);
                evaluator.relinearize_inplace(encrypted, rlk);
                evaluator.rescale_to_next_inplace(encrypted);

                // check correctness of modulus switching
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
            // squaring two random vectors 100 times
            size_t slot_size = 16;
            parms.set_poly_modulus_degree(128);
            parms.set_coeff_modulus(CoeffModulus::Create(128, { 50, 50, 50 }));

            auto context = SEALContext::Create(parms, true, sec_level_type::none);
            auto next_parms_id = context->first_context_data()->next_context_data()->parms_id();
            KeyGenerator keygen(context);

            CKKSEncoder encoder(context);
            Encryptor encryptor(context, keygen.public_key());
            Decryptor decryptor(context, keygen.secret_key());
            Evaluator evaluator(context);
            RelinKeys rlk = keygen.relin_keys_local();

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
                encoder.encode(input, context->first_parms_id(), delta, plain);

                encryptor.encrypt(plain, encrypted);

                // check correctness of encryption
                ASSERT_TRUE(encrypted.parms_id() == context->first_parms_id());

                evaluator.square_inplace(encrypted);
                evaluator.relinearize_inplace(encrypted, rlk);
                evaluator.rescale_to_next_inplace(encrypted);

                // check correctness of modulus switching
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
        EncryptionParameters parms(scheme_type::CKKS);
        {
            // modulus switching without rescaling for random vectors
            size_t slot_size = 64;
            parms.set_poly_modulus_degree(slot_size * 2);
            parms.set_coeff_modulus(CoeffModulus::Create(slot_size * 2, { 60, 60, 60, 60, 60 }));

            auto context = SEALContext::Create(parms, true, sec_level_type::none);
            auto next_parms_id = context->first_context_data()->next_context_data()->parms_id();
            KeyGenerator keygen(context);

            CKKSEncoder encoder(context);
            Encryptor encryptor(context, keygen.public_key());
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
                encoder.encode(input, context->first_parms_id(), delta, plain);

                encryptor.encrypt(plain, encrypted);

                // check correctness of encryption
                ASSERT_TRUE(encrypted.parms_id() == context->first_parms_id());

                // Not inplace
                Ciphertext destination;
                evaluator.mod_switch_to_next(encrypted, destination);

                // check correctness of modulus switching
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

                // check correctness of modulus switching
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
            // modulus switching without rescaling for random vectors
            size_t slot_size = 32;
            parms.set_poly_modulus_degree(slot_size * 2);
            parms.set_coeff_modulus(CoeffModulus::Create(slot_size * 2, { 40, 40, 40, 40, 40 }));

            auto context = SEALContext::Create(parms, true, sec_level_type::none);
            auto next_parms_id = context->first_context_data()->next_context_data()->parms_id();
            KeyGenerator keygen(context);

            CKKSEncoder encoder(context);
            Encryptor encryptor(context, keygen.public_key());
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
                encoder.encode(input, context->first_parms_id(), delta, plain);

                encryptor.encrypt(plain, encrypted);

                // check correctness of encryption
                ASSERT_TRUE(encrypted.parms_id() == context->first_parms_id());

                // Not inplace
                Ciphertext destination;
                evaluator.mod_switch_to_next(encrypted, destination);

                // check correctness of modulus switching
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

                // check correctness of modulus switching
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
            // modulus switching without rescaling for random vectors
            size_t slot_size = 32;
            parms.set_poly_modulus_degree(128);
            parms.set_coeff_modulus(CoeffModulus::Create(128, { 40, 40, 40, 40, 40 }));

            auto context = SEALContext::Create(parms, true, sec_level_type::none);
            auto next_parms_id = context->first_context_data()->next_context_data()->parms_id();
            KeyGenerator keygen(context);

            CKKSEncoder encoder(context);
            Encryptor encryptor(context, keygen.public_key());
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
                encoder.encode(input, context->first_parms_id(), delta, plain);

                encryptor.encrypt(plain, encrypted);

                // check correctness of encryption
                ASSERT_TRUE(encrypted.parms_id() == context->first_parms_id());

                // Not inplace
                Ciphertext destination;
                evaluator.mod_switch_to_next(encrypted, destination);

                // check correctness of modulus switching
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

                // check correctness of modulus switching
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
        EncryptionParameters parms(scheme_type::CKKS);
        {
            // multiplication and addition without rescaling for random vectors
            size_t slot_size = 64;
            parms.set_poly_modulus_degree(slot_size * 2);
            parms.set_coeff_modulus(CoeffModulus::Create(slot_size * 2, { 50, 50, 50 }));

            auto context = SEALContext::Create(parms, true, sec_level_type::none);
            auto next_parms_id = context->first_context_data()->next_context_data()->parms_id();
            KeyGenerator keygen(context);

            CKKSEncoder encoder(context);
            Encryptor encryptor(context, keygen.public_key());
            Decryptor decryptor(context, keygen.secret_key());
            Evaluator evaluator(context);
            RelinKeys rlk = keygen.relin_keys_local();

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
                encoder.encode(input1, context->first_parms_id(), delta, plain1);
                encoder.encode(input2, context->first_parms_id(), delta, plain2);
                encoder.encode(input3, context->first_parms_id(), delta * delta, plain3);

                encryptor.encrypt(plain1, encrypted1);
                encryptor.encrypt(plain2, encrypted2);
                encryptor.encrypt(plain3, encrypted3);

                // check correctness of encryption
                ASSERT_TRUE(encrypted1.parms_id() == context->first_parms_id());
                // check correctness of encryption
                ASSERT_TRUE(encrypted2.parms_id() == context->first_parms_id());
                // check correctness of encryption
                ASSERT_TRUE(encrypted3.parms_id() == context->first_parms_id());

                // enc1*enc2
                evaluator.multiply_inplace(encrypted1, encrypted2);
                evaluator.relinearize_inplace(encrypted1, rlk);
                evaluator.rescale_to_next_inplace(encrypted1);

                // check correctness of modulus switching with rescaling
                ASSERT_TRUE(encrypted1.parms_id() == next_parms_id);

                // move enc3 to the level of enc1 * enc2
                evaluator.rescale_to_inplace(encrypted3, next_parms_id);

                // enc1*enc2 + enc3
                evaluator.add_inplace(encrypted1, encrypted3);

                // decryption
                decryptor.decrypt(encrypted1, plainRes);
                // decoding
                encoder.decode(plainRes, output);

                for (size_t i = 0; i < slot_size; i++)
                {
                    auto tmp = abs(expected[i].real() - output[i].real());
                    ASSERT_TRUE(tmp < 0.5);
                }
            }
        }
        {
            // multiplication and addition without rescaling for random vectors
            size_t slot_size = 16;
            parms.set_poly_modulus_degree(128);
            parms.set_coeff_modulus(CoeffModulus::Create(128, { 50, 50, 50 }));

            auto context = SEALContext::Create(parms, true, sec_level_type::none);
            auto next_parms_id = context->first_context_data()->next_context_data()->parms_id();
            KeyGenerator keygen(context);

            CKKSEncoder encoder(context);
            Encryptor encryptor(context, keygen.public_key());
            Decryptor decryptor(context, keygen.secret_key());
            Evaluator evaluator(context);
            RelinKeys rlk = keygen.relin_keys_local();

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
                encoder.encode(input1, context->first_parms_id(), delta, plain1);
                encoder.encode(input2, context->first_parms_id(), delta, plain2);
                encoder.encode(input3, context->first_parms_id(), delta * delta, plain3);

                encryptor.encrypt(plain1, encrypted1);
                encryptor.encrypt(plain2, encrypted2);
                encryptor.encrypt(plain3, encrypted3);

                // check correctness of encryption
                ASSERT_TRUE(encrypted1.parms_id() == context->first_parms_id());
                // check correctness of encryption
                ASSERT_TRUE(encrypted2.parms_id() == context->first_parms_id());
                // check correctness of encryption
                ASSERT_TRUE(encrypted3.parms_id() == context->first_parms_id());

                // enc1*enc2
                evaluator.multiply_inplace(encrypted1, encrypted2);
                evaluator.relinearize_inplace(encrypted1, rlk);
                evaluator.rescale_to_next_inplace(encrypted1);

                // check correctness of modulus switching with rescaling
                ASSERT_TRUE(encrypted1.parms_id() == next_parms_id);

                // move enc3 to the level of enc1 * enc2
                evaluator.rescale_to_inplace(encrypted3, next_parms_id);

                // enc1*enc2 + enc3
                evaluator.add_inplace(encrypted1, encrypted3);

                // decryption
                decryptor.decrypt(encrypted1, plainRes);
                // decoding
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
        EncryptionParameters parms(scheme_type::CKKS);
        {
            // maximal number of slots
            size_t slot_size = 4;
            parms.set_poly_modulus_degree(slot_size * 2);
            parms.set_coeff_modulus(CoeffModulus::Create(slot_size * 2, { 40, 40, 40, 40 }));

            auto context = SEALContext::Create(parms, false, sec_level_type::none);
            KeyGenerator keygen(context);
            GaloisKeys glk = keygen.galois_keys_local();

            Encryptor encryptor(context, keygen.public_key());
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

            encoder.encode(input, context->first_parms_id(), delta, plain);
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

            encoder.encode(input, context->first_parms_id(), delta, plain);
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

            encoder.encode(input, context->first_parms_id(), delta, plain);
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

            encoder.encode(input, context->first_parms_id(), delta, plain);
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

            auto context = SEALContext::Create(parms, false, sec_level_type::none);
            KeyGenerator keygen(context);
            GaloisKeys glk = keygen.galois_keys_local();

            Encryptor encryptor(context, keygen.public_key());
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

            encoder.encode(input, context->first_parms_id(), delta, plain);
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

            encoder.encode(input, context->first_parms_id(), delta, plain);
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

            encoder.encode(input, context->first_parms_id(), delta, plain);
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

            encoder.encode(input, context->first_parms_id(), delta, plain);
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
        EncryptionParameters parms(scheme_type::CKKS);
        {
            // maximal number of slots
            size_t slot_size = 4;
            parms.set_poly_modulus_degree(slot_size * 2);
            parms.set_coeff_modulus(CoeffModulus::Create(slot_size * 2, { 40, 40, 40, 40 }));

            auto context = SEALContext::Create(parms, true, sec_level_type::none);
            KeyGenerator keygen(context);
            GaloisKeys glk = keygen.galois_keys_local();

            Encryptor encryptor(context, keygen.public_key());
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

            encoder.encode(input, context->first_parms_id(), delta, plain);
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

            encoder.encode(input, context->first_parms_id(), delta, plain);
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

            encoder.encode(input, context->first_parms_id(), delta, plain);
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

            encoder.encode(input, context->first_parms_id(), delta, plain);
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

            auto context = SEALContext::Create(parms, true, sec_level_type::none);
            KeyGenerator keygen(context);
            GaloisKeys glk = keygen.galois_keys_local();

            Encryptor encryptor(context, keygen.public_key());
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

            encoder.encode(input, context->first_parms_id(), delta, plain);
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

            encoder.encode(input, context->first_parms_id(), delta, plain);
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

            encoder.encode(input, context->first_parms_id(), delta, plain);
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

            encoder.encode(input, context->first_parms_id(), delta, plain);
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
        EncryptionParameters parms(scheme_type::BFV);
        Modulus plain_modulus(1 << 8);
        parms.set_poly_modulus_degree(128);
        parms.set_plain_modulus(plain_modulus);
        parms.set_coeff_modulus(CoeffModulus::Create(128, { 40, 40, 40 }));

        auto context = SEALContext::Create(parms, false, sec_level_type::none);
        KeyGenerator keygen(context);

        IntegerEncoder encoder(context);
        Encryptor encryptor(context, keygen.public_key());
        Evaluator evaluator(context);
        Decryptor decryptor(context, keygen.secret_key());

        Ciphertext encrypted;
        Plaintext plain;
        encryptor.encrypt(encoder.encode(1), encrypted);
        evaluator.square_inplace(encrypted);
        decryptor.decrypt(encrypted, plain);
        ASSERT_EQ(1ULL, encoder.decode_uint64(plain));
        ASSERT_TRUE(encrypted.parms_id() == context->first_parms_id());

        encryptor.encrypt(encoder.encode(0), encrypted);
        evaluator.square_inplace(encrypted);
        decryptor.decrypt(encrypted, plain);
        ASSERT_EQ(0ULL, encoder.decode_uint64(plain));
        ASSERT_TRUE(encrypted.parms_id() == context->first_parms_id());

        encryptor.encrypt(encoder.encode(-5), encrypted);
        evaluator.square_inplace(encrypted);
        decryptor.decrypt(encrypted, plain);
        ASSERT_EQ(25ULL, encoder.decode_uint64(plain));
        ASSERT_TRUE(encrypted.parms_id() == context->first_parms_id());

        encryptor.encrypt(encoder.encode(-1), encrypted);
        evaluator.square_inplace(encrypted);
        decryptor.decrypt(encrypted, plain);
        ASSERT_EQ(1ULL, encoder.decode_uint64(plain));
        ASSERT_TRUE(encrypted.parms_id() == context->first_parms_id());

        encryptor.encrypt(encoder.encode(123), encrypted);
        evaluator.square_inplace(encrypted);
        decryptor.decrypt(encrypted, plain);
        ASSERT_EQ(15129ULL, encoder.decode_uint64(plain));
        ASSERT_TRUE(encrypted.parms_id() == context->first_parms_id());

        encryptor.encrypt(encoder.encode(0x10000), encrypted);
        evaluator.square_inplace(encrypted);
        decryptor.decrypt(encrypted, plain);
        ASSERT_EQ(0x100000000ULL, encoder.decode_uint64(plain));
        ASSERT_TRUE(encrypted.parms_id() == context->first_parms_id());

        encryptor.encrypt(encoder.encode(123), encrypted);
        evaluator.square_inplace(encrypted);
        evaluator.square_inplace(encrypted);
        decryptor.decrypt(encrypted, plain);
        ASSERT_EQ(228886641ULL, encoder.decode_uint64(plain));
        ASSERT_TRUE(encrypted.parms_id() == context->first_parms_id());
    }

    TEST(EvaluatorTest, BFVEncryptMultiplyManyDecrypt)
    {
        EncryptionParameters parms(scheme_type::BFV);
        Modulus plain_modulus(1 << 6);
        parms.set_poly_modulus_degree(128);
        parms.set_plain_modulus(plain_modulus);
        parms.set_coeff_modulus(CoeffModulus::Create(128, { 40, 40, 40 }));

        auto context = SEALContext::Create(parms, false, sec_level_type::none);
        KeyGenerator keygen(context);

        IntegerEncoder encoder(context);
        Encryptor encryptor(context, keygen.public_key());
        Evaluator evaluator(context);
        Decryptor decryptor(context, keygen.secret_key());
        RelinKeys rlk = keygen.relin_keys_local();

        Ciphertext encrypted1, encrypted2, encrypted3, encrypted4, product;
        Plaintext plain;
        encryptor.encrypt(encoder.encode(5), encrypted1);
        encryptor.encrypt(encoder.encode(6), encrypted2);
        encryptor.encrypt(encoder.encode(7), encrypted3);
        vector<Ciphertext> encrypteds{ encrypted1, encrypted2, encrypted3 };
        evaluator.multiply_many(encrypteds, rlk, product);
        ASSERT_EQ(3, encrypteds.size());
        decryptor.decrypt(product, plain);
        ASSERT_EQ(static_cast<uint64_t>(210), encoder.decode_uint64(plain));
        ASSERT_TRUE(encrypted1.parms_id() == product.parms_id());
        ASSERT_TRUE(encrypted2.parms_id() == product.parms_id());
        ASSERT_TRUE(encrypted3.parms_id() == product.parms_id());
        ASSERT_TRUE(product.parms_id() == context->first_parms_id());

        encryptor.encrypt(encoder.encode(-9), encrypted1);
        encryptor.encrypt(encoder.encode(-17), encrypted2);
        encrypteds = { encrypted1, encrypted2 };
        evaluator.multiply_many(encrypteds, rlk, product);
        ASSERT_EQ(2, encrypteds.size());
        decryptor.decrypt(product, plain);
        ASSERT_EQ(static_cast<uint64_t>(153), encoder.decode_uint64(plain));
        ASSERT_TRUE(encrypted1.parms_id() == product.parms_id());
        ASSERT_TRUE(encrypted2.parms_id() == product.parms_id());
        ASSERT_TRUE(product.parms_id() == context->first_parms_id());

        encryptor.encrypt(encoder.encode(2), encrypted1);
        encryptor.encrypt(encoder.encode(-31), encrypted2);
        encryptor.encrypt(encoder.encode(7), encrypted3);
        encrypteds = { encrypted1, encrypted2, encrypted3 };
        evaluator.multiply_many(encrypteds, rlk, product);
        ASSERT_EQ(3, encrypteds.size());
        decryptor.decrypt(product, plain);
        ASSERT_TRUE(static_cast<int64_t>(-434) == encoder.decode_int64(plain));
        ASSERT_TRUE(encrypted1.parms_id() == product.parms_id());
        ASSERT_TRUE(encrypted2.parms_id() == product.parms_id());
        ASSERT_TRUE(encrypted3.parms_id() == product.parms_id());
        ASSERT_TRUE(product.parms_id() == context->first_parms_id());

        encryptor.encrypt(encoder.encode(1), encrypted1);
        encryptor.encrypt(encoder.encode(-1), encrypted2);
        encryptor.encrypt(encoder.encode(1), encrypted3);
        encryptor.encrypt(encoder.encode(-1), encrypted4);
        encrypteds = { encrypted1, encrypted2, encrypted3, encrypted4 };
        evaluator.multiply_many(encrypteds, rlk, product);
        ASSERT_EQ(4, encrypteds.size());
        decryptor.decrypt(product, plain);
        ASSERT_EQ(static_cast<uint64_t>(1), encoder.decode_uint64(plain));
        ASSERT_TRUE(encrypted1.parms_id() == product.parms_id());
        ASSERT_TRUE(encrypted2.parms_id() == product.parms_id());
        ASSERT_TRUE(encrypted3.parms_id() == product.parms_id());
        ASSERT_TRUE(encrypted4.parms_id() == product.parms_id());
        ASSERT_TRUE(product.parms_id() == context->first_parms_id());

        encryptor.encrypt(encoder.encode(98765), encrypted1);
        encryptor.encrypt(encoder.encode(0), encrypted2);
        encryptor.encrypt(encoder.encode(12345), encrypted3);
        encryptor.encrypt(encoder.encode(34567), encrypted4);
        encrypteds = { encrypted1, encrypted2, encrypted3, encrypted4 };
        evaluator.multiply_many(encrypteds, rlk, product);
        ASSERT_EQ(4, encrypteds.size());
        decryptor.decrypt(product, plain);
        ASSERT_EQ(static_cast<uint64_t>(0), encoder.decode_uint64(plain));
        ASSERT_TRUE(encrypted1.parms_id() == product.parms_id());
        ASSERT_TRUE(encrypted2.parms_id() == product.parms_id());
        ASSERT_TRUE(encrypted3.parms_id() == product.parms_id());
        ASSERT_TRUE(encrypted4.parms_id() == product.parms_id());
        ASSERT_TRUE(product.parms_id() == context->first_parms_id());
    }

    TEST(EvaluatorTest, BFVEncryptExponentiateDecrypt)
    {
        EncryptionParameters parms(scheme_type::BFV);
        Modulus plain_modulus(1 << 6);
        parms.set_poly_modulus_degree(128);
        parms.set_plain_modulus(plain_modulus);
        parms.set_coeff_modulus(CoeffModulus::Create(128, { 40, 40, 40 }));

        auto context = SEALContext::Create(parms, false, sec_level_type::none);
        KeyGenerator keygen(context);

        IntegerEncoder encoder(context);
        Encryptor encryptor(context, keygen.public_key());
        Evaluator evaluator(context);
        Decryptor decryptor(context, keygen.secret_key());
        RelinKeys rlk = keygen.relin_keys_local();

        Ciphertext encrypted;
        Plaintext plain;
        encryptor.encrypt(encoder.encode(5), encrypted);
        evaluator.exponentiate_inplace(encrypted, 1, rlk);
        decryptor.decrypt(encrypted, plain);
        ASSERT_EQ(static_cast<uint64_t>(5), encoder.decode_uint64(plain));
        ASSERT_TRUE(encrypted.parms_id() == context->first_parms_id());

        encryptor.encrypt(encoder.encode(7), encrypted);
        evaluator.exponentiate_inplace(encrypted, 2, rlk);
        decryptor.decrypt(encrypted, plain);
        ASSERT_EQ(static_cast<uint64_t>(49), encoder.decode_uint64(plain));
        ASSERT_TRUE(encrypted.parms_id() == context->first_parms_id());

        encryptor.encrypt(encoder.encode(-7), encrypted);
        evaluator.exponentiate_inplace(encrypted, 3, rlk);
        decryptor.decrypt(encrypted, plain);
        ASSERT_TRUE(static_cast<int64_t>(-343) == encoder.decode_int64(plain));
        ASSERT_TRUE(encrypted.parms_id() == context->first_parms_id());

        encryptor.encrypt(encoder.encode(0x100), encrypted);
        evaluator.exponentiate_inplace(encrypted, 4, rlk);
        decryptor.decrypt(encrypted, plain);
        ASSERT_EQ(static_cast<uint64_t>(0x100000000), encoder.decode_uint64(plain));
        ASSERT_TRUE(encrypted.parms_id() == context->first_parms_id());
    }

    TEST(EvaluatorTest, BFVEncryptAddManyDecrypt)
    {
        EncryptionParameters parms(scheme_type::BFV);
        Modulus plain_modulus(1 << 6);
        parms.set_poly_modulus_degree(128);
        parms.set_plain_modulus(plain_modulus);
        parms.set_coeff_modulus(CoeffModulus::Create(128, { 40, 40 }));

        auto context = SEALContext::Create(parms, false, sec_level_type::none);
        KeyGenerator keygen(context);

        IntegerEncoder encoder(context);
        Encryptor encryptor(context, keygen.public_key());
        Evaluator evaluator(context);
        Decryptor decryptor(context, keygen.secret_key());

        Ciphertext encrypted1, encrypted2, encrypted3, encrypted4, sum;
        Plaintext plain;
        encryptor.encrypt(encoder.encode(5), encrypted1);
        encryptor.encrypt(encoder.encode(6), encrypted2);
        encryptor.encrypt(encoder.encode(7), encrypted3);
        vector<Ciphertext> encrypteds = { encrypted1, encrypted2, encrypted3 };
        evaluator.add_many(encrypteds, sum);
        decryptor.decrypt(sum, plain);
        ASSERT_EQ(static_cast<uint64_t>(18), encoder.decode_uint64(plain));
        ASSERT_TRUE(encrypted1.parms_id() == sum.parms_id());
        ASSERT_TRUE(encrypted2.parms_id() == sum.parms_id());
        ASSERT_TRUE(encrypted3.parms_id() == sum.parms_id());
        ASSERT_TRUE(sum.parms_id() == context->first_parms_id());

        encryptor.encrypt(encoder.encode(-9), encrypted1);
        encryptor.encrypt(encoder.encode(-17), encrypted2);
        encrypteds = {
            encrypted1,
            encrypted2,
        };
        evaluator.add_many(encrypteds, sum);
        decryptor.decrypt(sum, plain);
        ASSERT_TRUE(static_cast<int64_t>(-26) == encoder.decode_int64(plain));
        ASSERT_TRUE(encrypted1.parms_id() == sum.parms_id());
        ASSERT_TRUE(encrypted2.parms_id() == sum.parms_id());
        ASSERT_TRUE(sum.parms_id() == context->first_parms_id());

        encryptor.encrypt(encoder.encode(2), encrypted1);
        encryptor.encrypt(encoder.encode(-31), encrypted2);
        encryptor.encrypt(encoder.encode(7), encrypted3);
        encrypteds = { encrypted1, encrypted2, encrypted3 };
        evaluator.add_many(encrypteds, sum);
        decryptor.decrypt(sum, plain);
        ASSERT_TRUE(static_cast<int64_t>(-22) == encoder.decode_int64(plain));
        ASSERT_TRUE(encrypted1.parms_id() == sum.parms_id());
        ASSERT_TRUE(encrypted2.parms_id() == sum.parms_id());
        ASSERT_TRUE(encrypted3.parms_id() == sum.parms_id());
        ASSERT_TRUE(sum.parms_id() == context->first_parms_id());

        encryptor.encrypt(encoder.encode(1), encrypted1);
        encryptor.encrypt(encoder.encode(-1), encrypted2);
        encryptor.encrypt(encoder.encode(1), encrypted3);
        encryptor.encrypt(encoder.encode(-1), encrypted4);
        encrypteds = { encrypted1, encrypted2, encrypted3, encrypted4 };
        evaluator.add_many(encrypteds, sum);
        decryptor.decrypt(sum, plain);
        ASSERT_EQ(static_cast<uint64_t>(0), encoder.decode_uint64(plain));
        ASSERT_TRUE(encrypted1.parms_id() == sum.parms_id());
        ASSERT_TRUE(encrypted2.parms_id() == sum.parms_id());
        ASSERT_TRUE(encrypted3.parms_id() == sum.parms_id());
        ASSERT_TRUE(encrypted4.parms_id() == sum.parms_id());
        ASSERT_TRUE(sum.parms_id() == context->first_parms_id());

        encryptor.encrypt(encoder.encode(98765), encrypted1);
        encryptor.encrypt(encoder.encode(0), encrypted2);
        encryptor.encrypt(encoder.encode(12345), encrypted3);
        encryptor.encrypt(encoder.encode(34567), encrypted4);
        encrypteds = { encrypted1, encrypted2, encrypted3, encrypted4 };
        evaluator.add_many(encrypteds, sum);
        decryptor.decrypt(sum, plain);
        ASSERT_EQ(static_cast<uint64_t>(145677), encoder.decode_uint64(plain));
        ASSERT_TRUE(encrypted1.parms_id() == sum.parms_id());
        ASSERT_TRUE(encrypted2.parms_id() == sum.parms_id());
        ASSERT_TRUE(encrypted3.parms_id() == sum.parms_id());
        ASSERT_TRUE(encrypted4.parms_id() == sum.parms_id());
        ASSERT_TRUE(sum.parms_id() == context->first_parms_id());
    }

    TEST(EvaluatorTest, TransformPlainToNTT)
    {
        EncryptionParameters parms(scheme_type::BFV);
        Modulus plain_modulus(1 << 6);
        parms.set_poly_modulus_degree(128);
        parms.set_plain_modulus(plain_modulus);
        parms.set_coeff_modulus(CoeffModulus::Create(128, { 40, 40, 40 }));
        auto context = SEALContext::Create(parms, true, sec_level_type::none);

        Evaluator evaluator(context);
        Plaintext plain("0");
        ASSERT_FALSE(plain.is_ntt_form());
        evaluator.transform_to_ntt_inplace(plain, context->first_parms_id());
        ASSERT_TRUE(plain.is_zero());
        ASSERT_TRUE(plain.is_ntt_form());
        ASSERT_TRUE(plain.parms_id() == context->first_parms_id());

        plain.release();
        plain = "0";
        ASSERT_FALSE(plain.is_ntt_form());
        auto next_parms_id = context->first_context_data()->next_context_data()->parms_id();
        evaluator.transform_to_ntt_inplace(plain, next_parms_id);
        ASSERT_TRUE(plain.is_zero());
        ASSERT_TRUE(plain.is_ntt_form());
        ASSERT_TRUE(plain.parms_id() == next_parms_id);

        plain.release();
        plain = "1";
        ASSERT_FALSE(plain.is_ntt_form());
        evaluator.transform_to_ntt_inplace(plain, context->first_parms_id());
        for (size_t i = 0; i < 256; i++)
        {
            ASSERT_TRUE(plain[i] == uint64_t(1));
        }
        ASSERT_TRUE(plain.is_ntt_form());
        ASSERT_TRUE(plain.parms_id() == context->first_parms_id());

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
        evaluator.transform_to_ntt_inplace(plain, context->first_parms_id());
        for (size_t i = 0; i < 256; i++)
        {
            ASSERT_TRUE(plain[i] == uint64_t(2));
        }
        ASSERT_TRUE(plain.is_ntt_form());
        ASSERT_TRUE(plain.parms_id() == context->first_parms_id());

        plain.release();
        plain = "2";
        evaluator.transform_to_ntt_inplace(plain, next_parms_id);
        for (size_t i = 0; i < 128; i++)
        {
            ASSERT_TRUE(plain[i] == uint64_t(2));
        }
        ASSERT_TRUE(plain.is_ntt_form());
        ASSERT_TRUE(plain.parms_id() == next_parms_id);
    }

    TEST(EvaluatorTest, TransformEncryptedToFromNTT)
    {
        EncryptionParameters parms(scheme_type::BFV);
        Modulus plain_modulus(1 << 6);
        parms.set_poly_modulus_degree(128);
        parms.set_plain_modulus(plain_modulus);
        parms.set_coeff_modulus(CoeffModulus::Create(128, { 40, 40 }));

        auto context = SEALContext::Create(parms, false, sec_level_type::none);
        KeyGenerator keygen(context);

        Encryptor encryptor(context, keygen.public_key());
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
        ASSERT_TRUE(encrypted.parms_id() == context->first_parms_id());

        plain = "1";
        encryptor.encrypt(plain, encrypted);
        evaluator.transform_to_ntt_inplace(encrypted);
        evaluator.transform_from_ntt_inplace(encrypted);
        decryptor.decrypt(encrypted, plain);
        ASSERT_TRUE(plain.to_string() == "1");
        ASSERT_TRUE(encrypted.parms_id() == context->first_parms_id());

        plain = "Fx^10 + Ex^9 + Dx^8 + Cx^7 + Bx^6 + Ax^5 + 1x^4 + 2x^3 + 3x^2 + 4x^1 + 5";
        encryptor.encrypt(plain, encrypted);
        evaluator.transform_to_ntt_inplace(encrypted);
        evaluator.transform_from_ntt_inplace(encrypted);
        decryptor.decrypt(encrypted, plain);
        ASSERT_TRUE(plain.to_string() == "Fx^10 + Ex^9 + Dx^8 + Cx^7 + Bx^6 + Ax^5 + 1x^4 + 2x^3 + 3x^2 + 4x^1 + 5");
        ASSERT_TRUE(encrypted.parms_id() == context->first_parms_id());
    }

    TEST(EvaluatorTest, BFVEncryptMultiplyPlainNTTDecrypt)
    {
        EncryptionParameters parms(scheme_type::BFV);
        Modulus plain_modulus(1 << 6);
        parms.set_poly_modulus_degree(128);
        parms.set_plain_modulus(plain_modulus);
        parms.set_coeff_modulus(CoeffModulus::Create(128, { 40, 40 }));

        auto context = SEALContext::Create(parms, false, sec_level_type::none);
        KeyGenerator keygen(context);

        Encryptor encryptor(context, keygen.public_key());
        Evaluator evaluator(context);
        Decryptor decryptor(context, keygen.secret_key());

        Plaintext plain;
        Plaintext plain_multiplier;
        Ciphertext encrypted;

        plain = 0;
        encryptor.encrypt(plain, encrypted);
        evaluator.transform_to_ntt_inplace(encrypted);
        plain_multiplier = 1;
        evaluator.transform_to_ntt_inplace(plain_multiplier, context->first_parms_id());
        evaluator.multiply_plain_inplace(encrypted, plain_multiplier);
        evaluator.transform_from_ntt_inplace(encrypted);
        decryptor.decrypt(encrypted, plain);
        ASSERT_TRUE(plain.to_string() == "0");
        ASSERT_TRUE(encrypted.parms_id() == context->first_parms_id());

        plain = 2;
        encryptor.encrypt(plain, encrypted);
        evaluator.transform_to_ntt_inplace(encrypted);
        plain_multiplier.release();
        plain_multiplier = 3;
        evaluator.transform_to_ntt_inplace(plain_multiplier, context->first_parms_id());
        evaluator.multiply_plain_inplace(encrypted, plain_multiplier);
        evaluator.transform_from_ntt_inplace(encrypted);
        decryptor.decrypt(encrypted, plain);
        ASSERT_TRUE(plain.to_string() == "6");
        ASSERT_TRUE(encrypted.parms_id() == context->first_parms_id());

        plain = 1;
        encryptor.encrypt(plain, encrypted);
        evaluator.transform_to_ntt_inplace(encrypted);
        plain_multiplier.release();
        plain_multiplier = "Fx^10 + Ex^9 + Dx^8 + Cx^7 + Bx^6 + Ax^5 + 1x^4 + 2x^3 + 3x^2 + 4x^1 + 5";
        evaluator.transform_to_ntt_inplace(plain_multiplier, context->first_parms_id());
        evaluator.multiply_plain_inplace(encrypted, plain_multiplier);
        evaluator.transform_from_ntt_inplace(encrypted);
        decryptor.decrypt(encrypted, plain);
        ASSERT_TRUE(plain.to_string() == "Fx^10 + Ex^9 + Dx^8 + Cx^7 + Bx^6 + Ax^5 + 1x^4 + 2x^3 + 3x^2 + 4x^1 + 5");
        ASSERT_TRUE(encrypted.parms_id() == context->first_parms_id());

        plain = "1x^20";
        encryptor.encrypt(plain, encrypted);
        evaluator.transform_to_ntt_inplace(encrypted);
        plain_multiplier.release();
        plain_multiplier = "Fx^10 + Ex^9 + Dx^8 + Cx^7 + Bx^6 + Ax^5 + 1x^4 + 2x^3 + 3x^2 + 4x^1 + 5";
        evaluator.transform_to_ntt_inplace(plain_multiplier, context->first_parms_id());
        evaluator.multiply_plain_inplace(encrypted, plain_multiplier);
        evaluator.transform_from_ntt_inplace(encrypted);
        decryptor.decrypt(encrypted, plain);
        ASSERT_TRUE(
            plain.to_string() ==
            "Fx^30 + Ex^29 + Dx^28 + Cx^27 + Bx^26 + Ax^25 + 1x^24 + 2x^23 + 3x^22 + 4x^21 + 5x^20");
        ASSERT_TRUE(encrypted.parms_id() == context->first_parms_id());
    }

    TEST(EvaluatorTest, BFVEncryptApplyGaloisDecrypt)
    {
        EncryptionParameters parms(scheme_type::BFV);
        Modulus plain_modulus(257);
        parms.set_poly_modulus_degree(8);
        parms.set_plain_modulus(plain_modulus);
        parms.set_coeff_modulus(CoeffModulus::Create(8, { 40, 40 }));

        auto context = SEALContext::Create(parms, false, sec_level_type::none);
        KeyGenerator keygen(context);
        GaloisKeys glk = keygen.galois_keys_local(vector<uint32_t>{ 1, 3, 5, 15 });

        Encryptor encryptor(context, keygen.public_key());
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
        EncryptionParameters parms(scheme_type::BFV);
        Modulus plain_modulus(257);
        parms.set_poly_modulus_degree(8);
        parms.set_plain_modulus(plain_modulus);
        parms.set_coeff_modulus(CoeffModulus::Create(8, { 40, 40 }));

        auto context = SEALContext::Create(parms, false, sec_level_type::none);
        KeyGenerator keygen(context);
        GaloisKeys glk = keygen.galois_keys_local();

        Encryptor encryptor(context, keygen.public_key());
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
        // the common parameters: the plaintext and the polynomial moduli
        Modulus plain_modulus(1 << 6);

        // the parameters and the context of the higher level
        EncryptionParameters parms(scheme_type::BFV);
        parms.set_poly_modulus_degree(128);
        parms.set_plain_modulus(plain_modulus);
        parms.set_coeff_modulus(CoeffModulus::Create(128, { 30, 30, 30, 30 }));

        auto context = SEALContext::Create(parms, true, sec_level_type::none);
        KeyGenerator keygen(context);
        SecretKey secret_key = keygen.secret_key();
        Encryptor encryptor(context, keygen.public_key());
        Evaluator evaluator(context);
        Decryptor decryptor(context, keygen.secret_key());
        auto parms_id = context->first_parms_id();

        Ciphertext encrypted(context);
        Ciphertext encryptedRes;
        Plaintext plain;

        plain = 0;
        encryptor.encrypt(plain, encrypted);
        evaluator.mod_switch_to_next(encrypted, encryptedRes);
        decryptor.decrypt(encryptedRes, plain);
        parms_id = context->get_context_data(parms_id)->next_context_data()->parms_id();
        ASSERT_TRUE(encryptedRes.parms_id() == parms_id);
        ASSERT_TRUE(plain.to_string() == "0");

        evaluator.mod_switch_to_next_inplace(encryptedRes);
        decryptor.decrypt(encryptedRes, plain);
        parms_id = context->get_context_data(parms_id)->next_context_data()->parms_id();
        ASSERT_TRUE(encryptedRes.parms_id() == parms_id);
        ASSERT_TRUE(plain.to_string() == "0");

        parms_id = context->first_parms_id();
        plain = 1;
        encryptor.encrypt(plain, encrypted);
        evaluator.mod_switch_to_next(encrypted, encryptedRes);
        decryptor.decrypt(encryptedRes, plain);
        parms_id = context->get_context_data(parms_id)->next_context_data()->parms_id();
        ASSERT_TRUE(encryptedRes.parms_id() == parms_id);
        ASSERT_TRUE(plain.to_string() == "1");

        evaluator.mod_switch_to_next_inplace(encryptedRes);
        decryptor.decrypt(encryptedRes, plain);
        parms_id = context->get_context_data(parms_id)->next_context_data()->parms_id();
        ASSERT_TRUE(encryptedRes.parms_id() == parms_id);
        ASSERT_TRUE(plain.to_string() == "1");

        parms_id = context->first_parms_id();
        plain = "1x^127";
        encryptor.encrypt(plain, encrypted);
        evaluator.mod_switch_to_next(encrypted, encryptedRes);
        decryptor.decrypt(encryptedRes, plain);
        parms_id = context->get_context_data(parms_id)->next_context_data()->parms_id();
        ASSERT_TRUE(encryptedRes.parms_id() == parms_id);
        ASSERT_TRUE(plain.to_string() == "1x^127");

        evaluator.mod_switch_to_next_inplace(encryptedRes);
        decryptor.decrypt(encryptedRes, plain);
        parms_id = context->get_context_data(parms_id)->next_context_data()->parms_id();
        ASSERT_TRUE(encryptedRes.parms_id() == parms_id);
        ASSERT_TRUE(plain.to_string() == "1x^127");

        parms_id = context->first_parms_id();
        plain = "5x^64 + Ax^5";
        encryptor.encrypt(plain, encrypted);
        evaluator.mod_switch_to_next(encrypted, encryptedRes);
        decryptor.decrypt(encryptedRes, plain);
        parms_id = context->get_context_data(parms_id)->next_context_data()->parms_id();
        ASSERT_TRUE(encryptedRes.parms_id() == parms_id);
        ASSERT_TRUE(plain.to_string() == "5x^64 + Ax^5");

        evaluator.mod_switch_to_next_inplace(encryptedRes);
        decryptor.decrypt(encryptedRes, plain);
        parms_id = context->get_context_data(parms_id)->next_context_data()->parms_id();
        ASSERT_TRUE(encryptedRes.parms_id() == parms_id);
        ASSERT_TRUE(plain.to_string() == "5x^64 + Ax^5");
    }

    TEST(EvaluatorTest, BFVEncryptModSwitchToDecrypt)
    {
        // the common parameters: the plaintext and the polynomial moduli
        Modulus plain_modulus(1 << 6);

        // the parameters and the context of the higher level
        EncryptionParameters parms(scheme_type::BFV);
        parms.set_poly_modulus_degree(128);
        parms.set_plain_modulus(plain_modulus);
        parms.set_coeff_modulus(CoeffModulus::Create(128, { 30, 30, 30, 30 }));

        auto context = SEALContext::Create(parms, true, sec_level_type::none);
        KeyGenerator keygen(context);
        SecretKey secret_key = keygen.secret_key();
        Encryptor encryptor(context, keygen.public_key());
        Evaluator evaluator(context);
        Decryptor decryptor(context, keygen.secret_key());
        auto parms_id = context->first_parms_id();

        Ciphertext encrypted(context);
        Plaintext plain;

        plain = 0;
        encryptor.encrypt(plain, encrypted);
        evaluator.mod_switch_to_inplace(encrypted, parms_id);
        decryptor.decrypt(encrypted, plain);
        ASSERT_TRUE(encrypted.parms_id() == parms_id);
        ASSERT_TRUE(plain.to_string() == "0");

        parms_id = context->get_context_data(parms_id)->next_context_data()->parms_id();
        encryptor.encrypt(plain, encrypted);
        evaluator.mod_switch_to_inplace(encrypted, parms_id);
        decryptor.decrypt(encrypted, plain);
        ASSERT_TRUE(encrypted.parms_id() == parms_id);
        ASSERT_TRUE(plain.to_string() == "0");

        parms_id = context->get_context_data(parms_id)->next_context_data()->parms_id();
        encryptor.encrypt(plain, encrypted);
        evaluator.mod_switch_to_inplace(encrypted, parms_id);
        decryptor.decrypt(encrypted, plain);
        ASSERT_TRUE(encrypted.parms_id() == parms_id);
        ASSERT_TRUE(plain.to_string() == "0");

        parms_id = context->first_parms_id();
        encryptor.encrypt(plain, encrypted);
        parms_id = context->get_context_data(parms_id)->next_context_data()->next_context_data()->parms_id();
        evaluator.mod_switch_to_inplace(encrypted, parms_id);
        decryptor.decrypt(encrypted, plain);
        ASSERT_TRUE(encrypted.parms_id() == parms_id);
        ASSERT_TRUE(plain.to_string() == "0");

        parms_id = context->first_parms_id();
        plain = 1;
        encryptor.encrypt(plain, encrypted);
        evaluator.mod_switch_to_inplace(encrypted, parms_id);
        decryptor.decrypt(encrypted, plain);
        ASSERT_TRUE(encrypted.parms_id() == parms_id);
        ASSERT_TRUE(plain.to_string() == "1");

        parms_id = context->get_context_data(parms_id)->next_context_data()->parms_id();
        encryptor.encrypt(plain, encrypted);
        evaluator.mod_switch_to_inplace(encrypted, parms_id);
        decryptor.decrypt(encrypted, plain);
        ASSERT_TRUE(encrypted.parms_id() == parms_id);
        ASSERT_TRUE(plain.to_string() == "1");

        parms_id = context->get_context_data(parms_id)->next_context_data()->parms_id();
        encryptor.encrypt(plain, encrypted);
        evaluator.mod_switch_to_inplace(encrypted, parms_id);
        decryptor.decrypt(encrypted, plain);
        ASSERT_TRUE(encrypted.parms_id() == parms_id);
        ASSERT_TRUE(plain.to_string() == "1");

        parms_id = context->first_parms_id();
        encryptor.encrypt(plain, encrypted);
        parms_id = context->get_context_data(parms_id)->next_context_data()->next_context_data()->parms_id();
        evaluator.mod_switch_to_inplace(encrypted, parms_id);
        decryptor.decrypt(encrypted, plain);
        ASSERT_TRUE(encrypted.parms_id() == parms_id);
        ASSERT_TRUE(plain.to_string() == "1");

        parms_id = context->first_parms_id();
        plain = "1x^127";
        encryptor.encrypt(plain, encrypted);
        evaluator.mod_switch_to_inplace(encrypted, parms_id);
        decryptor.decrypt(encrypted, plain);
        ASSERT_TRUE(encrypted.parms_id() == parms_id);
        ASSERT_TRUE(plain.to_string() == "1x^127");

        parms_id = context->get_context_data(parms_id)->next_context_data()->parms_id();
        encryptor.encrypt(plain, encrypted);
        evaluator.mod_switch_to_inplace(encrypted, parms_id);
        decryptor.decrypt(encrypted, plain);
        ASSERT_TRUE(encrypted.parms_id() == parms_id);
        ASSERT_TRUE(plain.to_string() == "1x^127");

        parms_id = context->get_context_data(parms_id)->next_context_data()->parms_id();
        encryptor.encrypt(plain, encrypted);
        evaluator.mod_switch_to_inplace(encrypted, parms_id);
        decryptor.decrypt(encrypted, plain);
        ASSERT_TRUE(encrypted.parms_id() == parms_id);
        ASSERT_TRUE(plain.to_string() == "1x^127");

        parms_id = context->first_parms_id();
        encryptor.encrypt(plain, encrypted);
        parms_id = context->get_context_data(parms_id)->next_context_data()->next_context_data()->parms_id();
        evaluator.mod_switch_to_inplace(encrypted, parms_id);
        decryptor.decrypt(encrypted, plain);
        ASSERT_TRUE(encrypted.parms_id() == parms_id);
        ASSERT_TRUE(plain.to_string() == "1x^127");

        parms_id = context->first_parms_id();
        plain = "5x^64 + Ax^5";
        encryptor.encrypt(plain, encrypted);
        evaluator.mod_switch_to_inplace(encrypted, parms_id);
        decryptor.decrypt(encrypted, plain);
        ASSERT_TRUE(encrypted.parms_id() == parms_id);
        ASSERT_TRUE(plain.to_string() == "5x^64 + Ax^5");

        parms_id = context->get_context_data(parms_id)->next_context_data()->parms_id();
        encryptor.encrypt(plain, encrypted);
        evaluator.mod_switch_to_inplace(encrypted, parms_id);
        decryptor.decrypt(encrypted, plain);
        ASSERT_TRUE(encrypted.parms_id() == parms_id);
        ASSERT_TRUE(plain.to_string() == "5x^64 + Ax^5");

        parms_id = context->get_context_data(parms_id)->next_context_data()->parms_id();
        encryptor.encrypt(plain, encrypted);
        evaluator.mod_switch_to_inplace(encrypted, parms_id);
        decryptor.decrypt(encrypted, plain);
        ASSERT_TRUE(encrypted.parms_id() == parms_id);
        ASSERT_TRUE(plain.to_string() == "5x^64 + Ax^5");

        parms_id = context->first_parms_id();
        encryptor.encrypt(plain, encrypted);
        parms_id = context->get_context_data(parms_id)->next_context_data()->next_context_data()->parms_id();
        evaluator.mod_switch_to_inplace(encrypted, parms_id);
        decryptor.decrypt(encrypted, plain);
        ASSERT_TRUE(encrypted.parms_id() == parms_id);
        ASSERT_TRUE(plain.to_string() == "5x^64 + Ax^5");
    }
} // namespace sealtest
